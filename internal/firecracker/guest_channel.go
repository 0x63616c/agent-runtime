package firecracker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxauthority"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
)

const (
	maximumGuestControlResponseBytes = 48 << 10
	maximumGuestOutputBytes          = 32 << 10
	maximumGuestOutputChunks         = 4
	maximumGuestSecretBytes          = 16 << 10
)

// GuestOutput is one bounded, ordered private guest-output chunk. Its caller
// must route it to a durable output owner before any future profile can claim
// command-output delivery.
type GuestOutput struct {
	Stream   string
	Sequence uint64
	Digest   string
	Data     []byte
}

// GuestDispatchResult records the only terminal result accepted from a guest
// dispatch exchange and the bounded output that preceded it.
type GuestDispatchResult struct {
	State       string
	Outputs     []GuestOutput
	Observation *sandboxhostprotocol.Observation
}

// GuestIdentityBinder binds the boot identities that the guest must echo on
// every private vsock connection. A host obtains those values only from the
// immutable launch request and verified fixture stage.
type GuestIdentityBinder interface {
	BindGuestIdentity(context.Context, string, string) error
}

// GuestDispatchCanceller is the private cancellation extension of the bounded
// guest operation protocol. It is separate from Close so a live guest can reap
// one fenced operation before the host must reap the entire Jailer.
type GuestDispatchCanceller interface {
	CancelDispatch(context.Context, sandboxhostprotocol.Envelope) error
}

// UnixGuestControlChannel is the host-side private Firecracker vsock-UDS
// channel. It exposes no TCP, proxy, or arbitrary destination surface.
type UnixGuestControlChannel struct {
	dial unixSocketDialer

	mu             sync.Mutex
	socket         string
	vmID           string
	fixtureVersion string
	closed         bool
	connections    map[net.Conn]struct{}
	proxySessions  map[*sandboxauthority.ProxySession]struct{}
}

// guestSecretSession is the one-use, connection-bound SecretSink for an
// authenticated guest command. Its textual frames are deliberately bounded
// and never enter logs, audit facts, command payloads, or durable output.
type guestSecretSession struct {
	connection net.Conn
	reader     *bufio.Reader
	envelopeID string

	mu         sync.Mutex
	delivered  bool
	treeReaped bool
}

// NewUnixGuestControlChannel constructs a channel before the exact staged UDS
// and immutable guest identity are bound.
func NewUnixGuestControlChannel(dialer unixSocketDialer) (*UnixGuestControlChannel, error) {
	if dialer == nil {
		return nil, fmt.Errorf("create guest control channel: %w", ErrSmokeUnavailable)
	}
	return &UnixGuestControlChannel{dial: dialer, connections: make(map[net.Conn]struct{}), proxySessions: make(map[*sandboxauthority.ProxySession]struct{})}, nil
}

// BindGuestIdentity fixes the exact boot VM and verified fixture identity once.
func (channel *UnixGuestControlChannel) BindGuestIdentity(ctx context.Context, vmID, fixtureVersion string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if channel == nil || !validVMID(vmID) || !validFixtureVersion(fixtureVersion) {
		return fmt.Errorf("bind guest identity: %w", ErrSmokeUnavailable)
	}
	channel.mu.Lock()
	defer channel.mu.Unlock()
	if channel.closed || channel.vmID != "" || channel.fixtureVersion != "" {
		return fmt.Errorf("bind guest identity: %w", ErrSmokeUnavailable)
	}
	channel.vmID = vmID
	channel.fixtureVersion = fixtureVersion
	return nil
}

// Bind fixes the exact host-visible staged vsock UDS once.
func (channel *UnixGuestControlChannel) Bind(ctx context.Context, socket string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if channel == nil || !safeAbsolutePath(socket) {
		return fmt.Errorf("bind guest control channel: %w", ErrSmokeUnavailable)
	}
	channel.mu.Lock()
	defer channel.mu.Unlock()
	if channel.closed || channel.socket != "" || channel.vmID == "" || channel.fixtureVersion == "" {
		return fmt.Errorf("bind guest control channel: %w", ErrSmokeUnavailable)
	}
	channel.socket = socket
	return nil
}

// Ping proves the private peer reports the exact immutable VM identity.
func (channel *UnixGuestControlChannel) Ping(ctx context.Context, vmID string) error {
	if channel == nil || vmID == "" {
		return fmt.Errorf("ping guest control: %w", ErrSmokeUnavailable)
	}
	channel.mu.Lock()
	expectedVMID := channel.vmID
	channel.mu.Unlock()
	if vmID != expectedVMID {
		return fmt.Errorf("ping guest control: %w", ErrSmokeUnavailable)
	}
	connection, reader, err := channel.open(ctx)
	if err != nil {
		return err
	}
	defer channel.release(connection)
	if _, err := fmt.Fprint(connection, "PING bootstrap\n"); err != nil {
		return fmt.Errorf("write guest ping: %w", err)
	}
	line, err := readGuestControlResponse(reader)
	if err != nil || line != "PONG "+expectedVMID+" bootstrap" {
		return fmt.Errorf("ping guest control: %w", ErrSmokeUnavailable)
	}
	return nil
}

// ExecuteDispatch carries one host-authenticated, lease-fenced envelope over
// the private peer. A guest can only answer unavailable until its profile has
// protected Linux/KVM evidence; a malformed or widened response is refused.
func (channel *UnixGuestControlChannel) ExecuteDispatch(ctx context.Context, envelope sandboxhostprotocol.Envelope) error {
	frame, err := EncodeGuestDispatch(envelope)
	if err != nil {
		return err
	}
	channel.mu.Lock()
	vmID := channel.vmID
	channel.mu.Unlock()
	if envelope.SandboxID != vmID {
		return fmt.Errorf("dispatch guest control: %w", ErrCapabilityUnavailable)
	}
	connection, reader, err := channel.open(ctx)
	if err != nil {
		return err
	}
	defer channel.release(connection)
	if _, err := fmt.Fprintf(connection, "DISPATCH %s\n", base64.RawURLEncoding.EncodeToString(frame)); err != nil {
		return fmt.Errorf("write guest dispatch: %w", err)
	}
	line, err := readGuestControlResponse(reader)
	if err != nil || line != "RESULT UNAVAILABLE "+envelope.EnvelopeID {
		return fmt.Errorf("read guest dispatch result: %w", ErrCapabilityUnavailable)
	}
	return fmt.Errorf("guest dispatch: %w", ErrCapabilityUnavailable)
}

// ExecuteAuthenticatedDispatch transports the exact control-signed canonical
// envelope retained by sandboxhostprocess after control trust verification.
func (channel *UnixGuestControlChannel) ExecuteAuthenticatedDispatch(ctx context.Context, envelope sandboxhostprotocol.Envelope, authenticatedEnvelope []byte) error {
	result, err := channel.DispatchAuthenticated(ctx, envelope, authenticatedEnvelope)
	if err != nil {
		return err
	}
	if result.State == "SUCCEEDED" {
		return nil
	}
	if result.State != "UNAVAILABLE" {
		return fmt.Errorf("authenticated guest dispatch state: %w", ErrCapabilityUnavailable)
	}
	return fmt.Errorf("authenticated guest dispatch: %w", ErrCapabilityUnavailable)
}

// DispatchAuthenticated carries a signed control envelope and returns bounded
// ordered output before the guest's terminal result. It does not itself make
// that output durable or authorize a Firecracker profile.
func (channel *UnixGuestControlChannel) DispatchAuthenticated(ctx context.Context, envelope sandboxhostprotocol.Envelope, authenticatedEnvelope []byte) (GuestDispatchResult, error) {
	frame, err := EncodeAuthenticatedGuestDispatch(envelope, authenticatedEnvelope)
	if err != nil {
		return GuestDispatchResult{}, err
	}
	channel.mu.Lock()
	vmID := channel.vmID
	channel.mu.Unlock()
	if envelope.SandboxID != vmID {
		return GuestDispatchResult{}, fmt.Errorf("dispatch guest control: %w", ErrCapabilityUnavailable)
	}
	connection, reader, err := channel.open(ctx)
	if err != nil {
		return GuestDispatchResult{}, err
	}
	defer channel.release(connection)
	if _, err := fmt.Fprintf(connection, "DISPATCH %s\n", base64.RawURLEncoding.EncodeToString(frame)); err != nil {
		return GuestDispatchResult{}, fmt.Errorf("write authenticated guest dispatch: %w", err)
	}
	return readGuestDispatchResult(reader, envelope)
}

// DispatchAuthenticatedSecret binds one resolver/Manager lifecycle to the
// same authenticated vsock connection that proves the exact guest request.
// Output is held until the guest proves tree reaping and the sink confirms
// revocation, then literal-redacted chunks cross the durable host boundary.
func (channel *UnixGuestControlChannel) DispatchAuthenticatedSecret(ctx context.Context, envelope sandboxhostprotocol.Envelope, authenticatedEnvelope []byte, authority *SecretExecutionAuthority, emit sandboxhostprotocol.GuestOutputEmitter) error {
	if channel == nil || authority == nil || emit == nil {
		return fmt.Errorf("dispatch authenticated guest secret: %w", ErrCapabilityUnavailable)
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	command, err := DecodeGuestSecretCommand(envelope.Payload)
	if err != nil || envelope.OperationKind != GuestSecretCommandOperationKind || command.Secret.Principal != envelope.Principal || command.Secret.SandboxID != envelope.SandboxID || command.Secret.ProcessID != envelope.ProcessID || command.Secret.OperationID != envelope.OperationID || !command.Secret.ExpiresAt.Equal(envelope.ExpiresAt) {
		return fmt.Errorf("dispatch authenticated guest secret: %w", ErrCapabilityUnavailable)
	}
	frame, err := EncodeAuthenticatedGuestDispatch(envelope, authenticatedEnvelope)
	if err != nil {
		return err
	}
	channel.mu.Lock()
	vmID := channel.vmID
	channel.mu.Unlock()
	if envelope.SandboxID != vmID {
		return fmt.Errorf("dispatch authenticated guest secret: %w", ErrCapabilityUnavailable)
	}
	connection, reader, err := channel.open(ctx)
	if err != nil {
		return err
	}
	defer channel.release(connection)
	stopCancellation := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopCancellation()
	if _, err := fmt.Fprintf(connection, "SECRET_DISPATCH %s\n", base64.RawURLEncoding.EncodeToString(frame)); err != nil {
		return fmt.Errorf("write authenticated guest secret dispatch: %w", err)
	}
	request, err := readGuestSecretRequest(reader, envelope.EnvelopeID)
	if err != nil || request != command.Secret {
		return fmt.Errorf("read guest secret request: %w", ErrCapabilityUnavailable)
	}
	session := &guestSecretSession{connection: connection, reader: reader, envelopeID: envelope.EnvelopeID}
	scoped, err := authority.BindSink(session)
	if err != nil {
		return err
	}
	active, started, settled := false, false, false
	defer func() {
		if !active || settled {
			return
		}
		if started {
			_ = scoped.AbandonAfterLostContact(context.Background(), command.Secret.ProcessID)
			return
		}
		_ = scoped.AbortBeforeStart(context.Background(), command.Secret.ProcessID)
	}()
	if _, err := scoped.Begin(ctx, envelope); err != nil {
		return err
	}
	active = true
	// Set this before writing: an interrupted write can leave the peer with a
	// complete START frame, so only a Jailer reaper may settle that uncertainty.
	started = true
	if _, err := fmt.Fprintf(connection, "SECRET_START %s\n", envelope.EnvelopeID); err != nil {
		return fmt.Errorf("write guest secret start: %w", err)
	}
	result, err := readGuestSecretResultBeforeReap(reader, envelope.EnvelopeID)
	if err != nil {
		return err
	}
	durableOutputs := make([]sandboxhostprotocol.GuestOutput, 0, len(result.Outputs))
	for _, output := range result.Outputs {
		if output.Stream != "stdout" && output.Stream != "stderr" {
			continue
		}
		redacted := scoped.RedactOutput(command.Secret.ProcessID, output.Data)
		durableOutputs = append(durableOutputs, sandboxhostprotocol.GuestOutput{Stream: output.Stream, Sequence: output.Sequence, Data: append([]byte(nil), redacted...)})
		for index := range redacted {
			redacted[index] = 0
		}
	}
	session.markTreeReaped()
	if err := scoped.RevokeAfterTreeReap(ctx, command.Secret.ProcessID); err != nil {
		zeroGuestOutputs(durableOutputs)
		return err
	}
	settled = true
	terminal, err := readGuestSecretTerminal(reader, envelope.EnvelopeID)
	if err != nil {
		zeroGuestOutputs(durableOutputs)
		return err
	}
	for index, output := range durableOutputs {
		err := emit(ctx, output)
		if err != nil {
			zeroGuestOutputs(durableOutputs[index:])
			return fmt.Errorf("durably emit redacted guest output: %w", err)
		}
	}
	if terminal != "SUCCEEDED" {
		return fmt.Errorf("authenticated guest secret result: %w", ErrCapabilityUnavailable)
	}
	return nil
}

func zeroGuestOutputs(outputs []sandboxhostprotocol.GuestOutput) {
	for _, output := range outputs {
		for index := range output.Data {
			output.Data[index] = 0
		}
	}
}

// CancelDispatch asks the exact bound guest to cancel one fenced operation.
// It never accepts a caller-selected VM or a zero fence, and it leaves the
// host's durable uncertain-result recovery as the terminal authority.
func (channel *UnixGuestControlChannel) CancelDispatch(ctx context.Context, envelope sandboxhostprotocol.Envelope) error {
	if channel == nil {
		return fmt.Errorf("cancel guest dispatch: %w", ErrCapabilityUnavailable)
	}
	channel.mu.Lock()
	vmID := channel.vmID
	channel.mu.Unlock()
	if envelope.EnvelopeID == "" || envelope.FencingToken == 0 || envelope.SandboxID != vmID {
		return fmt.Errorf("cancel guest dispatch: %w", ErrCapabilityUnavailable)
	}
	connection, reader, err := channel.open(ctx)
	if err != nil {
		return err
	}
	defer channel.release(connection)
	if _, err := fmt.Fprintf(connection, "CANCEL %s %d\n", envelope.EnvelopeID, envelope.FencingToken); err != nil {
		return fmt.Errorf("write guest cancellation: %w", err)
	}
	line, err := readGuestControlResponse(reader)
	if err != nil || line != "CANCELLED "+envelope.EnvelopeID {
		return fmt.Errorf("read guest cancellation: %w", ErrCapabilityUnavailable)
	}
	return nil
}

// ProxyAuthenticated relays one bounded, control-signed guest proxy request
// over the exact private AF_VSOCK channel. It accepts neither a guest-selected
// resolver nor a general stream: one signed input produces at most one bounded
// response and every close path revokes the host-owned proxy session.
func (channel *UnixGuestControlChannel) ProxyAuthenticated(ctx context.Context, envelope sandboxhostprotocol.Envelope, authenticatedEnvelope []byte, session *sandboxauthority.ProxySession, now time.Time, resolver sandboxauthority.Resolver, dialer sandboxauthority.Dialer) (GuestDispatchResult, error) {
	if channel == nil {
		return GuestDispatchResult{}, fmt.Errorf("proxy guest control: %w", ErrCapabilityUnavailable)
	}
	if err := contextError(ctx); err != nil {
		return GuestDispatchResult{}, err
	}
	if _, ok := ctx.Deadline(); !ok {
		return GuestDispatchResult{}, fmt.Errorf("proxy guest control: %w", ErrCapabilityUnavailable)
	}
	if session == nil {
		return GuestDispatchResult{}, fmt.Errorf("proxy guest control: %w", ErrCapabilityUnavailable)
	}
	payload, err := DecodeGuestProxyPayload(envelope.Payload)
	if err != nil || envelope.OperationKind != GuestProxyOperationKind || payload.Request.SandboxID != envelope.SandboxID || payload.Request.ProcessID != envelope.ProcessID || payload.Request.OperationID != envelope.OperationID || payload.Request.FencingToken != envelope.FencingToken {
		return GuestDispatchResult{}, fmt.Errorf("proxy guest control: %w", ErrCapabilityUnavailable)
	}
	frame, err := EncodeAuthenticatedGuestDispatch(envelope, authenticatedEnvelope)
	if err != nil {
		return GuestDispatchResult{}, err
	}
	channel.mu.Lock()
	vmID := channel.vmID
	if !channel.closed {
		channel.proxySessions[session] = struct{}{}
	}
	closed := channel.closed
	channel.mu.Unlock()
	if closed || payload.Request.VMID != vmID {
		return GuestDispatchResult{}, fmt.Errorf("proxy guest control: %w", ErrCapabilityUnavailable)
	}
	defer func() {
		channel.mu.Lock()
		delete(channel.proxySessions, session)
		channel.mu.Unlock()
		_ = session.Close(context.Background())
	}()

	connection, reader, err := channel.open(ctx)
	if err != nil {
		return GuestDispatchResult{}, err
	}
	defer channel.release(connection)
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = session.Close(context.Background())
		_ = connection.Close()
	})
	defer stopCancellation()
	if _, err := fmt.Fprintf(connection, "PROXY %s\n", base64.RawURLEncoding.EncodeToString(frame)); err != nil {
		return GuestDispatchResult{}, fmt.Errorf("write authenticated guest proxy: %w", err)
	}
	request, err := readGuestProxyOpen(reader)
	if err != nil || !sameGuestProxyRequest(request, payload.Request) {
		return GuestDispatchResult{}, fmt.Errorf("read guest proxy open: %w", ErrCapabilityUnavailable)
	}
	remote, err := session.Connect(ctx, request, now, resolver, dialer)
	if err != nil {
		return GuestDispatchResult{}, err
	}
	defer func() { _ = remote.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		if err := remote.SetDeadline(deadline); err != nil {
			return GuestDispatchResult{}, fmt.Errorf("bound guest proxy deadline: %w", err)
		}
	}
	if _, err := fmt.Fprintf(connection, "PROXY_CONNECTED %s\n", envelope.EnvelopeID); err != nil {
		return GuestDispatchResult{}, fmt.Errorf("write guest proxy connection: %w", err)
	}
	input, err := readGuestProxyData(reader, envelope.EnvelopeID)
	if err != nil || !bytes.Equal(input, payload.Input) {
		return GuestDispatchResult{}, fmt.Errorf("read guest proxy input: %w", ErrCapabilityUnavailable)
	}
	if err := writeAll(remote, input); err != nil {
		return GuestDispatchResult{}, fmt.Errorf("write proxied guest input: %w", err)
	}
	if writer, ok := remote.(interface{ CloseWrite() error }); ok {
		if err := writer.CloseWrite(); err != nil {
			return GuestDispatchResult{}, fmt.Errorf("finish proxied guest input: %w", err)
		}
	}
	output, err := io.ReadAll(io.LimitReader(remote, maximumGuestProxyBytes+1))
	if err != nil || len(output) > maximumGuestProxyBytes {
		return GuestDispatchResult{}, fmt.Errorf("read proxied guest output: %w", ErrCapabilityUnavailable)
	}
	if len(output) > 0 {
		if _, err := fmt.Fprintf(connection, "PROXY_OUTPUT %s 0 %s %s\n", envelope.EnvelopeID, sandboxhostprotocol.Digest(output), base64.RawURLEncoding.EncodeToString(output)); err != nil {
			return GuestDispatchResult{}, fmt.Errorf("write proxied guest output: %w", err)
		}
	}
	if _, err := fmt.Fprintf(connection, "PROXY_RESULT SUCCEEDED %s\n", envelope.EnvelopeID); err != nil {
		return GuestDispatchResult{}, fmt.Errorf("write proxied guest result: %w", err)
	}
	return readGuestDispatchResult(reader, envelope)
}

// Close tears down every in-flight private guest exchange before the Jailer
// reaper terminates its process. Once closed, the channel cannot be reused.
func (channel *UnixGuestControlChannel) Close(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if channel == nil {
		return fmt.Errorf("close guest control: %w", ErrSmokeUnavailable)
	}
	channel.mu.Lock()
	if channel.closed {
		channel.mu.Unlock()
		return nil
	}
	channel.closed = true
	connections := make([]net.Conn, 0, len(channel.connections))
	for connection := range channel.connections {
		connections = append(connections, connection)
	}
	proxySessions := make([]*sandboxauthority.ProxySession, 0, len(channel.proxySessions))
	for session := range channel.proxySessions {
		proxySessions = append(proxySessions, session)
	}
	channel.mu.Unlock()
	var closeErr error
	for _, connection := range connections {
		closeErr = joinGuestControlError(closeErr, connection.Close())
	}
	for _, session := range proxySessions {
		closeErr = joinGuestControlError(closeErr, session.Close(ctx))
	}
	return closeErr
}

func (channel *UnixGuestControlChannel) open(ctx context.Context) (net.Conn, *bufio.Reader, error) {
	if err := contextError(ctx); err != nil {
		return nil, nil, err
	}
	if channel == nil {
		return nil, nil, fmt.Errorf("open guest control: %w", ErrSmokeUnavailable)
	}
	channel.mu.Lock()
	socket, vmID, fixtureVersion, closed := channel.socket, channel.vmID, channel.fixtureVersion, channel.closed
	channel.mu.Unlock()
	if closed || socket == "" || vmID == "" || fixtureVersion == "" {
		return nil, nil, fmt.Errorf("open guest control: %w", ErrSmokeUnavailable)
	}
	connection, err := channel.dial.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, nil, fmt.Errorf("open guest control: %w", ErrSmokeUnavailable)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			_ = connection.Close()
			return nil, nil, fmt.Errorf("bound guest control deadline: %w", err)
		}
	} else if err := connection.SetDeadline(time.Time{}); err != nil {
		_ = connection.Close()
		return nil, nil, fmt.Errorf("clear guest control deadline: %w", err)
	}
	channel.mu.Lock()
	if channel.closed {
		channel.mu.Unlock()
		_ = connection.Close()
		return nil, nil, fmt.Errorf("open guest control: %w", ErrSmokeUnavailable)
	}
	channel.connections[connection] = struct{}{}
	channel.mu.Unlock()
	if _, err := fmt.Fprintf(connection, "CONNECT %s %s\n", vmID, fixtureVersion); err != nil {
		channel.release(connection)
		return nil, nil, fmt.Errorf("write guest CONNECT: %w", err)
	}
	reader := bufio.NewReaderSize(connection, maximumGuestControlResponseBytes+1)
	line, err := readGuestControlResponse(reader)
	if err != nil || line != "OK "+vmID+" "+fixtureVersion {
		channel.release(connection)
		return nil, nil, fmt.Errorf("open guest control: %w", ErrSmokeUnavailable)
	}
	return connection, reader, nil
}

func (channel *UnixGuestControlChannel) release(connection net.Conn) {
	channel.mu.Lock()
	delete(channel.connections, connection)
	channel.mu.Unlock()
	_ = connection.Close()
}

func readGuestControlResponse(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil || len(line) == 0 || len(line) > maximumGuestControlResponseBytes || !strings.HasSuffix(line, "\n") {
		return "", fmt.Errorf("invalid bounded guest control response")
	}
	return strings.TrimSuffix(line, "\n"), nil
}

// readGuestDispatchResult accepts the legacy bounded output/result exchange
// and its additive terminal-observation frame.  An observation is optional so
// existing unavailable/profile-gated guests remain compatible, but when one
// is present it must be canonical, complete, and bound to this exact fenced
// envelope. The guest does not gain authority merely by sending this frame:
// the host must still decide whether it can truthfully sign it.
func readGuestDispatchResult(reader *bufio.Reader, envelope sandboxhostprotocol.Envelope) (GuestDispatchResult, error) {
	result := GuestDispatchResult{}
	observationSeen := false
	for {
		line, err := readGuestControlResponse(reader)
		if err != nil {
			return GuestDispatchResult{}, fmt.Errorf("read guest result: %w", ErrCapabilityUnavailable)
		}
		fields := strings.Split(line, " ")
		if len(fields) == 6 && fields[0] == "OUTPUT" && !observationSeen && fields[1] == envelope.EnvelopeID && validGuestOutputStream(fields[2]) && len(result.Outputs) < maximumGuestOutputChunks {
			sequence, sequenceErr := strconv.ParseUint(fields[3], 10, 64)
			chunk, decodeErr := base64.RawURLEncoding.DecodeString(fields[5])
			if sequenceErr != nil || sequence != uint64(len(result.Outputs)) || decodeErr != nil || len(chunk) == 0 || len(chunk) > maximumGuestOutputBytes || fields[4] != sandboxhostprotocol.Digest(chunk) {
				return GuestDispatchResult{}, fmt.Errorf("read guest output: %w", ErrCapabilityUnavailable)
			}
			result.Outputs = append(result.Outputs, GuestOutput{Stream: fields[2], Sequence: sequence, Digest: fields[4], Data: append([]byte(nil), chunk...)})
			continue
		}
		if len(fields) == 3 && fields[0] == "OBSERVATION" && !observationSeen && fields[1] == envelope.EnvelopeID {
			observation, decodeErr := decodeGuestTerminalObservation(fields[2], envelope)
			if decodeErr != nil {
				return GuestDispatchResult{}, fmt.Errorf("read guest terminal observation: %w", ErrCapabilityUnavailable)
			}
			result.Observation = observation
			observationSeen = true
			continue
		}
		if len(fields) == 3 && fields[0] == "RESULT" && (fields[1] == "UNAVAILABLE" || fields[1] == "SUCCEEDED" || fields[1] == "FAILED") && fields[2] == envelope.EnvelopeID && (!observationSeen || fields[1] != "UNAVAILABLE") {
			result.State = fields[1]
			return result, nil
		}
		return GuestDispatchResult{}, fmt.Errorf("read guest terminal result: %w", ErrCapabilityUnavailable)
	}
}

func decodeGuestTerminalObservation(encoded string, envelope sandboxhostprotocol.Envelope) (*sandboxhostprotocol.Observation, error) {
	wire, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(wire) == 0 || len(wire) > maximumGuestControlResponseBytes {
		return nil, fmt.Errorf("invalid bounded observation encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var observation sandboxhostprotocol.Observation
	if err := decoder.Decode(&observation); err != nil {
		return nil, fmt.Errorf("invalid observation")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("invalid trailing observation")
	}
	canonical, err := json.Marshal(observation)
	if err != nil || !bytes.Equal(canonical, wire) || !sandboxhostprotocol.ValidObservation(&observation) || observation.Sandbox.ID != envelope.SandboxID {
		return nil, fmt.Errorf("invalid canonical observation")
	}
	if envelope.ProcessID == "" {
		if observation.Process != nil {
			return nil, fmt.Errorf("unexpected process observation")
		}
	} else if observation.Process == nil || observation.Process.ID != envelope.ProcessID || observation.Process.SandboxID != envelope.SandboxID {
		return nil, fmt.Errorf("unbound process observation")
	}
	return &observation, nil
}

func readGuestSecretRequest(reader *bufio.Reader, envelopeID string) (sandboxauthority.SecretRequest, error) {
	line, err := readGuestControlResponse(reader)
	if err != nil {
		return sandboxauthority.SecretRequest{}, err
	}
	fields := strings.Split(line, " ")
	if len(fields) != 3 || fields[0] != "SECRET_REQUEST" || fields[1] != envelopeID {
		return sandboxauthority.SecretRequest{}, fmt.Errorf("invalid guest secret request")
	}
	payload, err := base64.RawURLEncoding.DecodeString(fields[2])
	if err != nil || len(payload) == 0 || len(payload) > maximumGuestControlResponseBytes {
		return sandboxauthority.SecretRequest{}, fmt.Errorf("decode guest secret request")
	}
	return DecodeGuestSecretRequest(payload)
}

func readGuestSecretResultBeforeReap(reader *bufio.Reader, envelopeID string) (GuestDispatchResult, error) {
	result := GuestDispatchResult{}
	for {
		line, err := readGuestControlResponse(reader)
		if err != nil {
			return GuestDispatchResult{}, fmt.Errorf("read guest secret result: %w", ErrCapabilityUnavailable)
		}
		fields := strings.Split(line, " ")
		if len(fields) == 6 && fields[0] == "OUTPUT" && fields[1] == envelopeID && validGuestOutputStream(fields[2]) && len(result.Outputs) < maximumGuestOutputChunks {
			sequence, sequenceErr := strconv.ParseUint(fields[3], 10, 64)
			chunk, decodeErr := base64.RawURLEncoding.DecodeString(fields[5])
			if sequenceErr != nil || sequence != uint64(len(result.Outputs)) || decodeErr != nil || len(chunk) == 0 || len(chunk) > maximumGuestOutputBytes || fields[4] != sandboxhostprotocol.Digest(chunk) {
				return GuestDispatchResult{}, fmt.Errorf("read guest secret output: %w", ErrCapabilityUnavailable)
			}
			result.Outputs = append(result.Outputs, GuestOutput{Stream: fields[2], Sequence: sequence, Digest: fields[4], Data: append([]byte(nil), chunk...)})
			continue
		}
		if len(fields) == 2 && fields[0] == "SECRET_TREE_REAPED" && fields[1] == envelopeID {
			return result, nil
		}
		return GuestDispatchResult{}, fmt.Errorf("read guest secret tree reaping: %w", ErrCapabilityUnavailable)
	}
}

func readGuestSecretTerminal(reader *bufio.Reader, envelopeID string) (string, error) {
	line, err := readGuestControlResponse(reader)
	if err != nil {
		return "", fmt.Errorf("read guest secret terminal: %w", ErrCapabilityUnavailable)
	}
	fields := strings.Split(line, " ")
	if len(fields) != 3 || fields[0] != "RESULT" || fields[2] != envelopeID || (fields[1] != "SUCCEEDED" && fields[1] != "FAILED") {
		return "", fmt.Errorf("read guest secret terminal: %w", ErrCapabilityUnavailable)
	}
	return fields[1], nil
}

func (session *guestSecretSession) Deliver(ctx context.Context, request sandboxauthority.SecretRequest, value []byte) error {
	if session == nil || len(value) == 0 || len(value) > maximumGuestSecretBytes || !validSecretRequestShape(request) {
		return fmt.Errorf("deliver guest secret session: %w", ErrCapabilityUnavailable)
	}
	if err := contextError(ctx); err != nil {
		return fmt.Errorf("deliver guest secret session: %w", ErrCapabilityUnavailable)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.delivered {
		return fmt.Errorf("deliver guest secret session: %w", ErrCapabilityUnavailable)
	}
	if _, err := fmt.Fprintf(session.connection, "SECRET_VALUE %s %s\n", session.envelopeID, base64.RawURLEncoding.EncodeToString(value)); err != nil {
		return fmt.Errorf("write guest secret value: %w", err)
	}
	line, err := readGuestControlResponse(session.reader)
	if err != nil || line != "SECRET_READY "+session.envelopeID {
		return fmt.Errorf("confirm guest secret value: %w", ErrCapabilityUnavailable)
	}
	session.delivered = true
	return nil
}

func (session *guestSecretSession) AbortBeforeStart(ctx context.Context, request sandboxauthority.SecretRequest) error {
	if session == nil || !validSecretRequestShape(request) {
		return fmt.Errorf("abort guest secret session: %w", ErrCapabilityUnavailable)
	}
	if err := contextError(ctx); err != nil {
		return fmt.Errorf("abort guest secret session: %w", ErrCapabilityUnavailable)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if !session.delivered {
		return fmt.Errorf("abort guest secret session: %w", ErrCapabilityUnavailable)
	}
	if _, err := fmt.Fprintf(session.connection, "SECRET_ABORT %s\n", session.envelopeID); err != nil {
		return fmt.Errorf("write guest secret abort: %w", err)
	}
	line, err := readGuestControlResponse(session.reader)
	if err != nil || line != "SECRET_ABORTED "+session.envelopeID {
		return fmt.Errorf("confirm guest secret abort: %w", ErrCapabilityUnavailable)
	}
	return nil
}

func (session *guestSecretSession) RevokeAfterTreeReap(ctx context.Context, request sandboxauthority.SecretRequest) error {
	if session == nil || !validSecretRequestShape(request) {
		return fmt.Errorf("revoke guest secret session: %w", ErrCapabilityUnavailable)
	}
	if err := contextError(ctx); err != nil {
		return fmt.Errorf("revoke guest secret session: %w", ErrCapabilityUnavailable)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if !session.delivered || !session.treeReaped {
		return fmt.Errorf("revoke guest secret session: %w", ErrCapabilityUnavailable)
	}
	if _, err := fmt.Fprintf(session.connection, "SECRET_REVOKE %s\n", session.envelopeID); err != nil {
		return fmt.Errorf("write guest secret revoke: %w", err)
	}
	line, err := readGuestControlResponse(session.reader)
	if err != nil || line != "SECRET_REVOKED "+session.envelopeID {
		return fmt.Errorf("confirm guest secret revoke: %w", ErrCapabilityUnavailable)
	}
	return nil
}

func (session *guestSecretSession) markTreeReaped() {
	session.mu.Lock()
	session.treeReaped = true
	session.mu.Unlock()
}

func readGuestProxyOpen(reader *bufio.Reader) (sandboxauthority.ProxySessionRequest, error) {
	line, err := readGuestControlResponse(reader)
	if err != nil {
		return sandboxauthority.ProxySessionRequest{}, err
	}
	fields := strings.Split(line, " ")
	if len(fields) != 2 || fields[0] != "PROXY_OPEN" {
		return sandboxauthority.ProxySessionRequest{}, fmt.Errorf("invalid guest proxy open")
	}
	frame, err := base64.RawURLEncoding.DecodeString(fields[1])
	if err != nil {
		return sandboxauthority.ProxySessionRequest{}, fmt.Errorf("decode guest proxy open: %w", err)
	}
	return DecodeGuestProxyOpen(frame)
}

func readGuestProxyData(reader *bufio.Reader, envelopeID string) ([]byte, error) {
	line, err := readGuestControlResponse(reader)
	if err != nil {
		return nil, err
	}
	fields := strings.Split(line, " ")
	if len(fields) != 3 || fields[0] != "PROXY_DATA" || fields[1] != envelopeID {
		return nil, fmt.Errorf("invalid guest proxy data")
	}
	data, err := base64.RawURLEncoding.DecodeString(fields[2])
	if err != nil || len(data) > maximumGuestProxyBytes {
		return nil, fmt.Errorf("decode guest proxy data")
	}
	return data, nil
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

func validGuestOutputStream(stream string) bool {
	return stream == "control" || stream == "stdout" || stream == "stderr"
}

func joinGuestControlError(left, right error) error {
	if left != nil {
		return fmt.Errorf("close guest control: %w", left)
	}
	if right != nil {
		return fmt.Errorf("close guest control: %w", right)
	}
	return nil
}
