package firecracker

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
)

const (
	maximumGuestControlResponseBytes = 48 << 10
	maximumGuestOutputBytes          = 32 << 10
	maximumGuestOutputChunks         = 4
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
	State   string
	Outputs []GuestOutput
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
}

// NewUnixGuestControlChannel constructs a channel before the exact staged UDS
// and immutable guest identity are bound.
func NewUnixGuestControlChannel(dialer unixSocketDialer) (*UnixGuestControlChannel, error) {
	if dialer == nil {
		return nil, fmt.Errorf("create guest control channel: %w", ErrSmokeUnavailable)
	}
	return &UnixGuestControlChannel{dial: dialer, connections: make(map[net.Conn]struct{})}, nil
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
	return readGuestDispatchResult(reader, envelope.EnvelopeID)
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
	channel.mu.Unlock()
	var closeErr error
	for _, connection := range connections {
		closeErr = joinGuestControlError(closeErr, connection.Close())
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

func readGuestDispatchResult(reader *bufio.Reader, envelopeID string) (GuestDispatchResult, error) {
	result := GuestDispatchResult{}
	for {
		line, err := readGuestControlResponse(reader)
		if err != nil {
			return GuestDispatchResult{}, fmt.Errorf("read guest result: %w", ErrCapabilityUnavailable)
		}
		fields := strings.Split(line, " ")
		if len(fields) == 6 && fields[0] == "OUTPUT" && fields[1] == envelopeID && validGuestOutputStream(fields[2]) && len(result.Outputs) < maximumGuestOutputChunks {
			sequence, sequenceErr := strconv.ParseUint(fields[3], 10, 64)
			chunk, decodeErr := base64.RawURLEncoding.DecodeString(fields[5])
			if sequenceErr != nil || sequence != uint64(len(result.Outputs)) || decodeErr != nil || len(chunk) == 0 || len(chunk) > maximumGuestOutputBytes || fields[4] != sandboxhostprotocol.Digest(chunk) {
				return GuestDispatchResult{}, fmt.Errorf("read guest output: %w", ErrCapabilityUnavailable)
			}
			result.Outputs = append(result.Outputs, GuestOutput{Stream: fields[2], Sequence: sequence, Digest: fields[4], Data: append([]byte(nil), chunk...)})
			continue
		}
		if len(fields) == 3 && fields[0] == "RESULT" && fields[1] == "UNAVAILABLE" && fields[2] == envelopeID {
			result.State = fields[1]
			return result, nil
		}
		return GuestDispatchResult{}, fmt.Errorf("read guest terminal result: %w", ErrCapabilityUnavailable)
	}
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
