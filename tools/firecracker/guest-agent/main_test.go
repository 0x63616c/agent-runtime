package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/firecracker"
	"github.com/0x63616c/agent-runtime/internal/sandboxauthority"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
)

func TestServeEmitsMarkerAndEchoesOneNonce(t *testing.T) {
	var output bytes.Buffer

	if err := serve("sandbox-001", "fixture-v1", strings.NewReader("PING nonce-123\n"), &output, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("serve() error = %v", err)
	}
	if got, want := output.String(), "AGENT_RUNTIME_FC_SMOKE sandbox-001 fixture-v1 agent-runtime-firecracker-guest/v1\nPONG sandbox-001 nonce-123\n"; got != want {
		t.Fatalf("serve() output = %q, want %q", got, want)
	}
}

func TestServeRefusesAnUnboundedControlLine(t *testing.T) {
	var output bytes.Buffer
	request := "PING " + strings.Repeat("a", 1025) + "\n"

	if err := serve("sandbox-001", "fixture-v1", strings.NewReader(request), &output, func(context.Context) error { return nil }); err == nil {
		t.Fatal("serve() error = nil, want bounded-control refusal")
	}
}

func TestServeAcknowledgesThenRunsOneBoundedShutdown(t *testing.T) {
	var output bytes.Buffer
	var shutdownCalls int
	shutdown := func(ctx context.Context) error {
		shutdownCalls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > maximumShutdownDuration || time.Until(deadline) <= 0 {
			t.Fatalf("shutdown deadline = %v, %v; want an active bounded deadline", deadline, ok)
		}
		if got, want := output.String(), "AGENT_RUNTIME_FC_SMOKE sandbox-001 fixture-v1 agent-runtime-firecracker-guest/v1\nPONG sandbox-001 nonce-123\n"; got != want {
			t.Fatalf("output before shutdown = %q, want %q", got, want)
		}
		return nil
	}

	if err := serve("sandbox-001", "fixture-v1", strings.NewReader("PING nonce-123\n"), &output, shutdown); err != nil {
		t.Fatalf("serve() error = %v", err)
	}
	if shutdownCalls != 1 {
		t.Fatalf("shutdown calls = %d, want 1", shutdownCalls)
	}
}

func TestServeGuestControlEmitsSerialMarkerThenCompletesOneVSockHandshake(t *testing.T) {
	var serial bytes.Buffer
	connection := &recordingGuestConnection{requests: strings.NewReader("CONNECT sandbox-001 fixture-v1\nPING nonce-123\n")}
	listener := &recordingGuestListener{connection: connection}
	var shutdownCalls int

	err := serveGuestControl(
		"sandbox-001",
		"fixture-v1",
		&serial,
		func() (guestControlListener, error) { return listener, nil },
		func(context.Context) error { shutdownCalls++; return nil },
	)
	if err != nil {
		t.Fatalf("serveGuestControl() error = %v", err)
	}
	if got, want := serial.String(), "AGENT_RUNTIME_FC_SMOKE sandbox-001 fixture-v1 agent-runtime-firecracker-guest/v1\n"; got != want {
		t.Fatalf("serial marker = %q, want %q", got, want)
	}
	if got, want := connection.String(), "OK sandbox-001 fixture-v1\nPONG sandbox-001 nonce-123\n"; got != want {
		t.Fatalf("guest control response = %q, want %q", got, want)
	}
	if shutdownCalls != 1 {
		t.Fatalf("shutdown calls = %d, want 1", shutdownCalls)
	}
	if !connection.closed || !listener.closed {
		t.Fatalf("guest control cleanup connection=%v listener=%v, want both closed", connection.closed, listener.closed)
	}
}

func TestServeGuestControlRefusesAMismatchedConnectWithoutLeakingControlInput(t *testing.T) {
	const secretNonce = "nonce-that-must-not-appear-in-errors"
	var serial bytes.Buffer
	connection := &recordingGuestConnection{requests: strings.NewReader("CONNECT another-sandbox fixture-v1\nPING " + secretNonce + "\n")}
	listener := &recordingGuestListener{connection: connection}

	err := serveGuestControl(
		"sandbox-001",
		"fixture-v1",
		&serial,
		func() (guestControlListener, error) { return listener, nil },
		func(context.Context) error { t.Fatal("shutdown must not run after a rejected CONNECT"); return nil },
	)
	if err == nil {
		t.Fatal("serveGuestControl() error = nil, want rejected CONNECT")
	}
	if strings.Contains(err.Error(), secretNonce) {
		t.Fatalf("control error leaked nonce: %q", err)
	}
	if got := connection.String(); got != "" {
		t.Fatalf("guest control response = %q, want no response", got)
	}
}

func TestServeGuestControlRefusesAnOverlongPingFrame(t *testing.T) {
	var serial bytes.Buffer
	connection := &recordingGuestConnection{requests: strings.NewReader("CONNECT sandbox-001 fixture-v1\nPING " + strings.Repeat("a", maximumControlLineBytes) + "\n")}
	listener := &recordingGuestListener{connection: connection}

	err := serveGuestControl(
		"sandbox-001",
		"fixture-v1",
		&serial,
		func() (guestControlListener, error) { return listener, nil },
		func(context.Context) error { t.Fatal("shutdown must not run after an oversized PING"); return nil },
	)
	if err == nil {
		t.Fatal("serveGuestControl() error = nil, want oversized-frame refusal")
	}
	if got, want := connection.String(), "OK sandbox-001 fixture-v1\n"; got != want {
		t.Fatalf("guest control response = %q, want %q", got, want)
	}
}

func TestServeGuestControlReturnsBoundedUnavailableResultForAnAuthenticatedDispatchFrame(t *testing.T) {
	var serial bytes.Buffer
	envelope := sandboxhostprotocol.Envelope{
		EnvelopeID:   "envelope-001",
		DeliveryID:   "delivery-001",
		FencingToken: 1,
		SandboxID:    "sandbox-001",
		Payload:      []byte("bounded"),
	}
	envelope.PayloadDigest = sandboxhostprotocol.Digest(envelope.Payload)
	authenticatedEnvelope, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal authenticated envelope: %v", err)
	}
	frame, err := firecracker.EncodeAuthenticatedGuestDispatch(envelope, authenticatedEnvelope)
	if err != nil {
		t.Fatalf("EncodeGuestDispatch() error = %v", err)
	}
	connection := &recordingGuestConnection{requests: strings.NewReader("CONNECT sandbox-001 fixture-v1\nDISPATCH " + base64.RawURLEncoding.EncodeToString(frame) + "\n")}
	listener := &recordingGuestListener{connection: connection}

	err = serveGuestControl(
		"sandbox-001",
		"fixture-v1",
		&serial,
		func() (guestControlListener, error) { return listener, nil },
		func(context.Context) error { return nil },
	)
	if err != nil {
		t.Fatalf("serveGuestControl() error = %v", err)
	}
	marker := []byte("guest-control-unavailable")
	if got, want := connection.String(), "OK sandbox-001 fixture-v1\nOUTPUT envelope-001 control 0 "+sandboxhostprotocol.Digest(marker)+" "+base64.RawURLEncoding.EncodeToString(marker)+"\nRESULT UNAVAILABLE envelope-001\n"; got != want {
		t.Fatalf("guest control response = %q, want %q", got, want)
	}
}

func TestServeGuestControlRefusesSecretDispatchBeforeRequestingAnyValue(t *testing.T) {
	var serial bytes.Buffer
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	request := sandboxauthority.SecretRequest{Principal: "principal-001", SandboxID: "sandbox-001", ProcessID: "process-001", OperationID: "operation-001", Binding: "binding-001", Purpose: "command", ExpiresAt: now.Add(time.Minute)}
	payload, err := json.Marshal(firecracker.GuestSecretCommand{Version: firecracker.GuestSecretCommandOperationKind, Command: json.RawMessage(`{"version":"agent-runtime.guest-command/v1"}`), Secret: request})
	if err != nil {
		t.Fatal(err)
	}
	envelope := sandboxhostprotocol.Envelope{EnvelopeID: "envelope-001", DeliveryID: "delivery-001", FencingToken: 1, Principal: request.Principal, SandboxID: request.SandboxID, ProcessID: request.ProcessID, OperationID: request.OperationID, OperationKind: firecracker.GuestSecretCommandOperationKind, ExpiresAt: request.ExpiresAt, Payload: payload}
	envelope.PayloadDigest = sandboxhostprotocol.Digest(payload)
	authenticatedEnvelope, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := firecracker.EncodeAuthenticatedGuestDispatch(envelope, authenticatedEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	connection := &recordingGuestConnection{requests: strings.NewReader("CONNECT sandbox-001 fixture-v1\nSECRET_DISPATCH " + base64.RawURLEncoding.EncodeToString(frame) + "\n")}
	listener := &recordingGuestListener{connection: connection}
	if err := serveGuestControl("sandbox-001", "fixture-v1", &serial, func() (guestControlListener, error) { return listener, nil }, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("serveGuestControl() error = %v", err)
	}
	if got, want := connection.String(), "OK sandbox-001 fixture-v1\nRESULT UNAVAILABLE envelope-001\n"; got != want {
		t.Fatalf("guest secret response = %q, want %q", got, want)
	}
}

func TestServeGuestSecretOperationRequiresValueStartReapAndRevokeInOrder(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	request := sandboxauthority.SecretRequest{Principal: "principal-001", SandboxID: "sandbox-001", ProcessID: "process-001", OperationID: "operation-001", Binding: "binding-001", Purpose: "command", ExpiresAt: now.Add(time.Minute)}
	command := firecracker.GuestSecretCommand{Version: firecracker.GuestSecretCommandOperationKind, Command: json.RawMessage(`{"version":"agent-runtime.guest-command/v1"}`), Secret: request}
	envelope := sandboxhostprotocol.Envelope{EnvelopeID: "envelope-001"}
	connection := &recordingGuestConnection{requests: strings.NewReader("SECRET_VALUE envelope-001 c2VjcmV0LXZhbHVl\nSECRET_START envelope-001\nSECRET_REVOKE envelope-001\n")}
	executor := &recordingGuestSecretExecutor{}
	if err := serveGuestSecretOperation(connection, bufio.NewReader(connection), envelope, command, executor); err != nil {
		t.Fatalf("serveGuestSecretOperation() error = %v", err)
	}
	output := []byte("before secret-value after")
	if got, want := connection.String(), "SECRET_REQUEST envelope-001 "+base64.RawURLEncoding.EncodeToString(mustEncodeGuestSecretRequest(t, request))+"\nSECRET_READY envelope-001\nOUTPUT envelope-001 stdout 0 "+sandboxhostprotocol.Digest(output)+" "+base64.RawURLEncoding.EncodeToString(output)+"\nSECRET_TREE_REAPED envelope-001\nSECRET_REVOKED envelope-001\nRESULT SUCCEEDED envelope-001\n"; got != want {
		t.Fatalf("secret exchange = %q, want %q", got, want)
	}
	if got := string(executor.value); got != "secret-value" || !executor.revoked {
		t.Fatalf("executor lifecycle = value %q revoked %t", got, executor.revoked)
	}
}

func mustEncodeGuestSecretRequest(t *testing.T, request sandboxauthority.SecretRequest) []byte {
	t.Helper()
	payload, err := firecracker.EncodeGuestSecretRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

type recordingGuestSecretExecutor struct {
	value   []byte
	revoked bool
}

func (*recordingGuestSecretExecutor) Available() bool { return true }
func (executor *recordingGuestSecretExecutor) Deliver(_ context.Context, value []byte) error {
	executor.value = append([]byte(nil), value...)
	return nil
}
func (*recordingGuestSecretExecutor) Run(context.Context, json.RawMessage) (guestCommandResult, error) {
	return guestCommandResult{stdout: []byte("before secret-value after")}, nil
}
func (executor *recordingGuestSecretExecutor) RevokeAfterTreeReap(context.Context) error {
	executor.revoked = true
	return nil
}

func TestServeGuestControlAcknowledgesABoundedCancellationWithoutStartingWork(t *testing.T) {
	var serial bytes.Buffer
	connection := &recordingGuestConnection{requests: strings.NewReader("CONNECT sandbox-001 fixture-v1\nCANCEL envelope-001 7\n")}
	listener := &recordingGuestListener{connection: connection}

	err := serveGuestControl(
		"sandbox-001",
		"fixture-v1",
		&serial,
		func() (guestControlListener, error) { return listener, nil },
		func(context.Context) error { return nil },
	)
	if err != nil {
		t.Fatalf("serveGuestControl() error = %v", err)
	}
	if got, want := connection.String(), "OK sandbox-001 fixture-v1\nCANCELLED envelope-001\n"; got != want {
		t.Fatalf("guest control response = %q, want %q", got, want)
	}
}

func TestServeGuestControlRelaysOnlyTheSignedBoundedProxyOperation(t *testing.T) {
	var serial bytes.Buffer
	request := sandboxauthority.ProxySessionRequest{
		SandboxID: "sandbox-001", ProcessID: "process-001", OperationID: "operation-001", VMID: "sandbox-001", FencingToken: 9,
		Destination: sandboxauthority.EgressDestination{Domain: "api.example.invalid", Protocol: "tcp", Port: 443},
	}
	payload, err := json.Marshal(firecracker.GuestProxyPayload{Version: firecracker.GuestProxyOperationKind, Request: request, Input: []byte("request")})
	if err != nil {
		t.Fatal(err)
	}
	envelope := sandboxhostprotocol.Envelope{EnvelopeID: "envelope-001", DeliveryID: "delivery-001", FencingToken: 9, SandboxID: "sandbox-001", ProcessID: "process-001", OperationID: "operation-001", OperationKind: firecracker.GuestProxyOperationKind, Payload: payload}
	envelope.PayloadDigest = sandboxhostprotocol.Digest(payload)
	authenticated, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := firecracker.EncodeAuthenticatedGuestDispatch(envelope, authenticated)
	if err != nil {
		t.Fatal(err)
	}
	response := []byte("response")
	open, err := firecracker.EncodeGuestProxyOpen(request)
	if err != nil {
		t.Fatal(err)
	}
	connection := &recordingGuestConnection{requests: strings.NewReader("CONNECT sandbox-001 fixture-v1\nPROXY " + base64.RawURLEncoding.EncodeToString(frame) + "\nPROXY_CONNECTED envelope-001\nPROXY_OUTPUT envelope-001 0 " + sandboxhostprotocol.Digest(response) + " " + base64.RawURLEncoding.EncodeToString(response) + "\nPROXY_RESULT SUCCEEDED envelope-001\n")}
	listener := &recordingGuestListener{connection: connection}
	if err := serveGuestControl("sandbox-001", "fixture-v1", &serial, func() (guestControlListener, error) { return listener, nil }, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("serveGuestControl() error = %v", err)
	}
	want := "OK sandbox-001 fixture-v1\nPROXY_OPEN " + base64.RawURLEncoding.EncodeToString(open) + "\nPROXY_DATA envelope-001 cmVxdWVzdA\nOUTPUT envelope-001 stdout 0 " + sandboxhostprotocol.Digest(response) + " " + base64.RawURLEncoding.EncodeToString(response) + "\nRESULT SUCCEEDED envelope-001\n"
	if got := connection.String(); got != want {
		t.Fatalf("guest proxy response = %q, want %q", got, want)
	}
}

func TestGuestCommandRunnerUsesTypedArgvAndBoundsTheGuestProcessTreeOutput(t *testing.T) {
	payload, err := json.Marshal(guestCommand{Version: guestCommandVersion, Argv: []string{"/bin/echo", "typed-output"}, WorkingDirectory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	result, err := runGuestCommand(context.Background(), payload)
	if err != nil || string(result.stdout) != "typed-output\n" || len(result.stderr) != 0 {
		t.Fatalf("runGuestCommand() = (%q, %q, %v)", result.stdout, result.stderr, err)
	}
	unsafe, _ := json.Marshal(guestCommand{Version: guestCommandVersion, Argv: []string{"/bin/echo", "x"}, WorkingDirectory: "/proc"})
	if _, err := runGuestCommand(context.Background(), unsafe); err == nil {
		t.Fatal("runGuestCommand() accepted a reserved process workdir")
	}
}

func TestGuestControlPortIsTheFixedPrivateGuestPort(t *testing.T) {
	if got, want := guestControlPort, uint32(10777); got != want {
		t.Fatalf("guest control port = %d, want %d", got, want)
	}
}

func TestServeGuestControlRefusesUnsafeBootIdentityBeforeWritingTheSerialMarker(t *testing.T) {
	var serial bytes.Buffer
	listenerCalls := 0

	err := serveGuestControl(
		"sandbox-001\nsecret",
		"fixture-v1",
		&serial,
		func() (guestControlListener, error) { listenerCalls++; return nil, nil },
		func(context.Context) error {
			t.Fatal("shutdown must not run after an unsafe boot identity")
			return nil
		},
	)
	if err == nil {
		t.Fatal("serveGuestControl() error = nil, want unsafe-identity refusal")
	}
	if listenerCalls != 0 {
		t.Fatalf("listener calls = %d, want 0", listenerCalls)
	}
	if got := serial.String(); got != "" {
		t.Fatalf("serial marker = %q, want no output", got)
	}
}

func TestSystemShutdownRefusesACancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := systemShutdown(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("systemShutdown() error = %v, want context cancellation", err)
	}
}

func TestWaitForGuestControlPollRetriesAnInterruptedPoll(t *testing.T) {
	calls := 0
	err := waitForGuestControlPoll(func(_ int32, _ int16, _ int) (int, int16, error) {
		calls++
		if calls == 1 {
			return 0, 0, syscall.EINTR
		}
		return 1, guestControlPollIn, nil
	}, 7, guestControlPollIn, time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("waitForGuestControlPoll() error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("poll calls = %d, want 2", calls)
	}
}

func TestWaitForGuestControlPollFailsClosedOnTerminalPollEvents(t *testing.T) {
	for _, event := range []int16{guestControlPollError, guestControlPollHangup, guestControlPollInvalid} {
		t.Run("event", func(t *testing.T) {
			err := waitForGuestControlPoll(func(_ int32, _ int16, _ int) (int, int16, error) {
				return 1, event, nil
			}, 7, guestControlPollIn, time.Now().Add(time.Second))
			if err == nil {
				t.Fatal("waitForGuestControlPoll() error = nil, want terminal-event refusal")
			}
		})
	}
}

func TestAcceptGuestControlConnectionRetriesAndAcceptsOnlyTheHostCID(t *testing.T) {
	connection := &recordingGuestConnection{requests: strings.NewReader("")}
	acceptCalls := 0
	result, err := acceptGuestControlConnection(
		func() error { return nil },
		func() (guestControlConnection, uint32, error) {
			acceptCalls++
			if acceptCalls == 1 {
				return nil, 0, syscall.EAGAIN
			}
			return connection, guestControlHostCID, nil
		},
	)
	if err != nil {
		t.Fatalf("acceptGuestControlConnection() error = %v", err)
	}
	if result != connection {
		t.Fatalf("accepted connection = %T, want original connection", result)
	}
	if acceptCalls != 2 {
		t.Fatalf("accept calls = %d, want 2", acceptCalls)
	}
}

func TestAcceptGuestControlConnectionClosesANonHostPeer(t *testing.T) {
	connection := &recordingGuestConnection{requests: strings.NewReader("")}

	_, err := acceptGuestControlConnection(
		func() error { return nil },
		func() (guestControlConnection, uint32, error) { return connection, guestControlHostCID + 1, nil },
	)
	if err == nil {
		t.Fatal("acceptGuestControlConnection() error = nil, want non-host peer refusal")
	}
	if !connection.closed {
		t.Fatal("non-host connection was not closed")
	}
}

func TestWriteAllGuestControlCompletesPartialWrites(t *testing.T) {
	var output bytes.Buffer
	count, err := writeAllGuestControl([]byte("PONG"), func(remaining []byte) (int, error) {
		if len(remaining) > 1 {
			return output.Write(remaining[:1])
		}
		return output.Write(remaining)
	})
	if err != nil {
		t.Fatalf("writeAllGuestControl() error = %v", err)
	}
	if count != len("PONG") || output.String() != "PONG" {
		t.Fatalf("write result = (%d, %q), want (4, PONG)", count, output.String())
	}
}

func TestWriteAllGuestControlRefusesAZeroByteWrite(t *testing.T) {
	_, err := writeAllGuestControl([]byte("PONG"), func([]byte) (int, error) { return 0, nil })
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("writeAllGuestControl() error = %v, want io.ErrShortWrite", err)
	}
}

type recordingGuestListener struct {
	connection guestControlConnection
	err        error
	closed     bool
}

func (listener *recordingGuestListener) Accept() (guestControlConnection, error) {
	if listener.err != nil {
		return nil, listener.err
	}
	return listener.connection, nil
}

func (listener *recordingGuestListener) Close() error {
	listener.closed = true
	return nil
}

func (listener *recordingGuestListener) SetDeadline(time.Time) error { return nil }

type recordingGuestConnection struct {
	requests  io.Reader
	responses bytes.Buffer
	closed    bool
}

func (connection *recordingGuestConnection) Read(buffer []byte) (int, error) {
	return connection.requests.Read(buffer)
}

func (connection *recordingGuestConnection) Write(buffer []byte) (int, error) {
	return connection.responses.Write(buffer)
}

func (connection *recordingGuestConnection) String() string { return connection.responses.String() }

func (connection *recordingGuestConnection) Close() error {
	connection.closed = true
	return nil
}

func (connection *recordingGuestConnection) SetDeadline(time.Time) error { return nil }

var _ guestControlConnection = (*recordingGuestConnection)(nil)
var _ guestControlListener = (*recordingGuestListener)(nil)
