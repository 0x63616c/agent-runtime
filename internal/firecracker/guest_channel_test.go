package firecracker

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxauthority"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
)

func TestUnixGuestControlChannelExchangesOnlyTheBoundIdentityAndUnavailableDispatch(t *testing.T) {
	dialer := &guestChannelDialer{}
	dialer.handler = func(connection net.Conn) {
		defer connection.Close()
		reader := bufio.NewReader(connection)
		if line := guestChannelTestReadLine(t, reader); line != "CONNECT sandbox-001 fixture-v1" {
			t.Errorf("CONNECT = %q, want bound identity", line)
			return
		}
		if _, err := connection.Write([]byte("OK sandbox-001 fixture-v1\n")); err != nil {
			t.Errorf("write CONNECT reply: %v", err)
			return
		}
		operation := guestChannelTestReadLine(t, reader)
		if operation == "PING bootstrap" {
			_, _ = connection.Write([]byte("PONG sandbox-001 bootstrap\n"))
			return
		}
		if operation == "CANCEL envelope-001 9" {
			_, _ = connection.Write([]byte("CANCELLED envelope-001\n"))
			return
		}
		fields := strings.Fields(operation)
		if len(fields) != 2 || fields[0] != "DISPATCH" {
			t.Errorf("operation = %q, want DISPATCH", operation)
			return
		}
		frame, err := base64.RawURLEncoding.DecodeString(fields[1])
		if err != nil {
			t.Errorf("decode dispatch: %v", err)
			return
		}
		envelope, err := DecodeGuestDispatch(frame)
		if err != nil || envelope.EnvelopeID != "envelope-001" || envelope.FencingToken != 9 {
			t.Errorf("DecodeGuestDispatch() = %#v, %v", envelope, err)
			return
		}
		if _, _, err := DecodeAuthenticatedGuestDispatch(frame); err == nil {
			marker := []byte("guest-control-unavailable")
			_, _ = connection.Write([]byte("OUTPUT envelope-001 control 0 " + sandboxhostprotocol.Digest(marker) + " " + base64.RawURLEncoding.EncodeToString(marker) + "\n"))
		}
		_, _ = connection.Write([]byte("RESULT UNAVAILABLE envelope-001\n"))
	}
	channel, err := NewUnixGuestControlChannel(dialer)
	if err != nil {
		t.Fatalf("NewUnixGuestControlChannel() error = %v", err)
	}
	if err := channel.BindGuestIdentity(context.Background(), "sandbox-001", "fixture-v1"); err != nil {
		t.Fatalf("BindGuestIdentity() error = %v", err)
	}
	if err := channel.Bind(context.Background(), "/srv/jailer/sandbox-001/root/run/firecracker.vsock"); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if err := channel.Ping(context.Background(), "sandbox-001"); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	envelope := sandboxhostprotocol.Envelope{EnvelopeID: "envelope-001", DeliveryID: "delivery-001", FencingToken: 9, SandboxID: "sandbox-001", Payload: []byte("bounded")}
	envelope.PayloadDigest = sandboxhostprotocol.Digest(envelope.Payload)
	if err := channel.ExecuteDispatch(context.Background(), envelope); !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("ExecuteDispatch() error = %v, want unavailable guest result", err)
	}
	authenticatedEnvelope, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal authenticated envelope: %v", err)
	}
	result, err := channel.DispatchAuthenticated(context.Background(), envelope, authenticatedEnvelope)
	if err != nil || result.State != "UNAVAILABLE" || len(result.Outputs) != 1 || result.Outputs[0].Stream != "control" || string(result.Outputs[0].Data) != "guest-control-unavailable" {
		t.Fatalf("DispatchAuthenticated() = (%#v, %v), want bounded unavailable marker", result, err)
	}
	if err := channel.CancelDispatch(context.Background(), envelope); err != nil {
		t.Fatalf("CancelDispatch() error = %v", err)
	}
	dialer.wait()
	if got, want := dialer.targets(), []string{"unix:/srv/jailer/sandbox-001/root/run/firecracker.vsock", "unix:/srv/jailer/sandbox-001/root/run/firecracker.vsock", "unix:/srv/jailer/sandbox-001/root/run/firecracker.vsock", "unix:/srv/jailer/sandbox-001/root/run/firecracker.vsock"}; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("dial targets = %v, want %v", got, want)
	}
}

func TestUnixGuestControlChannelRefusesIdentitySubstitutionAndUseAfterReaperClose(t *testing.T) {
	dialer := &guestChannelDialer{}
	channel, err := NewUnixGuestControlChannel(dialer)
	if err != nil {
		t.Fatalf("NewUnixGuestControlChannel() error = %v", err)
	}
	if err := channel.BindGuestIdentity(context.Background(), "sandbox-001", "fixture-v1"); err != nil {
		t.Fatalf("BindGuestIdentity() error = %v", err)
	}
	if err := channel.BindGuestIdentity(context.Background(), "sandbox-002", "fixture-v1"); !errors.Is(err, ErrSmokeUnavailable) {
		t.Fatalf("BindGuestIdentity() substitution error = %v, want unavailable", err)
	}
	if err := channel.Bind(context.Background(), "/srv/jailer/sandbox-001/root/run/firecracker.vsock"); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if err := channel.Ping(context.Background(), "sandbox-002"); !errors.Is(err, ErrSmokeUnavailable) {
		t.Fatalf("Ping() substituted identity error = %v, want unavailable", err)
	}
	if err := channel.CancelDispatch(context.Background(), sandboxhostprotocol.Envelope{EnvelopeID: "envelope-001", FencingToken: 1, SandboxID: "sandbox-002"}); !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("CancelDispatch() substituted identity error = %v, want unavailable", err)
	}
	if err := channel.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := channel.Ping(context.Background(), "sandbox-001"); !errors.Is(err, ErrSmokeUnavailable) {
		t.Fatalf("Ping() after close error = %v, want unavailable", err)
	}
	if got := len(dialer.targets()); got != 0 {
		t.Fatalf("dial calls = %d, want none after local refusals", got)
	}
}

func TestUnixGuestControlChannelReaperCloseInterruptsAnActivePrivateExchange(t *testing.T) {
	peerClosed := make(chan struct{})
	dialer := &guestChannelDialer{handler: func(connection net.Conn) {
		defer connection.Close()
		reader := bufio.NewReader(connection)
		if line := guestChannelTestReadLine(t, reader); line != "CONNECT sandbox-001 fixture-v1" {
			t.Errorf("CONNECT = %q, want bound identity", line)
			return
		}
		if _, err := connection.Write([]byte("OK sandbox-001 fixture-v1\n")); err != nil {
			t.Errorf("write CONNECT reply: %v", err)
			return
		}
		_, _ = reader.ReadByte()
		close(peerClosed)
	}}
	channel, err := NewUnixGuestControlChannel(dialer)
	if err != nil {
		t.Fatalf("NewUnixGuestControlChannel() error = %v", err)
	}
	if err := channel.BindGuestIdentity(context.Background(), "sandbox-001", "fixture-v1"); err != nil {
		t.Fatalf("BindGuestIdentity() error = %v", err)
	}
	if err := channel.Bind(context.Background(), "/srv/jailer/sandbox-001/root/run/firecracker.vsock"); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	_, _, err = channel.open(context.Background())
	if err != nil {
		t.Fatalf("open() error = %v", err)
	}
	if err := channel.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	<-peerClosed
	dialer.wait()
}

func TestGuestDispatchResultRefusesTamperedOrOutOfOrderOutputBeforeTerminalState(t *testing.T) {
	chunk := []byte("bounded-output")
	encoded := base64.RawURLEncoding.EncodeToString(chunk)
	valid := "OUTPUT envelope-001 stdout 0 " + sandboxhostprotocol.Digest(chunk) + " " + encoded + "\nRESULT UNAVAILABLE envelope-001\n"
	for name, wire := range map[string]string{
		"wrong digest":    "OUTPUT envelope-001 stdout 0 sha256:bad " + encoded + "\nRESULT UNAVAILABLE envelope-001\n",
		"wrong sequence":  "OUTPUT envelope-001 stdout 1 " + sandboxhostprotocol.Digest(chunk) + " " + encoded + "\nRESULT UNAVAILABLE envelope-001\n",
		"wrong envelope":  "OUTPUT another-envelope stdout 0 " + sandboxhostprotocol.Digest(chunk) + " " + encoded + "\nRESULT UNAVAILABLE envelope-001\n",
		"valid transport": valid,
	} {
		t.Run(name, func(t *testing.T) {
			result, err := readGuestDispatchResult(bufio.NewReader(strings.NewReader(wire)), "envelope-001")
			if name == "valid transport" {
				if err != nil || len(result.Outputs) != 1 || string(result.Outputs[0].Data) != string(chunk) {
					t.Fatalf("readGuestDispatchResult() = (%#v, %v), want bounded output", result, err)
				}
				return
			}
			if !errors.Is(err, ErrCapabilityUnavailable) {
				t.Fatalf("readGuestDispatchResult() error = %v, want output refusal", err)
			}
		})
	}
}

func TestUnixGuestControlChannelRelaysOnlyTheSignedLeaseBoundProxyRequest(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	request := sandboxauthority.ProxySessionRequest{
		SandboxID: "sandbox-001", ProcessID: "process-001", OperationID: "operation-001", VMID: "sandbox-001", FencingToken: 9,
		Destination: sandboxauthority.EgressDestination{Domain: "api.example.invalid", Protocol: "tcp", Port: 443},
	}
	payload, err := json.Marshal(GuestProxyPayload{Version: GuestProxyOperationKind, Request: request, Input: []byte("request")})
	if err != nil {
		t.Fatal(err)
	}
	envelope := sandboxhostprotocol.Envelope{EnvelopeID: "envelope-001", DeliveryID: "delivery-001", FencingToken: 9, SandboxID: "sandbox-001", ProcessID: "process-001", OperationID: "operation-001", OperationKind: GuestProxyOperationKind, Payload: payload}
	envelope.PayloadDigest = sandboxhostprotocol.Digest(payload)
	authenticated, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	remoteClient, remoteServer := net.Pipe()
	remoteDone := make(chan struct{})
	go func() {
		defer close(remoteDone)
		defer remoteServer.Close()
		got := make([]byte, len("request"))
		if _, err := io.ReadFull(remoteServer, got); err != nil || string(got) != "request" {
			return
		}
		_, _ = remoteServer.Write([]byte("response"))
	}()
	dialer := &guestChannelDialer{handler: func(connection net.Conn) {
		defer connection.Close()
		reader := bufio.NewReader(connection)
		if line := guestChannelTestReadLine(t, reader); line != "CONNECT sandbox-001 fixture-v1" {
			t.Errorf("CONNECT = %q", line)
			return
		}
		_, _ = connection.Write([]byte("OK sandbox-001 fixture-v1\n"))
		fields := strings.Fields(guestChannelTestReadLine(t, reader))
		if len(fields) != 2 || fields[0] != "PROXY" {
			t.Errorf("operation = %v, want PROXY", fields)
			return
		}
		frame, decodeErr := base64.RawURLEncoding.DecodeString(fields[1])
		if decodeErr != nil {
			t.Errorf("decode proxy frame: %v", decodeErr)
			return
		}
		gotEnvelope, _, decodeErr := DecodeAuthenticatedGuestDispatch(frame)
		if decodeErr != nil || gotEnvelope.EnvelopeID != envelope.EnvelopeID {
			t.Errorf("DecodeAuthenticatedGuestDispatch() = %#v, %v", gotEnvelope, decodeErr)
			return
		}
		open, encodeErr := EncodeGuestProxyOpen(request)
		if encodeErr != nil {
			t.Errorf("EncodeGuestProxyOpen() error = %v", encodeErr)
			return
		}
		_, _ = fmt.Fprintf(connection, "PROXY_OPEN %s\n", base64.RawURLEncoding.EncodeToString(open))
		if line := guestChannelTestReadLine(t, reader); line != "PROXY_CONNECTED envelope-001" {
			t.Errorf("connected = %q", line)
			return
		}
		if _, err := connection.Write([]byte("PROXY_DATA envelope-001 cmVxdWVzdA\n")); err != nil {
			t.Errorf("write proxy data: %v", err)
			return
		}
		output := []byte("response")
		if line := guestChannelTestReadLine(t, reader); line != "PROXY_OUTPUT envelope-001 0 "+sandboxhostprotocol.Digest(output)+" "+base64.RawURLEncoding.EncodeToString(output) {
			t.Errorf("proxy output = %q", line)
			return
		}
		if line := guestChannelTestReadLine(t, reader); line != "PROXY_RESULT SUCCEEDED envelope-001" {
			t.Errorf("proxy result = %q", line)
			return
		}
		_, _ = fmt.Fprintf(connection, "OUTPUT envelope-001 stdout 0 %s %s\n", sandboxhostprotocol.Digest(output), base64.RawURLEncoding.EncodeToString(output))
		_, _ = connection.Write([]byte("RESULT SUCCEEDED envelope-001\n"))
	}}
	channel, err := NewUnixGuestControlChannel(dialer)
	if err != nil {
		t.Fatal(err)
	}
	if err := channel.BindGuestIdentity(context.Background(), "sandbox-001", "fixture-v1"); err != nil {
		t.Fatal(err)
	}
	if err := channel.Bind(context.Background(), "/srv/jailer/sandbox-001/root/run/firecracker.vsock"); err != nil {
		t.Fatal(err)
	}
	lease := sandboxauthority.EgressLease{Principal: "principal-001", SandboxID: "sandbox-001", ProcessID: "process-001", OperationID: "operation-001", ExpiresAt: now.Add(time.Minute), Rules: []sandboxauthority.EgressRule{{Domain: "api.example.invalid", Protocol: "tcp", Ports: []sandboxauthority.PortRange{{First: 443, Last: 443}}}}}
	session, err := sandboxauthority.NewProxySession(lease, "sandbox-001", 9, now)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := channel.ProxyAuthenticated(ctx, envelope, authenticated, session, now, guestChannelResolver("8.8.8.8"), guestChannelDialerFunc(func(context.Context, string, string) (net.Conn, error) { return remoteClient, nil }))
	if err != nil || result.State != "SUCCEEDED" || len(result.Outputs) != 1 || string(result.Outputs[0].Data) != "response" {
		t.Fatalf("ProxyAuthenticated() = (%#v, %v), want bounded relayed result", result, err)
	}
	<-remoteDone
	dialer.wait()
}

func TestUnixGuestControlChannelRefusesSubstitutedProxyOpenBeforeDialing(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	request := sandboxauthority.ProxySessionRequest{SandboxID: "sandbox-001", ProcessID: "process-001", OperationID: "operation-001", VMID: "sandbox-001", FencingToken: 9, Destination: sandboxauthority.EgressDestination{Domain: "api.example.invalid", Protocol: "tcp", Port: 443}}
	payload, _ := json.Marshal(GuestProxyPayload{Version: GuestProxyOperationKind, Request: request})
	envelope := sandboxhostprotocol.Envelope{EnvelopeID: "envelope-001", DeliveryID: "delivery-001", FencingToken: 9, SandboxID: "sandbox-001", ProcessID: "process-001", OperationID: "operation-001", OperationKind: GuestProxyOperationKind, Payload: payload}
	envelope.PayloadDigest = sandboxhostprotocol.Digest(payload)
	authenticated, _ := json.Marshal(envelope)
	dialer := &guestChannelDialer{handler: func(connection net.Conn) {
		defer connection.Close()
		reader := bufio.NewReader(connection)
		_ = guestChannelTestReadLine(t, reader)
		_, _ = connection.Write([]byte("OK sandbox-001 fixture-v1\n"))
		_ = guestChannelTestReadLine(t, reader)
		request.FencingToken++
		open, _ := EncodeGuestProxyOpen(request)
		_, _ = fmt.Fprintf(connection, "PROXY_OPEN %s\n", base64.RawURLEncoding.EncodeToString(open))
	}}
	channel, _ := NewUnixGuestControlChannel(dialer)
	_ = channel.BindGuestIdentity(context.Background(), "sandbox-001", "fixture-v1")
	_ = channel.Bind(context.Background(), "/srv/jailer/sandbox-001/root/run/firecracker.vsock")
	lease := sandboxauthority.EgressLease{Principal: "principal-001", SandboxID: "sandbox-001", ProcessID: "process-001", OperationID: "operation-001", ExpiresAt: now.Add(time.Minute), Rules: []sandboxauthority.EgressRule{{Domain: "api.example.invalid", Protocol: "tcp", Ports: []sandboxauthority.PortRange{{First: 443, Last: 443}}}}}
	session, _ := sandboxauthority.NewProxySession(lease, "sandbox-001", 9, now)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := channel.ProxyAuthenticated(ctx, envelope, authenticated, session, now, guestChannelResolver("8.8.8.8"), guestChannelDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("dialled substituted proxy request")
		return nil, nil
	})); !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("ProxyAuthenticated() error = %v, want capability unavailable", err)
	}
	dialer.wait()
}

func TestUnixGuestControlChannelReaperClosesTheBoundProxySession(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	request := sandboxauthority.ProxySessionRequest{SandboxID: "sandbox-001", ProcessID: "process-001", OperationID: "operation-001", VMID: "sandbox-001", FencingToken: 9, Destination: sandboxauthority.EgressDestination{Domain: "api.example.invalid", Protocol: "tcp", Port: 443}}
	payload, _ := json.Marshal(GuestProxyPayload{Version: GuestProxyOperationKind, Request: request})
	envelope := sandboxhostprotocol.Envelope{EnvelopeID: "envelope-001", DeliveryID: "delivery-001", FencingToken: 9, SandboxID: "sandbox-001", ProcessID: "process-001", OperationID: "operation-001", OperationKind: GuestProxyOperationKind, Payload: payload}
	envelope.PayloadDigest = sandboxhostprotocol.Digest(payload)
	authenticated, _ := json.Marshal(envelope)
	remoteClient, remoteServer := net.Pipe()
	remoteClosed := make(chan error, 1)
	go func() {
		_, err := remoteServer.Read(make([]byte, 1))
		remoteClosed <- err
		_ = remoteServer.Close()
	}()
	connected := make(chan struct{})
	dialer := &guestChannelDialer{handler: func(connection net.Conn) {
		defer connection.Close()
		reader := bufio.NewReader(connection)
		_ = guestChannelTestReadLine(t, reader)
		_, _ = connection.Write([]byte("OK sandbox-001 fixture-v1\n"))
		_ = guestChannelTestReadLine(t, reader)
		open, _ := EncodeGuestProxyOpen(request)
		_, _ = fmt.Fprintf(connection, "PROXY_OPEN %s\n", base64.RawURLEncoding.EncodeToString(open))
		if line := guestChannelTestReadLine(t, reader); line != "PROXY_CONNECTED envelope-001" {
			return
		}
		close(connected)
		_, _ = reader.ReadByte()
	}}
	channel, _ := NewUnixGuestControlChannel(dialer)
	_ = channel.BindGuestIdentity(context.Background(), "sandbox-001", "fixture-v1")
	_ = channel.Bind(context.Background(), "/srv/jailer/sandbox-001/root/run/firecracker.vsock")
	lease := sandboxauthority.EgressLease{Principal: "principal-001", SandboxID: "sandbox-001", ProcessID: "process-001", OperationID: "operation-001", ExpiresAt: now.Add(time.Minute), Rules: []sandboxauthority.EgressRule{{Domain: "api.example.invalid", Protocol: "tcp", Ports: []sandboxauthority.PortRange{{First: 443, Last: 443}}}}}
	session, _ := sandboxauthority.NewProxySession(lease, "sandbox-001", 9, now)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := channel.ProxyAuthenticated(ctx, envelope, authenticated, session, now, guestChannelResolver("8.8.8.8"), guestChannelDialerFunc(func(context.Context, string, string) (net.Conn, error) { return remoteClient, nil }))
		result <- err
	}()
	<-connected
	if err := channel.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-result; err == nil {
		t.Fatal("ProxyAuthenticated() completed after reaper close")
	}
	if err := <-remoteClosed; err == nil {
		t.Fatal("reaper left the outbound proxy connection open")
	}
	dialer.wait()
}

type guestChannelDialer struct {
	mu      sync.Mutex
	calls   []string
	handler func(net.Conn)
	wg      sync.WaitGroup
}

func (dialer *guestChannelDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	dialer.mu.Lock()
	dialer.calls = append(dialer.calls, network+":"+address)
	handler := dialer.handler
	dialer.mu.Unlock()
	if handler == nil {
		return nil, errors.New("guest test dial is not configured")
	}
	client, server := net.Pipe()
	dialer.wg.Add(1)
	go func() {
		defer dialer.wg.Done()
		handler(server)
	}()
	return client, nil
}

func (dialer *guestChannelDialer) targets() []string {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	return append([]string(nil), dialer.calls...)
}

func (dialer *guestChannelDialer) wait() { dialer.wg.Wait() }

func guestChannelTestReadLine(t *testing.T, reader *bufio.Reader) string {
	t.Helper()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Errorf("read guest test line: %v", err)
		return ""
	}
	return strings.TrimSuffix(line, "\n")
}

type guestChannelResolver string

func (resolver guestChannelResolver) Resolve(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP(string(resolver))}}, nil
}

type guestChannelDialerFunc func(context.Context, string, string) (net.Conn, error)

func (dialer guestChannelDialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return dialer(ctx, network, address)
}
