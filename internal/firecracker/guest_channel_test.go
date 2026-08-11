package firecracker

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"

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
