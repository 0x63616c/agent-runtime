package sandboxauthority

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestProxySessionBindsLeaseVMFenceDestinationAndReaper(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	session := newTestProxySession(t, now)
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	request := testProxySessionRequest()
	connection, err := session.Connect(context.Background(), request, now, publicResolver("8.8.8.8"), dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		return client, nil
	}))
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := connection.Write([]byte("x")); err == nil {
		t.Fatal("reaper left proxy connection open")
	}
}

func TestProxySessionRefusesReplayIdentitySubstitutionAndUnadmittedDestination(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	for name, mutate := range map[string]func(*ProxySessionRequest){
		"wrong sandbox":   func(request *ProxySessionRequest) { request.SandboxID = "other" },
		"wrong process":   func(request *ProxySessionRequest) { request.ProcessID = "other" },
		"wrong operation": func(request *ProxySessionRequest) { request.OperationID = "other" },
		"wrong VM":        func(request *ProxySessionRequest) { request.VMID = "vm-02" },
		"stale fence":     func(request *ProxySessionRequest) { request.FencingToken++ },
		"wrong target": func(request *ProxySessionRequest) {
			request.Destination.Domain = "metadata.google.internal"
		},
	} {
		t.Run(name, func(t *testing.T) {
			session := newTestProxySession(t, now)
			request := testProxySessionRequest()
			mutate(&request)
			if _, err := session.Connect(context.Background(), request, now, publicResolver("8.8.8.8"), failingDialer{}); !errors.Is(err, ErrDenied) {
				t.Fatalf("Connect() error = %v, want denied", err)
			}
		})
	}

	t.Run("replay", func(t *testing.T) {
		session := newTestProxySession(t, now)
		first, peer := net.Pipe()
		defer func() { _ = peer.Close() }()
		request := testProxySessionRequest()
		if _, err := session.Connect(context.Background(), request, now, publicResolver("8.8.8.8"), dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			return first, nil
		})); err != nil {
			t.Fatalf("first Connect() error = %v", err)
		}
		if _, err := session.Connect(context.Background(), request, now, publicResolver("8.8.8.8"), failingDialer{}); !errors.Is(err, ErrDenied) {
			t.Fatalf("replayed Connect() error = %v, want denied", err)
		}
	})
}

func TestProxySessionRefusesPrivateResolutionAndExpiredLeaseWithoutDialing(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	for name, test := range map[string]struct {
		when     time.Time
		resolver Resolver
	}{
		"private resolution": {when: now, resolver: publicResolver("169.254.169.254")},
		"expired lease":      {when: now.Add(time.Minute), resolver: publicResolver("8.8.8.8")},
	} {
		t.Run(name, func(t *testing.T) {
			session := newTestProxySession(t, now)
			if _, err := session.Connect(context.Background(), testProxySessionRequest(), test.when, test.resolver, failingDialer{}); err == nil {
				t.Fatal("Connect() accepted a prohibited proxy target")
			}
		})
	}
}

func newTestProxySession(t *testing.T, now time.Time) *ProxySession {
	t.Helper()
	lease := EgressLease{
		Principal:   "principal-001",
		SandboxID:   "sandbox-001",
		ProcessID:   "process-001",
		OperationID: "operation-001",
		ExpiresAt:   now.Add(time.Minute),
		Rules: []EgressRule{{
			Domain:   "api.example.invalid",
			Protocol: "tcp",
			Ports:    []PortRange{{First: 443, Last: 443}},
		}},
	}
	session, err := NewProxySession(lease, "vm-01", 9, now)
	if err != nil {
		t.Fatalf("NewProxySession() error = %v", err)
	}
	return session
}

func testProxySessionRequest() ProxySessionRequest {
	return ProxySessionRequest{
		SandboxID:    "sandbox-001",
		ProcessID:    "process-001",
		OperationID:  "operation-001",
		VMID:         "vm-01",
		FencingToken: 9,
		Destination: EgressDestination{
			Domain:   "api.example.invalid",
			Protocol: "tcp",
			Port:     443,
		},
	}
}

func publicResolver(address string) Resolver {
	return resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP(address)}}, nil
	})
}

type failingDialer struct{}

func (failingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("dial must not run")
}
