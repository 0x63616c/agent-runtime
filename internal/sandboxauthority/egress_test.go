package sandboxauthority

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestEgressLeaseAllowsOnlyFrozenDomainPortAndPinsOnePublicResolution(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	lease, err := NewEgressLease(EgressLease{Principal: "tenant:alice", SandboxID: "sbx_01", ProcessID: "prc_01", OperationID: "op_01", ExpiresAt: now.Add(time.Minute), Rules: []EgressRule{{Domain: "*.example.invalid", Protocol: "tcp", Ports: []PortRange{{First: 443, Last: 443}}}}}, now)
	if err != nil {
		t.Fatal(err)
	}
	dialed := ""
	client, server := net.Pipe()
	defer server.Close()
	connection, err := lease.Connect(context.Background(), EgressDestination{Domain: "api.example.invalid", Protocol: "tcp", Port: 443}, now, resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	}), dialerFunc(func(_ context.Context, _ string, address string) (net.Conn, error) {
		dialed = address
		return client, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	if dialed != "8.8.8.8:443" {
		t.Fatalf("dialed %q", dialed)
	}
	if err := lease.Authorize(EgressDestination{Domain: "example.invalid", Protocol: "tcp", Port: 443}, now); err == nil {
		t.Fatal("wildcard authorized apex")
	}
}
func TestEgressLeaseRefusesPrivateResolvedAddressAndExpiredAuthority(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	lease, err := NewEgressLease(EgressLease{Principal: "p", SandboxID: "s", ProcessID: "p", OperationID: "o", ExpiresAt: now.Add(time.Minute), Rules: []EgressRule{{Domain: "api.example.invalid", Protocol: "tcp", Ports: []PortRange{{First: 443, Last: 443}}}}}, now)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	_, err = lease.Connect(context.Background(), EgressDestination{Domain: "api.example.invalid", Protocol: "tcp", Port: 443}, now, resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
	}), dialerFunc(func(context.Context, string, string) (net.Conn, error) { called = true; return nil, nil }))
	if err == nil || called {
		t.Fatalf("private egress = %v, dial=%t", err, called)
	}
	if err := lease.Authorize(EgressDestination{Domain: "api.example.invalid", Protocol: "tcp", Port: 443}, now.Add(time.Minute)); err != ErrExpired {
		t.Fatalf("expired authority = %v", err)
	}
}

type resolverFunc func(context.Context, string) ([]net.IPAddr, error)

func (f resolverFunc) Resolve(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f(ctx, host)
}

type dialerFunc func(context.Context, string, string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}
