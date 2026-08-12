//go:build integration

package runtimeapiprocess

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestIntegrationProcessWithholdsReadinessUntilListenerAccepts(t *testing.T) {
	config, err := Parse(strings.NewReader(`{"version":1,"listen_address":"127.0.0.1:0","storage":{"mode":"memory-unsafe"},"model_profiles":["balanced"],"max_request_bytes":4194304,"principals":[{"tenant":"local","principal":"admin","admin":true,"bearer_token_environment":"ADMIN_TOKEN"}]}`))
	if err != nil {
		t.Fatalf("parse process configuration: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	blocked := &acceptBlockingListener{Listener: listener, accepting: make(chan struct{}), allow: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	announced := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, config, func(name string) (string, bool) {
			return map[string]string{"ADMIN_TOKEN": "admin-token-0000"}[name], name == "ADMIN_TOKEN"
		}, blocked, func(string) { announced <- struct{}{} })
	}()
	<-blocked.accepting
	select {
	case <-announced:
		t.Fatal("readiness callback ran before the listener accepted the internal health probe")
	default:
	}
	close(blocked.allow)
	<-announced
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("stop runtime process: %v", err)
	}
}

type acceptBlockingListener struct {
	net.Listener
	accepting chan struct{}
	allow     chan struct{}
}

func (listener *acceptBlockingListener) Accept() (net.Conn, error) {
	select {
	case listener.accepting <- struct{}{}:
	default:
	}
	<-listener.allow
	return listener.Listener.Accept()
}
