package runtimeapiprocess

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRunDoesNotAnnounceReadinessUntilCompositionSucceeds(t *testing.T) {
	config, err := Parse(strings.NewReader(`{
  "version": 1,
  "listen_address": "127.0.0.1:0",
  "storage": {"mode":"memory-unsafe"},
  "model_profiles": ["balanced"],
  "max_request_bytes": 4194304,
  "principals": [{"tenant":"local","principal":"admin","admin":true,"bearer_token_environment":"ADMIN_TOKEN"}]
}`))
	if err != nil {
		t.Fatalf("parse configuration: %v", err)
	}
	announcements := 0
	err = Run(context.Background(), config, func(string) (string, bool) { return "", false }, func(string) { announcements++ })
	if err == nil || !strings.Contains(err.Error(), "bearer token") {
		t.Fatalf("run error = %v, want missing bearer-token composition failure", err)
	}
	if announcements != 0 {
		t.Fatalf("readiness announcements = %d, want none before failed composition", announcements)
	}
}

func TestRunDoesNotAnnounceReadinessAfterCancellation(t *testing.T) {
	config, err := Parse(strings.NewReader(`{
  "version": 1,
  "listen_address": "127.0.0.1:0",
  "storage": {"mode":"memory-unsafe"},
  "model_profiles": ["balanced"],
  "max_request_bytes": 4194304,
  "principals": [{"tenant":"local","principal":"admin","admin":true,"bearer_token_environment":"ADMIN_TOKEN"}]
}`))
	if err != nil {
		t.Fatalf("parse configuration: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	announcements := 0
	if err := Run(ctx, config, func(string) (string, bool) { return "admin-token-0000", true }, func(string) { announcements++ }); err != nil {
		t.Fatalf("run cancelled process: %v", err)
	}
	if announcements != 0 {
		t.Fatalf("readiness announcements = %d, want none after cancellation", announcements)
	}
}

func TestRuntimeAPIServerUsesFiniteBodyAndResponseDeadlines(t *testing.T) {
	server := newHTTPServer(http.NotFoundHandler())
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.WriteTimeout <= 0 || server.IdleTimeout <= 0 {
		t.Fatalf("server deadlines = header=%s read=%s write=%s idle=%s, want every public connection phase bounded", server.ReadHeaderTimeout, server.ReadTimeout, server.WriteTimeout, server.IdleTimeout)
	}
	if server.ReadTimeout < server.ReadHeaderTimeout {
		t.Fatalf("read timeout = %s, want at least header timeout %s", server.ReadTimeout, server.ReadHeaderTimeout)
	}
	if server.WriteTimeout < server.ReadTimeout {
		t.Fatalf("write timeout = %s, want at least read timeout %s", server.WriteTimeout, server.ReadTimeout)
	}
	if server.MaxHeaderBytes != 16<<10 {
		t.Fatalf("max header bytes = %d, want 16384", server.MaxHeaderBytes)
	}
	if server.ReadTimeout > 30*time.Second || server.WriteTimeout > 30*time.Second {
		t.Fatalf("server deadlines = read %s write %s, want bounded operational limits", server.ReadTimeout, server.WriteTimeout)
	}
}

func TestRuntimeAPIServerClosesSlowMutationBodyAtReadDeadline(t *testing.T) {
	bodyRead := make(chan error, 1)
	server := newHTTPServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, err := request.Body.Read(make([]byte, 1))
		bodyRead <- err
		writer.WriteHeader(http.StatusNoContent)
	}))
	server.ReadHeaderTimeout = 20 * time.Millisecond
	server.ReadTimeout = 40 * time.Millisecond
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	stopped := make(chan error, 1)
	go func() { stopped <- server.Serve(listener) }()
	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = connection.Close() }()
	if _, err := connection.Write([]byte("POST / HTTP/1.1\r\nHost: runtime\r\nContent-Length: 1\r\n\r\n")); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	response := make([]byte, 1)
	if _, err := connection.Read(response); err != nil {
		t.Fatalf("read timeout response: %v", err)
	}
	if err := <-bodyRead; err == nil {
		t.Fatal("slow request body read = nil, want read deadline failure")
	}
	if err := server.Close(); err != nil {
		t.Fatalf("close server: %v", err)
	}
	if err := <-stopped; err != nil && err != http.ErrServerClosed {
		t.Fatalf("serve: %v", err)
	}
}
