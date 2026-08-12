package runtimeapiprocess

import (
	"context"
	"strings"
	"testing"
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

func TestReadinessGateSuppressesCallbackAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	gate := newReadinessGate(ctx, func(string) { t.Fatal("readiness callback ran after cancellation") })
	cancel()
	gate.announce("127.0.0.1:8088")
	gate.stop()
}
