package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
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
