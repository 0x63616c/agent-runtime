package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestServeEmitsMarkerAndEchoesOneNonce(t *testing.T) {
	var output bytes.Buffer

	if err := serve("sandbox-001", "fixture-v1", strings.NewReader("PING nonce-123\n"), &output); err != nil {
		t.Fatalf("serve() error = %v", err)
	}
	if got, want := output.String(), "AGENT_RUNTIME_FC_SMOKE sandbox-001 fixture-v1 agent-runtime-firecracker-guest/v1\nPONG sandbox-001 nonce-123\n"; got != want {
		t.Fatalf("serve() output = %q, want %q", got, want)
	}
}

func TestServeRefusesAnUnboundedControlLine(t *testing.T) {
	var output bytes.Buffer
	request := "PING " + strings.Repeat("a", 1025) + "\n"

	if err := serve("sandbox-001", "fixture-v1", strings.NewReader(request), &output); err == nil {
		t.Fatal("serve() error = nil, want bounded-control refusal")
	}
}
