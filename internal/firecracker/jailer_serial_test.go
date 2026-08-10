package firecracker

import (
	"context"
	"errors"
	"testing"
)

func TestBoundedJailerOutputAwaitsOnlyAnExactSerialMarkerLine(t *testing.T) {
	output := newBoundedJailerOutput(1024)
	marker := "AGENT_RUNTIME_FC_SMOKE sandbox-001 fixture-v1 agent-runtime-firecracker-guest/v1"
	result := make(chan error, 1)
	go func() { result <- output.AwaitSerial(context.Background(), marker) }()

	if _, err := output.Write([]byte("prefix " + marker + "\npartial")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if _, err := output.Write([]byte(" noise\n" + marker + "\r\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := <-result; err != nil {
		t.Fatalf("AwaitSerial() error = %v, want exact CRLF-terminated marker", err)
	}
}

func TestBoundedJailerOutputPreservesCancellationAndRefusesUnboundedOrClosedMarkerSearch(t *testing.T) {
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := newBoundedJailerOutput(1024).AwaitSerial(ctx, "AGENT_RUNTIME_FC_SMOKE sandbox-001 fixture-v1 agent-runtime-firecracker-guest/v1"); !errors.Is(err, context.Canceled) {
			t.Fatalf("AwaitSerial() error = %v, want preserved cancellation", err)
		}
	})
	t.Run("bound exhausted", func(t *testing.T) {
		output := newBoundedJailerOutput(4)
		if _, err := output.Write([]byte("noise")); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
		if err := output.AwaitSerial(context.Background(), "AGENT_RUNTIME_FC_SMOKE sandbox-001 fixture-v1 agent-runtime-firecracker-guest/v1"); !errors.Is(err, ErrSmokeUnavailable) {
			t.Fatalf("AwaitSerial() error = %v, want bounded marker refusal", err)
		}
	})
	t.Run("stream closed", func(t *testing.T) {
		output := newBoundedJailerOutput(1024)
		output.Close()
		if err := output.AwaitSerial(context.Background(), "AGENT_RUNTIME_FC_SMOKE sandbox-001 fixture-v1 agent-runtime-firecracker-guest/v1"); !errors.Is(err, ErrSmokeUnavailable) {
			t.Fatalf("AwaitSerial() error = %v, want closed-stream refusal", err)
		}
	})
	t.Run("unterminated marker", func(t *testing.T) {
		output := newBoundedJailerOutput(1024)
		marker := "AGENT_RUNTIME_FC_SMOKE sandbox-001 fixture-v1 agent-runtime-firecracker-guest/v1"
		if _, err := output.Write([]byte(marker)); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
		output.Close()
		if err := output.AwaitSerial(context.Background(), marker); !errors.Is(err, ErrSmokeUnavailable) {
			t.Fatalf("AwaitSerial() error = %v, want unterminated marker refusal", err)
		}
	})
}

func TestOSJailerCommandRefusesASerialMarkerWrittenOnlyToStderr(t *testing.T) {
	command := newOSJailerCommand("/opt/firecracker/jailer", []string{"--id", "sandbox-001"}, "/srv/agent-runtime/jailer/firecracker/sandbox-001/root").(*osJailerCommand)
	marker := "AGENT_RUNTIME_FC_SMOKE sandbox-001 fixture-v1 agent-runtime-firecracker-guest/v1"
	if _, err := command.diagnostics.Write([]byte(marker + "\n")); err != nil {
		t.Fatalf("write stderr diagnostic: %v", err)
	}
	command.SerialOutput().Close()
	if err := command.SerialOutput().AwaitSerial(context.Background(), marker); !errors.Is(err, ErrSmokeUnavailable) {
		t.Fatalf("AwaitSerial() error = %v, want stderr-only marker refusal", err)
	}
}
