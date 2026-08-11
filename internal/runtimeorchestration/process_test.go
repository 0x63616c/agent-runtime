package runtimeorchestration

import (
	"context"
	"testing"
	"time"
)

func TestWaitForIntervalSignalsElapsedDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if err := waitForInterval(ctx, time.Millisecond); err != context.DeadlineExceeded {
		t.Fatalf("wait interval error = %v, want deadline exceeded", err)
	}
}
