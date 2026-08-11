package runtimeorchestration

import (
	"context"
	"testing"
	"time"
)

func TestWaitForIntervalCompletesSuccessfullyAfterElapsedInterval(t *testing.T) {
	if err := waitForInterval(context.Background(), time.Millisecond); err != nil {
		t.Fatalf("wait interval error = %v, want nil", err)
	}
}

func TestWaitForIntervalPreservesCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForInterval(ctx, time.Second); err != context.Canceled {
		t.Fatalf("wait interval error = %v, want canceled", err)
	}
}

func TestPublishUntilCancelledScansAfterANormalInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waits, scans := 0, 0
	err := publishUntilCancelled(ctx, func(context.Context, time.Duration) error {
		waits++
		if waits == 1 {
			return nil
		}
		cancel()
		return context.Canceled
	}, func(context.Context) error {
		scans++
		return nil
	})
	if err != nil {
		t.Fatalf("publish loop error = %v, want nil", err)
	}
	if scans != 1 {
		t.Fatalf("scans = %d, want one scan after the normal interval", scans)
	}
}

func TestPublishUntilCancelledDoesNotScanAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	scans := 0
	err := publishUntilCancelled(ctx, func(context.Context, time.Duration) error {
		return context.Canceled
	}, func(context.Context) error {
		scans++
		return nil
	})
	if err != nil {
		t.Fatalf("publish loop error = %v, want nil", err)
	}
	if scans != 0 {
		t.Fatalf("scans = %d, want no scan after cancellation", scans)
	}
}
