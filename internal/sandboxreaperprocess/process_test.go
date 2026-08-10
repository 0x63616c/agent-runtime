package sandboxreaperprocess

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/sandboxcontrol"
)

func TestParseRequiresFiniteExplicitReaperDeclaration(t *testing.T) {
	t.Parallel()

	config, err := Parse(strings.NewReader(`{"version":1,"database_dsn_environment":"SANDBOX_DATABASE_DSN","interval_millis":1000,"page_size":100}`))
	if err != nil || config.interval != time.Second || config.pageSize != 100 {
		t.Fatalf("Parse() = %#v, %v", config, err)
	}
	if _, err := Parse(strings.NewReader(`{"version":1,"database_dsn_environment":"ambient-dsn","interval_millis":0,"page_size":0}`)); err == nil {
		t.Fatal("Parse() accepted ambient or unbounded declaration")
	}
}

func TestReconcileOnceInvokesEveryDurableRecoveryBoundary(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	store := &recordingStore{}
	summary, err := ReconcileOnce(context.Background(), store, now, 73)
	if err != nil {
		t.Fatal(err)
	}
	if store.recovered != 1 || store.claimed != 1 || store.reaped != 1 || store.now != now || store.pageSize != 73 || summary.ObservedAt != now {
		t.Fatalf("reconciliation calls = %#v", store)
	}
}

func TestLoopUsesInjectedClockAndWait(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	source, _ := clock.NewFake(now)
	store := &recordingStore{}
	waits := 0
	observed := 0
	err := Loop(context.Background(), store, source, time.Second, 7, func(context.Context, time.Duration) error {
		waits++
		return context.Canceled
	}, func(Summary) { observed++ })
	if err != nil || waits != 1 || observed != 1 || store.recovered != 1 || store.now != now || store.pageSize != 7 {
		t.Fatalf("Loop() waits=%d store=%#v error=%v", waits, store, err)
	}
}

type recordingStore struct {
	recovered int
	claimed   int
	reaped    int
	now       time.Time
	pageSize  int
}

func (store *recordingStore) RecoverExpiredAssignments(_ context.Context, now time.Time, pageSize int) ([]sandboxcontrol.Operation, error) {
	store.recovered++
	store.now, store.pageSize = now, pageSize
	return nil, nil
}

func (store *recordingStore) ClaimExpiredCleanup(_ context.Context, _ time.Time, _ int) ([]sandboxcontrol.Operation, error) {
	store.claimed++
	return nil, nil
}

func (store *recordingStore) Reap(_ context.Context, _ time.Time, _ int) ([]sandboxcontrol.Operation, error) {
	store.reaped++
	return nil, nil
}
