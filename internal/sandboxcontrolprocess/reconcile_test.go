package sandboxcontrolprocess

import (
	"context"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxcontrol"
)

func TestReconcileOnceInvokesEveryDurableRecoveryBoundary(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	store := &recordingReconciliationStore{}
	if err := reconcileOnce(context.Background(), store, now, 73); err != nil {
		t.Fatal(err)
	}
	if store.recovered != 1 || store.claimed != 1 || store.reaped != 1 || store.now != now || store.pageSize != 73 {
		t.Fatalf("reconciliation calls = %#v", store)
	}
}

type recordingReconciliationStore struct {
	recovered int
	claimed   int
	reaped    int
	now       time.Time
	pageSize  int
}

func (store *recordingReconciliationStore) RecoverExpiredAssignments(_ context.Context, now time.Time, pageSize int) ([]sandboxcontrol.Operation, error) {
	store.recovered++
	store.now, store.pageSize = now, pageSize
	return nil, nil
}

func (store *recordingReconciliationStore) ClaimExpiredCleanup(_ context.Context, _ time.Time, _ int) ([]sandboxcontrol.Operation, error) {
	store.claimed++
	return nil, nil
}

func (store *recordingReconciliationStore) Reap(_ context.Context, _ time.Time, _ int) ([]sandboxcontrol.Operation, error) {
	store.reaped++
	return nil, nil
}
