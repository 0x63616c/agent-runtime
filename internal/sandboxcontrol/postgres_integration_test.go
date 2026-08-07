//go:build integration

package sandboxcontrol

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresLedgerSurvivesRestartAndReconcilesExpiredAuthority(t *testing.T) {
	dsn := os.Getenv("AR_SANDBOXCONTROL_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("AR_SANDBOXCONTROL_POSTGRES_DSN is required for the integration suite")
	}
	ctx := context.Background()
	pool := openIntegrationPool(t, ctx, dsn)
	if _, err := pool.Exec(ctx, `TRUNCATE runtime.sandbox_operation_outbox, runtime.sandbox_operations RESTART IDENTITY`); err != nil {
		t.Fatalf("truncate integration ledger: %v", err)
	}
	ledger, err := NewPostgresLedger(pool)
	if err != nil {
		t.Fatalf("NewPostgresLedger() error = %v", err)
	}
	now := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	input := Operation{Principal: "tenant-a:principal-a", ID: "op_restart", CanonicalDigest: "sha256:request", EffectiveSpecDigest: "sha256:effective", AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour), CleanupRequired: true}
	accepted, replay, err := ledger.Accept(ctx, input)
	if err != nil || replay {
		t.Fatalf("Accept() = %#v, %v, %v", accepted, replay, err)
	}
	assigned, err := ledger.Assign(ctx, input.Principal, input.ID, "host-a", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Assign() error = %v", err)
	}
	pool.Close()

	pool = openIntegrationPool(t, ctx, dsn)
	t.Cleanup(pool.Close)
	ledger, err = NewPostgresLedger(pool)
	if err != nil {
		t.Fatalf("NewPostgresLedger(after restart) error = %v", err)
	}
	reconnected, replay, err := ledger.Accept(ctx, input)
	if err != nil || !replay || reconnected != assigned {
		t.Fatalf("Accept(after restart) = %#v, %v, %v; want %#v", reconnected, replay, err, assigned)
	}
	if _, err := ledger.Get(ctx, "tenant-b:principal-b", input.ID); !errors.Is(err, ErrNotFoundOrDenied) {
		t.Fatalf("cross-principal Get() error = %v, want ErrNotFoundOrDenied", err)
	}
	recovered, err := ledger.RecoverExpiredAssignments(ctx, now.Add(time.Minute), 10)
	if err != nil || len(recovered) != 1 || recovered[0].State != StateUncertain || recovered[0].Assignment.FencingToken != assigned.Assignment.FencingToken+1 {
		t.Fatalf("RecoverExpiredAssignments() = %#v, %v", recovered, err)
	}
	if _, err := ledger.RecordHostResult(ctx, input.Principal, input.ID, HostResult{HostID: "host-a", FencingToken: assigned.Assignment.FencingToken, State: StateSucceeded, ObservedAt: now.Add(30 * time.Second)}); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("stale RecordHostResult() error = %v, want ErrStaleFence", err)
	}
	reassigned, err := ledger.Assign(ctx, input.Principal, input.ID, "host-b", now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("reconcile Assign() error = %v", err)
	}
	completed, err := ledger.RecordHostResult(ctx, input.Principal, input.ID, HostResult{HostID: "host-b", FencingToken: reassigned.Assignment.FencingToken, State: StateSucceeded, ObservedAt: now.Add(2 * time.Minute)})
	if err != nil {
		t.Fatalf("successful RecordHostResult() error = %v", err)
	}
	claimed, err := ledger.ClaimExpiredCleanup(ctx, now.Add(time.Hour), 10)
	if err != nil || len(claimed) != 1 || claimed[0].State != StateCleanupPending || claimed[0].Version != completed.Version+1 || claimed[0].Assignment.HostID != "" {
		t.Fatalf("ClaimExpiredCleanup() = %#v, %v", claimed, err)
	}
	confirmed, err := ledger.Transition(ctx, input.Principal, input.ID, claimed[0].Version, StateCleanupConfirmed)
	if err != nil {
		t.Fatalf("cleanup-confirmed Transition() error = %v", err)
	}
	reaped, err := ledger.Reap(ctx, now.Add(time.Hour), 10)
	if err != nil || len(reaped) != 1 || reaped[0].State != StateTombstoned || reaped[0].Version != confirmed.Version+1 {
		t.Fatalf("Reap() = %#v, %v", reaped, err)
	}
	if _, _, err := ledger.Accept(ctx, input); !errors.Is(err, ErrOperationIDExpired) {
		t.Fatalf("Accept(tombstone) error = %v, want ErrOperationIDExpired", err)
	}
	records, err := ledger.ReadOutbox(ctx, 0, 100)
	if err != nil || len(records) != 8 {
		t.Fatalf("ReadOutbox() count = %d, error = %v, records = %#v", len(records), err, records)
	}
	for index, record := range records {
		if record.ID != uint64(index+1) || record.OperationVersion != uint64(index+1) {
			t.Fatalf("ReadOutbox()[%d] = %#v; want matching durable sequences", index, record)
		}
	}
}

func TestPostgresLedgerConcurrentlyAcceptsOneImmutableOperation(t *testing.T) {
	dsn := os.Getenv("AR_SANDBOXCONTROL_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("AR_SANDBOXCONTROL_POSTGRES_DSN is required for the integration suite")
	}
	ctx := context.Background()
	pool := openIntegrationPool(t, ctx, dsn)
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `TRUNCATE runtime.sandbox_operation_outbox, runtime.sandbox_operations RESTART IDENTITY`); err != nil {
		t.Fatalf("truncate integration ledger: %v", err)
	}
	ledger, err := NewPostgresLedger(pool)
	if err != nil {
		t.Fatalf("NewPostgresLedger() error = %v", err)
	}
	now := time.Date(2026, 8, 7, 2, 0, 0, 0, time.UTC)
	input := Operation{Principal: "tenant-a:principal-a", ID: "op_concurrent", CanonicalDigest: "sha256:request", EffectiveSpecDigest: "sha256:effective", AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour)}

	const callers = 32
	var firsts atomic.Int64
	var wait sync.WaitGroup
	errorsByCaller := make(chan error, callers)
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			operation, replay, err := ledger.Accept(ctx, input)
			if err == nil && operation.State != StateAccepted {
				err = errors.New("accepted operation has wrong state")
			}
			if !replay {
				firsts.Add(1)
			}
			errorsByCaller <- err
		}()
	}
	wait.Wait()
	close(errorsByCaller)
	for err := range errorsByCaller {
		if err != nil {
			t.Fatalf("concurrent Accept() error = %v", err)
		}
	}
	if firsts.Load() != 1 {
		t.Fatalf("non-replay accepts = %d, want 1", firsts.Load())
	}
	records, err := ledger.ReadOutbox(ctx, 0, 10)
	if err != nil || len(records) != 1 || records[0].Event != OutboxAccepted {
		t.Fatalf("ReadOutbox() = %#v, %v; want one acceptance", records, err)
	}
	changed := input
	changed.CanonicalDigest = "sha256:changed"
	if _, _, err := ledger.Accept(ctx, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("Accept(changed immutable request) error = %v, want ErrConflict", err)
	}
}

func openIntegrationPool(t *testing.T, ctx context.Context, dsn string) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse integration PostgreSQL configuration: %v", err)
	}
	config.MaxConns = 40
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("open integration PostgreSQL pool: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping integration PostgreSQL: %v", err)
	}
	return pool
}
