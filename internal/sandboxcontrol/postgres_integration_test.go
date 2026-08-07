//go:build integration

package sandboxcontrol

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresLedgerSurvivesRestartAndReconcilesExpiredAuthority(t *testing.T) {
	dsn := os.Getenv("AR_SANDBOXCONTROL_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("AR_SANDBOXCONTROL_POSTGRES_DSN is required for the integration suite")
	}
	ctx := context.Background()
	pool := openIntegrationPool(t, ctx, dsn)
	if _, err := pool.Exec(ctx, `TRUNCATE runtime.sandbox_host_outputs, runtime.sandbox_host_dispatches, runtime.sandbox_host_enrollments, runtime.sandbox_operation_outbox, runtime.sandbox_operations RESTART IDENTITY`); err != nil {
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
	if _, err := pool.Exec(ctx, `TRUNCATE runtime.sandbox_host_outputs, runtime.sandbox_host_dispatches, runtime.sandbox_host_enrollments, runtime.sandbox_operation_outbox, runtime.sandbox_operations RESTART IDENTITY`); err != nil {
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

func TestPostgresHostControlPersistsLostAckAndQuarantineAcrossRestart(t *testing.T) {
	dsn := os.Getenv("AR_SANDBOXCONTROL_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("AR_SANDBOXCONTROL_POSTGRES_DSN is required for the integration suite")
	}
	ctx := context.Background()
	pool := openIntegrationPool(t, ctx, dsn)
	if _, err := pool.Exec(ctx, `TRUNCATE runtime.sandbox_host_outputs, runtime.sandbox_host_dispatches, runtime.sandbox_host_enrollments, runtime.sandbox_operation_outbox, runtime.sandbox_operations RESTART IDENTITY`); err != nil {
		t.Fatalf("truncate host integration ledger: %v", err)
	}
	ledger, err := NewPostgresLedger(pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 7, 3, 0, 0, 0, time.UTC)
	host := HostEnrollment{HostID: "host_pg", Tenant: "tenant-pg", Pool: "pool-pg", Generation: 2, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: digest("1"), SigningPublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize), CapabilityDigest: digest("2"), Status: HostActive, ExpiresAt: now.Add(time.Hour)}
	if err := ledger.ProvisionHost(ctx, host); err != nil {
		t.Fatal(err)
	}
	operation := Operation{Principal: "tenant-pg:subject-pg", Tenant: host.Tenant, ID: "op_pg_host", Kind: "close-sandbox", TargetKind: "sandbox", TargetID: "sbx_pg_host", InputDigest: digest("3"), CanonicalDigest: digest("4"), EffectiveSpecDigest: digest("5"), CapabilityDigest: host.CapabilityDigest, DispatchBody: `{"version":"sandbox.control/v1"}`, AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour), CleanupRequired: true}
	if _, _, err := ledger.Accept(ctx, operation); err != nil {
		t.Fatal(err)
	}
	identity := HostIdentity{HostID: host.HostID, Generation: host.Generation, CertificateDigest: host.CertificateDigest}
	first, err := ledger.PullHostAssignment(ctx, identity, now, now.Add(time.Minute), DeliverySeed{AssignmentID: "assignment_pg", EnvelopeID: "envelope_pg_1", DeliveryID: "delivery_pg_1", Nonce: "nonce_pg_1"}, testEnvelopeSigner)
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()

	pool = openIntegrationPool(t, ctx, dsn)
	t.Cleanup(pool.Close)
	ledger, _ = NewPostgresLedger(pool)
	duplicate, err := ledger.PullHostAssignment(ctx, identity, now.Add(time.Second), now.Add(time.Minute), DeliverySeed{AssignmentID: "assignment_changed", EnvelopeID: "envelope_changed", DeliveryID: "delivery_changed", Nonce: "nonce_changed"}, testEnvelopeSigner)
	if err != nil || duplicate.EnvelopeDigest != first.EnvelopeDigest || string(duplicate.Envelope) != string(first.Envelope) {
		t.Fatalf("PullHostAssignment(after restart) = %#v, %v", duplicate, err)
	}
	if _, err := ledger.AcknowledgeHostAssignment(ctx, identity, first.Operation.Assignment.AssignmentID, first.Operation.Assignment.FencingToken, digest("6"), now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	firstOutput := sandboxhostprotocol.Output{ProtocolVersion: sandboxhostprotocol.Version, OutputID: "output_pg_01", HostID: host.HostID, HostGeneration: host.Generation, AssignmentID: first.Operation.Assignment.AssignmentID, LeaseEpoch: first.Operation.Assignment.LeaseEpoch, FencingToken: first.Operation.Assignment.FencingToken, Principal: operation.Principal, OperationID: operation.ID, Stream: "stderr", Sequence: 1, ChunkDigest: digest("7"), SizeBytes: 8, ObservedAt: now.Add(2 * time.Second)}
	if duplicate, err := ledger.RecordAuthenticatedHostOutput(ctx, identity, firstOutput, now.Add(2*time.Second)); err != nil || duplicate {
		t.Fatalf("RecordAuthenticatedHostOutput(first) = %t, %v", duplicate, err)
	}
	if duplicate, err := ledger.RecordAuthenticatedHostOutput(ctx, identity, firstOutput, now.Add(2*time.Second)); err != nil || !duplicate {
		t.Fatalf("RecordAuthenticatedHostOutput(duplicate) = %t, %v", duplicate, err)
	}
	gap := firstOutput
	gap.OutputID, gap.Sequence = "output_pg_03", 3
	if _, err := ledger.RecordAuthenticatedHostOutput(ctx, identity, gap, now.Add(2*time.Second)); !errors.Is(err, ErrHostProtocolViolation) {
		t.Fatalf("RecordAuthenticatedHostOutput(gap) error = %v", err)
	}
	resultRetry, err := ledger.PullHostAssignment(ctx, identity, now.Add(2500*time.Millisecond), now.Add(time.Minute), DeliverySeed{AssignmentID: "replacement", EnvelopeID: "replacement", DeliveryID: "replacement", Nonce: "replacement"}, testEnvelopeSigner)
	if err != nil || resultRetry.EnvelopeDigest != first.EnvelopeDigest || resultRetry.ReceiptDigest != digest("6") || string(resultRetry.Envelope) != string(first.Envelope) {
		t.Fatalf("PullHostAssignment(after receipt) = %#v, %v", resultRetry, err)
	}
	if _, err := ledger.QuarantineHost(ctx, identity, "invalid-result-signature", now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := ledger.Get(ctx, operation.Principal, operation.ID)
	if err != nil || got.State != StateUncertain || got.Assignment.HostID != "" || got.Assignment.FencingToken != first.Operation.Assignment.FencingToken+1 {
		t.Fatalf("operation after persisted quarantine = %#v, %v", got, err)
	}
	if _, err := ledger.AuthenticateHost(ctx, identity, now.Add(4*time.Second)); !errors.Is(err, ErrHostDenied) {
		t.Fatalf("AuthenticateHost(quarantined) error = %v", err)
	}
}

func TestPostgresHostControlRecoversTerminalOutputAndResultAcksAfterLeaseExpiry(t *testing.T) {
	dsn := os.Getenv("AR_SANDBOXCONTROL_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("AR_SANDBOXCONTROL_POSTGRES_DSN is required for the integration suite")
	}
	ctx := context.Background()
	pool := openIntegrationPool(t, ctx, dsn)
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `TRUNCATE runtime.sandbox_host_outputs, runtime.sandbox_host_dispatches, runtime.sandbox_host_enrollments, runtime.sandbox_operation_outbox, runtime.sandbox_operations RESTART IDENTITY`); err != nil {
		t.Fatalf("truncate host ACK recovery ledger: %v", err)
	}
	ledger, err := NewPostgresLedger(pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 7, 4, 0, 0, 0, time.UTC)
	host := HostEnrollment{HostID: "host_pg_ack", Tenant: "tenant-pg", Pool: "pool-pg", Generation: 1, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: digest("1"), SigningPublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize), CapabilityDigest: digest("2"), Status: HostActive, ExpiresAt: now.Add(time.Hour)}
	if err := ledger.ProvisionHost(ctx, host); err != nil {
		t.Fatal(err)
	}
	operation := Operation{Principal: "tenant-pg:subject-pg", Tenant: host.Tenant, ID: "op_pg_ack", Kind: "close-sandbox", TargetKind: "sandbox", TargetID: "sbx_pg_ack", InputDigest: digest("3"), CanonicalDigest: digest("4"), EffectiveSpecDigest: digest("5"), CapabilityDigest: host.CapabilityDigest, DispatchBody: `{"version":"sandbox.control/v1"}`, AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour), CleanupRequired: true}
	if _, _, err := ledger.Accept(ctx, operation); err != nil {
		t.Fatal(err)
	}
	identity := HostIdentity{HostID: host.HostID, Generation: host.Generation, CertificateDigest: host.CertificateDigest}
	dispatch, err := ledger.PullHostAssignment(ctx, identity, now, now.Add(time.Minute), DeliverySeed{AssignmentID: "assignment_pg_ack", EnvelopeID: "envelope_pg_ack", DeliveryID: "delivery_pg_ack", Nonce: "nonce_pg_ack"}, testEnvelopeSigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.AcknowledgeHostAssignment(ctx, identity, dispatch.Operation.Assignment.AssignmentID, dispatch.Operation.Assignment.FencingToken, digest("6"), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	output := sandboxhostprotocol.Output{ProtocolVersion: sandboxhostprotocol.Version, OutputID: "output_pg_ack", HostID: host.HostID, HostGeneration: host.Generation, AssignmentID: dispatch.Operation.Assignment.AssignmentID, LeaseEpoch: dispatch.Operation.Assignment.LeaseEpoch, FencingToken: dispatch.Operation.Assignment.FencingToken, Principal: operation.Principal, OperationID: operation.ID, Stream: "stderr", Sequence: 1, ChunkDigest: digest("7"), SizeBytes: 8, ObservedAt: now.Add(2 * time.Second)}
	if duplicate, err := ledger.RecordAuthenticatedHostOutput(ctx, identity, output, now.Add(2*time.Second)); err != nil || duplicate {
		t.Fatalf("RecordAuthenticatedHostOutput(first) = %t, %v", duplicate, err)
	}
	result := sandboxhostprotocol.Result{ProtocolVersion: sandboxhostprotocol.Version, ResultID: "result_pg_ack", HostID: host.HostID, HostGeneration: host.Generation, AssignmentID: dispatch.Operation.Assignment.AssignmentID, LeaseEpoch: dispatch.Operation.Assignment.LeaseEpoch, FencingToken: dispatch.Operation.Assignment.FencingToken, Principal: operation.Principal, OperationID: operation.ID, EffectiveSpecDigest: operation.EffectiveSpecDigest, CapabilityDigest: operation.CapabilityDigest, State: "succeeded", ObservedAt: now.Add(3 * time.Second)}
	if completed, err := ledger.RecordAuthenticatedHostResult(ctx, identity, result, now.Add(3*time.Second)); err != nil || completed.State != StateSucceeded {
		t.Fatalf("RecordAuthenticatedHostResult(first) = %#v, %v", completed, err)
	}
	retryAt := now.Add(2 * time.Minute)
	if duplicate, err := ledger.RecordAuthenticatedHostOutput(ctx, identity, output, retryAt); err != nil || !duplicate {
		t.Fatalf("RecordAuthenticatedHostOutput(after lease expiry) = %t, %v", duplicate, err)
	}
	if completed, err := ledger.RecordAuthenticatedHostResult(ctx, identity, result, retryAt); err != nil || completed.State != StateSucceeded {
		t.Fatalf("RecordAuthenticatedHostResult(after lease expiry) = %#v, %v", completed, err)
	}
	if _, err := ledger.AuthenticateHost(ctx, identity, retryAt); err != nil {
		t.Fatalf("host was quarantined after exact ACK recovery: %v", err)
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
