//go:build integration

package sandboxcontrol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/firecrackerlaunchgrant"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/0x63616c/agent-runtime/internal/sandboxm4bridge"
	"github.com/0x63616c/agent-runtime/sandbox"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresHostDispatchMintsAnM4CapabilityFromTheEnrolledFence(t *testing.T) {
	dsn := os.Getenv("AR_SANDBOXCONTROL_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("AR_SANDBOXCONTROL_POSTGRES_DSN is required for the integration suite")
	}
	ctx := context.Background()
	pool := openIntegrationPool(t, ctx, dsn)
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `TRUNCATE runtime.sandbox_host_outputs, runtime.sandbox_host_dispatches, runtime.sandbox_host_enrollments, runtime.sandbox_operation_outbox, runtime.sandbox_operations RESTART IDENTITY`); err != nil {
		t.Fatal(err)
	}
	ledger, err := NewPostgresLedger(pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	controlPublic, controlPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostPublic, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host := HostEnrollment{HostID: "host_pg_m4", Tenant: "tenant-pg", Pool: "pool-pg", Generation: 3, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: digest("1"), SigningPublicKey: hostPublic, CapabilityDigest: digest("2"), Status: HostActive, ExpiresAt: now.Add(time.Hour)}
	if err := ledger.ProvisionHost(ctx, host, AttestationInput{Profile: AttestationProfileLocalMetadata}, nil); err != nil {
		t.Fatal(err)
	}
	operation := Operation{Principal: "tenant-pg:subject-pg", Tenant: host.Tenant, ID: "op_pg_m4", Kind: firecrackerlaunchgrant.OperatorBootProbeOperation, TargetKind: "sandbox", TargetID: "sbx_pg_m4", InputDigest: digest("3"), CanonicalDigest: digest("4"), EffectiveSpecDigest: digest("5"), CapabilityDigest: host.CapabilityDigest, DispatchBody: `{"version":"sandbox.control/v1"}`, AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour), CleanupRequired: true}
	if _, _, err := ledger.Accept(ctx, operation); err != nil {
		t.Fatal(err)
	}
	trust := sandboxhostprotocol.TrustBundle{Version: 1, RevocationEpoch: 9, Current: sandboxhostprotocol.SigningKey{ID: "control_pg", Version: 3, PublicKey: controlPublic, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}}
	dispatch, err := ledger.PullHostAssignment(ctx, HostIdentity{HostID: host.HostID, Generation: host.Generation, CertificateDigest: host.CertificateDigest}, now, now.Add(2*time.Minute), DeliverySeed{AssignmentID: "assignment_pg_m4", EnvelopeID: "envelope_pg_m4", DeliveryID: "delivery_pg_m4", Nonce: "MDEyMzQ1Njc4OWFiY2RlZg"}, func(envelope sandboxhostprotocol.Envelope) ([]byte, error) {
		return sandboxhostprotocol.SignEnvelopeWithTrust(envelope, trust, controlPrivate)
	})
	if err != nil {
		t.Fatal(err)
	}
	capability, err := sandboxm4bridge.NewBootProbeCapability(dispatch.Envelope, host.HostID, host.Generation, trust, hostPrivate, now.Add(time.Second), firecrackerlaunchgrant.TrustedM4Identity{VMID: "sandbox-001", FixtureVersion: "fixture-v1", PlanDigest: sandbox.Digest(digest("6")), FixtureDigest: sandbox.Digest(digest("7")), StageDigest: sandbox.Digest(digest("8")), AuthorityDigest: sandbox.Digest(digest("9"))})
	if err != nil {
		t.Fatalf("NewBootProbeCapability(PostgreSQL dispatch) error = %v", err)
	}
	grant := capability.Grant()
	if grant.Envelope.AssignmentID != dispatch.Operation.Assignment.AssignmentID || grant.Envelope.FencingToken != dispatch.Operation.Assignment.FencingToken || grant.Envelope.Tenant != operation.Tenant {
		t.Fatalf("M4 grant detached from PostgreSQL assignment: %#v", grant.Envelope)
	}
}

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
	if err := ledger.ProvisionHost(ctx, host, AttestationInput{Profile: AttestationProfileLocalMetadata}, nil); err != nil {
		t.Fatal(err)
	}
	operation := Operation{Principal: "tenant-pg:subject-pg", Tenant: host.Tenant, ID: "op_pg_host", Kind: "close-sandbox", TargetKind: "sandbox", TargetID: "sbx_pg_host", InputDigest: digest("3"), CanonicalDigest: digest("4"), EffectiveSpecDigest: digest("5"), CapabilityDigest: host.CapabilityDigest, DispatchBody: `{"version":"sandbox.control/v1"}`, AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour), CleanupRequired: true}
	if _, _, err := ledger.Accept(ctx, operation); err != nil {
		t.Fatal(err)
	}
	identity := HostIdentity{HostID: host.HostID, Generation: host.Generation, CertificateDigest: host.CertificateDigest}
	var delivered sandboxhostprotocol.Envelope
	signer := func(envelope sandboxhostprotocol.Envelope) ([]byte, error) {
		delivered = envelope
		return testEnvelopeSigner(envelope)
	}
	first, err := ledger.PullHostAssignment(ctx, identity, now, now.Add(time.Minute), DeliverySeed{AssignmentID: "assignment_pg", EnvelopeID: "envelope_pg_1", DeliveryID: "delivery_pg_1", Nonce: "nonce_pg_1"}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := delivered.HostObservationKeyDigest, sandboxhostprotocol.Digest(host.SigningPublicKey); got != want {
		t.Fatalf("PostgreSQL dispatch HostObservationKeyDigest = %q, want %q", got, want)
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

func TestPostgresProvisionHostPersistsVerifierFailureWithoutRawEvidence(t *testing.T) {
	dsn := os.Getenv("AR_SANDBOXCONTROL_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("AR_SANDBOXCONTROL_POSTGRES_DSN is required for the integration suite")
	}
	ctx := context.Background()
	pool := openIntegrationPool(t, ctx, dsn)
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `TRUNCATE runtime.sandbox_host_outputs, runtime.sandbox_host_dispatches, runtime.sandbox_host_enrollments, runtime.sandbox_operation_outbox, runtime.sandbox_operations RESTART IDENTITY`); err != nil {
		t.Fatal(err)
	}
	ledger, err := NewPostgresLedger(pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	host := HostEnrollment{HostID: "host_pg_attestation_failed", Tenant: "tenant-pg", Pool: "pool-pg", Generation: 1, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: digest("1"), SigningPublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize), CapabilityDigest: digest("2"), Status: HostActive, ExpiresAt: now.Add(time.Hour)}
	const rawEvidence = "synthetic-raw-attestation"
	verifier := AttestationVerifierFunc(func(context.Context, AttestationEvidence) error { return errors.New("measurement refused") })
	if err := ledger.ProvisionHost(ctx, host, AttestationInput{Profile: AttestationProfileVerified, Evidence: []byte(rawEvidence)}, verifier); !errors.Is(err, ErrHostAttestationFailed) {
		t.Fatalf("ProvisionHost() error = %v", err)
	}
	var profile, state, status, digest string
	if err := pool.QueryRow(ctx, `SELECT attestation_profile, attestation_state, status, attestation_digest FROM runtime.sandbox_host_enrollments WHERE host_id=$1 AND generation=$2`, host.HostID, 1).Scan(&profile, &state, &status, &digest); err != nil {
		t.Fatal(err)
	}
	if profile != string(AttestationProfileVerified) || state != string(AttestationFailed) || status != string(HostAttestationFailed) || digest == "" || digest == rawEvidence {
		t.Fatalf("persisted attestation outcome = %q %q %q %q", profile, state, status, digest)
	}
	if _, err := ledger.AuthenticateHost(ctx, HostIdentity{HostID: host.HostID, Generation: host.Generation, CertificateDigest: host.CertificateDigest}, now); !errors.Is(err, ErrHostDenied) {
		t.Fatalf("AuthenticateHost() error = %v", err)
	}
}

func TestPostgresProvisionHostComparesConcurrentWinnerAndFailedOutcome(t *testing.T) {
	dsn := os.Getenv("AR_SANDBOXCONTROL_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("AR_SANDBOXCONTROL_POSTGRES_DSN is required for the integration suite")
	}
	ctx := context.Background()
	pool := openIntegrationPool(t, ctx, dsn)
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `TRUNCATE runtime.sandbox_host_outputs, runtime.sandbox_host_dispatches, runtime.sandbox_host_enrollments, runtime.sandbox_operation_outbox, runtime.sandbox_operations RESTART IDENTITY`); err != nil {
		t.Fatal(err)
	}
	ledger, _ := NewPostgresLedger(pool)
	now := time.Date(2026, 8, 8, 13, 0, 0, 0, time.UTC)

	t.Run("compares winner", func(t *testing.T) {
		const contenders = 4
		ready := sync.WaitGroup{}
		ready.Add(contenders)
		release := make(chan struct{})
		verifier := AttestationVerifierFunc(func(context.Context, AttestationEvidence) error {
			ready.Done()
			<-release
			return nil
		})
		errorsByContender := make(chan error, contenders)
		for contender := 0; contender < contenders; contender++ {
			contender := contender
			go func() {
				certificate := digest("a")
				if contender%2 != 0 {
					certificate = digest("b")
				}
				host := HostEnrollment{HostID: "host_pg_concurrent", Tenant: "tenant-pg", Pool: "pool-pg", Generation: 1, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: certificate, SigningPublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize), CapabilityDigest: digest("2"), Status: HostActive, ExpiresAt: now.Add(time.Hour)}
				errorsByContender <- ledger.ProvisionHost(ctx, host, AttestationInput{Profile: AttestationProfileVerified, Evidence: []byte("concurrent-evidence")}, verifier)
			}()
		}
		ready.Wait()
		close(release)
		var succeeded, conflicted int
		for contender := 0; contender < contenders; contender++ {
			err := <-errorsByContender
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, ErrConflict):
				conflicted++
			default:
				t.Fatalf("concurrent ProvisionHost() error = %v", err)
			}
		}
		if succeeded == 0 || conflicted == 0 || succeeded+conflicted != contenders {
			t.Fatalf("concurrent outcomes succeeded=%d conflicted=%d", succeeded, conflicted)
		}
	})

	t.Run("returns durable failed outcome", func(t *testing.T) {
		const contenders = 4
		ready := sync.WaitGroup{}
		ready.Add(contenders)
		release := make(chan struct{})
		verifier := AttestationVerifierFunc(func(context.Context, AttestationEvidence) error {
			ready.Done()
			<-release
			return errors.New("measurement refused")
		})
		errorsByContender := make(chan error, contenders)
		host := HostEnrollment{HostID: "host_pg_concurrent_failed", Tenant: "tenant-pg", Pool: "pool-pg", Generation: 1, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: digest("1"), SigningPublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize), CapabilityDigest: digest("2"), Status: HostActive, ExpiresAt: now.Add(time.Hour)}
		for contender := 0; contender < contenders; contender++ {
			go func() {
				errorsByContender <- ledger.ProvisionHost(ctx, host, AttestationInput{Profile: AttestationProfileVerified, Evidence: []byte("failed-evidence")}, verifier)
			}()
		}
		ready.Wait()
		close(release)
		for contender := 0; contender < contenders; contender++ {
			if err := <-errorsByContender; !errors.Is(err, ErrHostAttestationFailed) {
				t.Fatalf("concurrent failed ProvisionHost() error = %v", err)
			}
		}
	})
}

func TestPostgresAttestationTupleConstraintAndCorruptRowRefusal(t *testing.T) {
	dsn := os.Getenv("AR_SANDBOXCONTROL_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("AR_SANDBOXCONTROL_POSTGRES_DSN is required for the integration suite")
	}
	ctx := context.Background()
	pool := openIntegrationPool(t, ctx, dsn)
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `TRUNCATE runtime.sandbox_host_outputs, runtime.sandbox_host_dispatches, runtime.sandbox_host_enrollments, runtime.sandbox_operation_outbox, runtime.sandbox_operations RESTART IDENTITY`); err != nil {
		t.Fatal(err)
	}
	ledger, _ := NewPostgresLedger(pool)
	now := time.Date(2026, 8, 8, 14, 0, 0, 0, time.UTC)
	host := HostEnrollment{HostID: "host_pg_corrupt", Tenant: "tenant-pg", Pool: "pool-pg", Generation: 1, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: digest("1"), SigningPublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize), CapabilityDigest: digest("2"), Status: HostActive, ExpiresAt: now.Add(time.Hour)}
	if err := ledger.ProvisionHost(ctx, host, AttestationInput{Profile: AttestationProfileLocalMetadata}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE runtime.sandbox_host_enrollments SET attestation_profile='verified-v1' WHERE host_id=$1`, host.HostID); err == nil {
		t.Fatal("attestation tuple database constraint accepted a corrupt tuple")
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE runtime.sandbox_host_enrollments DROP CONSTRAINT sandbox_host_enrollments_attestation_tuple_check`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM runtime.sandbox_host_enrollments WHERE host_id='host_pg_corrupt'`)
		_, _ = pool.Exec(context.Background(), `ALTER TABLE runtime.sandbox_host_enrollments ADD CONSTRAINT sandbox_host_enrollments_attestation_tuple_check CHECK ((attestation_profile='local-metadata-v1' AND attestation_state='metadata-only' AND attestation_digest IS NULL AND status IN ('active','revoked','quarantined')) OR (attestation_profile='verified-v1' AND attestation_state='verified' AND attestation_digest IS NOT NULL AND status IN ('active','revoked','quarantined')) OR (attestation_profile='verified-v1' AND attestation_state='failed' AND attestation_digest IS NOT NULL AND status='attestation-failed'))`)
	})
	if _, err := pool.Exec(ctx, `UPDATE runtime.sandbox_host_enrollments SET attestation_profile='verified-v1' WHERE host_id=$1`, host.HostID); err != nil {
		t.Fatal(err)
	}
	identity := HostIdentity{HostID: host.HostID, Generation: host.Generation, CertificateDigest: host.CertificateDigest}
	if _, err := ledger.AuthenticateHost(ctx, identity, now); !errors.Is(err, ErrHostDenied) {
		t.Fatalf("AuthenticateHost(corrupt tuple) error = %v", err)
	}
}

func TestPostgresHostControlRecoversNormalUncertainResultAckAndRequeuesAfterCleanup(t *testing.T) {
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
	if err := ledger.ProvisionHost(ctx, host, AttestationInput{Profile: AttestationProfileLocalMetadata}, nil); err != nil {
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
	started := sandboxhostprotocol.Result{ProtocolVersion: sandboxhostprotocol.Version, ResultID: "started_pg_ack", HostID: host.HostID, HostGeneration: host.Generation, AssignmentID: dispatch.Operation.Assignment.AssignmentID, LeaseEpoch: dispatch.Operation.Assignment.LeaseEpoch, FencingToken: dispatch.Operation.Assignment.FencingToken, Principal: operation.Principal, OperationID: operation.ID, EffectiveSpecDigest: operation.EffectiveSpecDigest, CapabilityDigest: operation.CapabilityDigest, State: "started", ObservedAt: now.Add(3 * time.Second)}
	if startedOperation, err := ledger.RecordAuthenticatedHostResult(ctx, identity, started, started.ObservedAt); err != nil || startedOperation.State != StateStarted {
		t.Fatalf("RecordAuthenticatedHostResult(started) = %#v, %v", startedOperation, err)
	}
	uncertain := started
	uncertain.ResultID, uncertain.State, uncertain.ObservedAt = "uncertain_pg_ack", "uncertain", now.Add(4*time.Second)
	first, err := ledger.RecordAuthenticatedHostResult(ctx, identity, uncertain, uncertain.ObservedAt)
	if err != nil || first.State != StateUncertain {
		t.Fatalf("RecordAuthenticatedHostResult(uncertain) = %#v, %v", first, err)
	}
	retryAt := now.Add(2 * time.Minute)
	if duplicate, err := ledger.RecordAuthenticatedHostOutput(ctx, identity, output, retryAt); err != nil || !duplicate {
		t.Fatalf("RecordAuthenticatedHostOutput(after lease expiry) = %t, %v", duplicate, err)
	}
	if replay, err := ledger.RecordAuthenticatedHostResult(ctx, identity, uncertain, retryAt); err != nil || replay.State != StateUncertain || replay.Version != first.Version {
		t.Fatalf("RecordAuthenticatedHostResult(uncertain after lease expiry) = %#v, %v", replay, err)
	}
	requeued, err := ledger.ConfirmHostCleanupAndRequeue(ctx, operation.Principal, operation.ID, first.Version, retryAt)
	if err != nil || requeued.State != StateAccepted || requeued.Assignment.HostID != "" || requeued.Assignment.FencingToken != first.Assignment.FencingToken+1 {
		t.Fatalf("ConfirmHostCleanupAndRequeue(normal uncertain) = %#v, %v", requeued, err)
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
