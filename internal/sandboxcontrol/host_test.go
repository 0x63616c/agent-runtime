package sandboxcontrol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
)

func TestMemoryHostControlLostAckRestartFenceAndQuarantine(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	ledger := NewMemoryLedger()
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostPublic := hostPrivate.Public().(ed25519.PublicKey)
	host := HostEnrollment{HostID: "host_01", Tenant: "tenant_01", Pool: "pool_01", Generation: 3, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: digest("1"), SigningPublicKey: hostPublic, CapabilityDigest: digest("2"), Status: HostActive, ExpiresAt: now.Add(time.Hour)}
	if err := ledger.ProvisionHost(context.Background(), host, AttestationInput{Profile: AttestationProfileLocalMetadata}, nil); err != nil {
		t.Fatal(err)
	}
	operation := Operation{Principal: "tenant_01:subject_01", Tenant: "tenant_01", ID: "op_host", Kind: "close-sandbox", TargetKind: "sandbox", TargetID: "sbx_host", InputDigest: digest("3"), CanonicalDigest: digest("4"), EffectiveSpecDigest: digest("5"), CapabilityDigest: host.CapabilityDigest, DispatchBody: `{"version":"sandbox.control/v1"}`, AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour), CleanupRequired: true}
	if _, _, err := ledger.Accept(context.Background(), operation); err != nil {
		t.Fatal(err)
	}
	identity := HostIdentity{HostID: host.HostID, Generation: host.Generation, CertificateDigest: host.CertificateDigest}
	delivery := DeliverySeed{AssignmentID: "assignment_01", EnvelopeID: "envelope_01", DeliveryID: "delivery_01", Nonce: "nonce_01"}
	first, err := ledger.PullHostAssignment(context.Background(), identity, now, now.Add(time.Minute), delivery, testEnvelopeSigner)
	if err != nil || first.Operation.ID != operation.ID || first.Operation.Assignment.FencingToken != 1 {
		t.Fatalf("PullHostAssignment() = %#v, %v", first, err)
	}
	firstOutput := sandboxhostprotocol.Output{ProtocolVersion: sandboxhostprotocol.Version, OutputID: "output_01", HostID: host.HostID, HostGeneration: host.Generation, AssignmentID: first.Operation.Assignment.AssignmentID, LeaseEpoch: first.Operation.Assignment.LeaseEpoch, FencingToken: first.Operation.Assignment.FencingToken, Principal: operation.Principal, OperationID: operation.ID, Stream: "stdout", Sequence: 1, ChunkDigest: digest("7"), SizeBytes: 12, ObservedAt: now.Add(time.Second)}
	if duplicate, err := ledger.RecordAuthenticatedHostOutput(context.Background(), identity, firstOutput, now.Add(time.Second)); err != nil || duplicate {
		t.Fatalf("RecordAuthenticatedHostOutput(first) = %t, %v", duplicate, err)
	}
	if duplicate, err := ledger.RecordAuthenticatedHostOutput(context.Background(), identity, firstOutput, now.Add(time.Second)); err != nil || !duplicate {
		t.Fatalf("RecordAuthenticatedHostOutput(duplicate) = %t, %v", duplicate, err)
	}
	gap := firstOutput
	gap.OutputID, gap.Sequence = "output_03", 3
	if _, err := ledger.RecordAuthenticatedHostOutput(context.Background(), identity, gap, now.Add(time.Second)); !errors.Is(err, ErrHostProtocolViolation) {
		t.Fatalf("RecordAuthenticatedHostOutput(gap) error = %v", err)
	}
	duplicate, err := ledger.PullHostAssignment(context.Background(), identity, now.Add(time.Second), now.Add(time.Minute), DeliverySeed{AssignmentID: "different", EnvelopeID: "different", DeliveryID: "different", Nonce: "different"}, testEnvelopeSigner)
	if err != nil || duplicate.EnvelopeDigest != first.EnvelopeDigest || string(duplicate.Envelope) != string(first.Envelope) {
		t.Fatalf("lost-ack PullHostAssignment() = %#v, %v", duplicate, err)
	}
	premature := sandboxhostprotocol.Result{HostID: host.HostID, HostGeneration: host.Generation, AssignmentID: first.Operation.Assignment.AssignmentID, LeaseEpoch: first.Operation.Assignment.LeaseEpoch, FencingToken: first.Operation.Assignment.FencingToken, Principal: operation.Principal, OperationID: operation.ID, EffectiveSpecDigest: operation.EffectiveSpecDigest, CapabilityDigest: operation.CapabilityDigest, State: "succeeded", ObservedAt: now.Add(1500 * time.Millisecond)}
	if _, err := ledger.RecordAuthenticatedHostResult(context.Background(), identity, premature, now.Add(1500*time.Millisecond)); !errors.Is(err, ErrHostProtocolViolation) {
		t.Fatalf("result before receipt error = %v", err)
	}
	if _, err := ledger.AcknowledgeHostAssignment(context.Background(), identity, first.Operation.Assignment.AssignmentID, first.Operation.Assignment.FencingToken, sandboxhostprotocol.Digest([]byte("receipt")), now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	started := premature
	started.ResultID, started.State, started.ObservedAt = "result_started", "started", now.Add(2*time.Second)
	startedOperation, err := ledger.RecordAuthenticatedHostResult(context.Background(), identity, started, now.Add(2*time.Second))
	if err != nil || startedOperation.State != StateStarted {
		t.Fatalf("RecordAuthenticatedHostResult(started) = %#v, %v", startedOperation, err)
	}
	startedRetry, err := ledger.RecordAuthenticatedHostResult(context.Background(), identity, started, now.Add(2*time.Second))
	if err != nil || startedRetry.Version != startedOperation.Version {
		t.Fatalf("RecordAuthenticatedHostResult(duplicate) = %#v, %v", startedRetry, err)
	}
	resultRetry, err := ledger.PullHostAssignment(context.Background(), identity, now.Add(2500*time.Millisecond), now.Add(time.Minute), DeliverySeed{AssignmentID: "replacement", EnvelopeID: "replacement", DeliveryID: "replacement", Nonce: "replacement"}, testEnvelopeSigner)
	if err != nil || resultRetry.EnvelopeDigest != first.EnvelopeDigest || resultRetry.ReceiptDigest == "" || string(resultRetry.Envelope) != string(first.Envelope) {
		t.Fatalf("lost-result PullHostAssignment() = %#v, %v", resultRetry, err)
	}
	renewed, err := ledger.RenewHostAssignment(context.Background(), identity, first.Operation.Assignment.AssignmentID, first.Operation.Assignment.FencingToken, now.Add(3*time.Second), now.Add(2*time.Minute), DeliverySeed{EnvelopeID: "envelope_02", DeliveryID: "delivery_02", Nonce: "nonce_02"}, testEnvelopeSigner)
	if err != nil || renewed.Operation.Assignment.FencingToken != 2 || renewed.Operation.Assignment.LeaseEpoch != 2 {
		t.Fatalf("RenewHostAssignment() = %#v, %v", renewed, err)
	}
	stale := sandboxhostprotocol.Result{HostID: host.HostID, HostGeneration: host.Generation, AssignmentID: first.Operation.Assignment.AssignmentID, LeaseEpoch: 1, FencingToken: 1, Principal: operation.Principal, OperationID: operation.ID, EffectiveSpecDigest: operation.EffectiveSpecDigest, CapabilityDigest: operation.CapabilityDigest, State: "succeeded", ObservedAt: now.Add(4 * time.Second)}
	if _, err := ledger.RecordAuthenticatedHostResult(context.Background(), identity, stale, now.Add(4*time.Second)); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("stale result error = %v", err)
	}
	if _, err := ledger.QuarantineHost(context.Background(), identity, "protocol-violation", now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.PullHostAssignment(context.Background(), identity, now.Add(6*time.Second), now.Add(time.Minute), DeliverySeed{}, testEnvelopeSigner); !errors.Is(err, ErrHostDenied) {
		t.Fatalf("quarantined PullHostAssignment() error = %v", err)
	}
	got, err := ledger.Get(context.Background(), operation.Principal, operation.ID)
	if err != nil || got.State != StateUncertain || got.Assignment.HostID != "" || got.Assignment.FencingToken != 3 {
		t.Fatalf("operation after quarantine = %#v, %v", got, err)
	}
	requeued, err := ledger.ConfirmHostCleanupAndRequeue(context.Background(), got.Principal, got.ID, got.Version, now.Add(6*time.Second))
	if err != nil || requeued.State != StateAccepted || requeued.Assignment.FencingToken != got.Assignment.FencingToken {
		t.Fatalf("ConfirmHostCleanupAndRequeue() = %#v, %v", requeued, err)
	}
}

func TestMemoryHostControlFencesDataPlaneReceiptAndRequiresItForTransferSuccess(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	ledger := NewMemoryLedger()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host := HostEnrollment{HostID: "host_data_receipt", Tenant: "tenant_01", Pool: "pool_01", Generation: 1, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: digest("1"), SigningPublicKey: publicKey, CapabilityDigest: digest("2"), Status: HostActive, ExpiresAt: now.Add(time.Hour)}
	if err := ledger.ProvisionHost(context.Background(), host, AttestationInput{Profile: AttestationProfileLocalMetadata}, nil); err != nil {
		t.Fatal(err)
	}
	operation := Operation{Principal: "tenant_01:subject_01", Tenant: host.Tenant, ID: "op_data_receipt", Kind: "agent-runtime.guest-transfer/v1", TargetKind: "sandbox", TargetID: "sbx_data_receipt", InputDigest: digest("3"), CanonicalDigest: digest("4"), EffectiveSpecDigest: digest("5"), CapabilityDigest: host.CapabilityDigest, DispatchBody: `{"version":"sandbox.control/v1"}`, AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour), CleanupRequired: true}
	if _, _, err := ledger.Accept(context.Background(), operation); err != nil {
		t.Fatal(err)
	}
	identity := HostIdentity{HostID: host.HostID, Generation: host.Generation, CertificateDigest: host.CertificateDigest}
	dispatch, err := ledger.PullHostAssignment(context.Background(), identity, now, now.Add(time.Minute), DeliverySeed{AssignmentID: "assignment_data_receipt", EnvelopeID: "envelope_data_receipt", DeliveryID: "delivery_data_receipt", Nonce: "nonce_data_receipt"}, testEnvelopeSigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.AcknowledgeHostAssignment(context.Background(), identity, dispatch.Operation.Assignment.AssignmentID, dispatch.Operation.Assignment.FencingToken, digest("6"), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	reference := []byte(`{"artifact_id":"artifact_01","version":"agent-runtime.transfer-receipt/v1"}`)
	receipt := sandboxhostprotocol.DataPlaneReceipt{ProtocolVersion: sandboxhostprotocol.Version, ReceiptID: "receipt_data_01", HostID: host.HostID, HostGeneration: host.Generation, AssignmentID: dispatch.Operation.Assignment.AssignmentID, LeaseEpoch: dispatch.Operation.Assignment.LeaseEpoch, FencingToken: dispatch.Operation.Assignment.FencingToken, OperationID: operation.ID, Kind: "transfer", ReceiptDigest: sandboxhostprotocol.Digest(reference)}
	if _, err := ledger.RecordAuthenticatedDataPlaneReceipt(context.Background(), identity, receipt, now.Add(time.Second)); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("receipt before started error = %v", err)
	}
	started := sandboxhostprotocol.Result{ProtocolVersion: sandboxhostprotocol.Version, ResultID: "started_data_receipt", HostID: host.HostID, HostGeneration: host.Generation, AssignmentID: receipt.AssignmentID, LeaseEpoch: receipt.LeaseEpoch, FencingToken: receipt.FencingToken, Principal: operation.Principal, OperationID: operation.ID, EffectiveSpecDigest: operation.EffectiveSpecDigest, CapabilityDigest: operation.CapabilityDigest, State: "started", ObservedAt: now.Add(2 * time.Second)}
	if got, err := ledger.RecordAuthenticatedHostResult(context.Background(), identity, started, started.ObservedAt); err != nil || got.State != StateStarted {
		t.Fatalf("RecordAuthenticatedHostResult(started) = %#v, %v", got, err)
	}
	succeeded := started
	succeeded.ResultID, succeeded.State, succeeded.ObservedAt = "succeeded_data_receipt", "succeeded", now.Add(3*time.Second)
	if _, err := ledger.RecordAuthenticatedHostResult(context.Background(), identity, succeeded, succeeded.ObservedAt); !errors.Is(err, ErrHostProtocolViolation) {
		t.Fatalf("success without receipt error = %v", err)
	}
	if duplicate, err := ledger.RecordAuthenticatedDataPlaneReceipt(context.Background(), identity, receipt, now.Add(3*time.Second)); err != nil || duplicate {
		t.Fatalf("RecordAuthenticatedDataPlaneReceipt(first) = %t, %v", duplicate, err)
	}
	if duplicate, err := ledger.RecordAuthenticatedDataPlaneReceipt(context.Background(), identity, receipt, now.Add(3*time.Second)); err != nil || !duplicate {
		t.Fatalf("RecordAuthenticatedDataPlaneReceipt(replay) = %t, %v", duplicate, err)
	}
	altered := receipt
	altered.ReceiptID = "receipt_data_02"
	if _, err := ledger.RecordAuthenticatedDataPlaneReceipt(context.Background(), identity, altered, now.Add(3*time.Second)); !errors.Is(err, ErrHostProtocolViolation) {
		t.Fatalf("altered receipt error = %v", err)
	}
	if got, err := ledger.RecordAuthenticatedHostResult(context.Background(), identity, succeeded, succeeded.ObservedAt); err != nil || got.State != StateSucceeded {
		t.Fatalf("RecordAuthenticatedHostResult(succeeded) = %#v, %v", got, err)
	}
}

func TestAttestationVerifierRecordsFailureAndRefusesFailedHost(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host := HostEnrollment{HostID: "host_attestation_failed", Tenant: "tenant_01", Pool: "pool_01", Generation: 1, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: digest("1"), SigningPublicKey: publicKey, CapabilityDigest: digest("2"), Status: HostActive, ExpiresAt: now.Add(time.Hour)}
	verifier := AttestationVerifierFunc(func(context.Context, AttestationEvidence) error {
		return errors.New("measurement mismatch")
	})
	ledger := NewMemoryLedger()
	if err := ledger.ProvisionHost(context.Background(), host, AttestationInput{Profile: AttestationProfileVerified, Evidence: []byte("synthetic-attestation")}, verifier); !errors.Is(err, ErrHostAttestationFailed) {
		t.Fatalf("ProvisionHost() failed attestation error = %v", err)
	}
	if _, err := ledger.AuthenticateHost(context.Background(), HostIdentity{HostID: host.HostID, Generation: host.Generation, CertificateDigest: host.CertificateDigest}, now); !errors.Is(err, ErrHostDenied) {
		t.Fatalf("AuthenticateHost() accepted failed attestation: %v", err)
	}
}

func TestLocalMetadataAttestationIsAdmittedWithoutClaimingVerification(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host := HostEnrollment{HostID: "host_attestation_local", Tenant: "tenant_01", Pool: "pool_01", Generation: 1, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: digest("1"), SigningPublicKey: publicKey, CapabilityDigest: digest("2"), Status: HostActive, ExpiresAt: now.Add(time.Hour)}
	ledger := NewMemoryLedger()
	if err := ledger.ProvisionHost(context.Background(), host, AttestationInput{Profile: AttestationProfileLocalMetadata}, nil); err != nil {
		t.Fatal(err)
	}
	authenticated, err := ledger.AuthenticateHost(context.Background(), HostIdentity{HostID: host.HostID, Generation: host.Generation, CertificateDigest: host.CertificateDigest}, now)
	if err != nil || authenticated.AttestationState != AttestationMetadataOnly {
		t.Fatalf("AuthenticateHost() rejected metadata-only local profile: %v", err)
	}
}

func TestProvisionHostRejectsCallerSuppliedAttestationOutcome(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	host := HostEnrollment{HostID: "host_forged_attestation", Tenant: "tenant_01", Pool: "pool_01", Generation: 1, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: digest("1"), SigningPublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize), CapabilityDigest: digest("2"), AttestationDigest: digest("3"), AttestationProfile: AttestationProfileVerified, AttestationState: AttestationVerified, Status: HostActive, ExpiresAt: now.Add(time.Hour)}
	if err := NewMemoryLedger().ProvisionHost(context.Background(), host, AttestationInput{Profile: AttestationProfileLocalMetadata}, nil); err == nil {
		t.Fatal("ProvisionHost() trusted a caller-supplied verified state")
	}
}

func TestProvisionHostRejectsOversizedAttestationBeforeVerifier(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	host := HostEnrollment{HostID: "host_oversized_attestation", Tenant: "tenant_01", Pool: "pool_01", Generation: 1, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: digest("1"), SigningPublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize), CapabilityDigest: digest("2"), Status: HostActive, ExpiresAt: now.Add(time.Hour)}
	called := false
	verifier := AttestationVerifierFunc(func(context.Context, AttestationEvidence) error {
		called = true
		return nil
	})
	err := NewMemoryLedger().ProvisionHost(context.Background(), host, AttestationInput{Profile: AttestationProfileVerified, Evidence: make([]byte, maxAttestationEvidenceBytes+1)}, verifier)
	if err == nil || errors.Is(err, ErrHostAttestationFailed) || called {
		t.Fatalf("ProvisionHost() oversized evidence error = %v, verifier called = %t", err, called)
	}
}

func TestProvisionHostZeroesBorrowedVerifierEvidence(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	host := HostEnrollment{HostID: "host_zero_attestation", Tenant: "tenant_01", Pool: "pool_01", Generation: 1, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: digest("1"), SigningPublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize), CapabilityDigest: digest("2"), Status: HostActive, ExpiresAt: now.Add(time.Hour)}
	var borrowed []byte
	verifier := AttestationVerifierFunc(func(_ context.Context, evidence AttestationEvidence) error {
		borrowed = evidence.Evidence
		return nil
	})
	if err := NewMemoryLedger().ProvisionHost(context.Background(), host, AttestationInput{Profile: AttestationProfileVerified, Evidence: []byte("synthetic-attestation")}, verifier); err != nil {
		t.Fatal(err)
	}
	for index, value := range borrowed {
		if value != 0 {
			t.Fatalf("borrowed verifier evidence byte %d = %d, want zero", index, value)
		}
	}
}

func TestMemoryLedgerRefusesCorruptPersistedAttestationTuple(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	host := HostEnrollment{HostID: "host_corrupt_attestation", Tenant: "tenant_01", Pool: "pool_01", Generation: 1, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: digest("1"), SigningPublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize), CapabilityDigest: digest("2"), Status: HostActive, ExpiresAt: now.Add(time.Hour)}
	ledger := NewMemoryLedger()
	if err := ledger.ProvisionHost(context.Background(), host, AttestationInput{Profile: AttestationProfileLocalMetadata}, nil); err != nil {
		t.Fatal(err)
	}
	key := hostEnrollmentKey(host.HostID, host.Generation)
	corrupt := ledger.hosts[key]
	corrupt.AttestationProfile = AttestationProfileVerified
	ledger.hosts[key] = corrupt
	identity := HostIdentity{HostID: host.HostID, Generation: host.Generation, CertificateDigest: host.CertificateDigest}
	if _, err := ledger.AuthenticateHost(context.Background(), identity, now); !errors.Is(err, ErrHostDenied) {
		t.Fatalf("AuthenticateHost(corrupt attestation) error = %v", err)
	}
}

func TestMemoryHostControlRecoversTerminalOutputAndResultAcksAfterLeaseExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 7, 13, 0, 0, 0, time.UTC)
	ledger := NewMemoryLedger()
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host := HostEnrollment{HostID: "host_ack_recovery", Tenant: "tenant_01", Pool: "pool_01", Generation: 1, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: digest("1"), SigningPublicKey: hostPrivate.Public().(ed25519.PublicKey), CapabilityDigest: digest("2"), Status: HostActive, ExpiresAt: now.Add(time.Hour)}
	if err := ledger.ProvisionHost(context.Background(), host, AttestationInput{Profile: AttestationProfileLocalMetadata}, nil); err != nil {
		t.Fatal(err)
	}
	operation := Operation{Principal: "tenant_01:subject_01", Tenant: host.Tenant, ID: "op_ack_recovery", Kind: "close-sandbox", TargetKind: "sandbox", TargetID: "sbx_ack_recovery", InputDigest: digest("3"), CanonicalDigest: digest("4"), EffectiveSpecDigest: digest("5"), CapabilityDigest: host.CapabilityDigest, DispatchBody: `{"version":"sandbox.control/v1"}`, AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour), CleanupRequired: true}
	if _, _, err := ledger.Accept(context.Background(), operation); err != nil {
		t.Fatal(err)
	}
	identity := HostIdentity{HostID: host.HostID, Generation: host.Generation, CertificateDigest: host.CertificateDigest}
	dispatch, err := ledger.PullHostAssignment(context.Background(), identity, now, now.Add(time.Minute), DeliverySeed{AssignmentID: "assignment_ack_recovery", EnvelopeID: "envelope_ack_recovery", DeliveryID: "delivery_ack_recovery", Nonce: "nonce_ack_recovery"}, testEnvelopeSigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.AcknowledgeHostAssignment(context.Background(), identity, dispatch.Operation.Assignment.AssignmentID, dispatch.Operation.Assignment.FencingToken, digest("6"), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	output := sandboxhostprotocol.Output{ProtocolVersion: sandboxhostprotocol.Version, OutputID: "output_ack_recovery", HostID: host.HostID, HostGeneration: host.Generation, AssignmentID: dispatch.Operation.Assignment.AssignmentID, LeaseEpoch: dispatch.Operation.Assignment.LeaseEpoch, FencingToken: dispatch.Operation.Assignment.FencingToken, Principal: operation.Principal, OperationID: operation.ID, Stream: "stdout", Sequence: 1, ChunkDigest: digest("7"), SizeBytes: 12, ObservedAt: now.Add(2 * time.Second)}
	if duplicate, err := ledger.RecordAuthenticatedHostOutput(context.Background(), identity, output, now.Add(2*time.Second)); err != nil || duplicate {
		t.Fatalf("RecordAuthenticatedHostOutput(first) = %t, %v", duplicate, err)
	}
	result := sandboxhostprotocol.Result{ProtocolVersion: sandboxhostprotocol.Version, ResultID: "result_ack_recovery", HostID: host.HostID, HostGeneration: host.Generation, AssignmentID: dispatch.Operation.Assignment.AssignmentID, LeaseEpoch: dispatch.Operation.Assignment.LeaseEpoch, FencingToken: dispatch.Operation.Assignment.FencingToken, Principal: operation.Principal, OperationID: operation.ID, EffectiveSpecDigest: operation.EffectiveSpecDigest, CapabilityDigest: operation.CapabilityDigest, State: "succeeded", ObservedAt: now.Add(3 * time.Second)}
	if completed, err := ledger.RecordAuthenticatedHostResult(context.Background(), identity, result, now.Add(3*time.Second)); err != nil || completed.State != StateSucceeded {
		t.Fatalf("RecordAuthenticatedHostResult(first) = %#v, %v", completed, err)
	}
	retryAt := now.Add(2 * time.Minute)
	if duplicate, err := ledger.RecordAuthenticatedHostOutput(context.Background(), identity, output, retryAt); err != nil || !duplicate {
		t.Fatalf("RecordAuthenticatedHostOutput(after lease expiry) = %t, %v", duplicate, err)
	}
	if completed, err := ledger.RecordAuthenticatedHostResult(context.Background(), identity, result, retryAt); err != nil || completed.State != StateSucceeded {
		t.Fatalf("RecordAuthenticatedHostResult(after lease expiry) = %#v, %v", completed, err)
	}
	if _, err := ledger.AuthenticateHost(context.Background(), identity, retryAt); err != nil {
		t.Fatalf("host was quarantined after exact ACK recovery: %v", err)
	}
}

func TestMemoryHostControlRoutesNormalUncertainResultThroughCleanupAndAcceptsItsExactLateReplay(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 7, 14, 0, 0, 0, time.UTC)
	ledger := NewMemoryLedger()
	hostPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host := HostEnrollment{HostID: "host_uncertain", Tenant: "tenant_01", Pool: "pool_01", Generation: 1, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: digest("1"), SigningPublicKey: hostPublic, CapabilityDigest: digest("2"), Status: HostActive, ExpiresAt: now.Add(time.Hour)}
	if err := ledger.ProvisionHost(context.Background(), host, AttestationInput{Profile: AttestationProfileLocalMetadata}, nil); err != nil {
		t.Fatal(err)
	}
	operation := Operation{Principal: "tenant_01:subject_01", Tenant: host.Tenant, ID: "op_uncertain", Kind: "close-sandbox", TargetKind: "sandbox", TargetID: "sbx_uncertain", InputDigest: digest("3"), CanonicalDigest: digest("4"), EffectiveSpecDigest: digest("5"), CapabilityDigest: host.CapabilityDigest, DispatchBody: `{"version":"sandbox.control/v1"}`, AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour), CleanupRequired: true}
	if _, _, err := ledger.Accept(context.Background(), operation); err != nil {
		t.Fatal(err)
	}
	identity := HostIdentity{HostID: host.HostID, Generation: host.Generation, CertificateDigest: host.CertificateDigest}
	dispatch, err := ledger.PullHostAssignment(context.Background(), identity, now, now.Add(time.Minute), DeliverySeed{AssignmentID: "assignment_uncertain", EnvelopeID: "envelope_uncertain", DeliveryID: "delivery_uncertain", Nonce: "nonce_uncertain"}, testEnvelopeSigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.AcknowledgeHostAssignment(context.Background(), identity, dispatch.Operation.Assignment.AssignmentID, dispatch.Operation.Assignment.FencingToken, digest("6"), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	started := sandboxhostprotocol.Result{ProtocolVersion: sandboxhostprotocol.Version, ResultID: "started_uncertain", HostID: host.HostID, HostGeneration: host.Generation, AssignmentID: dispatch.Operation.Assignment.AssignmentID, LeaseEpoch: dispatch.Operation.Assignment.LeaseEpoch, FencingToken: dispatch.Operation.Assignment.FencingToken, Principal: operation.Principal, OperationID: operation.ID, EffectiveSpecDigest: operation.EffectiveSpecDigest, CapabilityDigest: operation.CapabilityDigest, State: "started", ObservedAt: now.Add(2 * time.Second)}
	if got, err := ledger.RecordAuthenticatedHostResult(context.Background(), identity, started, started.ObservedAt); err != nil || got.State != StateStarted {
		t.Fatalf("RecordAuthenticatedHostResult(started) = %#v, %v", got, err)
	}
	uncertain := started
	uncertain.ResultID, uncertain.State, uncertain.ObservedAt = "uncertain_uncertain", "uncertain", now.Add(3*time.Second)
	first, err := ledger.RecordAuthenticatedHostResult(context.Background(), identity, uncertain, uncertain.ObservedAt)
	if err != nil || first.State != StateUncertain {
		t.Fatalf("RecordAuthenticatedHostResult(uncertain) = %#v, %v", first, err)
	}
	late := now.Add(2 * time.Minute)
	if replay, err := ledger.RecordAuthenticatedHostResult(context.Background(), identity, uncertain, late); err != nil || replay.State != StateUncertain || replay.Version != first.Version {
		t.Fatalf("RecordAuthenticatedHostResult(late uncertain replay) = %#v, %v", replay, err)
	}
	requeued, err := ledger.ConfirmHostCleanupAndRequeue(context.Background(), operation.Principal, operation.ID, first.Version, late)
	if err != nil || requeued.State != StateAccepted || requeued.Assignment.HostID != "" || requeued.Assignment.FencingToken != first.Assignment.FencingToken+1 {
		t.Fatalf("ConfirmHostCleanupAndRequeue(normal uncertain) = %#v, %v", requeued, err)
	}
}

func TestMemoryHostControlRefusesWrongTenantRevokedAndRogueIdentity(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	ledger := NewMemoryLedger()
	host := HostEnrollment{HostID: "host_01", Tenant: "tenant_01", Pool: "pool_01", Generation: 1, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: digest("1"), SigningPublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize), CapabilityDigest: digest("2"), Status: HostActive, ExpiresAt: now.Add(time.Hour)}
	if err := ledger.ProvisionHost(context.Background(), host, AttestationInput{Profile: AttestationProfileLocalMetadata}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.AuthenticateHost(context.Background(), HostIdentity{HostID: host.HostID, Generation: host.Generation, CertificateDigest: digest("9")}, now); !errors.Is(err, ErrHostDenied) {
		t.Fatalf("rogue AuthenticateHost() error = %v", err)
	}
	if err := ledger.RevokeHost(context.Background(), host.HostID, host.Generation, now); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.AuthenticateHost(context.Background(), HostIdentity{HostID: host.HostID, Generation: host.Generation, CertificateDigest: host.CertificateDigest}, now); !errors.Is(err, ErrHostDenied) {
		t.Fatalf("revoked AuthenticateHost() error = %v", err)
	}
}

func TestMemoryHostControlOverlapsRotationThenRevokesOldGeneration(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	ledger := NewMemoryLedger()
	first := HostEnrollment{HostID: "host_rotate", Tenant: "tenant_01", Pool: "pool_01", Generation: 1, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: digest("1"), SigningPublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize), CapabilityDigest: digest("2"), Status: HostActive, ExpiresAt: now.Add(time.Hour)}
	second := first
	second.Generation = 2
	second.CertificateDigest = digest("3")
	if err := ledger.ProvisionHost(context.Background(), first, AttestationInput{Profile: AttestationProfileLocalMetadata}, nil); err != nil {
		t.Fatal(err)
	}
	if err := ledger.ProvisionHost(context.Background(), second, AttestationInput{Profile: AttestationProfileLocalMetadata}, nil); err != nil {
		t.Fatal(err)
	}
	firstIdentity := HostIdentity{HostID: first.HostID, Generation: first.Generation, CertificateDigest: first.CertificateDigest}
	secondIdentity := HostIdentity{HostID: second.HostID, Generation: second.Generation, CertificateDigest: second.CertificateDigest}
	if _, err := ledger.AuthenticateHost(context.Background(), firstIdentity, now); err != nil {
		t.Fatalf("old generation during overlap: %v", err)
	}
	if _, err := ledger.AuthenticateHost(context.Background(), secondIdentity, now); err != nil {
		t.Fatalf("next generation during overlap: %v", err)
	}
	operation := Operation{Principal: "tenant_01:subject_01", Tenant: "tenant_01", ID: "op_rotate", Kind: "close-sandbox", TargetKind: "sandbox", TargetID: "sbx_rotate", InputDigest: digest("4"), CanonicalDigest: digest("5"), EffectiveSpecDigest: digest("6"), CapabilityDigest: second.CapabilityDigest, DispatchBody: `{"version":"sandbox.control/v1"}`, AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour), CleanupRequired: true}
	if _, _, err := ledger.Accept(context.Background(), operation); err != nil {
		t.Fatal(err)
	}
	assigned, err := ledger.PullHostAssignment(context.Background(), secondIdentity, now, now.Add(time.Minute), DeliverySeed{AssignmentID: "assignment_rotate", EnvelopeID: "envelope_rotate", DeliveryID: "delivery_rotate", Nonce: "nonce_rotate"}, testEnvelopeSigner)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.RevokeHost(context.Background(), first.HostID, first.Generation, now); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.AuthenticateHost(context.Background(), firstIdentity, now); !errors.Is(err, ErrHostDenied) {
		t.Fatalf("revoked old generation error = %v", err)
	}
	if _, err := ledger.AuthenticateHost(context.Background(), secondIdentity, now); err != nil {
		t.Fatalf("new generation after cutover: %v", err)
	}
	got, err := ledger.Get(context.Background(), operation.Principal, operation.ID)
	if err != nil || got.Assignment.HostGeneration != second.Generation || got.Assignment.FencingToken != assigned.Operation.Assignment.FencingToken || got.State != StateDispatched {
		t.Fatalf("new generation assignment after old revocation = %#v, %v", got, err)
	}
}

func TestMemoryHostControlRefusesExpiredAndTerminalHeartbeat(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name       string
		renewAt    time.Time
		completeAt time.Time
	}{
		{name: "expired", renewAt: now.Add(time.Minute)},
		{name: "terminal", renewAt: now.Add(3 * time.Second), completeAt: now.Add(2 * time.Second)},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ledger := NewMemoryLedger()
			host := HostEnrollment{HostID: "host_heartbeat_" + test.name, Tenant: "tenant_01", Pool: "pool_01", Generation: 1, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: digest("1"), SigningPublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize), CapabilityDigest: digest("2"), Status: HostActive, ExpiresAt: now.Add(time.Hour)}
			if err := ledger.ProvisionHost(context.Background(), host, AttestationInput{Profile: AttestationProfileLocalMetadata}, nil); err != nil {
				t.Fatal(err)
			}
			operation := Operation{Principal: "tenant_01:subject_01", Tenant: "tenant_01", ID: "op_heartbeat_" + test.name, Kind: "close-sandbox", TargetKind: "sandbox", TargetID: "sbx_heartbeat", InputDigest: digest("3"), CanonicalDigest: digest("4"), EffectiveSpecDigest: digest("5"), CapabilityDigest: host.CapabilityDigest, DispatchBody: `{"version":"sandbox.control/v1"}`, AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour), CleanupRequired: true}
			if _, _, err := ledger.Accept(context.Background(), operation); err != nil {
				t.Fatal(err)
			}
			identity := HostIdentity{HostID: host.HostID, Generation: host.Generation, CertificateDigest: host.CertificateDigest}
			dispatch, err := ledger.PullHostAssignment(context.Background(), identity, now, now.Add(time.Minute), DeliverySeed{AssignmentID: "assignment_" + test.name, EnvelopeID: "envelope_01", DeliveryID: "delivery_01", Nonce: "nonce_01"}, testEnvelopeSigner)
			if err != nil {
				t.Fatal(err)
			}
			if !test.completeAt.IsZero() {
				if _, err := ledger.AcknowledgeHostAssignment(context.Background(), identity, dispatch.Operation.Assignment.AssignmentID, dispatch.Operation.Assignment.FencingToken, digest("6"), now.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				result := sandboxhostprotocol.Result{ResultID: "result_terminal", HostID: host.HostID, HostGeneration: host.Generation, AssignmentID: dispatch.Operation.Assignment.AssignmentID, LeaseEpoch: dispatch.Operation.Assignment.LeaseEpoch, FencingToken: dispatch.Operation.Assignment.FencingToken, Principal: operation.Principal, OperationID: operation.ID, EffectiveSpecDigest: operation.EffectiveSpecDigest, CapabilityDigest: operation.CapabilityDigest, State: "succeeded", ObservedAt: test.completeAt}
				if _, err := ledger.RecordAuthenticatedHostResult(context.Background(), identity, result, test.completeAt); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := ledger.RenewHostAssignment(context.Background(), identity, dispatch.Operation.Assignment.AssignmentID, dispatch.Operation.Assignment.FencingToken, test.renewAt, test.renewAt.Add(time.Minute), DeliverySeed{EnvelopeID: "envelope_02", DeliveryID: "delivery_02", Nonce: "nonce_02"}, testEnvelopeSigner); !errors.Is(err, ErrStaleFence) {
				t.Fatalf("RenewHostAssignment() error = %v", err)
			}
			got, err := ledger.Get(context.Background(), operation.Principal, operation.ID)
			if err != nil || got.Assignment.FencingToken != dispatch.Operation.Assignment.FencingToken {
				t.Fatalf("operation after refused renewal = %#v, %v", got, err)
			}
		})
	}
}

func testEnvelopeSigner(envelope sandboxhostprotocol.Envelope) ([]byte, error) {
	envelope.ControlKeyID = "test"
	return []byte(envelope.AssignmentID + ":" + envelope.EnvelopeID + ":" + envelope.DeliveryID), nil
}

func digest(character string) string {
	return "sha256:" + character + "000000000000000000000000000000000000000000000000000000000000000"
}
