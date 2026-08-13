package sandboxhostprotocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestEnvelopeCanonicalSignatureAndHostBinding(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	envelope := testEnvelope(now)
	signed, err := SignEnvelope(envelope, "control-key-01", privateKey)
	if err != nil {
		t.Fatalf("SignEnvelope() error = %v", err)
	}
	verified, err := VerifyEnvelope(signed, "host_01", 7, now.Add(time.Second), map[string]ed25519.PublicKey{"control-key-01": publicKey})
	if err != nil || verified.AssignmentID != envelope.AssignmentID {
		t.Fatalf("VerifyEnvelope() = %#v, %v", verified, err)
	}

	mutated := append([]byte(nil), signed...)
	mutated[len(mutated)/2] ^= 1
	if _, err := VerifyEnvelope(mutated, "host_01", 7, now.Add(time.Second), map[string]ed25519.PublicKey{"control-key-01": publicKey}); err == nil {
		t.Fatal("VerifyEnvelope() accepted altered canonical bytes")
	}
	if _, err := VerifyEnvelope(signed, "host_rogue", 7, now.Add(time.Second), map[string]ed25519.PublicKey{"control-key-01": publicKey}); err == nil {
		t.Fatal("VerifyEnvelope() accepted wrong host")
	}
	if _, err := VerifyEnvelope(signed, "host_01", 6, now.Add(time.Second), map[string]ed25519.PublicKey{"control-key-01": publicKey}); err == nil {
		t.Fatal("VerifyEnvelope() accepted stale generation")
	}
	if _, err := VerifyEnvelope(signed, "host_01", 7, envelope.ExpiresAt, map[string]ed25519.PublicKey{"control-key-01": publicKey}); err == nil {
		t.Fatal("VerifyEnvelope() accepted expired envelope")
	}
}

func TestValidateAuthenticatedEnvelopeWireRefusesRebinding(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 10, 2, 0, 0, 0, time.UTC)
	wire, err := SignEnvelope(testEnvelope(now), "control-key-01", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := VerifyEnvelope(wire, "host_01", 7, now.Add(time.Second), map[string]ed25519.PublicKey{"control-key-01": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAuthenticatedEnvelopeWire(wire, envelope); err != nil {
		t.Fatalf("ValidateAuthenticatedEnvelopeWire() = %v", err)
	}
	envelope.FencingToken++
	if err := ValidateAuthenticatedEnvelopeWire(wire, envelope); err == nil {
		t.Fatal("ValidateAuthenticatedEnvelopeWire() accepted a rebound fence")
	}
}

func TestEnvelopeTrustPromotesNextKeyThenRefusesRetiredKey(t *testing.T) {
	t.Parallel()

	currentPublic, currentPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nextPublic, nextPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	futurePublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	current := SigningKey{ID: "control-current", Version: 1, PublicKey: currentPublic, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour)}
	next := SigningKey{ID: "control-next", Version: 2, PublicKey: nextPublic, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour)}
	future := SigningKey{ID: "control-future", Version: 3, PublicKey: futurePublic, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour)}
	trust, err := NewAtomicTrust(TrustBundle{Version: 1, RevocationEpoch: 7, Current: current, Next: &next})
	if err != nil {
		t.Fatal(err)
	}

	oldEnvelope, err := SignEnvelopeWithTrust(testEnvelope(now), trust.Snapshot(), currentPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEnvelopeWithTrust(oldEnvelope, "host_01", 7, now.Add(time.Second), trust.Snapshot()); err != nil {
		t.Fatalf("VerifyEnvelopeWithTrust() before rotation: %v", err)
	}

	if err := trust.Update(TrustBundle{Version: 2, RevocationEpoch: 7, Current: next, Next: &future}); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEnvelopeWithTrust(oldEnvelope, "host_01", 7, now.Add(time.Second), trust.Snapshot()); err == nil {
		t.Fatal("VerifyEnvelopeWithTrust() accepted a retired key after promotion")
	}
	newEnvelope, err := SignEnvelopeWithTrust(testEnvelope(now), trust.Snapshot(), nextPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEnvelopeWithTrust(newEnvelope, "host_01", 7, now.Add(time.Second), trust.Snapshot()); err != nil {
		t.Fatalf("VerifyEnvelopeWithTrust() after rotation: %v", err)
	}

	if err := trust.Update(TrustBundle{Version: 3, RevocationEpoch: 7, Current: next}); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEnvelopeWithTrust(oldEnvelope, "host_01", 7, now.Add(time.Second), trust.Snapshot()); err == nil {
		t.Fatal("VerifyEnvelopeWithTrust() accepted a retired key")
	}
}

func TestEnvelopeTrustBindsKeyValidityAndRevocationEpoch(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	key := SigningKey{ID: "control-current", Version: 1, PublicKey: publicKey, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	trust, err := NewAtomicTrust(TrustBundle{Version: 1, RevocationEpoch: 4, Current: key})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignEnvelopeWithTrust(testEnvelope(now), trust.Snapshot(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEnvelopeWithTrust(signed, "host_01", 7, now.Add(time.Second), trust.Snapshot()); err != nil {
		t.Fatalf("VerifyEnvelopeWithTrust() with matching epoch: %v", err)
	}
	if err := trust.Update(TrustBundle{Version: 2, RevocationEpoch: 5, Current: key}); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEnvelopeWithTrust(signed, "host_01", 7, now.Add(time.Second), trust.Snapshot()); err == nil {
		t.Fatal("VerifyEnvelopeWithTrust() accepted a revoked epoch")
	}

	expired := key
	expired.NotAfter = now.Add(30 * time.Second)
	if _, err := SignEnvelopeWithTrust(testEnvelope(now), TrustBundle{Version: 3, RevocationEpoch: 5, Current: expired}, privateKey); err == nil {
		t.Fatal("SignEnvelopeWithTrust() accepted an envelope beyond key validity")
	}
}

func TestTrustRejectsCurrentAndNextWithTheSameKeyID(t *testing.T) {
	t.Parallel()

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	current := SigningKey{ID: "control-key", Version: 1, PublicKey: publicKey, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	next := current
	next.Version = 2
	if _, err := NewAtomicTrust(TrustBundle{Version: 1, RevocationEpoch: 1, Current: current, Next: &next}); err == nil {
		t.Fatal("NewAtomicTrust() accepted colliding current and next key IDs")
	}
}

func TestTrustRejectsOutOfOrderVersionsAndDuplicatePublicKeys(t *testing.T) {
	t.Parallel()

	firstPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secondPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	first := SigningKey{ID: "control-first", Version: 1, PublicKey: firstPublic, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	second := SigningKey{ID: "control-second", Version: 2, PublicKey: secondPublic, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	if _, err := NewAtomicTrust(TrustBundle{Version: 1, RevocationEpoch: 1, Current: second, Next: &first}); err == nil {
		t.Fatal("NewAtomicTrust() accepted an out-of-order next key version")
	}
	duplicate := first
	duplicate.ID, duplicate.Version = "control-duplicate", 2
	if _, err := NewAtomicTrust(TrustBundle{Version: 1, RevocationEpoch: 1, Current: first, Next: &duplicate}); err == nil {
		t.Fatal("NewAtomicTrust() accepted duplicate public key material under two IDs")
	}
	trust, err := NewAtomicTrust(TrustBundle{Version: 1, RevocationEpoch: 1, Current: first})
	if err != nil {
		t.Fatal(err)
	}
	duplicatedDuringUpdate := first
	duplicatedDuringUpdate.ID, duplicatedDuringUpdate.Version = "control-duplicate-update", 2
	if err := trust.Update(TrustBundle{Version: 2, RevocationEpoch: 1, Current: first, Next: &duplicatedDuringUpdate}); err == nil {
		t.Fatal("Update() accepted duplicate public key material under a new ID")
	}
}

func TestResultSignatureBindsAssignmentAndFence(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	result := Result{ProtocolVersion: Version, ResultID: "result_01", HostID: "host_01", HostGeneration: 7, AssignmentID: "assignment_01", LeaseEpoch: 4, FencingToken: 4, Principal: "tenant_01:subject_01", OperationID: "op_01", EffectiveSpecDigest: digestA, CapabilityDigest: digestB, State: "succeeded", ObservedAt: now}
	signed, err := SignResult(result, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyResult(signed, now.Add(time.Second), publicKey)
	if err != nil || verified.FencingToken != 4 {
		t.Fatalf("VerifyResult() = %#v, %v", verified, err)
	}
	changed := verified
	changed.FencingToken++
	changedBytes, err := encodeSignedResult(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyResult(changedBytes, now.Add(time.Second), publicKey); err == nil {
		t.Fatal("VerifyResult() accepted a changed fence")
	}
}

func TestResultOptionalObservationIsSignedAndPreservesLegacyWire(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	legacy := testResult(now)
	legacyWire, err := SignResult(legacy, privateKey)
	if err != nil {
		t.Fatalf("SignResult(legacy) = %v", err)
	}
	if strings.Contains(string(legacyWire), `"observation"`) {
		t.Fatalf("legacy result wire unexpectedly gained observation: %s", legacyWire)
	}
	if _, err := VerifyResult(legacyWire, now.Add(time.Second), publicKey); err != nil {
		t.Fatalf("VerifyResult(legacy) = %v", err)
	}

	exitCode := int32(0)
	observed := legacy
	observed.Observation = &Observation{
		Sandbox: SandboxObservation{ID: "sbx_01", ActualState: "ready"},
		Process: &ProcessObservation{
			ID: "prc_01", SandboxID: "sbx_01", State: "terminal",
			Result: &ProcessResult{StartedAt: now.Add(-time.Minute), FinishedAt: now, ExitCode: &exitCode, Reason: "exited", Cleanup: "confirmed"},
			Stdout: OutputRetention{EarliestCursor: "1", RetainedBytes: 12},
			Stderr: OutputRetention{},
		},
	}
	wire, err := SignResult(observed, privateKey)
	if err != nil {
		t.Fatalf("SignResult(observed) = %v", err)
	}
	verified, err := VerifyResult(wire, now.Add(time.Second), publicKey)
	if err != nil || verified.Observation == nil || verified.Observation.Process == nil || verified.Observation.Process.Result == nil || *verified.Observation.Process.Result.ExitCode != 0 {
		t.Fatalf("VerifyResult(observed) = %#v, %v", verified, err)
	}
	changed := verified
	changed.Observation.Sandbox.ActualState = "lost"
	changedWire, err := encodeSignedResult(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyResult(changedWire, now.Add(time.Second), publicKey); err == nil {
		t.Fatal("VerifyResult() accepted an altered signed observation")
	}
}

func TestResultObservationRejectsIncoherentOrUnsafeMetadata(t *testing.T) {
	t.Parallel()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	for name, observation := range map[string]*Observation{
		"unknown sandbox state":                    {Sandbox: SandboxObservation{ID: "sbx_01", ActualState: "host-private-state"}},
		"process belongs to another sandbox":       {Sandbox: SandboxObservation{ID: "sbx_01", ActualState: "ready"}, Process: &ProcessObservation{ID: "prc_01", SandboxID: "sbx_02", State: "running"}},
		"non terminal result":                      {Sandbox: SandboxObservation{ID: "sbx_01", ActualState: "ready"}, Process: &ProcessObservation{ID: "prc_01", SandboxID: "sbx_01", State: "running", Result: &ProcessResult{Reason: "outcome-uncertain"}}},
		"raw failure is not a safe classification": {Sandbox: SandboxObservation{ID: "sbx_01", ActualState: "failed", Failure: &FailureObservation{Code: "host-error-/var/lib/private", Retry: "never"}}},
	} {
		t.Run(name, func(t *testing.T) {
			result := testResult(now)
			result.Observation = observation
			if _, err := SignResult(result, privateKey); err == nil {
				t.Fatal("SignResult() accepted invalid observation")
			}
		})
	}
}

func TestOutputSignatureBindsSequenceAndChunkDigest(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	output := Output{ProtocolVersion: Version, OutputID: "output_01", HostID: "host_01", HostGeneration: 7, AssignmentID: "assignment_01", LeaseEpoch: 4, FencingToken: 4, Principal: "tenant_01:subject_01", OperationID: "op_01", Stream: "stdout", Sequence: 1, ChunkDigest: digestA, SizeBytes: 12, ObservedAt: now}
	signed, err := SignOutput(output, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyOutput(signed, now.Add(time.Second), publicKey)
	if err != nil || verified.Sequence != 1 || verified.ChunkDigest != digestA {
		t.Fatalf("VerifyOutput() = %#v, %v", verified, err)
	}
	changed := verified
	changed.Sequence++
	changedBytes, err := encodeSignedOutput(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOutput(changedBytes, now.Add(time.Second), publicKey); err == nil {
		t.Fatal("VerifyOutput() accepted a changed sequence")
	}
}

func TestDataPlaneReceiptSignatureBindsReferenceAndFence(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reference := []byte(`{"artifact_id":"artifact_01","version":"agent-runtime.transfer-receipt/v1"}`)
	receipt := DataPlaneReceipt{ProtocolVersion: Version, ReceiptID: "receipt_01", HostID: "host_01", HostGeneration: 7, AssignmentID: "assignment_01", LeaseEpoch: 4, FencingToken: 4, OperationID: "op_01", Kind: "transfer", ReceiptDigest: Digest(reference)}
	signed, err := SignDataPlaneReceipt(receipt, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(signed, reference) {
		t.Fatal("signed data-plane receipt exposed private reference metadata")
	}
	verified, err := VerifyDataPlaneReceipt(signed, publicKey)
	if err != nil || verified.ReceiptID != receipt.ReceiptID || verified.ReceiptDigest != Digest(reference) {
		t.Fatalf("VerifyDataPlaneReceipt() = %#v, %v", verified, err)
	}
	changed := verified
	changed.FencingToken++
	changedBytes, err := encodeSignedDataPlaneReceipt(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDataPlaneReceipt(changedBytes, publicKey); err == nil {
		t.Fatal("VerifyDataPlaneReceipt() accepted a changed fence")
	}
}

func testEnvelope(now time.Time) Envelope {
	payload := []byte(`{"kind":"close-sandbox"}`)
	return Envelope{ProtocolVersion: Version, EnvelopeID: "envelope_01", DeliveryID: "delivery_01", Nonce: "nonce_01", IssuedAt: now, ExpiresAt: now.Add(time.Minute), HostID: "host_01", HostGeneration: 7, AssignmentID: "assignment_01", LeaseEpoch: 4, FencingToken: 4, Principal: "tenant_01:subject_01", Tenant: "tenant_01", SandboxID: "sbx_01", OperationID: "op_01", OperationKind: "close-sandbox", EffectiveSpecDigest: digestA, CapabilityDigest: digestB, CanonicalRequestDigest: digestC, PayloadDigest: Digest(payload), SequenceContract: "host-proposed/control-owned-v1", Payload: payload}
}

func testResult(now time.Time) Result {
	return Result{ProtocolVersion: Version, ResultID: "result_01", HostID: "host_01", HostGeneration: 7, AssignmentID: "assignment_01", LeaseEpoch: 4, FencingToken: 4, Principal: "tenant_01:subject_01", OperationID: "op_01", EffectiveSpecDigest: digestA, CapabilityDigest: digestB, State: "succeeded", ObservedAt: now}
}

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	digestC = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)
