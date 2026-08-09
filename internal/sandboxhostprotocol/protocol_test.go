package sandboxhostprotocol

import (
	"crypto/ed25519"
	"crypto/rand"
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

func TestEnvelopeTrustRotatesCurrentKeyThenRefusesRetiredKey(t *testing.T) {
	t.Parallel()

	currentPublic, currentPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nextPublic, nextPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	current := SigningKey{ID: "control-current", Version: 1, PublicKey: currentPublic, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour)}
	next := SigningKey{ID: "control-next", Version: 2, PublicKey: nextPublic, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour)}
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

	if err := trust.Update(TrustBundle{Version: 2, RevocationEpoch: 7, Current: next, Next: &current}); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEnvelopeWithTrust(oldEnvelope, "host_01", 7, now.Add(time.Second), trust.Snapshot()); err != nil {
		t.Fatalf("VerifyEnvelopeWithTrust() during overlap: %v", err)
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

func testEnvelope(now time.Time) Envelope {
	payload := []byte(`{"kind":"close-sandbox"}`)
	return Envelope{ProtocolVersion: Version, EnvelopeID: "envelope_01", DeliveryID: "delivery_01", Nonce: "nonce_01", IssuedAt: now, ExpiresAt: now.Add(time.Minute), HostID: "host_01", HostGeneration: 7, AssignmentID: "assignment_01", LeaseEpoch: 4, FencingToken: 4, Principal: "tenant_01:subject_01", Tenant: "tenant_01", SandboxID: "sbx_01", OperationID: "op_01", OperationKind: "close-sandbox", EffectiveSpecDigest: digestA, CapabilityDigest: digestB, CanonicalRequestDigest: digestC, PayloadDigest: Digest(payload), SequenceContract: "host-proposed/control-owned-v1", Payload: payload}
}

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	digestC = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)
