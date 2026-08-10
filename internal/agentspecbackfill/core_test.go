package agentspecbackfill_test

import (
	"context"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/agentspecbackfill"
)

func TestRequestUsesCanonicalDigestNameAndBoundedImmutableStatus(t *testing.T) {
	request := validRequest()
	digest, err := request.Digest()
	if err != nil {
		t.Fatalf("digest request: %v", err)
	}
	if digest != "sha256:873b7b017d3d2741db1060c80c9dc549b61f0ccf5826d9643f389374a89c4f77" {
		t.Fatalf("request digest = %q", digest)
	}
	if name, err := request.Name(); err != nil || name != "asb-q45xwal5hutudwyqmdeazhofjg3b6dgplatnszb7hcjxjke4j53q" {
		t.Fatalf("request name = %q, %v", name, err)
	}
	status := agentbackfillVerifiedStatus(t, request)
	if err := status.ValidateFor(request, time.Date(2026, 8, 9, 0, 5, 0, 0, time.UTC)); err != nil {
		t.Fatalf("validate status: %v", err)
	}
	if encoded, err := status.Canonical(); err != nil || len(encoded) == 0 {
		t.Fatalf("canonical status = %x, %v", encoded, err)
	}
	changed := status
	changed.Phase = agentspecbackfill.PhaseRefused
	if err := changed.ValidateTransitionFrom(status); err == nil {
		t.Fatal("terminal status transition succeeded")
	}
}

func TestVerifyRefusesFrozenSnapshotAndImmutableContentFailures(t *testing.T) {
	request := validRequest()
	set := agentspecbackfill.FrozenLegacySet{
		Snapshot:  agentspecbackfill.Snapshot{Fingerprint: request.SnapshotFingerprint, Count: 1},
		Revisions: []agentspecbackfill.LegacyRevision{{TenantID: "tenant_a", AgentID: "agent_0000000000000001", RevisionID: "arev_0000000000000001", SpecificationDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SpecificationSizeBytes: 42}},
	}
	for _, failure := range []error{agentspecbackfill.ErrStaleSnapshot, agentspecbackfill.ErrWrongOwner, agentspecbackfill.ErrContentIntegrity} {
		status, err := agentspecbackfill.Verify(context.Background(), request, fixedReader{set: set}, failingVerifier{err: failure}, time.Date(2026, 8, 9, 0, 1, 0, 0, time.UTC))
		if err != nil {
			t.Fatalf("verify %v: %v", failure, err)
		}
		if status.Phase != agentspecbackfill.PhaseRefused || status.Reason != agentspecbackfill.RefusalContent {
			t.Fatalf("failure %v status = %#v", failure, status)
		}
	}
	stale := set
	stale.Snapshot.Fingerprint = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	status, err := agentspecbackfill.Verify(context.Background(), request, fixedReader{set: stale}, passingVerifier{}, time.Date(2026, 8, 9, 0, 1, 0, 0, time.UTC))
	if err != nil || status.Phase != agentspecbackfill.PhaseRefused || status.Reason != agentspecbackfill.RefusalSnapshot {
		t.Fatalf("stale snapshot = %#v, %v", status, err)
	}
	expired := request
	expired.ExpiresAt = time.Date(2026, 8, 9, 0, 0, 30, 0, time.UTC)
	status, err = agentspecbackfill.Verify(context.Background(), expired, fixedReader{set: set}, passingVerifier{}, time.Date(2026, 8, 9, 0, 1, 0, 0, time.UTC))
	if err != nil || status.Phase != agentspecbackfill.PhaseRefused || status.Reason != agentspecbackfill.RefusalExpired {
		t.Fatalf("expired request = %#v, %v", status, err)
	}
}

func TestArchiveIsRequestKeyedAndRetainsCertificateAbsentTerminalResult(t *testing.T) {
	request := validRequest()
	status := agentspecbackfill.Status{Phase: agentspecbackfill.PhaseRefused, RequestDigest: mustDigest(t, request), SnapshotFingerprint: request.SnapshotFingerprint, SnapshotCount: request.SnapshotCount, Reason: agentspecbackfill.RefusalExpired, CompletedAt: time.Date(2026, 8, 9, 0, 1, 0, 0, time.UTC)}
	bundle, err := agentspecbackfill.NewArchiveBundle(request, status, agentspecbackfill.Audit{Code: "expired"}, nil)
	if err != nil {
		t.Fatalf("new archive bundle: %v", err)
	}
	if bundle.CertificatePresent() {
		t.Fatal("refused terminal result has certificate")
	}
	if key := bundle.Key("retained/preflight"); key != "retained/preflight/agentspecbackfill/v1/asb-q45xwal5hutudwyqmdeazhofjg3b6dgplatnszb7hcjxjke4j53q/sha256-873b7b017d3d2741db1060c80c9dc549b61f0ccf5826d9643f389374a89c4f77.cbor" {
		t.Fatalf("archive key = %q", key)
	}
	if _, err := bundle.Canonical(); err != nil {
		t.Fatalf("canonical archive: %v", err)
	}
}

func validRequest() agentspecbackfill.Request {
	return agentspecbackfill.Request{StackDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111", MigrationVersion: 4, MigrationArtifactDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222", ManifestDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333", ControllerImageDigest: "sha256:4444444444444444444444444444444444444444444444444444444444444444", SnapshotFingerprint: "sha256:5555555555555555555555555555555555555555555555555555555555555555", SnapshotCount: 1, FenceNonce: "MDEyMzQ1Njc4OWFiY2RlZg", StaticReadinessDigest: "sha256:6666666666666666666666666666666666666666666666666666666666666666", DatabaseAuthorityDigest: "sha256:7777777777777777777777777777777777777777777777777777777777777777", BlobReadCapabilityDigest: "sha256:8888888888888888888888888888888888888888888888888888888888888888", ExpiresAt: time.Date(2026, 8, 9, 0, 10, 0, 0, time.UTC)}
}

func mustDigest(t *testing.T, request agentspecbackfill.Request) string {
	t.Helper()
	value, err := request.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func agentbackfillVerifiedStatus(t *testing.T, request agentspecbackfill.Request) agentspecbackfill.Status {
	t.Helper()
	return agentspecbackfill.Status{Phase: agentspecbackfill.PhaseVerified, RequestDigest: mustDigest(t, request), SnapshotFingerprint: request.SnapshotFingerprint, SnapshotCount: request.SnapshotCount, CompletedAt: time.Date(2026, 8, 9, 0, 1, 0, 0, time.UTC)}
}

type fixedReader struct {
	set agentspecbackfill.FrozenLegacySet
}

func (reader fixedReader) ReadFrozen(context.Context) (agentspecbackfill.FrozenLegacySet, error) {
	return reader.set, nil
}

type failingVerifier struct{ err error }

func (verifier failingVerifier) VerifyImmutable(context.Context, agentspecbackfill.LegacyRevision) error {
	return verifier.err
}

type passingVerifier struct{}

func (passingVerifier) VerifyImmutable(context.Context, agentspecbackfill.LegacyRevision) error {
	return nil
}
