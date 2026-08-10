package agentspecbackfillcr

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/agentspecbackfill"
)

func TestRequestRoundTripsOnlyItsBoundedCanonicalWire(t *testing.T) {
	t.Parallel()

	request, err := NewRequest(validCoreRequest())
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := request.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRequest(bytes.NewReader(canonical))
	if err != nil || parsed != request {
		t.Fatalf("ParseRequest() = %#v, %v", parsed, err)
	}
	for _, input := range [][]byte{
		append(append([]byte(nil), canonical...), '\n'),
		[]byte(strings.Replace(string(canonical), `"kind":"AgentSpecBackfill"`, `"kind":"AgentSpecBackfill","rawSpecification":"forbidden"`, 1)),
		bytes.Repeat([]byte("x"), maximumRequestWireBytes+1),
	} {
		if _, err := ParseRequest(bytes.NewReader(input)); err == nil {
			t.Fatalf("ParseRequest(%q) accepted unsafe wire", input)
		}
	}
}

func TestRequestRefusesNameAndImmutableSpecMutation(t *testing.T) {
	t.Parallel()

	request, err := NewRequest(validCoreRequest())
	if err != nil {
		t.Fatal(err)
	}
	mutated := request
	mutated.Spec.StackDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := mutated.Canonical(); err == nil {
		t.Fatal("Canonical() accepted a spec that no longer matches its capability name")
	}
	if err := request.ValidateImmutableMutation(mutated); err == nil {
		t.Fatal("ValidateImmutableMutation() accepted a changed spec")
	}
}

func TestStatusIsBoundedCanonicalAndTerminallyImmutable(t *testing.T) {
	t.Parallel()

	request, err := NewRequest(validCoreRequest())
	if err != nil {
		t.Fatal(err)
	}
	request.Metadata.UID = "uid-01"
	request.Metadata.Generation = 1
	now := request.Spec.CreatedAt.Add(time.Second)
	digest, err := request.Spec.Digest()
	if err != nil {
		t.Fatal(err)
	}
	status := Status{Phase: agentspecbackfill.PhaseVerified, RequestUID: "uid-01", ObservedGeneration: 1, ControllerImageDigest: request.Spec.ControllerImageDigest, RequestDigest: digest, SnapshotFingerprint: request.Spec.SnapshotFingerprint, SnapshotCount: request.Spec.SnapshotCount, ManifestDigest: request.Spec.ManifestDigest, StaticReadinessDigest: request.Spec.StaticReadinessDigest, VerifiedCount: request.Spec.SnapshotCount, CompletedAt: now}
	canonical, err := status.CanonicalFor(request, now)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseStatus(bytes.NewReader(canonical), request, now)
	if err != nil || parsed != status {
		t.Fatalf("ParseStatus() = %#v, %v", parsed, err)
	}
	mutated := status
	mutated.Phase = agentspecbackfill.PhaseRefused
	mutated.Reason = agentspecbackfill.RefusalContent
	mutated.VerifiedCount = 0
	if err := mutated.ValidateTransitionFrom(status, request, now); err == nil {
		t.Fatal("ValidateTransitionFrom() accepted terminal status mutation")
	}
	for _, input := range [][]byte{
		append(append([]byte(nil), canonical...), '\n'),
		[]byte(strings.Replace(string(canonical), `"phase":"Verified"`, `"phase":"Verified","rawOutput":"forbidden"`, 1)),
		bytes.Repeat([]byte("x"), maximumStatusWireBytes+1),
	} {
		if _, err := ParseStatus(bytes.NewReader(input), request, now); err == nil {
			t.Fatalf("ParseStatus(%q) accepted unsafe wire", input)
		}
	}
}

func validCoreRequest() agentspecbackfill.Request {
	return agentspecbackfill.Request{StackDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111", MigrationVersion: 4, MigrationArtifactDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222", ManifestDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333", ControllerImageDigest: "sha256:4444444444444444444444444444444444444444444444444444444444444444", SnapshotFingerprint: "sha256:5555555555555555555555555555555555555555555555555555555555555555", SnapshotCount: 1, FenceNonce: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY", StaticReadinessDigest: "sha256:6666666666666666666666666666666666666666666666666666666666666666", DatabaseAuthorityDigest: "sha256:7777777777777777777777777777777777777777777777777777777777777777", BlobReadCapabilityDigest: "sha256:8888888888888888888888888888888888888888888888888888888888888888", CreatedAt: time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 8, 9, 0, 10, 0, 0, time.UTC)}
}
