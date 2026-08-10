package agentspecbackfillcrd_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/agentspecbackfill"
	"github.com/0x63616c/agent-runtime/internal/agentspecbackfillcr"
	"github.com/0x63616c/agent-runtime/internal/agentspecbackfillcrd"
)

func TestRenderProducesTheStrictV1AgentSpecBackfillCRD(t *testing.T) {
	t.Parallel()
	first, err := agentspecbackfillcrd.Render()
	if err != nil {
		t.Fatal(err)
	}
	second, err := agentspecbackfillcrd.Render()
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("expected deterministic rendering, equal=%t err=%v", bytes.Equal(first, second), err)
	}
	if err := agentspecbackfillcrd.Validate(first); err != nil {
		t.Fatalf("validate rendered CRD: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(first, &document); err != nil {
		t.Fatal(err)
	}
	if document["apiVersion"] != "apiextensions.k8s.io/v1" || document["kind"] != "CustomResourceDefinition" {
		t.Fatalf("unexpected CRD identity: %#v", document)
	}
	spec := document["spec"].(map[string]any)
	if spec["group"] != "runtime.0x63616c.dev" || spec["scope"] != "Namespaced" || spec["preserveUnknownFields"] != false {
		t.Fatalf("unexpected CRD scope: %#v", spec)
	}
	version := spec["versions"].([]any)[0].(map[string]any)
	if version["name"] != "v1alpha1" || version["served"] != true || version["storage"] != true || version["subresources"].(map[string]any)["status"] == nil {
		t.Fatalf("missing v1 status subresource: %#v", version)
	}
	root := version["schema"].(map[string]any)["openAPIV3Schema"].(map[string]any)
	properties := root["properties"].(map[string]any)
	specification := properties["spec"].(map[string]any)
	if specification["additionalProperties"] != false || !contains(specification["x-kubernetes-validations"].([]any), "self == oldSelf") {
		t.Fatalf("spec is not strictly immutable: %#v", specification)
	}
	fields := specification["properties"].(map[string]any)
	if len(fields) != 13 || fields["migrationVersion"].(map[string]any)["minimum"] != float64(4) || fields["migrationVersion"].(map[string]any)["maximum"] != float64(4) || fields["fenceNonce"].(map[string]any)["pattern"] != "^[A-Za-z0-9_-]{43}$" {
		t.Fatalf("spec does not preserve canonical request bounds: %#v", fields)
	}
	status := properties["status"].(map[string]any)
	if status["additionalProperties"] != false || status["x-kubernetes-validations"] == nil || !contains(status["x-kubernetes-validations"].([]any), "oldSelf.phase") {
		t.Fatalf("status is not bounded and terminally immutable: %#v", status)
	}
}

func TestFixtureMatchesTheGeneratedCRDAndRejectsUnsafeDrift(t *testing.T) {
	t.Parallel()
	rendered, err := agentspecbackfillcrd.Render()
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile(filepath.Join("testdata", "agent-spec-backfill-crd.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := agentspecbackfillcrd.Validate(fixture); err != nil {
		t.Fatal("CRD fixture is stale; regenerate it from the structural schema")
	}
	var mutated map[string]any
	if err := json.Unmarshal(rendered, &mutated); err != nil {
		t.Fatal(err)
	}
	versions := mutated["spec"].(map[string]any)["versions"].([]any)
	versions[0].(map[string]any)["subresources"] = map[string]any{}
	unsafe, err := json.Marshal(mutated)
	if err != nil {
		t.Fatal(err)
	}
	if err := agentspecbackfillcrd.Validate(unsafe); err == nil {
		t.Fatal("expected CRD without status subresource to be refused")
	}
}

func TestSchemaProjectsTheCanonicalRequestAndStatusWires(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	request, err := agentspecbackfillcr.NewRequest(canonicalCoreRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	request.Metadata.UID, request.Metadata.Generation = "uid-01", 1
	requestWire, err := request.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := request.Spec.Digest()
	if err != nil {
		t.Fatal(err)
	}
	status := agentspecbackfillcr.Status{Phase: agentspecbackfill.PhaseVerified, RequestUID: request.Metadata.UID, ObservedGeneration: request.Metadata.Generation, ControllerImageDigest: request.Spec.ControllerImageDigest, RequestDigest: digest, SnapshotFingerprint: request.Spec.SnapshotFingerprint, SnapshotCount: request.Spec.SnapshotCount, ManifestDigest: request.Spec.ManifestDigest, StaticReadinessDigest: request.Spec.StaticReadinessDigest, VerifiedCount: request.Spec.SnapshotCount, CompletedAt: now}
	statusWire, err := status.CanonicalFor(request, now)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := agentspecbackfillcrd.Render()
	if err != nil {
		t.Fatal(err)
	}
	var manifest, requestDocument map[string]any
	if err := json.Unmarshal(rendered, &manifest); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(requestWire, &requestDocument); err != nil {
		t.Fatal(err)
	}
	var statusDocument map[string]any
	if err := json.Unmarshal(statusWire, &statusDocument); err != nil {
		t.Fatal(err)
	}
	properties := manifest["spec"].(map[string]any)["versions"].([]any)[0].(map[string]any)["schema"].(map[string]any)["openAPIV3Schema"].(map[string]any)["properties"].(map[string]any)
	assertSchemaCoversWire(t, properties["spec"].(map[string]any)["properties"].(map[string]any), requestDocument["spec"].(map[string]any))
	assertSchemaCoversWire(t, properties["status"].(map[string]any)["properties"].(map[string]any), statusDocument)
}

func contains(values []any, needle string) bool {
	for _, value := range values {
		entry, ok := value.(map[string]any)
		if ok && strings.Contains(entry["rule"].(string), needle) {
			return true
		}
	}
	return false
}

func assertSchemaCoversWire(t *testing.T, fields, wire map[string]any) {
	t.Helper()
	for name := range wire {
		if _, found := fields[name]; !found {
			t.Fatalf("generated schema does not cover canonical wire field %q", name)
		}
	}
}

func canonicalCoreRequest(now time.Time) agentspecbackfill.Request {
	return agentspecbackfill.Request{StackDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111", MigrationVersion: 4, MigrationArtifactDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222", ManifestDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333", ControllerImageDigest: "sha256:4444444444444444444444444444444444444444444444444444444444444444", SnapshotFingerprint: "sha256:5555555555555555555555555555555555555555555555555555555555555555", SnapshotCount: 1, FenceNonce: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY", StaticReadinessDigest: "sha256:6666666666666666666666666666666666666666666666666666666666666666", DatabaseAuthorityDigest: "sha256:7777777777777777777777777777777777777777777777777777777777777777", BlobReadCapabilityDigest: "sha256:8888888888888888888888888888888888888888888888888888888888888888", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
}
