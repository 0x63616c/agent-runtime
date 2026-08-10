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
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsvalidation "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/validation"
	structuralschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	celvalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	"k8s.io/apimachinery/pkg/util/validation/field"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
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
	if specification["additionalProperties"] != nil || !contains(specification["x-kubernetes-validations"].([]any), "self == oldSelf") {
		t.Fatalf("spec is not strictly immutable: %#v", specification)
	}
	fields := specification["properties"].(map[string]any)
	if len(fields) != 13 || fields["migrationVersion"].(map[string]any)["minimum"] != float64(4) || fields["migrationVersion"].(map[string]any)["maximum"] != float64(4) || fields["snapshotCount"].(map[string]any)["maximum"] != float64(9223372036854775807) || fields["fenceNonce"].(map[string]any)["pattern"] != "^[A-Za-z0-9_-]{43}$" {
		t.Fatalf("spec does not preserve canonical request bounds: %#v", fields)
	}
	status := properties["status"].(map[string]any)
	if status["additionalProperties"] != nil || status["x-kubernetes-validations"] == nil || !contains(status["x-kubernetes-validations"].([]any), "oldSelf.phase") {
		t.Fatalf("status is not bounded and terminally immutable: %#v", status)
	}
}

func TestRenderedCRDPassesPinnedKubernetesStructuralAndCELValidation(t *testing.T) {
	t.Parallel()
	rendered, err := agentspecbackfillcrd.Render()
	if err != nil {
		t.Fatal(err)
	}
	var external apiextensionsv1.CustomResourceDefinition
	if err := json.Unmarshal(rendered, &external); err != nil {
		t.Fatal(err)
	}
	var internal apiextensions.CustomResourceDefinition
	if err := apiextensionsv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(&external, &internal, nil); err != nil {
		t.Fatal(err)
	}
	internal.Status.StoredVersions = []string{"v1alpha1"}
	if validationErrors := apiextensionsvalidation.ValidateCustomResourceDefinition(t.Context(), &internal); len(validationErrors) != 0 {
		t.Fatalf("pinned Kubernetes rejects rendered CRD: %v", validationErrors)
	}
}

func TestPinnedKubernetesCELRefusesStatusThatDoesNotBindItsRequest(t *testing.T) {
	t.Parallel()
	structural, object := validatedCRDObject(t)
	validator := celvalidation.NewValidator(structural, true, celconfig.PerCallLimit)
	if validator == nil {
		t.Fatal("expected generated schema to compile CEL validation")
	}
	if errs, _ := validator.Validate(t.Context(), field.NewPath("root"), structural, object, nil, celconfig.RuntimeCELCostBudget); len(errs) != 0 {
		t.Fatalf("expected canonical request/status to pass CEL validation: %v", errs)
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "controller image", mutate: func(value map[string]any) {
			value["status"].(map[string]any)["controllerImageDigest"] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
		{name: "snapshot fingerprint", mutate: func(value map[string]any) {
			value["status"].(map[string]any)["snapshotFingerprint"] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
		{name: "snapshot count", mutate: func(value map[string]any) { value["status"].(map[string]any)["snapshotCount"] = int64(2) }},
		{name: "manifest digest", mutate: func(value map[string]any) {
			value["status"].(map[string]any)["manifestDigest"] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
		{name: "static readiness digest", mutate: func(value map[string]any) {
			value["status"].(map[string]any)["staticReadinessDigest"] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
		{name: "verified count", mutate: func(value map[string]any) { value["status"].(map[string]any)["verifiedCount"] = int64(2) }},
		{name: "verified reason", mutate: func(value map[string]any) { value["status"].(map[string]any)["reason"] = "content" }},
		{name: "expired before expiry", mutate: func(value map[string]any) {
			status := value["status"].(map[string]any)
			status["phase"], status["reason"] = "Refused", "expired"
		}},
		{name: "not admitted after creation", mutate: func(value map[string]any) {
			status := value["status"].(map[string]any)
			status["phase"], status["reason"] = "Refused", "not_admitted"
		}},
		{name: "integrity refusal at expiry", mutate: func(value map[string]any) {
			status := value["status"].(map[string]any)
			status["phase"], status["reason"], status["completedAt"] = "Refused", "content", value["spec"].(map[string]any)["requestExpiresAt"]
		}},
		{name: "nonterminal completion", mutate: func(value map[string]any) { value["status"].(map[string]any)["phase"] = "Pending" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := cloneObject(object)
			test.mutate(invalid)
			if errs, _ := validator.Validate(t.Context(), field.NewPath("root"), structural, invalid, nil, celconfig.RuntimeCELCostBudget); len(errs) == 0 {
				t.Fatal("expected unsafe status to be refused")
			}
		})
	}
	updated := cloneObject(object)
	updated["status"].(map[string]any)["completedAt"] = "2026-08-09T12:00:00.000000001Z"
	if errs, _ := validator.Validate(t.Context(), field.NewPath("root"), structural, updated, object, celconfig.RuntimeCELCostBudget); len(errs) == 0 {
		t.Fatal("expected terminal status mutation to be refused")
	}
	updated = cloneObject(object)
	updated["spec"].(map[string]any)["manifestDigest"] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	updated["status"].(map[string]any)["manifestDigest"] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if errs, _ := validator.Validate(t.Context(), field.NewPath("root"), structural, updated, object, celconfig.RuntimeCELCostBudget); len(errs) == 0 {
		t.Fatal("expected immutable spec mutation to be refused")
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

func validatedCRDObject(t *testing.T) (*structuralschema.Structural, map[string]any) {
	t.Helper()
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
	var object map[string]any
	if err := json.Unmarshal(requestWire, &object); err != nil {
		t.Fatal(err)
	}
	var statusObject map[string]any
	if err := json.Unmarshal(statusWire, &statusObject); err != nil {
		t.Fatal(err)
	}
	object["status"] = statusObject
	object = normalizeNumbers(object).(map[string]any)
	rendered, err := agentspecbackfillcrd.Render()
	if err != nil {
		t.Fatal(err)
	}
	var external apiextensionsv1.CustomResourceDefinition
	if err := json.Unmarshal(rendered, &external); err != nil {
		t.Fatal(err)
	}
	var internal apiextensions.CustomResourceDefinition
	if err := apiextensionsv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(&external, &internal, nil); err != nil {
		t.Fatal(err)
	}
	structural, err := structuralschema.NewStructural(internal.Spec.Validation.OpenAPIV3Schema)
	if err != nil {
		t.Fatal(err)
	}
	return structural, object
}

func cloneObject(object map[string]any) map[string]any {
	encoded, _ := json.Marshal(object)
	var cloned map[string]any
	_ = json.Unmarshal(encoded, &cloned)
	return normalizeNumbers(cloned).(map[string]any)
}

func normalizeNumbers(value any) any {
	switch typed := value.(type) {
	case float64:
		return int64(typed)
	case map[string]any:
		for key, child := range typed {
			typed[key] = normalizeNumbers(child)
		}
	case []any:
		for index, child := range typed {
			typed[index] = normalizeNumbers(child)
		}
	}
	return value
}
