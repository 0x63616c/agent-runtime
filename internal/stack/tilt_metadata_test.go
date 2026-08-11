package stack

import "testing"

func TestTiltControllerMetadataIsTheOnlyAcceptedExtraSecretLabel(t *testing.T) {
	expected := map[string]string{"app.kubernetes.io/part-of": "agent-runtime", "agent-runtime.dev/stack": "safe-stack"}
	accepted := map[string]string{"app.kubernetes.io/part-of": "agent-runtime", "agent-runtime.dev/stack": "safe-stack", "app.kubernetes.io/managed-by": "tilt"}
	if !equalStringMapAllowingTiltManager(accepted, expected) {
		t.Fatal("expected the exact Tilt manager label to be accepted")
	}
	for _, rejected := range []map[string]string{
		{"app.kubernetes.io/part-of": "agent-runtime", "agent-runtime.dev/stack": "safe-stack", "app.kubernetes.io/managed-by": "other"},
		{"app.kubernetes.io/part-of": "agent-runtime", "agent-runtime.dev/stack": "safe-stack", "app.kubernetes.io/managed-by": "tilt", "extra": "authority"},
	} {
		if equalStringMapAllowingTiltManager(rejected, expected) {
			t.Fatalf("accepted unexpected controller metadata: %#v", rejected)
		}
	}
}

func TestTiltNamespaceMetadataDoesNotPermitOtherLabels(t *testing.T) {
	accepted := map[string]string{"app.kubernetes.io/part-of": "agent-runtime", "agent-runtime.dev/stack": "safe-stack", "agent-runtime.dev/profile": "local", "kubernetes.io/metadata.name": "ar-safe-stack", "app.kubernetes.io/managed-by": "tilt"}
	if !onlyExpectedNamespaceLabels(accepted, "ar-safe-stack") {
		t.Fatal("expected the exact Tilt namespace metadata to be accepted")
	}
	accepted["other"] = "authority"
	if onlyExpectedNamespaceLabels(accepted, "ar-safe-stack") {
		t.Fatal("accepted an unexpected namespace label")
	}
}

func TestTiltLastAppliedAnnotationIsTheOnlyAcceptedExtraSecretAnnotation(t *testing.T) {
	expected := map[string]string{"agent-runtime.dev/bootstrap-uid": "uid", "agent-runtime.dev/render-digest": "sha256:expected"}
	accepted := map[string]string{"agent-runtime.dev/bootstrap-uid": "uid", "agent-runtime.dev/render-digest": "sha256:expected", "kubectl.kubernetes.io/last-applied-configuration": "tilt-managed"}
	if !equalStringMapAllowingTiltLastApplied(accepted, expected) {
		t.Fatal("expected Tilt last-applied metadata to be accepted")
	}
	accepted["extra"] = "authority"
	if equalStringMapAllowingTiltLastApplied(accepted, expected) {
		t.Fatal("accepted an unexpected Secret annotation")
	}
}
