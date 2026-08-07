package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/roles"
	"github.com/0x63616c/agent-runtime/internal/stack"
)

func TestRenderBuildsOneTypedThreeProfileStack(t *testing.T) {
	document, err := renderStack("two-stack-a", "local")
	if err != nil {
		t.Fatalf("render stack: %v", err)
	}
	spec, err := stack.Parse(bytes.NewReader(document))
	if err != nil {
		t.Fatalf("parse rendered local stack: %v", err)
	}
	for _, profile := range []stack.Profile{stack.ProfileLocal, stack.ProfileCI, stack.ProfileProduction} {
		rendered, renderErr := stack.Render(spec, profile)
		if renderErr != nil {
			t.Fatalf("render %s: %v", profile, renderErr)
		}
		if _, manifestsErr := stack.RenderKubernetes(rendered); manifestsErr != nil {
			t.Fatalf("project %s Kubernetes manifests: %v", profile, manifestsErr)
		}
	}
	if got, want := spec.Namespace(stack.ProfileLocal), "ar-two-stack-a"; got != want {
		t.Fatalf("local namespace = %q, want %q", got, want)
	}
	if got, want := spec.Namespace(stack.ProfileCI), "ar-ci-two-stack-a"; got != want {
		t.Fatalf("ci namespace = %q, want %q", got, want)
	}
}

func TestLocalStackComposesRealTrustScopedRuntimeRoles(t *testing.T) {
	document, err := renderStack("role-proof", "local")
	if err != nil {
		t.Fatalf("render stack: %v", err)
	}
	spec, err := stack.Parse(bytes.NewReader(document))
	if err != nil {
		t.Fatalf("parse rendered local stack: %v", err)
	}
	rendered, err := stack.Render(spec, stack.ProfileLocal)
	if err != nil {
		t.Fatalf("render local stack: %v", err)
	}
	for _, expected := range []struct {
		resource stack.ResourceID
		role     roles.Role
	}{
		{resource: "api", role: roles.RoleAPI},
		{resource: "worker", role: roles.RoleOrchestration},
		{resource: "codec", role: roles.RoleCodec},
	} {
		resource := renderedResource(t, rendered.Resources(), expected.resource)
		if got := resource.Kubernetes.Command; len(got) != 1 || got[0] != "/runtime" {
			t.Fatalf("%s command = %v, want /runtime", expected.resource, got)
		}
		if got := resource.Kubernetes.Arguments; len(got) != 4 || got[0] != "--config-env" || got[1] != "RUNTIME_ROLE_CONFIG" || got[2] != "--role" || got[3] != string(expected.role) {
			t.Fatalf("%s arguments = %v, want real runtime role arguments", expected.resource, got)
		}
		var configuration string
		for _, environment := range resource.Kubernetes.Environment {
			if environment.Name == "RUNTIME_ROLE_CONFIG" {
				configuration = environment.Value
			}
		}
		config, parseErr := roles.Parse(strings.NewReader(configuration))
		if parseErr != nil || config.Role() != expected.role || config.Namespace() != "ar-role-proof" {
			t.Fatalf("%s runtime configuration = %q, parsed role=%q namespace=%q err=%v", expected.resource, configuration, config.Role(), config.Namespace(), parseErr)
		}
	}
}

func renderedResource(t *testing.T, resources []stack.Resource, id stack.ResourceID) stack.Resource {
	t.Helper()
	for _, resource := range resources {
		if resource.ID == id {
			return resource
		}
	}
	t.Fatalf("rendered resource %s not found", id)
	return stack.Resource{}
}

func TestMaterializeSecretsKeepsValuesPrivateAndStablePerStack(t *testing.T) {
	root := t.TempDir()
	first, err := materializeSecrets("safe-stack", root, strings.NewReader(strings.Repeat("x", 256)))
	if err != nil {
		t.Fatalf("materialize first secrets: %v", err)
	}
	second, err := materializeSecrets("safe-stack", root, strings.NewReader(strings.Repeat("y", 256)))
	if err != nil {
		t.Fatalf("materialize stable secrets: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("expected a stack's local Secret manifest to remain stable")
	}
	if !bytes.Contains(first, []byte(`"agent-runtime.dev/stack":"safe-stack"`)) {
		t.Fatal("expected Secret manifests to retain the sole Stack label")
	}
	path := filepath.Join(root, ".runtime", "dev", "safe-stack.secrets.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat private secret state: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private secret state mode = %o, want 600", info.Mode().Perm())
	}
}

func TestRenderRejectsUnsafeStackIdentity(t *testing.T) {
	if _, err := renderStack("production; rm", "local"); err == nil {
		t.Fatal("expected unsafe Stack identity to be rejected")
	}
}

func TestStateBindsOneStackToItsWorktreeAndAllocatedDashboardPort(t *testing.T) {
	root := t.TempDir()
	encoded, err := encodeState("safe-stack", root, 18432)
	if err != nil {
		t.Fatalf("encode state: %v", err)
	}
	if err := writePrivate(statePath(root, "safe-stack"), encoded); err != nil {
		t.Fatalf("write state: %v", err)
	}
	state, err := loadState(root, "safe-stack")
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if state.Namespace != "ar-safe-stack" || state.DashboardPort != 18432 {
		t.Fatalf("unexpected state: %+v", state)
	}
	if _, err := loadState(root, "other-stack"); err == nil {
		t.Fatal("expected a Stack not owned by this state file to be rejected")
	}
}
