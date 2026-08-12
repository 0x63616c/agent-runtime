package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
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

func TestLocalStackProjectsTheReviewedEightRoleTopology(t *testing.T) {
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
	expectedRoleCredentials := map[stack.ResourceID][]string{
		"api":             nil,
		"orchestration":   {"STATE_DATABASE_DSN", "TEMPORAL_AUTH_TOKEN"},
		"model":           {"CONVERSATION_ACCESS_TOKEN", "MODEL_API_KEY"},
		"tool":            {"SANDBOX_CONTROL_TOKEN", "TOOL_BROKER_TOKEN"},
		"blob-role":       {"BLOB_STORAGE_CREDENTIAL"},
		"codec":           {"CODEC_BLOB_CREDENTIAL"},
		"sandbox-control": {"SANDBOX_HOST_CA", "SANDBOX_STATE_DSN"},
		"sandbox-host":    {"SANDBOX_HOST_IDENTITY", "SANDBOX_CONTROL_TOKEN"},
	}
	expectedRoles := map[stack.ResourceID]roles.Role{
		"api": roles.RoleAPI, "orchestration": roles.RoleOrchestration,
		"model": roles.RoleModel, "tool": roles.RoleTool, "blob-role": roles.RoleBlob,
		"codec": roles.RoleCodec, "sandbox-control": roles.RoleSandboxControl, "sandbox-host": roles.RoleSandboxHost,
	}
	expectedEgress := map[stack.ResourceID][]stack.ResourceID{
		"api":             {"state", "telemetry"},
		"orchestration":   {"state", "telemetry", "temporal"},
		"model":           {"api", "egress-proxy", "telemetry"},
		"tool":            {"api", "sandbox-control", "telemetry"},
		"blob-role":       {"blob", "telemetry"},
		"codec":           {"blob", "telemetry"},
		"sandbox-control": {"state", "telemetry"},
		"sandbox-host":    {"sandbox-control", "telemetry"},
	}
	seenAccounts := map[string]struct{}{}
	for resourceID, expectedRole := range expectedRoles {
		expected := struct {
			resource stack.ResourceID
			role     roles.Role
		}{resource: resourceID, role: expectedRole}
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
		if resource.Kubernetes.ServiceAccount == "" {
			t.Fatalf("%s must declare its own ServiceAccount", expected.resource)
		}
		if _, duplicate := seenAccounts[resource.Kubernetes.ServiceAccount]; duplicate {
			t.Fatalf("%s shares ServiceAccount %q with another runtime role", expected.resource, resource.Kubernetes.ServiceAccount)
		}
		seenAccounts[resource.Kubernetes.ServiceAccount] = struct{}{}
		actualCredentials := make([]string, 0, len(resource.Kubernetes.SecretEnvironment))
		for _, environment := range resource.Kubernetes.SecretEnvironment {
			actualCredentials = append(actualCredentials, environment.Name)
		}
		if strings.Join(actualCredentials, ",") != strings.Join(expectedRoleCredentials[expected.resource], ",") {
			t.Fatalf("%s credentials = %v, want %v", expected.resource, actualCredentials, expectedRoleCredentials[expected.resource])
		}
		policy := renderedResource(t, rendered.Resources(), stack.ResourceID(string(expected.resource)+"-egress"))
		if policy.Kubernetes == nil || policy.Kubernetes.Network == nil || !policy.Kubernetes.Network.DefaultDeny || policy.Kubernetes.Network.Subject != expected.resource {
			t.Fatalf("%s must have a default-deny egress policy scoped to itself", expected.resource)
		}
		if strings.Join(resourceIDs(policy.Kubernetes.Network.AllowedEgress), ",") != strings.Join(resourceIDs(expectedEgress[expected.resource]), ",") {
			t.Fatalf("%s egress = %v, want %v", expected.resource, policy.Kubernetes.Network.AllowedEgress, expectedEgress[expected.resource])
		}
	}
	if len(seenAccounts) != 8 {
		t.Fatalf("runtime role ServiceAccounts = %d, want 8", len(seenAccounts))
	}
	for _, database := range []stack.ResourceID{"state", "temporal-state"} {
		resource := renderedResource(t, rendered.Resources(), database)
		if resource.Kubernetes == nil || resource.Kubernetes.Kind != "Deployment" || resource.Kubernetes.ServiceAccount == "" {
			t.Fatalf("%s must be an explicit separately identified database deployment", database)
		}
	}
}

func resourceIDs(resources []stack.ResourceID) []string {
	identities := make([]string, 0, len(resources))
	for _, resource := range resources {
		identities = append(identities, string(resource))
	}
	return identities
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
	first, err := materializeSecrets("safe-stack", root, strings.NewReader(strings.Repeat("x", 4096)))
	if err != nil {
		t.Fatalf("materialize first secrets: %v", err)
	}
	second, err := materializeSecrets("safe-stack", root, strings.NewReader(strings.Repeat("y", 4096)))
	if err != nil {
		t.Fatalf("materialize stable secrets: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("expected a stack's local Secret manifest to remain stable")
	}
	if !bytes.Contains(first, []byte(`"agent-runtime.dev/stack":"safe-stack"`)) {
		t.Fatal("expected Secret manifests to retain the sole Stack label")
	}
	var secrets struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			StringData map[string]string `json:"stringData"`
		} `json:"items"`
	}
	if err := json.Unmarshal(first, &secrets); err != nil {
		t.Fatalf("parse Secret manifests: %v", err)
	}
	expectedSecretKeys := map[string][]string{
		"ar-safe-stack-state-db-secret":              {"POSTGRES_PASSWORD", "STATE_DATABASE_DSN"},
		"ar-safe-stack-temporal-auth-secret":         {"TEMPORAL_AUTH_TOKEN"},
		"ar-safe-stack-conversation-secret":          {"CONVERSATION_ACCESS_TOKEN"},
		"ar-safe-stack-model-secret":                 {"MODEL_API_KEY"},
		"ar-safe-stack-tool-broker-secret":           {"TOOL_BROKER_TOKEN"},
		"ar-safe-stack-sandbox-control-secret":       {"SANDBOX_CONTROL_TOKEN"},
		"ar-safe-stack-blob-storage-secret":          {"BLOB_STORAGE_CREDENTIAL", "MINIO_ROOT_PASSWORD", "MINIO_ROOT_USER"},
		"ar-safe-stack-codec-blob-secret":            {"CODEC_BLOB_CREDENTIAL"},
		"ar-safe-stack-sandbox-host-ca-secret":       {"SANDBOX_HOST_CA"},
		"ar-safe-stack-sandbox-state-secret":         {"SANDBOX_STATE_DSN"},
		"ar-safe-stack-sandbox-host-identity-secret": {"SANDBOX_HOST_IDENTITY"},
		"ar-safe-stack-temporal-db-secret":           {"POSTGRES_PASSWORD"},
	}
	if len(secrets.Items) != len(expectedSecretKeys) {
		t.Fatalf("generated Secret count = %d, want %d", len(secrets.Items), len(expectedSecretKeys))
	}
	for _, secret := range secrets.Items {
		expected, found := expectedSecretKeys[secret.Metadata.Name]
		if !found {
			t.Fatalf("unexpected generated Secret %q", secret.Metadata.Name)
		}
		actual := make([]string, 0, len(secret.StringData))
		for key := range secret.StringData {
			actual = append(actual, key)
		}
		sort.Strings(actual)
		sort.Strings(expected)
		if strings.Join(actual, ",") != strings.Join(expected, ",") {
			t.Fatalf("generated Secret %s keys = %v, want %v", secret.Metadata.Name, actual, expected)
		}
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
