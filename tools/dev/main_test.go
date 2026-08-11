package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/roles"
	"github.com/0x63616c/agent-runtime/internal/stack"
)

func TestRenderBuildsOneTypedThreeProfileStack(t *testing.T) {
	document, err := renderStack("two-stack-a", "local", localFixtureScenarioWorkspaceApprovalReset)
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

func TestLocalFixtureScenarioIsExplicitAndAttachedOnlyToLocalRoles(t *testing.T) {
	for _, scenario := range []string{"workspace-approval-reset-v1", "workspace-approval-expiry-v1"} {
		document, err := renderStack("fixture-proof", "local", localFixtureScenario(scenario))
		if err != nil {
			t.Fatal(err)
		}
		if got := fixtureScenarioAttachments(t, document, "local", scenario); got != 2 {
			t.Fatalf("local Stack render attaches scenario %q to %d roles, want model and tool only", scenario, got)
		}
	}
}

func TestLocalFixtureScenarioIsRejectedOutsideTheDeclaredLocalRender(t *testing.T) {
	if _, err := renderStack("fixture-proof", "ci", localFixtureScenarioWorkspaceApprovalExpiry); err == nil {
		t.Fatal("CI render accepted a local fixture scenario")
	}
	if _, _, scenario, _, err := parseRenderArguments([]string{"--stack", "fixture-proof", "--profile", "local", "--fixture-scenario", string(localFixtureScenarioWorkspaceApprovalExpiry)}); err != nil || scenario != localFixtureScenarioWorkspaceApprovalExpiry {
		t.Fatalf("parse declared local fixture scenario = %q, %v", scenario, err)
	}
	if _, _, _, _, err := parseRenderArguments([]string{"--stack", "fixture-proof", "--profile", "production", "--fixture-scenario", string(localFixtureScenarioWorkspaceApprovalExpiry)}); err == nil {
		t.Fatal("production render accepted a local fixture scenario")
	}
	if _, _, _, _, err := parseRenderArguments([]string{"--stack", "fixture-proof", "--profile", "ci", "--fixture-scenario", string(localFixtureScenarioWorkspaceApprovalReset)}); err == nil {
		t.Fatal("CI render accepted the normal local fixture scenario")
	}
	if _, _, _, _, err := parseRenderArguments([]string{"--stack", "fixture-proof", "--fixture-scenario", "ambient"}); err == nil {
		t.Fatal("render accepted an undeclared fixture scenario")
	}
}

func TestLocalTiltArgumentsPreserveTheDeclaredFixtureScenario(t *testing.T) {
	arguments := localTiltUpArguments("fixture-proof", 43821, localFixtureScenarioWorkspaceApprovalExpiry)
	if got := strings.Join(arguments, " "); !strings.Contains(got, "--fixture-scenario=workspace-approval-expiry-v1") || !strings.Contains(got, "--stack=fixture-proof") {
		t.Fatalf("local Tilt arguments = %q, want exact Stack and fixture scenario", got)
	}
}

func fixtureScenarioAttachments(t *testing.T, document []byte, profile, scenario string) int {
	t.Helper()
	var rendered struct {
		Profiles map[string]struct {
			Resources []json.RawMessage `json:"resources"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(document, &rendered); err != nil {
		t.Fatalf("decode rendered Stack: %v", err)
	}
	attachments := 0
	for _, resource := range rendered.Profiles[profile].Resources {
		var object struct {
			Kubernetes struct {
				Environment []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"environment"`
			} `json:"kubernetes"`
		}
		if err := json.Unmarshal(resource, &object); err != nil {
			t.Fatalf("decode rendered resource: %v", err)
		}
		for _, environment := range object.Kubernetes.Environment {
			if environment.Name != "RUNTIME_ROLE_CONFIG" {
				continue
			}
			configuration, err := roles.Parse(strings.NewReader(environment.Value))
			if err != nil {
				t.Fatalf("parse rendered runtime role configuration: %v", err)
			}
			if configuration.LocalDemoWorker() != nil && configuration.LocalDemoWorker().FixtureScenario == localFixtureScenario(scenario) {
				attachments++
			}
		}
	}
	return attachments
}

func TestSyntheticNonlocalProfilesExcludeLocalDemoAuthority(t *testing.T) {
	document, err := renderStack("fixture-parity", "local", localFixtureScenarioWorkspaceApprovalReset)
	if err != nil {
		t.Fatal(err)
	}
	var rendered struct {
		Profiles map[string]struct {
			Resources []json.RawMessage `json:"resources"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(document, &rendered); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"ci", "production"} {
		for _, resource := range rendered.Profiles[profile].Resources {
			if bytes.Contains(resource, []byte(`local_demo_worker`)) {
				t.Fatalf("synthetic %s resource leaks local demo authority: %s", profile, resource)
			}
		}
	}
}

func TestLocalStackExactlyMatchesReviewedLocalTopologyAfterInstanceNormalization(t *testing.T) {
	reviewedDocument, err := os.ReadFile(filepath.Join("..", "..", "deploy", "production", "stack.json"))
	if err != nil {
		t.Fatalf("read reviewed Stack: %v", err)
	}
	reviewedSpec, err := stack.Parse(bytes.NewReader(reviewedDocument))
	if err != nil {
		t.Fatalf("parse reviewed Stack: %v", err)
	}
	reviewed, err := stack.Render(reviewedSpec, stack.ProfileLocal)
	if err != nil {
		t.Fatalf("render reviewed local profile: %v", err)
	}

	generatedDocument, err := renderStack("topology-proof", "local", localFixtureScenarioWorkspaceApprovalReset)
	if err != nil {
		t.Fatalf("render generated Stack: %v", err)
	}
	generatedSpec, err := stack.Parse(bytes.NewReader(generatedDocument))
	if err != nil {
		t.Fatalf("parse generated Stack: %v", err)
	}
	generated, err := stack.Render(generatedSpec, stack.ProfileLocal)
	if err != nil {
		t.Fatalf("render generated local profile: %v", err)
	}

	got := normalizedTopology(t, generated.Resources(), "ar-topology-proof")
	want := normalizedTopology(t, reviewed.Resources(), "ar-agent-runtime")
	if !bytes.Equal(got, want) {
		t.Fatalf("generated local resources differ from the reviewed local profile after only namespace and Tilt image normalization\ngot:  %s\nwant: %s", got, want)
	}
}

func normalizedTopology(t *testing.T, resources []stack.Resource, namespace string) []byte {
	t.Helper()
	for index := range resources {
		if resources[index].Kubernetes != nil && tiltBuiltResource(resources[index].ID) {
			resources[index].Kubernetes.Image = "<tilt-built-image>"
		}
	}
	encoded, err := json.Marshal(resources)
	if err != nil {
		t.Fatalf("encode normalized topology: %v", err)
	}
	return bytes.ReplaceAll(encoded, []byte(namespace), []byte("<stack-namespace>"))
}

func TestTwoLocalStackInstancesKeepTopologyStateAndSecretsIsolated(t *testing.T) {
	root := t.TempDir()
	instances := []struct {
		name   string
		port   int
		reader io.Reader
	}{
		{name: "isolation-a", port: 18101, reader: strings.NewReader(strings.Repeat("a", 4096))},
		{name: "isolation-b", port: 18102, reader: strings.NewReader(strings.Repeat("b", 4096))},
	}

	var normalized [][]byte
	for _, instance := range instances {
		document, err := renderStack(instance.name, "local", localFixtureScenarioWorkspaceApprovalReset)
		if err != nil {
			t.Fatalf("render %s: %v", instance.name, err)
		}
		if err := writePrivate(filepath.Join(root, ".runtime", "dev", instance.name+".stack.json"), document); err != nil {
			t.Fatalf("write %s Stack state: %v", instance.name, err)
		}
		if _, err := materializeSecrets(instance.name, root, instance.reader); err != nil {
			t.Fatalf("materialize %s secrets: %v", instance.name, err)
		}
		state, err := encodeState(instance.name, root, instance.port, "/explicit/kubeconfig", "local-development", localFixtureScenarioWorkspaceApprovalReset)
		if err != nil {
			t.Fatalf("encode %s state: %v", instance.name, err)
		}
		if err := writePrivate(statePath(root, instance.name), state); err != nil {
			t.Fatalf("write %s state: %v", instance.name, err)
		}
		loaded, err := loadState(root, instance.name)
		if err != nil {
			t.Fatalf("load %s state: %v", instance.name, err)
		}
		if loaded.Namespace != "ar-"+instance.name || loaded.DashboardPort != instance.port {
			t.Fatalf("%s state crossed instance boundary: %+v", instance.name, loaded)
		}
		spec, err := stack.Parse(bytes.NewReader(document))
		if err != nil {
			t.Fatalf("parse %s Stack: %v", instance.name, err)
		}
		rendered, err := stack.Render(spec, stack.ProfileLocal)
		if err != nil {
			t.Fatalf("render %s local profile: %v", instance.name, err)
		}
		normalized = append(normalized, normalizedTopology(t, rendered.Resources(), loaded.Namespace))
	}
	if !bytes.Equal(normalized[0], normalized[1]) {
		t.Fatal("isolated local instances do not retain identical reviewed topology")
	}
	for _, suffix := range []string{"stack.json", "secrets.json", "state.json"} {
		left := filepath.Join(root, ".runtime", "dev", instances[0].name+"."+suffix)
		right := filepath.Join(root, ".runtime", "dev", instances[1].name+"."+suffix)
		leftData, leftErr := os.ReadFile(left)
		rightData, rightErr := os.ReadFile(right)
		if leftErr != nil || rightErr != nil {
			t.Fatalf("read isolated %s files: left=%v right=%v", suffix, leftErr, rightErr)
		}
		if bytes.Equal(leftData, rightData) {
			t.Fatalf("two Stack instances unexpectedly share identical %s state", suffix)
		}
	}
}

func TestRetireBootstrapCapabilityRemovesOnlyTheVerifiedLocalCapability(t *testing.T) {
	root := t.TempDir()
	state := localState{Stack: "cleanup-proof", Namespace: "ar-cleanup-proof"}
	path := bootstrapCapabilityPath(root, state.Stack)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create capability directory: %v", err)
	}
	authority := stack.BootstrapAuthority{Stack: state.Stack, Profile: stack.ProfileLocal, Namespace: state.Namespace, NamespaceUID: "uid-cleanup", RenderDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Nonce: "private-cleanup-nonce"}
	if err := stack.WriteBootstrapAuthority(path, authority); err != nil {
		t.Fatalf("write capability: %v", err)
	}
	if err := retireBootstrapCapability(root, state); err != nil {
		t.Fatalf("retire capability: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("capability remains after retirement: %v", err)
	}
	if err := stack.WriteBootstrapAuthority(path, authority); err != nil {
		t.Fatalf("rewrite capability: %v", err)
	}
	state.Namespace = "ar-foreign"
	if err := retireBootstrapCapability(root, state); err == nil {
		t.Fatal("retire foreign capability unexpectedly succeeded")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("foreign capability was removed: %v", err)
	}
}

func TestLocalStackProjectsTheReviewedEightRoleTopology(t *testing.T) {
	document, err := renderStack("role-proof", "local", localFixtureScenarioWorkspaceApprovalReset)
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
		"orchestration":   {"STATE_DATABASE_DSN", "TEMPORAL_AUTH_TOKEN", "ORCHESTRATION_PAYLOAD_BLOB_ACCESS_KEY", "ORCHESTRATION_PAYLOAD_BLOB_SECRET_KEY"},
		"model":           {"CONVERSATION_ACCESS_TOKEN", "MODEL_API_KEY", "LOCAL_DEMO_STATE_DSN", "LOCAL_DEMO_CONTENT_ACCESS_KEY", "LOCAL_DEMO_CONTENT_SECRET_KEY"},
		"tool":            {"SANDBOX_CONTROL_TOKEN", "TOOL_BROKER_TOKEN", "LOCAL_DEMO_STATE_DSN", "LOCAL_DEMO_CONTENT_ACCESS_KEY", "LOCAL_DEMO_CONTENT_SECRET_KEY"},
		"blob-role":       {"BLOB_STORAGE_CREDENTIAL"},
		"codec":           {"CODEC_BLOB_CREDENTIAL"},
		"sandbox-control": {"SANDBOX_HOST_CA", "SANDBOX_STATE_DSN"},
		"sandbox-host":    {"SANDBOX_HOST_IDENTITY", "SANDBOX_CONTROL_TOKEN"},
	}
	expectedRoles := map[stack.ResourceID]roles.Role{
		"api": roles.RoleAPI, "orchestration": roles.RoleOrchestrationCodec,
		"model": roles.RoleModel, "tool": roles.RoleTool, "blob-role": roles.RoleBlob,
		"codec": roles.RoleCodec, "sandbox-control": roles.RoleSandboxControl, "sandbox-host": roles.RoleSandboxHost,
	}
	expectedEgress := map[stack.ResourceID][]stack.ResourceID{
		"api":             {"state", "telemetry"},
		"orchestration":   {"blob", "state", "telemetry", "temporal"},
		"model":           {"api", "blob", "egress-proxy", "state", "telemetry"},
		"tool":            {"api", "blob", "sandbox-control", "state", "telemetry"},
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
		"ar-safe-stack-state-db-secret":                   {"POSTGRES_PASSWORD", "STATE_DATABASE_DSN"},
		"ar-safe-stack-temporal-auth-secret":              {"TEMPORAL_AUTH_TOKEN"},
		"ar-safe-stack-conversation-secret":               {"CONVERSATION_ACCESS_TOKEN"},
		"ar-safe-stack-model-secret":                      {"MODEL_API_KEY", "LOCAL_DEMO_STATE_DSN", "LOCAL_DEMO_CONTENT_ACCESS_KEY", "LOCAL_DEMO_CONTENT_SECRET_KEY"},
		"ar-safe-stack-tool-broker-secret":                {"TOOL_BROKER_TOKEN", "LOCAL_DEMO_STATE_DSN", "LOCAL_DEMO_CONTENT_ACCESS_KEY", "LOCAL_DEMO_CONTENT_SECRET_KEY"},
		"ar-safe-stack-sandbox-control-secret":            {"SANDBOX_CONTROL_TOKEN"},
		"ar-safe-stack-blob-storage-secret":               {"BLOB_STORAGE_CREDENTIAL", "MINIO_ROOT_PASSWORD", "MINIO_ROOT_USER"},
		"ar-safe-stack-orchestration-payload-blob-secret": {"ORCHESTRATION_PAYLOAD_BLOB_ACCESS_KEY", "ORCHESTRATION_PAYLOAD_BLOB_SECRET_KEY"},
		"ar-safe-stack-runtime-api-secret":                {"AR_RUNTIME_MINIO_ACCESS_KEY", "AR_RUNTIME_MINIO_SECRET_KEY", "RUNTIME_API_ADMIN_TOKEN", "RUNTIME_API_DEVELOPER_TOKEN"},
		"ar-safe-stack-codec-blob-secret":                 {"CODEC_BLOB_CREDENTIAL"},
		"ar-safe-stack-sandbox-host-ca-secret":            {"SANDBOX_HOST_CA"},
		"ar-safe-stack-sandbox-state-secret":              {"SANDBOX_STATE_DSN"},
		"ar-safe-stack-sandbox-host-identity-secret":      {"SANDBOX_HOST_IDENTITY"},
		"ar-safe-stack-temporal-db-secret":                {"POSTGRES_PASSWORD"},
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

func TestMaterializeCISecretsUsesTheCIProfileIdentity(t *testing.T) {
	root := t.TempDir()
	manifest, err := materializeSecretsForProfile("ci-stack", "ci", root, strings.NewReader(strings.Repeat("c", 4096)))
	if err != nil {
		t.Fatalf("materialize CI secrets: %v", err)
	}
	if !bytes.Contains(manifest, []byte(`"agent-runtime.dev/profile":"ci"`)) {
		t.Fatalf("CI Secret manifest does not use CI profile label: %s", manifest)
	}
	if !bytes.Contains(manifest, []byte(`"name":"ar-ci-ci-stack-state-db-secret"`)) {
		t.Fatalf("CI Secret manifest does not use CI reference identity: %s", manifest)
	}
	if _, err := os.Stat(filepath.Join(root, ".runtime", "dev", "ci-stack.ci.secrets.json")); err != nil {
		t.Fatalf("stat profile-scoped CI secret state: %v", err)
	}
}

func TestRenderRejectsUnsafeStackIdentity(t *testing.T) {
	if _, err := renderStack("production; rm", "local", localFixtureScenarioWorkspaceApprovalReset); err == nil {
		t.Fatal("expected unsafe Stack identity to be rejected")
	}
}

func TestLocalLifecycleRequiresAnExplicitKubeconfigAndBoundedActor(t *testing.T) {
	if _, _, _, _, _, err := parseUpArguments([]string{"--stack", "safe-stack", "--root", ".", "--actor", "local-development"}); err == nil {
		t.Fatal("expected local Stack lifecycle to reject an inferred kubeconfig")
	}
	if _, _, _, _, _, err := parseUpArguments([]string{"--stack", "safe-stack", "--root", ".", "--kubeconfig", "/explicit/kubeconfig", "--actor", "operator; rm"}); err == nil {
		t.Fatal("expected local Stack lifecycle to reject an unsafe actor")
	}
	stackName, root, kubeconfig, actor, scenario, err := parseUpArguments([]string{"--stack", "safe-stack", "--root", ".", "--kubeconfig", "/explicit/kubeconfig", "--actor", "local-development"})
	if err != nil || stackName != "safe-stack" || !filepath.IsAbs(root) || kubeconfig != "/explicit/kubeconfig" || actor != "local-development" || scenario != localFixtureScenarioWorkspaceApprovalReset {
		t.Fatalf("parse explicit local Stack lifecycle = %q, %q, %q, %q, %q, %v", stackName, root, kubeconfig, actor, scenario, err)
	}
	_, _, _, _, scenario, err = parseUpArguments([]string{"--stack", "safe-stack", "--root", ".", "--kubeconfig", "/explicit/kubeconfig", "--actor", "local-development", "--fixture-scenario", string(localFixtureScenarioWorkspaceApprovalReset)})
	if err != nil || scenario != localFixtureScenarioWorkspaceApprovalReset {
		t.Fatalf("parse declared up fixture scenario = %q, %v", scenario, err)
	}
	if _, _, _, _, _, err := parseUpArguments([]string{"--stack", "safe-stack", "--root", ".", "--kubeconfig", "/explicit/kubeconfig", "--actor", "local-development", "--fixture-scenario", "ambient"}); err == nil {
		t.Fatal("up accepted an undeclared fixture scenario")
	}
}

func TestLocalLifecyclePinsKubeconfigAndActorInPrivateState(t *testing.T) {
	root := t.TempDir()
	encoded, err := encodeState("safe-stack", root, 18432, "/explicit/kubeconfig", "local-development", localFixtureScenarioWorkspaceApprovalExpiry)
	if err != nil {
		t.Fatalf("encode local lifecycle state: %v", err)
	}
	if err := writePrivate(statePath(root, "safe-stack"), encoded); err != nil {
		t.Fatalf("write local lifecycle state: %v", err)
	}
	state, err := loadState(root, "safe-stack")
	if err != nil || state.Kubeconfig != "/explicit/kubeconfig" || state.OperatorActor != "local-development" || state.FixtureScenario != string(localFixtureScenarioWorkspaceApprovalExpiry) {
		t.Fatalf("load local lifecycle state = %#v, %v", state, err)
	}
	for _, path := range []string{bootstrapCapabilityPath(root, "safe-stack"), operatorAuditPath(root, "safe-stack")} {
		if !strings.HasPrefix(path, filepath.Join(root, ".runtime", "dev")+string(filepath.Separator)) {
			t.Fatalf("local lifecycle path escapes private state root: %s", path)
		}
	}
}

func TestCommandEnvironmentReplacesAmbientKubeconfig(t *testing.T) {
	t.Setenv("KUBECONFIG", "/ambient/kubeconfig")
	environment := commandEnvironment("/explicit/kubeconfig")
	for _, entry := range environment {
		if entry == "KUBECONFIG=/ambient/kubeconfig" {
			t.Fatal("local lifecycle retained an ambient kubeconfig")
		}
	}
	if environment[len(environment)-1] != "KUBECONFIG=/explicit/kubeconfig" {
		t.Fatalf("local lifecycle kubeconfig = %q, want explicit path", environment[len(environment)-1])
	}
}

func TestStateBindsOneStackToItsWorktreeAndAllocatedDashboardPort(t *testing.T) {
	root := t.TempDir()
	encoded, err := encodeState("safe-stack", root, 18432, "/explicit/kubeconfig", "local-development", localFixtureScenarioWorkspaceApprovalReset)
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
