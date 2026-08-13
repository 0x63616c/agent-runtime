package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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

func TestCIRenderUsesStackScopedTiltImagesWhileProductionRetainsPublishedImages(t *testing.T) {
	document, err := renderStack("ci-image-proof", "ci", localFixtureScenarioWorkspaceApprovalReset)
	if err != nil {
		t.Fatalf("render Stack: %v", err)
	}
	var rendered struct {
		Profiles map[string]struct {
			Resources []json.RawMessage `json:"resources"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(document, &rendered); err != nil {
		t.Fatalf("decode rendered Stack: %v", err)
	}
	ciImages := map[stack.ResourceID]string{}
	for _, profile := range []string{"ci", "production"} {
		for _, resource := range rendered.Profiles[profile].Resources {
			var object struct {
				ID         stack.ResourceID `json:"id"`
				Kubernetes *struct {
					Image string `json:"image"`
				} `json:"kubernetes"`
			}
			if err := json.Unmarshal(resource, &object); err != nil {
				t.Fatalf("decode %s resource: %v", profile, err)
			}
			if object.Kubernetes == nil || !tiltBuiltResource(object.ID) {
				continue
			}
			if profile == "ci" {
				want := devImage("ci-image-proof", object.ID)
				if object.Kubernetes.Image != want {
					t.Fatalf("CI %s image = %q, want source-built %q", object.ID, object.Kubernetes.Image, want)
				}
				ciImages[object.ID] = object.Kubernetes.Image
				continue
			}
			want := "ghcr.io/0x63616c/agent-runtime@sha256:bef38a1e7b268a50db626879ada7e4fc7d9486641dfb76ca8d5d54f21f102603"
			if object.ID == "api" {
				want = "ghcr.io/0x63616c/agent-runtime@sha256:aa96439dbda5207c31dea06d72a5f58c7e0f3a929c6a8bcfd2a24e67d3365207"
			}
			if object.Kubernetes.Image != want {
				t.Fatalf("production %s image must remain the reviewed published digest, got %q", object.ID, object.Kubernetes.Image)
			}
		}
	}
	wantCIImages := map[stack.ResourceID]bool{
		"api": true, "orchestration": true, "model": true, "tool": true,
		"blob-role": true, "codec": true, "sandbox-control": true,
		"sandbox-host": true, "sandbox-host-bootstrap": true, "egress-proxy": true,
	}
	if len(ciImages) != len(wantCIImages) {
		t.Fatalf("CI Stack has %d source-built images, want %d: %#v", len(ciImages), len(wantCIImages), ciImages)
	}
	for id := range wantCIImages {
		if _, found := ciImages[id]; !found {
			t.Fatalf("CI Stack is missing source-built image for %s", id)
		}
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

func TestMaterializedSandboxHostCertificateCarriesItsFixedSPIFFEIdentity(t *testing.T) {
	root := t.TempDir()
	if _, err := materializeSecrets("spiffe-proof", root, strings.NewReader(strings.Repeat("s", 4096))); err != nil {
		t.Fatalf("materialize local secrets: %v", err)
	}
	wire, err := os.ReadFile(secretStatePath(root, "spiffe-proof", "local"))
	if err != nil {
		t.Fatal(err)
	}
	var state localSecrets
	if err := json.Unmarshal(wire, &state); err != nil {
		t.Fatal(err)
	}
	certificatePEM := state.Values["ar-spiffe-proof-sandbox-host-identity-secret"]["SANDBOX_HOST_TLS_CERT"]
	block, _ := pem.Decode([]byte(certificatePEM))
	if block == nil {
		t.Fatal("generated host certificate is not PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || len(certificate.URIs) != 1 || certificate.URIs[0].String() != "spiffe://agent-runtime/sandbox-host/sandbox-host-01/generation/1" {
		t.Fatalf("generated host certificate identity = %#v, %v", certificate.URIs, err)
	}
}

func TestMaterializedBlobTLSIsAChainValidMinIOServerCertificate(t *testing.T) {
	for _, profile := range []string{"local", "ci"} {
		t.Run(profile, func(t *testing.T) {
			root := t.TempDir()
			stackName := "blob-tls-proof"
			if _, err := materializeSecretsForProfile(stackName, profile, root, strings.NewReader(strings.Repeat(profile, 4096))); err != nil {
				t.Fatalf("materialize %s secrets: %v", profile, err)
			}
			wire, err := os.ReadFile(secretStatePath(root, stackName, profile))
			if err != nil {
				t.Fatalf("read private %s secret state: %v", profile, err)
			}
			var state localSecrets
			if err := json.Unmarshal(wire, &state); err != nil {
				t.Fatalf("parse private %s secret state: %v", profile, err)
			}
			secretName := "ar-" + stackName + "-blob-tls-secret"
			if profile == "ci" {
				secretName = "ar-ci-" + stackName + "-blob-tls-secret"
			}
			values := state.Values[secretName]
			names := []string{"blob", "blob." + profileNamespace(stackName, profile) + ".svc"}
			if !localServerTLSIsValid(values["BLOB_TLS_CA"], values["BLOB_TLS_CERT"], values["BLOB_TLS_KEY"], names) {
				t.Fatal("materialized blob TLS does not contain a chain-valid MinIO server identity")
			}
			block, _ := pem.Decode([]byte(values["BLOB_TLS_CERT"]))
			if block == nil {
				t.Fatal("materialized blob certificate is not PEM")
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("parse materialized blob certificate: %v", err)
			}
			actualNames := append([]string(nil), certificate.DNSNames...)
			sort.Strings(actualNames)
			sort.Strings(names)
			if strings.Join(actualNames, ",") != strings.Join(names, ",") {
				t.Fatalf("materialized blob certificate DNS SANs do not match the reviewed service identities")
			}
		})
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
	if err := retireBootstrapCapability(root, state); err != nil {
		t.Fatalf("retire already absent capability: %v", err)
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

func TestRemoveRetiredLocalStackStateRemovesOnlyNamedPrivateLifecycleFiles(t *testing.T) {
	root := t.TempDir()
	state := localState{Stack: "cleanup-proof", Namespace: "ar-cleanup-proof"}
	paths := []string{
		statePath(root, state.Stack),
		secretStatePath(root, state.Stack, "local"),
		filepath.Join(root, ".runtime", "dev", state.Stack+".stack.json"),
		operatorAuditPath(root, state.Stack),
	}
	for _, path := range paths {
		if err := writePrivate(path, []byte("private")); err != nil {
			t.Fatal(err)
		}
	}
	sibling := statePath(root, "sibling-stack")
	if err := writePrivate(sibling, []byte("preserve")); err != nil {
		t.Fatal(err)
	}
	if err := removeRetiredLocalStackState(root, state); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("retired private state %s remains: %v", path, err)
		}
	}
	if _, err := os.Stat(sibling); err != nil {
		t.Fatalf("sibling private state was removed: %v", err)
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
		"api":             {"STATE_DATABASE_DSN", "RUNTIME_API_ADMIN_TOKEN", "RUNTIME_API_DEVELOPER_TOKEN", "RUNTIME_API_CONTENT_ACCESS_KEY", "RUNTIME_API_CONTENT_SECRET_KEY", "OBSERVABILITY_CORRELATION_KEY"},
		"orchestration":   {"STATE_DATABASE_DSN", "TEMPORAL_AUTH_TOKEN", "ORCHESTRATION_PAYLOAD_BLOB_ACCESS_KEY", "ORCHESTRATION_PAYLOAD_BLOB_SECRET_KEY"},
		"model":           {"CONVERSATION_ACCESS_TOKEN", "MODEL_API_KEY", "LOCAL_DEMO_STATE_DSN", "LOCAL_DEMO_CONTENT_ACCESS_KEY", "LOCAL_DEMO_CONTENT_SECRET_KEY"},
		"tool":            {"TOOL_BROKER_TOKEN", "LOCAL_DEMO_STATE_DSN", "LOCAL_DEMO_CONTENT_ACCESS_KEY", "LOCAL_DEMO_CONTENT_SECRET_KEY"},
		"blob-role":       {"BLOB_STORAGE_CREDENTIAL"},
		"codec":           {"CODEC_BLOB_CREDENTIAL"},
		"sandbox-control": {"SANDBOX_AUTHORIZATION", "SANDBOX_ASSERTION_KEY", "SANDBOX_CONTROL_SIGNING_KEY", "SANDBOX_STATE_DSN"},
		"sandbox-host":    {"SANDBOX_HOST_SIGNING_KEY"},
	}
	expectedRoles := map[stack.ResourceID]roles.Role{
		"orchestration": roles.RoleOrchestrationCodec,
		"model":         roles.RoleModel, "tool": roles.RoleTool, "blob-role": roles.RoleBlob,
		"codec": roles.RoleCodec, "sandbox-control": roles.RoleSandboxControl, "sandbox-host": roles.RoleSandboxHost,
	}
	expectedEgress := map[stack.ResourceID][]stack.ResourceID{
		"api":             {"blob", "otel-collector", "state"},
		"orchestration":   {"blob", "otel-collector", "state", "temporal"},
		"model":           {"api", "blob", "egress-proxy", "otel-collector", "state"},
		"tool":            {"api", "blob", "otel-collector", "state"},
		"blob-role":       {"blob", "otel-collector"},
		"codec":           {"blob", "otel-collector"},
		"sandbox-control": {"otel-collector", "state"},
		"sandbox-host":    {"otel-collector", "sandbox-control"},
	}
	seenAccounts := map[string]struct{}{}
	api := renderedResource(t, rendered.Resources(), "api")
	if got := api.Kubernetes.Command; len(got) != 1 || got[0] != "/agent-runtime-api" {
		t.Fatalf("api command = %v, want /agent-runtime-api", got)
	}
	if got := api.Kubernetes.Arguments; len(got) != 2 || got[0] != "--config-env" || got[1] != "RUNTIME_API_CONFIG" {
		t.Fatalf("api arguments = %v, want runtime API configuration arguments", got)
	}
	apiConfig, found := "", false
	for _, environment := range api.Kubernetes.Environment {
		if environment.Name == "RUNTIME_API_CONFIG" {
			apiConfig, found = environment.Value, true
			break
		}
	}
	if !found || !strings.Contains(apiConfig, `"storage":{"mode":"postgres"`) || !strings.Contains(apiConfig, `"bucket":"ar-role-proof"`) {
		t.Fatalf("api durable configuration = %q", apiConfig)
	}
	actualAPICredentials := make([]string, 0, len(api.Kubernetes.SecretEnvironment))
	for _, environment := range api.Kubernetes.SecretEnvironment {
		actualAPICredentials = append(actualAPICredentials, environment.Name)
	}
	if strings.Join(actualAPICredentials, ",") != strings.Join(expectedRoleCredentials["api"], ",") {
		t.Fatalf("api credentials = %v, want %v", actualAPICredentials, expectedRoleCredentials["api"])
	}
	apiPolicy := renderedResource(t, rendered.Resources(), "api-egress")
	if strings.Join(resourceIDs(apiPolicy.Kubernetes.Network.AllowedEgress), ",") != strings.Join(resourceIDs(expectedEgress["api"]), ",") {
		t.Fatalf("api egress = %v, want %v", apiPolicy.Kubernetes.Network.AllowedEgress, expectedEgress["api"])
	}
	seenAccounts[api.Kubernetes.ServiceAccount] = struct{}{}
	for resourceID, expectedRole := range expectedRoles {
		expected := struct {
			resource stack.ResourceID
			role     roles.Role
		}{resource: resourceID, role: expectedRole}
		resource := renderedResource(t, rendered.Resources(), expected.resource)
		if expected.resource == "sandbox-control" {
			if got := resource.Kubernetes.Command; len(got) != 1 || got[0] != "/sandbox-control" {
				t.Fatalf("sandbox-control command = %v, want /sandbox-control", got)
			}
		}
		if expected.resource == "sandbox-host" {
			if got := resource.Kubernetes.Command; len(got) != 1 || got[0] != "/sandbox-host" {
				t.Fatalf("sandbox-host command = %v, want /sandbox-host", got)
			}
		}
		if expected.resource != "sandbox-control" && expected.resource != "sandbox-host" && (len(resource.Kubernetes.Command) != 1 || resource.Kubernetes.Command[0] != "/runtime") {
			got := resource.Kubernetes.Command
			t.Fatalf("%s command = %v, want /runtime", expected.resource, got)
		}
		if expected.resource != "sandbox-control" && expected.resource != "sandbox-host" && (len(resource.Kubernetes.Arguments) != 4 || resource.Kubernetes.Arguments[0] != "--config-env" || resource.Kubernetes.Arguments[1] != "RUNTIME_ROLE_CONFIG" || resource.Kubernetes.Arguments[2] != "--role" || resource.Kubernetes.Arguments[3] != string(expected.role)) {
			got := resource.Kubernetes.Arguments
			t.Fatalf("%s arguments = %v, want real runtime role arguments", expected.resource, got)
		}
		if expected.resource != "sandbox-control" && expected.resource != "sandbox-host" {
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
		"ar-safe-stack-sandbox-control-secret":            {"SANDBOX_ASSERTION_KEY", "SANDBOX_AUTHORIZATION", "SANDBOX_CONTROL_SIGNING_KEY", "SANDBOX_CONTROL_TOKEN", "SANDBOX_HOST_TLS_CERT", "SANDBOX_HOST_TLS_KEY", "SANDBOX_PUBLIC_TLS_CERT", "SANDBOX_PUBLIC_TLS_KEY"},
		"ar-safe-stack-blob-storage-secret":               {"BLOB_STORAGE_CREDENTIAL", "MINIO_ROOT_PASSWORD", "MINIO_ROOT_USER"},
		"ar-safe-stack-blob-tls-secret":                   {"BLOB_TLS_CA", "BLOB_TLS_CERT", "BLOB_TLS_KEY"},
		"ar-safe-stack-orchestration-payload-blob-secret": {"ORCHESTRATION_PAYLOAD_BLOB_ACCESS_KEY", "ORCHESTRATION_PAYLOAD_BLOB_SECRET_KEY"},
		"ar-safe-stack-runtime-api-secret":                {"OBSERVABILITY_CORRELATION_KEY", "RUNTIME_API_ADMIN_TOKEN", "RUNTIME_API_CONTENT_ACCESS_KEY", "RUNTIME_API_CONTENT_SECRET_KEY", "RUNTIME_API_DEVELOPER_TOKEN"},
		"ar-safe-stack-codec-blob-secret":                 {"CODEC_BLOB_CREDENTIAL"},
		"ar-safe-stack-sandbox-host-ca-secret":            {"SANDBOX_HOST_CA", "SANDBOX_HOST_CLIENT_CA"},
		"ar-safe-stack-sandbox-state-secret":              {"SANDBOX_STATE_DSN"},
		"ar-safe-stack-sandbox-host-identity-secret":      {"SANDBOX_CONTROL_CA", "SANDBOX_CONTROL_TRUST", "SANDBOX_HOST_IDENTITY", "SANDBOX_HOST_SIGNING_KEY", "SANDBOX_HOST_TLS_CERT", "SANDBOX_HOST_TLS_KEY"},
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
	document, err := renderStack("ci-stack", "ci", localFixtureScenarioWorkspaceApprovalReset)
	if err != nil {
		t.Fatalf("render CI stack: %v", err)
	}
	spec, err := stack.Parse(bytes.NewReader(document))
	if err != nil {
		t.Fatalf("parse CI stack: %v", err)
	}
	rendered, err := stack.Render(spec, stack.ProfileCI)
	if err != nil {
		t.Fatalf("render CI profile: %v", err)
	}
	authority := stack.BootstrapAuthority{
		Stack: "ci-stack", Profile: stack.ProfileCI, Namespace: "ar-ci-ci-stack",
		NamespaceUID: "uid-ci-stack", RenderDigest: rendered.Digest(), Nonce: "private-ci-bootstrap-nonce",
	}
	capabilityPath := filepath.Join(root, ".runtime", "dev", "ci-stack.ci.bootstrap.json")
	if err := os.MkdirAll(filepath.Dir(capabilityPath), 0o700); err != nil {
		t.Fatalf("create CI capability directory: %v", err)
	}
	if err := stack.WriteBootstrapAuthority(capabilityPath, authority); err != nil {
		t.Fatalf("write CI bootstrap capability: %v", err)
	}
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
	if !bytes.Contains(manifest, []byte(`"agent-runtime.dev/external-controller":"local-generated"`)) ||
		!bytes.Contains(manifest, []byte(`"agent-runtime.dev/bootstrap-uid":"uid-ci-stack"`)) ||
		!bytes.Contains(manifest, []byte(`"agent-runtime.dev/render-digest":"`+rendered.Digest()+`"`)) {
		t.Fatalf("CI Secret manifest is not bound to its reviewed bootstrap authority: %s", manifest)
	}
	if _, err := os.Stat(filepath.Join(root, ".runtime", "dev", "ci-stack.ci.secrets.json")); err != nil {
		t.Fatalf("stat profile-scoped CI secret state: %v", err)
	}
}

func TestMaterializeSecretsRefusesProductionProfile(t *testing.T) {
	if _, err := materializeSecretsForProfile("production-proof", "production", t.TempDir(), strings.NewReader(strings.Repeat("p", 4096))); err == nil {
		t.Fatal("local development secret materializer accepted production external Secret references")
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

func TestPrepareCreatesOnePrivateLifecycleStateForTiltReconciliation(t *testing.T) {
	root := t.TempDir()
	err := prepare(context.Background(), "tilt-smoke", root, "/explicit/kubeconfig", "two-stack-smoke", localFixtureScenarioWorkspaceApprovalReset, io.Discard)
	if err != nil {
		t.Fatalf("prepare local lifecycle: %v", err)
	}
	state, err := loadState(root, "tilt-smoke")
	if err != nil {
		t.Fatalf("load prepared state: %v", err)
	}
	if state.Kubeconfig != "/explicit/kubeconfig" || state.OperatorActor != "two-stack-smoke" || state.Namespace != "ar-tilt-smoke" {
		t.Fatalf("prepared local state = %#v", state)
	}
	if _, err := os.Stat(filepath.Join(root, ".runtime", "dev", "tilt-smoke.stack.json")); err != nil {
		t.Fatalf("prepared Stack document: %v", err)
	}
	if err := prepare(context.Background(), "tilt-smoke", root, "/explicit/kubeconfig", "two-stack-smoke", localFixtureScenarioWorkspaceApprovalReset, io.Discard); err == nil {
		t.Fatal("prepare adopted pre-existing private state")
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
