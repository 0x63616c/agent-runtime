package architecture_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/roles"
	"github.com/0x63616c/agent-runtime/internal/stack"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Self-hosted production Stack", func() {
	It("derives disposable profiles from production with only identity, lifecycle, and test-secret differences", func() {
		file, err := os.Open("../../deploy/production/stack.json")
		Expect(err).NotTo(HaveOccurred())
		spec, err := stack.Parse(file)
		Expect(file.Close()).To(Succeed())
		Expect(err).NotTo(HaveOccurred())

		production, err := stack.Render(spec, stack.ProfileProduction)
		Expect(err).NotTo(HaveOccurred())
		local, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		ci, err := stack.Render(spec, stack.ProfileCI)
		Expect(err).NotTo(HaveOccurred())
		Expect(normalizedProfile(local.Resources(), "ar-agent-runtime")).To(Equal(normalizedProfile(production.Resources(), "agent-runtime")))
		Expect(normalizedProfile(ci.Resources(), "ar-ci-agent-runtime")).To(Equal(normalizedProfile(production.Resources(), "agent-runtime")))
		for _, rendered := range []stack.Rendered{local, ci} {
			for _, resource := range rendered.Resources() {
				if resource.Kind != stack.ResourceSecretReference {
					continue
				}
				Expect(resource.SecretReference.Provider).To(Equal("local-generated"), resource.ID)
				Expect(resource.Retention.Policy).To(Equal(stack.RetentionEphemeral), resource.ID)
				Expect(resource.DeleteBehavior).To(Equal(stack.DeleteOwned), resource.ID)
			}
		}

		command := exec.Command("jq", "-f", "deploy/production/derive-profiles.jq", "deploy/production/stack.json")
		command.Dir = "../.."
		derived, err := command.Output()
		Expect(err).NotTo(HaveOccurred())
		checkedIn, err := os.ReadFile("../../deploy/production/stack.json")
		Expect(err).NotTo(HaveOccurred())
		Expect(derived).To(Equal(checkedIn), "derive-profiles.jq must be an idempotent checked-in generator")
	})

	It("renders explicit trust-scoped roles, secrets, defaults, ingress, and operator dependencies", func() {
		file, err := os.Open("../../deploy/production/stack.json")
		Expect(err).NotTo(HaveOccurred())
		spec, err := stack.Parse(file)
		Expect(file.Close()).To(Succeed())
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileProduction)
		Expect(err).NotTo(HaveOccurred())
		manifests, err := stack.RenderKubernetes(rendered)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(manifests.JSON())).To(ContainSubstring(`"name": "codec-ingress"`))
		Expect(string(manifests.JSON())).To(ContainSubstring(`"host": "codec.agent-runtime.example.invalid"`))
		Expect(string(manifests.JSON())).To(ContainSubstring(`"enableServiceLinks": false`))

		resources := rendered.Resources()
		for _, role := range []stack.ResourceID{"api", "orchestration", "model", "tool", "blob-role", "codec", "sandbox-control", "sandbox-host"} {
			resource := findResource(resources, role)
			Expect(resource.Kubernetes.Replicas).To(BeNumerically(">", 0), role)
			Expect(resource.Kubernetes.ServiceAccount).To(Not(BeEmpty()), role)
			Expect(resource.Kubernetes.Network).To(BeNil(), "network authority is declared by a separate NetworkPolicy resource")
			policy := findResource(resources, stack.ResourceID(string(role)+"-egress"))
			Expect(policy.Kubernetes.Network.DefaultDeny).To(BeTrue(), role)
			Expect(policy.Kubernetes.Network.AllowDNS).To(BeTrue(), "%s resolves declared service dependencies", role)
		}
		for _, policyID := range []stack.ResourceID{"state-egress", "blob-egress", "telemetry-egress", "temporal-state-egress"} {
			Expect(findResource(resources, policyID).Kubernetes.Network.AllowDNS).To(BeFalse(), "%s has no service-name dependency", policyID)
		}
		for _, policyID := range []stack.ResourceID{"temporal-egress", "migration-runner-egress", "blob-reconciler-egress"} {
			Expect(findResource(resources, policyID).Kubernetes.Network.AllowDNS).To(BeTrue(), "%s resolves a declared service dependency", policyID)
		}

		Expect(secretEnvironmentNames(findResource(resources, "orchestration"))).To(ContainElement("TEMPORAL_AUTH_TOKEN"))
		Expect(secretEnvironmentNames(findResource(resources, "model"))).NotTo(ContainElement("TEMPORAL_AUTH_TOKEN"))
		Expect(findResource(resources, "model-egress").Kubernetes.Network.AllowedEgress).To(ContainElement(stack.ResourceID("egress-proxy")))
		Expect(findResource(resources, "temporal-namespace").Orchestration.RetentionDays).To(BeNumerically(">", 0))
		Expect(findResource(resources, "temporal-persistence").Database.Database).To(Equal("temporal"))
		Expect(findResource(resources, "temporal-visibility-persistence").Database.Database).To(Equal("temporal_visibility"))
		Expect(findResource(resources, "runtime-database").Database.Migrations).ToNot(BeEmpty())
		Expect(findResource(resources, "state").Kubernetes.Image).To(Equal("postgres@sha256:e5507c984377515b8c9922b0eb19f55aba2063fdc7bccf268cefd53133f97054"))
		temporal := findResource(resources, "temporal")
		Expect(temporal.Kubernetes.Image).To(Equal("temporalio/auto-setup@sha256:b44cbfeb43dbeae42db113b44fb8414c3452f05643b3d6b1592f955277d73526"))
		bindAddress, found := environmentValue(temporal, "BIND_ON_IP")
		Expect(found).To(BeTrue())
		Expect(bindAddress).To(Equal("0.0.0.0"))
		Expect(temporal.Kubernetes.Readiness.Command).To(ContainElements("--address", "127.0.0.1:7233", "cluster", "health"))
		Expect(findResource(resources, "blob").Kubernetes.Image).To(Equal("minio/minio@sha256:a1ea29fa28355559ef137d71fc570e508a214ec84ff8083e39bc5428980b015e"))
		Expect(findResource(resources, "blob-reconciler").Kubernetes.Compute.RequestMemoryBytes).To(Equal(int64(67108864)))
		Expect(findResource(resources, "blob-reconciler").Kubernetes.Compute.LimitMemoryBytes).To(Equal(int64(268435456)))
		Expect(findResource(resources, "telemetry").Kubernetes.Image).To(Equal("jaegertracing/all-in-one@sha256:12fa17a231abded2c3b5b715bd252a043678495c588cbe772173991fbdcdf7c8"))
		telemetryTTL, found := environmentValue(findResource(resources, "telemetry"), "BADGER_SPAN_STORE_TTL")
		Expect(found).To(BeTrue())
		Expect(telemetryTTL).To(Equal("720h"))
		Expect(findResource(resources, "migration-runner").Kubernetes.Image).To(Equal("postgres@sha256:e5507c984377515b8c9922b0eb19f55aba2063fdc7bccf268cefd53133f97054"))
		expectedRoleConfigs := map[stack.ResourceID]string{
			"api":             `{"version":1,"role":"api","namespace":"agent-runtime","listen_address":"0.0.0.0:8080","dependencies":[{"name":"state","endpoint":"http://state.agent-runtime.svc:8080"},{"name":"telemetry","endpoint":"http://telemetry.agent-runtime.svc:4318"}]}`,
			"orchestration":   `{"version":1,"role":"orchestration-codec","namespace":"agent-runtime","listen_address":"0.0.0.0:8081","dependencies":[{"name":"state","endpoint":"postgres://state.agent-runtime.svc:5432/agent_runtime","secret_environment":"STATE_DATABASE_DSN"},{"name":"telemetry","endpoint":"http://telemetry.agent-runtime.svc:4318"},{"name":"temporal","endpoint":"temporal.agent-runtime.svc:7233","secret_environment":"TEMPORAL_AUTH_TOKEN"},{"name":"payload-blob","endpoint":"http://blob.agent-runtime.svc:9000","secret_environment":"ORCHESTRATION_PAYLOAD_BLOB_ACCESS_KEY"},{"name":"payload-blob-secret","endpoint":"http://blob.agent-runtime.svc:9000","secret_environment":"ORCHESTRATION_PAYLOAD_BLOB_SECRET_KEY"}],"worker":{"task_queue":"agent-runtime-session-v1","payload_blob_endpoint":"http://blob.agent-runtime.svc:9000","payload_blob_bucket":"agent-runtime-temporal-payload","payload_blob_prefix":"temporal-payload","payload_access_key_environment":"ORCHESTRATION_PAYLOAD_BLOB_ACCESS_KEY","payload_secret_key_environment":"ORCHESTRATION_PAYLOAD_BLOB_SECRET_KEY"}}`,
			"model":           `{"version":1,"role":"model","namespace":"agent-runtime","listen_address":"0.0.0.0:8082","dependencies":[{"name":"conversation","endpoint":"http://api.agent-runtime.svc:8080","secret_environment":"CONVERSATION_ACCESS_TOKEN"},{"name":"egress-proxy","endpoint":"http://egress-proxy.agent-runtime.svc:8088"},{"name":"model","endpoint":"https://model-provider.example.invalid","secret_environment":"MODEL_API_KEY"},{"name":"telemetry","endpoint":"http://telemetry.agent-runtime.svc:4318"}]}`,
			"tool":            `{"version":1,"role":"tool","namespace":"agent-runtime","listen_address":"0.0.0.0:8083","dependencies":[{"name":"sandbox-control","endpoint":"http://sandbox-control.agent-runtime.svc:8086","secret_environment":"SANDBOX_CONTROL_TOKEN"},{"name":"telemetry","endpoint":"http://telemetry.agent-runtime.svc:4318"},{"name":"tool-broker","endpoint":"http://api.agent-runtime.svc:8080","secret_environment":"TOOL_BROKER_TOKEN"}]}`,
			"blob-role":       `{"version":1,"role":"blob","namespace":"agent-runtime","listen_address":"0.0.0.0:8084","dependencies":[{"name":"storage","endpoint":"http://blob.agent-runtime.svc:9000","secret_environment":"BLOB_STORAGE_CREDENTIAL"},{"name":"telemetry","endpoint":"http://telemetry.agent-runtime.svc:4318"}]}`,
			"codec":           `{"version":1,"role":"codec","namespace":"agent-runtime","listen_address":"0.0.0.0:8085","dependencies":[{"name":"blob","endpoint":"http://blob.agent-runtime.svc:9000","secret_environment":"CODEC_BLOB_CREDENTIAL"},{"name":"telemetry","endpoint":"http://telemetry.agent-runtime.svc:4318"}]}`,
			"sandbox-control": `{"version":1,"role":"sandbox-control","namespace":"agent-runtime","listen_address":"0.0.0.0:8086","dependencies":[{"name":"host-ca","endpoint":"https://host-ca.example.invalid","secret_environment":"SANDBOX_HOST_CA"},{"name":"sandbox-state","endpoint":"postgres://state.agent-runtime.svc:5432/sandbox","secret_environment":"SANDBOX_STATE_DSN"},{"name":"telemetry","endpoint":"http://telemetry.agent-runtime.svc:4318"}]}`,
			"sandbox-host":    `{"version":1,"role":"sandbox-host","namespace":"agent-runtime","listen_address":"0.0.0.0:8087","dependencies":[{"name":"host-identity","endpoint":"https://host-identity.example.invalid","secret_environment":"SANDBOX_HOST_IDENTITY"},{"name":"sandbox-control","endpoint":"http://sandbox-control.agent-runtime.svc:8086","secret_environment":"SANDBOX_CONTROL_TOKEN"},{"name":"telemetry","endpoint":"http://telemetry.agent-runtime.svc:4318"}]}`,
		}
		for role, expectedConfig := range expectedRoleConfigs {
			stackConfig, found := environmentValue(findResource(resources, role), "RUNTIME_ROLE_CONFIG")
			Expect(found).To(BeTrue(), "resource %s", role)
			Expect(stackConfig).To(Equal(expectedConfig), "resource %s", role)
			roleConfig, parseErr := roles.Parse(strings.NewReader(stackConfig))
			Expect(parseErr).NotTo(HaveOccurred(), "resource %s", role)
			plan, prepareErr := roles.Prepare(context.Background(), roleConfig, architectureFixtureSecrets{})
			Expect(prepareErr).NotTo(HaveOccurred(), "resource %s", role)
			Expect(secretEnvironmentNames(findResource(resources, role))).To(ConsistOf(plan.SecretEnvironmentNames()), "resource %s", role)
		}
		Expect(expectedRoleConfigs).To(HaveLen(8))

		controlService := findResource(resources, "sandbox-control-service")
		Expect(controlService.Kubernetes.Ports).To(ConsistOf(stack.Port{Name: "http", Number: 8086, Protocol: "TCP"}))
		for _, role := range []stack.ResourceID{"tool", "sandbox-host"} {
			configuration, found := environmentValue(findResource(resources, role), "RUNTIME_ROLE_CONFIG")
			Expect(found).To(BeTrue())
			var document struct {
				Dependencies []roles.Dependency `json:"dependencies"`
			}
			Expect(json.Unmarshal([]byte(configuration), &document)).To(Succeed())
			Expect(document.Dependencies).To(ContainElement(roles.Dependency{
				Name:              "sandbox-control",
				Endpoint:          "http://sandbox-control.agent-runtime.svc:8086",
				SecretEnvironment: "SANDBOX_CONTROL_TOKEN",
			}), role)
		}
	})
})

func findResource(resources []stack.Resource, id stack.ResourceID) stack.Resource {
	for _, resource := range resources {
		if resource.ID == id {
			return resource
		}
	}
	Fail("expected declared resource " + string(id))
	return stack.Resource{}
}

func normalizedProfile(resources []stack.Resource, namespace string) []byte {
	normalized := make([]stack.Resource, len(resources))
	copy(normalized, resources)
	for index := range normalized {
		resource := &normalized[index]
		resource.Retention = stack.Retention{}
		resource.BackupRestoreOwner = ""
		resource.DeleteBehavior = ""
		if resource.SecretReference != nil {
			resource.SecretReference.Provider = "<profile-secret-provider>"
			resource.SecretReference.Reference = "<profile-secret-reference>"
		}
		if resource.Orchestration != nil {
			resource.Orchestration.Namespace = "<namespace>"
			resource.Orchestration.TaskQueuePrefix = "<namespace>-"
		}
		if resource.Blob != nil {
			resource.Blob.Bucket = "<namespace>"
			resource.Blob.Prefix = "<namespace>/payloads"
		}
		if resource.Kubernetes != nil {
			if resource.ID == "runtime-api" {
				resource.Kubernetes.Replicas = 0
				resource.Kubernetes.Compute = nil
			}
			for environmentIndex := range resource.Kubernetes.Environment {
				environment := &resource.Kubernetes.Environment[environmentIndex]
				if environment.Name == "BLOB_BUCKET" || environment.Name == "BLOB_TEMPORAL_BUCKET" {
					environment.Value = "<namespace>"
					continue
				}
				if environment.Name == "RUNTIME_API_CONFIG" {
					environment.Value = "<profile-runtime-api-config>"
					continue
				}
				if environment.Name != "RUNTIME_ROLE_CONFIG" {
					continue
				}
				var document any
				Expect(json.Unmarshal([]byte(environment.Value), &document)).To(Succeed())
				document = normalizeNamespaceStrings(document, namespace)
				encoded, err := json.Marshal(document)
				Expect(err).NotTo(HaveOccurred())
				environment.Value = string(encoded)
			}
		}
	}
	encoded, err := json.Marshal(normalized)
	Expect(err).NotTo(HaveOccurred())
	return bytes.TrimSpace(encoded)
}

func normalizeNamespaceStrings(value any, namespace string) any {
	switch typed := value.(type) {
	case string:
		return strings.ReplaceAll(typed, namespace, "<namespace>")
	case []any:
		for index := range typed {
			typed[index] = normalizeNamespaceStrings(typed[index], namespace)
		}
		return typed
	case map[string]any:
		for key := range typed {
			if key == "tenant" {
				typed[key] = "<profile-tenant>"
				continue
			}
			typed[key] = normalizeNamespaceStrings(typed[key], namespace)
		}
		return typed
	default:
		return value
	}
}

type architectureFixtureSecrets struct{}

func (architectureFixtureSecrets) Lookup(context.Context, string) (string, bool, error) {
	return "fixture-secret", true, nil
}

func (architectureFixtureSecrets) KnownCredentialEnvironmentNames(context.Context) ([]string, error) {
	return nil, nil
}

func secretEnvironmentNames(resource stack.Resource) []string {
	result := make([]string, 0, len(resource.Kubernetes.SecretEnvironment))
	for _, variable := range resource.Kubernetes.SecretEnvironment {
		result = append(result, variable.Name)
	}
	return result
}

func environmentValue(resource stack.Resource, name string) (string, bool) {
	for _, variable := range resource.Kubernetes.Environment {
		if variable.Name == name {
			return variable.Value, true
		}
	}
	return "", false
}
