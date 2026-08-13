package architecture_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/roles"
	"github.com/0x63616c/agent-runtime/internal/sandboxcontrolprocess"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprocess"
	"github.com/0x63616c/agent-runtime/internal/stack"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Self-hosted production Stack", func() {
	It("binds every declared database migration to its checked-in artifact bytes", func() {
		file, err := os.Open("../../deploy/production/stack.json")
		Expect(err).NotTo(HaveOccurred())
		spec, err := stack.Parse(file)
		Expect(file.Close()).To(Succeed())
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileProduction)
		Expect(err).NotTo(HaveOccurred())

		for _, resource := range rendered.Resources() {
			if resource.Database == nil {
				continue
			}
			for _, migration := range resource.Database.Migrations {
				for artifact, declaredDigest := range map[string]string{
					migration.UpgradeArtifact:  migration.UpgradeDigest,
					migration.RollbackArtifact: migration.RollbackDigest,
				} {
					contents, readErr := os.ReadFile(filepath.Join("../../deploy/production", artifact))
					Expect(readErr).NotTo(HaveOccurred(), "%s migration %d artifact %s", resource.ID, migration.Version, artifact)
					actualDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(contents))
					Expect(declaredDigest).To(Equal(actualDigest), "%s migration %d artifact %s", resource.ID, migration.Version, artifact)
				}
			}
		}
	})

	It("retains the sandbox-control migration inventory under the reviewed operator root", func() {
		for version := 1; version <= 15; version++ {
			for _, direction := range []string{"up", "down"} {
				source := filepath.Join("../../deploy/sandboxcontrol/migrations", fmt.Sprintf("v%d.%s.sql", version, direction))
				copied := filepath.Join("../../deploy/production/migrations", fmt.Sprintf("sandboxcontrol-v%d.%s.sql", version, direction))
				expected, err := os.ReadFile(source)
				Expect(err).NotTo(HaveOccurred(), source)
				actual, err := os.ReadFile(copied)
				Expect(err).NotTo(HaveOccurred(), copied)
				Expect(actual).To(Equal(expected), "sandbox-control migration v%d %s must remain source-identical", version, direction)
			}
		}
	})

	It("names independent migration authorities when runtime and sandbox share a schema", func() {
		file, err := os.Open("../../deploy/production/stack.json")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { Expect(file.Close()).To(Succeed()) })
		spec, err := stack.Parse(file)
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileProduction)
		Expect(err).NotTo(HaveOccurred())
		runtime := findResource(rendered.Resources(), "runtime-database")
		sandbox := findResource(rendered.Resources(), "sandbox-control-database")
		Expect(runtime.Database.Database).To(Equal(sandbox.Database.Database))
		Expect(runtime.Database.Schema).To(Equal(sandbox.Database.Schema))
		Expect(runtime.Database.MigrationAuthority).To(Equal("runtime"))
		Expect(sandbox.Database.MigrationAuthority).To(Equal("sandbox-control"))
	})

	It("derives disposable profiles from production with only identity, lifecycle, test-secret, and declared local transport differences", func() {
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
		Expect(normalizedProfile(local.Resources(), "ar-agent-runtime", true)).To(Equal(normalizedProfile(production.Resources(), "agent-runtime", false)))
		Expect(normalizedProfile(ci.Resources(), "ar-ci-agent-runtime", false)).To(Equal(normalizedProfile(production.Resources(), "agent-runtime", false)))
		localAPIConfig, found := environmentValue(findResource(local.Resources(), "api"), "RUNTIME_API_CONFIG")
		Expect(found).To(BeTrue())
		Expect(localAPIConfig).To(ContainSubstring(`"endpoint":"http://blob.ar-agent-runtime.svc:9000"`))
		Expect(localAPIConfig).To(ContainSubstring(`"profile":"local"`))
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
		for _, disposable := range []stack.Rendered{local, ci} {
			bootstrap := findResource(disposable.Resources(), "sandbox-host-bootstrap")
			Expect(bootstrap.Kubernetes.Kind).To(Equal("Job"))
			Expect(bootstrap.Kubernetes.PostMigration).To(BeTrue())
			Expect(bootstrap.Kubernetes.Suspend).To(BeTrue())
			Expect(findResource(disposable.Resources(), "sandbox-host").Dependencies).To(ContainElement(stack.ResourceID("sandbox-host-bootstrap")))
		}
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
		for _, absent := range []stack.ResourceID{"runtime-api", "runtime-api-account", "runtime-api-service", "runtime-api-egress"} {
			for _, resource := range resources {
				Expect(resource.ID).NotTo(Equal(absent), "the durable API replaces the health-only api workload rather than creating a second public endpoint")
			}
		}
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
		tool := findResource(resources, "tool")
		Expect(secretEnvironmentNames(tool)).NotTo(ContainElement("SANDBOX_CONTROL_TOKEN"))
		Expect(tool.Dependencies).NotTo(ContainElement(stack.ResourceID("sandbox-control-secret")))
		Expect(findResource(resources, "tool-egress").Kubernetes.Network.AllowedEgress).NotTo(ContainElement(stack.ResourceID("sandbox-control")))
		Expect(findResource(resources, "tool-egress").Dependencies).NotTo(ContainElement(stack.ResourceID("sandbox-control")))
		api := findResource(resources, "api")
		Expect(api.Kubernetes.Image).To(Equal("ghcr.io/0x63616c/agent-runtime@sha256:aa96439dbda5207c31dea06d72a5f58c7e0f3a929c6a8bcfd2a24e67d3365207"))
		Expect(api.Kubernetes.Command).To(ConsistOf("/agent-runtime-api"))
		Expect(api.Kubernetes.Arguments).To(ConsistOf("--config-env", "RUNTIME_API_CONFIG"))
		Expect(secretEnvironmentNames(api)).To(ConsistOf("STATE_DATABASE_DSN", "RUNTIME_API_ADMIN_TOKEN", "RUNTIME_API_DEVELOPER_TOKEN", "RUNTIME_API_CONTENT_ACCESS_KEY", "RUNTIME_API_CONTENT_SECRET_KEY", "OBSERVABILITY_CORRELATION_KEY"))
		Expect(findResource(resources, "api-egress").Kubernetes.Network.AllowedEgress).To(ConsistOf(stack.ResourceID("state"), stack.ResourceID("otel-collector"), stack.ResourceID("blob")))
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
		collectorConfigBytes, readErr := os.ReadFile("../../deploy/observability/otelcol/collector.yaml")
		Expect(readErr).NotTo(HaveOccurred())
		collectorConfig := findResource(resources, "otel-collector-config")
		Expect(collectorConfig.Kubernetes.Data).To(HaveKeyWithValue("collector.yaml", string(collectorConfigBytes)))
		collector := findResource(resources, "otel-collector")
		Expect(collector.Kubernetes.Image).To(Equal("otel/opentelemetry-collector-contrib@sha256:09f7a495e6542343cc25aa4e3facba144ba03b0f0b030e4469186e8164a9ed64"))
		Expect(collector.Kubernetes.Arguments).To(ConsistOf("--config=/etc/otel/collector.yaml"))
		Expect(collector.Kubernetes.ConfigMapMounts).To(ConsistOf(stack.ConfigMapMount{ConfigMap: "otel-collector-config", Key: "collector.yaml", Path: "/etc/otel/collector.yaml"}))
		Expect(findResource(resources, "otel-collector-service").Kubernetes.Ports).To(ConsistOf(
			stack.Port{Name: "otlp-grpc", Number: 4317, Protocol: "TCP"},
			stack.Port{Name: "otlp-http", Number: 4318, Protocol: "TCP"},
			stack.Port{Name: "metrics", Number: 8889, Protocol: "TCP"},
		))
		Expect(findResource(resources, "otel-collector-egress").Kubernetes.Network.AllowedEgress).To(ConsistOf(stack.ResourceID("telemetry")))
		Expect(findResource(resources, "otel-collector-ingress").Kubernetes.Network.AllowedIngress).To(ConsistOf(
			stack.ResourceID("api"), stack.ResourceID("orchestration"), stack.ResourceID("model"), stack.ResourceID("tool"),
			stack.ResourceID("blob-role"), stack.ResourceID("codec"), stack.ResourceID("sandbox-control"), stack.ResourceID("sandbox-host"),
		))
		for _, role := range []stack.ResourceID{"api", "orchestration", "model", "tool", "blob-role", "codec", "sandbox-control", "sandbox-host"} {
			Expect(findResource(resources, stack.ResourceID(string(role)+"-egress")).Kubernetes.Network.AllowedEgress).To(ContainElement(stack.ResourceID("otel-collector")), role)
		}
		Expect(findResource(resources, "migration-runner").Kubernetes.Image).To(Equal("postgres@sha256:e5507c984377515b8c9922b0eb19f55aba2063fdc7bccf268cefd53133f97054"))
		expectedRoleConfigs := map[stack.ResourceID]string{
			"orchestration": `{"version":1,"role":"orchestration-codec","namespace":"agent-runtime","listen_address":"0.0.0.0:8081","dependencies":[{"name":"state","endpoint":"postgres://state.agent-runtime.svc:5432/agent_runtime","secret_environment":"STATE_DATABASE_DSN"},{"name":"telemetry","endpoint":"http://otel-collector:4318"},{"name":"temporal","endpoint":"temporal.agent-runtime.svc:7233","secret_environment":"TEMPORAL_AUTH_TOKEN"},{"name":"payload-blob","endpoint":"http://blob.agent-runtime.svc:9000","secret_environment":"ORCHESTRATION_PAYLOAD_BLOB_ACCESS_KEY"},{"name":"payload-blob-secret","endpoint":"http://blob.agent-runtime.svc:9000","secret_environment":"ORCHESTRATION_PAYLOAD_BLOB_SECRET_KEY"}],"worker":{"task_queue":"agent-runtime-session-v1","payload_blob_endpoint":"http://blob.agent-runtime.svc:9000","payload_blob_bucket":"agent-runtime-temporal-payload","payload_blob_prefix":"temporal-payload","payload_access_key_environment":"ORCHESTRATION_PAYLOAD_BLOB_ACCESS_KEY","payload_secret_key_environment":"ORCHESTRATION_PAYLOAD_BLOB_SECRET_KEY"}}`,
			"model":         `{"version":1,"role":"model","namespace":"agent-runtime","listen_address":"0.0.0.0:8082","dependencies":[{"name":"conversation","endpoint":"http://api.agent-runtime.svc:8080","secret_environment":"CONVERSATION_ACCESS_TOKEN"},{"name":"egress-proxy","endpoint":"http://egress-proxy.agent-runtime.svc:8088"},{"name":"model","endpoint":"https://model-provider.example.invalid","secret_environment":"MODEL_API_KEY"},{"name":"telemetry","endpoint":"http://otel-collector:4318"}]}`,
			"tool":          `{"version":1,"role":"tool","namespace":"agent-runtime","listen_address":"0.0.0.0:8083","dependencies":[{"name":"telemetry","endpoint":"http://otel-collector:4318"},{"name":"tool-broker","endpoint":"http://api.agent-runtime.svc:8080","secret_environment":"TOOL_BROKER_TOKEN"}]}`,
			"blob-role":     `{"version":1,"role":"blob","namespace":"agent-runtime","listen_address":"0.0.0.0:8084","dependencies":[{"name":"storage","endpoint":"http://blob.agent-runtime.svc:9000","secret_environment":"BLOB_STORAGE_CREDENTIAL"},{"name":"telemetry","endpoint":"http://otel-collector:4318"}]}`,
			"codec":         `{"version":1,"role":"codec","namespace":"agent-runtime","listen_address":"0.0.0.0:8085","dependencies":[{"name":"blob","endpoint":"http://blob.agent-runtime.svc:9000","secret_environment":"CODEC_BLOB_CREDENTIAL"},{"name":"telemetry","endpoint":"http://otel-collector:4318"}]}`,
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
		Expect(expectedRoleConfigs).To(HaveLen(5))
		apiConfig, found := environmentValue(api, "RUNTIME_API_CONFIG")
		Expect(found).To(BeTrue())
		Expect(apiConfig).To(Equal(`{"version":1,"listen_address":"0.0.0.0:8080","public_listen":true,"storage":{"mode":"postgres","database_dsn_environment":"STATE_DATABASE_DSN","content":{"endpoint":"https://blob.agent-runtime.svc:9000","access_key_environment":"RUNTIME_API_CONTENT_ACCESS_KEY","secret_key_environment":"RUNTIME_API_CONTENT_SECRET_KEY","bucket":"agent-runtime","ca_file":"/etc/agent-runtime/blob-ca.crt"}},"model_profiles":["balanced"],"max_request_bytes":4194304,"observability":{"identity_correlation_key_environment":"OBSERVABILITY_CORRELATION_KEY","otlp_grpc_endpoint":"otel-collector:4317"},"principals":[{"tenant":"public","principal":"admin","admin":true,"bearer_token_environment":"RUNTIME_API_ADMIN_TOKEN"},{"tenant":"public","principal":"developer","admin":false,"bearer_token_environment":"RUNTIME_API_DEVELOPER_TOKEN"}],"profile":"production"}`))

		controlService := findResource(resources, "sandbox-control-service")
		Expect(controlService.Kubernetes.Ports).To(ConsistOf(
			stack.Port{Name: "public-tls", Number: 8086, Protocol: "TCP"},
			stack.Port{Name: "host-mtls", Number: 9443, Protocol: "TCP"},
		))
		control := findResource(resources, "sandbox-control")
		Expect(control.Kubernetes.Command).To(ConsistOf("/sandbox-control"))
		Expect(control.Kubernetes.Arguments).To(ConsistOf("--config", "/etc/sandbox-control/config.json"))
		Expect(secretEnvironmentNames(control)).To(ConsistOf("SANDBOX_AUTHORIZATION", "SANDBOX_ASSERTION_KEY", "SANDBOX_CONTROL_SIGNING_KEY", "SANDBOX_STATE_DSN"))
		Expect(control.Kubernetes.ConfigMapMounts).To(ConsistOf(stack.ConfigMapMount{ConfigMap: "sandbox-control-config", Key: "config.json", Path: "/etc/sandbox-control/config.json"}))
		Expect(control.Kubernetes.SecretMounts).To(ConsistOf(
			stack.SecretMount{Secret: "sandbox-control-secret", Key: "SANDBOX_PUBLIC_TLS_CERT", Path: "/run/sandbox-control/public/tls.crt"},
			stack.SecretMount{Secret: "sandbox-control-secret", Key: "SANDBOX_PUBLIC_TLS_KEY", Path: "/run/sandbox-control/public/tls.key"},
			stack.SecretMount{Secret: "sandbox-control-secret", Key: "SANDBOX_HOST_TLS_CERT", Path: "/run/sandbox-control/host/tls.crt"},
			stack.SecretMount{Secret: "sandbox-control-secret", Key: "SANDBOX_HOST_TLS_KEY", Path: "/run/sandbox-control/host/tls.key"},
			stack.SecretMount{Secret: "sandbox-host-ca-secret", Key: "SANDBOX_HOST_CLIENT_CA", Path: "/run/sandbox-control/host-client-ca/ca.crt"},
		))
		controlConfig := findResource(resources, "sandbox-control-config")
		_, err = sandboxcontrolprocess.Parse(strings.NewReader(controlConfig.Kubernetes.Data["config.json"]))
		Expect(err).NotTo(HaveOccurred())

		host := findResource(resources, "sandbox-host")
		Expect(host.Kubernetes.Command).To(ConsistOf("/sandbox-host"))
		Expect(host.Kubernetes.Arguments).To(ConsistOf("--config", "/etc/sandbox-host/config.json", "--poll-interval", "1s", "--firecracker-control"))
		Expect(host.Kubernetes.Ports).To(BeEmpty())
		Expect(secretEnvironmentNames(host)).To(ConsistOf("SANDBOX_HOST_SIGNING_KEY"))
		Expect(host.Kubernetes.VolumeMounts).To(ConsistOf(stack.PersistentVolumeMount{Claim: "sandbox-host-journal", Path: "/var/lib/sandbox-host", ReadOnly: false}))
		Expect(host.Kubernetes.ConfigMapMounts).To(ConsistOf(stack.ConfigMapMount{ConfigMap: "sandbox-host-config", Key: "config.json", Path: "/etc/sandbox-host/config.json"}))
		Expect(host.Kubernetes.SecretMounts).To(ConsistOf(
			stack.SecretMount{Secret: "sandbox-host-identity-secret", Key: "SANDBOX_CONTROL_CA", Path: "/run/sandbox-host/control-ca.crt"},
			stack.SecretMount{Secret: "sandbox-host-identity-secret", Key: "SANDBOX_HOST_TLS_CERT", Path: "/run/sandbox-host/tls.crt"},
			stack.SecretMount{Secret: "sandbox-host-identity-secret", Key: "SANDBOX_HOST_TLS_KEY", Path: "/run/sandbox-host/tls.key"},
			stack.SecretMount{Secret: "sandbox-host-identity-secret", Key: "SANDBOX_CONTROL_TRUST", Path: "/run/sandbox-host/control-trust.json"},
		))
		hostConfig := findResource(resources, "sandbox-host-config")
		_, err = sandboxhostprocess.Parse(strings.NewReader(hostConfig.Kubernetes.Data["config.json"]))
		Expect(err).NotTo(HaveOccurred())
	})

	It("keeps every first-party runtime dependency inside the declared image build boundary", func() {
		dockerfile, err := os.ReadFile("../../deploy/production/Dockerfile")
		Expect(err).NotTo(HaveOccurred())
		Expect(string(dockerfile)).To(ContainSubstring("COPY sandbox ./sandbox"))

		tiltfile, err := os.ReadFile("../../Tiltfile")
		Expect(err).NotTo(HaveOccurred())
		Expect(string(tiltfile)).To(ContainSubstring("'sandbox'"))
		Expect(string(tiltfile)).To(ContainSubstring("resource_deps=['temporal', 'migration-runner', 'sandbox-host-bootstrap']"))

		ignore, err := os.ReadFile("../../.dockerignore")
		Expect(err).NotTo(HaveOccurred())
		Expect(string(ignore)).To(ContainSubstring("!sandbox/**"))
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

func normalizedProfile(resources []stack.Resource, namespace string, localFixture bool) []byte {
	normalized := make([]stack.Resource, 0, len(resources))
	for _, resource := range resources {
		if resource.ID == "sandbox-host-bootstrap" || resource.ID == "sandbox-host-bootstrap-config" || resource.ID == "sandbox-host-bootstrap-egress" {
			continue
		}
		resource.Dependencies = removeBootstrapDependencies(resource.Dependencies)
		normalized = append(normalized, resource)
	}
	for index := range normalized {
		resource := &normalized[index]
		resource.Retention = stack.Retention{}
		resource.BackupRestoreOwner = ""
		resource.DeleteBehavior = ""
		if resource.SecretReference != nil {
			resource.SecretReference.Provider = "<profile-secret-provider>"
			resource.SecretReference.Reference = "<profile-secret-reference>"
		}
		if localFixture && (resource.ID == "model-secret" || resource.ID == "tool-broker-secret") {
			resource.SecretReference.Keys = removeLocalDemoKeys(resource.SecretReference.Keys)
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
			if resource.ID == "blob" {
				// The local profile is deliberately HTTP-only. CI and production
				// enable MinIO's reviewed TLS certificate directory instead.
				resource.Kubernetes.Arguments = nil
			}
			if resource.ID == "blob-reconciler" {
				resource.Kubernetes.Arguments = nil
				resource.Kubernetes.Environment = removeEnvironment(resource.Kubernetes.Environment, "MC_CERTS_DIR")
			}
			if localFixture && (resource.ID == "model" || resource.ID == "tool") {
				resource.Kubernetes.SecretEnvironment = removeLocalDemoEnvironment(resource.Kubernetes.SecretEnvironment)
			}
			if localFixture && (resource.ID == "model-egress" || resource.ID == "tool-egress") {
				resource.Kubernetes.Network.AllowedEgress = removeLocalDemoEgress(resource.Kubernetes.Network.AllowedEgress)
			}
			for environmentIndex := range resource.Kubernetes.Environment {
				environment := &resource.Kubernetes.Environment[environmentIndex]
				if environment.Name == "BLOB_BUCKET" || environment.Name == "BLOB_TEMPORAL_BUCKET" {
					environment.Value = "<namespace>"
					continue
				}
				if environment.Name != "RUNTIME_ROLE_CONFIG" && environment.Name != "RUNTIME_API_CONFIG" {
					continue
				}
				var document any
				Expect(json.Unmarshal([]byte(environment.Value), &document)).To(Succeed())
				if object, ok := document.(map[string]any); ok {
					if environment.Name == "RUNTIME_API_CONFIG" {
						storage := object["storage"].(map[string]any)
						content := storage["content"].(map[string]any)
						delete(content, "ca_file")
						delete(object, "profile")
					}
					if localFixture {
						delete(object, "local_demo_worker")
						if environment.Name == "RUNTIME_API_CONFIG" {
							storage := object["storage"].(map[string]any)
							content := storage["content"].(map[string]any)
							content["endpoint"] = strings.Replace(content["endpoint"].(string), "http://", "https://", 1)
						}
					}
				}
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

func removeBootstrapDependencies(values []stack.ResourceID) []stack.ResourceID {
	filtered := make([]stack.ResourceID, 0, len(values))
	for _, value := range values {
		if value != "sandbox-host-bootstrap" && value != "sandbox-host-bootstrap-config" && value != "sandbox-host-bootstrap-egress" {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func removeEnvironment(values []stack.EnvironmentVariable, name string) []stack.EnvironmentVariable {
	filtered := make([]stack.EnvironmentVariable, 0, len(values))
	for _, value := range values {
		if value.Name != name {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func removeLocalDemoKeys(keys []string) []string { return removeLocalDemoStrings(keys) }
func removeLocalDemoEgress(ids []stack.ResourceID) []stack.ResourceID {
	values := make([]string, len(ids))
	for index := range ids {
		values[index] = string(ids[index])
	}
	values = removeLocalDemoStrings(values)
	result := make([]stack.ResourceID, len(values))
	for index := range values {
		result[index] = stack.ResourceID(values[index])
	}
	return result
}
func removeLocalDemoEnvironment(values []stack.SecretEnvironmentVariable) []stack.SecretEnvironmentVariable {
	result := values[:0]
	for _, value := range values {
		if !strings.HasPrefix(value.Name, "LOCAL_DEMO_") {
			result = append(result, value)
		}
	}
	return result
}
func removeLocalDemoStrings(values []string) []string {
	result := values[:0]
	for _, value := range values {
		if value != "LOCAL_DEMO_STATE_DSN" && value != "LOCAL_DEMO_CONTENT_ACCESS_KEY" && value != "LOCAL_DEMO_CONTENT_SECRET_KEY" && value != "blob" && value != "state" {
			result = append(result, value)
		}
	}
	return result
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
