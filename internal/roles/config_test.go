package roles_test

import (
	"context"
	"fmt"
	"maps"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/roles"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Operator role configuration", func() {
	It("admits one explicit role with exactly its trust-scoped dependencies", func() {
		config, err := roles.Parse(strings.NewReader(orchestrationConfig))
		Expect(err).NotTo(HaveOccurred())
		Expect(config.Role()).To(Equal(roles.RoleOrchestration))
		Expect(config.Namespace()).To(Equal("agent-runtime"))

		plan, err := roles.Prepare(context.Background(), config, fakeSecrets{
			"TEMPORAL_AUTH_TOKEN": "temporal-secret",
			"STATE_DATABASE_DSN":  "postgres-secret",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(plan.Role()).To(Equal(roles.RoleOrchestration))
		Expect(plan.SecretEnvironmentNames()).To(ConsistOf("STATE_DATABASE_DSN", "TEMPORAL_AUTH_TOKEN"))
		Expect(plan.String()).NotTo(ContainSubstring("temporal-secret"))
		Expect(plan.String()).NotTo(ContainSubstring("postgres-secret"))
	})

	It("rejects a role with a foreign credential or a missing required credential", func() {
		foreignModelSecret := strings.Replace(
			orchestrationConfig,
			`{"name":"state","endpoint":"postgres://state.agent-runtime.svc:5432/agent_runtime","secret_environment":"STATE_DATABASE_DSN"}`,
			`{"name":"state","endpoint":"postgres://state.agent-runtime.svc:5432/agent_runtime","secret_environment":"STATE_DATABASE_DSN"},{"name":"model","endpoint":"https://models.example.invalid","secret_environment":"MODEL_API_KEY"}`,
			1,
		)
		_, err := roles.Parse(strings.NewReader(foreignModelSecret))
		Expect(err).To(MatchError(ContainSubstring("does not allow dependency model")))

		missingSecret := strings.Replace(orchestrationConfig, `"secret_environment":"TEMPORAL_AUTH_TOKEN"`, `"secret_environment":""`, 1)
		_, err = roles.Parse(strings.NewReader(missingSecret))
		Expect(err).To(MatchError(ContainSubstring("requires credential environment TEMPORAL_AUTH_TOKEN")))
	})

	It("does not permit an all role process to merge trust boundaries", func() {
		_, err := roles.Parse(strings.NewReader(strings.Replace(orchestrationConfig, `"role": "orchestration"`, `"role": "all"`, 1)))
		Expect(err).To(MatchError(ContainSubstring("role all is not a deployable trust boundary")))
	})

	It("admits only the isolated codec-enabled worker capability", func() {
		config, err := roles.Parse(strings.NewReader(orchestrationCodecConfig))
		Expect(err).NotTo(HaveOccurred())
		_, contentDeclared := config.DependencyEndpoint("runtime-content")
		Expect(contentDeclared).To(BeFalse())
		worker := config.Worker()
		Expect(worker).NotTo(BeNil())
		Expect(worker.PayloadBlobBucket).To(Equal("temporal-payload"))

		_, err = roles.Parse(strings.NewReader(strings.Replace(orchestrationCodecConfig, `"payload_blob_prefix":"temporal-payload"`, `"payload_blob_prefix":"../runtime-content"`, 1)))
		Expect(err).To(MatchError(ContainSubstring("worker capability is incomplete")))
		_, err = roles.Parse(strings.NewReader(strings.Replace(orchestrationCodecConfig, `"payload_access_key_environment":"ORCHESTRATION_PAYLOAD_BLOB_ACCESS_KEY"`, `"payload_access_key_environment":"BLOB_STORAGE_CREDENTIAL"`, 1)))
		Expect(err).To(MatchError(ContainSubstring("worker capability is incomplete")))
	})

	It("refuses application configuration and reports missing secrets without their values", func() {
		_, err := roles.Parse(strings.NewReader(strings.Replace(orchestrationConfig, `"role": "orchestration",`, `"role": "orchestration", "agents":[{"name":"not-an-operator-setting"}],`, 1)))
		Expect(err).To(HaveOccurred())

		config, err := roles.Parse(strings.NewReader(orchestrationConfig))
		Expect(err).NotTo(HaveOccurred())
		_, err = roles.Prepare(context.Background(), config, fakeSecrets{"TEMPORAL_AUTH_TOKEN": "present"})
		Expect(err).To(MatchError(ContainSubstring("STATE_DATABASE_DSN")))
		Expect(err).NotTo(MatchError(ContainSubstring("present")))
	})

	It("rejects every known credential that is not entitled to the selected role", func() {
		for _, fixture := range roleFixtures {
			config, err := roles.Parse(strings.NewReader(fixture.configuration))
			Expect(err).NotTo(HaveOccurred(), fixture.role)

			allowed := fakeSecrets{}
			for _, environment := range fixture.allowed {
				allowed[environment] = "synthetic-" + environment
			}
			plan, err := roles.Prepare(context.Background(), config, allowed)
			Expect(err).NotTo(HaveOccurred(), fixture.role)
			Expect(plan.SecretEnvironmentNames()).To(ConsistOf(fixture.allowed), fixture.role)

			for _, foreign := range roles.KnownCredentialEnvironmentNames() {
				if _, entitled := allowed[foreign]; entitled {
					continue
				}
				withForeign := maps.Clone(allowed)
				withForeign[foreign] = "synthetic-foreign-" + foreign
				_, err = roles.Prepare(context.Background(), config, withForeign)
				Expect(err).To(MatchError(ContainSubstring("not entitled to role "+string(fixture.role))), string(fixture.role)+" with "+foreign)
				Expect(err).NotTo(MatchError(ContainSubstring(withForeign[foreign])), string(fixture.role)+" with "+foreign)
			}
		}
	})
})

type fakeSecrets map[string]string

func (secrets fakeSecrets) Lookup(_ context.Context, environment string) (string, bool, error) {
	value, ok := secrets[environment]
	return value, ok, nil
}

func (secrets fakeSecrets) KnownCredentialEnvironmentNames(_ context.Context) ([]string, error) {
	environments := make([]string, 0, len(secrets))
	for environment, value := range secrets {
		if value != "" {
			environments = append(environments, environment)
		}
	}
	return environments, nil
}

type roleFixture struct {
	role          roles.Role
	configuration string
	allowed       []string
}

var roleFixtures = []roleFixture{
	{roles.RoleAPI, roleConfig(roles.RoleAPI, 8080, `[{"name":"state","endpoint":"http://state:8080"},{"name":"telemetry","endpoint":"http://telemetry:4318"}]`), nil},
	{roles.RoleOrchestration, orchestrationConfig, []string{"STATE_DATABASE_DSN", "TEMPORAL_AUTH_TOKEN"}},
	{roles.RoleOrchestrationCodec, orchestrationCodecConfig, []string{"ORCHESTRATION_PAYLOAD_BLOB_ACCESS_KEY", "ORCHESTRATION_PAYLOAD_BLOB_SECRET_KEY", "STATE_DATABASE_DSN", "TEMPORAL_AUTH_TOKEN"}},
	{roles.RoleModel, roleConfig(roles.RoleModel, 8082, `[{"name":"conversation","endpoint":"http://api:8080","secret_environment":"CONVERSATION_ACCESS_TOKEN"},{"name":"egress-proxy","endpoint":"http://egress-proxy:8088"},{"name":"model","endpoint":"https://model.example.invalid","secret_environment":"MODEL_API_KEY"},{"name":"telemetry","endpoint":"http://telemetry:4318"}]`), []string{"CONVERSATION_ACCESS_TOKEN", "MODEL_API_KEY"}},
	{roles.RoleTool, roleConfig(roles.RoleTool, 8083, `[{"name":"sandbox-control","endpoint":"https://sandbox-control:8443","secret_environment":"SANDBOX_CONTROL_TOKEN"},{"name":"telemetry","endpoint":"http://telemetry:4318"},{"name":"tool-broker","endpoint":"http://api:8080","secret_environment":"TOOL_BROKER_TOKEN"}]`), []string{"SANDBOX_CONTROL_TOKEN", "TOOL_BROKER_TOKEN"}},
	{roles.RoleBlob, roleConfig(roles.RoleBlob, 8084, `[{"name":"storage","endpoint":"http://blob:9000","secret_environment":"BLOB_STORAGE_CREDENTIAL"},{"name":"telemetry","endpoint":"http://telemetry:4318"}]`), []string{"BLOB_STORAGE_CREDENTIAL"}},
	{roles.RoleCodec, roleConfig(roles.RoleCodec, 8085, `[{"name":"blob","endpoint":"http://blob:9000","secret_environment":"CODEC_BLOB_CREDENTIAL"},{"name":"telemetry","endpoint":"http://telemetry:4318"}]`), []string{"CODEC_BLOB_CREDENTIAL"}},
	{roles.RoleSandboxControl, roleConfig(roles.RoleSandboxControl, 8086, `[{"name":"host-ca","endpoint":"https://host-ca.example.invalid","secret_environment":"SANDBOX_HOST_CA"},{"name":"sandbox-state","endpoint":"postgres://state:5432/sandbox","secret_environment":"SANDBOX_STATE_DSN"},{"name":"telemetry","endpoint":"http://telemetry:4318"}]`), []string{"SANDBOX_HOST_CA", "SANDBOX_STATE_DSN"}},
	{roles.RoleSandboxHost, roleConfig(roles.RoleSandboxHost, 8087, `[{"name":"host-identity","endpoint":"https://host.example.invalid","secret_environment":"SANDBOX_HOST_IDENTITY"},{"name":"sandbox-control","endpoint":"https://sandbox-control:8443","secret_environment":"SANDBOX_CONTROL_TOKEN"},{"name":"telemetry","endpoint":"http://telemetry:4318"}]`), []string{"SANDBOX_HOST_IDENTITY", "SANDBOX_CONTROL_TOKEN"}},
}

func roleConfig(role roles.Role, port int, dependencies string) string {
	return fmt.Sprintf(`{"version":1,"role":%q,"namespace":"agent-runtime","listen_address":"127.0.0.1:%d","dependencies":%s}`, role, port, dependencies)
}

const orchestrationConfig = `{
  "version": 1,
  "role": "orchestration",
  "namespace": "agent-runtime",
  "listen_address": "127.0.0.1:8081",
  "dependencies": [
    {"name":"state","endpoint":"postgres://state.agent-runtime.svc:5432/agent_runtime","secret_environment":"STATE_DATABASE_DSN"},
    {"name":"telemetry","endpoint":"http://telemetry.agent-runtime.svc:4318"},
    {"name":"temporal","endpoint":"temporal.agent-runtime.svc:7233","secret_environment":"TEMPORAL_AUTH_TOKEN"}
  ]
}`

const orchestrationCodecConfig = `{
  "version": 1,
  "role": "orchestration-codec",
  "namespace": "agent-runtime",
  "listen_address": "127.0.0.1:8088",
  "dependencies": [
    {"name":"state","endpoint":"postgres://state.agent-runtime.svc:5432/agent_runtime","secret_environment":"STATE_DATABASE_DSN"},
    {"name":"telemetry","endpoint":"http://telemetry.agent-runtime.svc:4318"},
    {"name":"temporal","endpoint":"temporal.agent-runtime.svc:7233","secret_environment":"TEMPORAL_AUTH_TOKEN"},
    {"name":"payload-blob","endpoint":"http://temporal-payload.minio.svc:9000","secret_environment":"ORCHESTRATION_PAYLOAD_BLOB_ACCESS_KEY"},
    {"name":"payload-blob-secret","endpoint":"http://temporal-payload.minio.svc:9000","secret_environment":"ORCHESTRATION_PAYLOAD_BLOB_SECRET_KEY"}
  ],
  "worker": {
    "task_queue":"agent-runtime-session-v1",
    "payload_blob_endpoint":"http://temporal-payload.minio.svc:9000",
    "payload_blob_bucket":"temporal-payload",
    "payload_blob_prefix":"temporal-payload",
    "payload_access_key_environment":"ORCHESTRATION_PAYLOAD_BLOB_ACCESS_KEY",
    "payload_secret_key_environment":"ORCHESTRATION_PAYLOAD_BLOB_SECRET_KEY"
  }
}`
