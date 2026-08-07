package roles_test

import (
	"context"
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
		Expect(err).To(MatchError(ContainSubstring("requires a secret_environment")))
	})

	It("does not permit an all role process to merge trust boundaries", func() {
		_, err := roles.Parse(strings.NewReader(strings.Replace(orchestrationConfig, `"role": "orchestration"`, `"role": "all"`, 1)))
		Expect(err).To(MatchError(ContainSubstring("role all is not a deployable trust boundary")))
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
})

type fakeSecrets map[string]string

func (secrets fakeSecrets) Lookup(_ context.Context, environment string) (string, bool, error) {
	value, ok := secrets[environment]
	return value, ok, nil
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
