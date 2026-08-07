package stack_test

import (
	"fmt"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/stack"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stack admission policy", func() {
	It("admits explicit bounded resources and rejects unsafe infrastructure defaults", func() {
		valid := []string{
			resourceStack(kubernetesResource("api", `{"api_version":"apps/v1","kind":"Deployment","name":"api","image":"registry.invalid/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","service_account":"runtime-api","ports":[],"compute":{"request_milli_cpu":100,"limit_milli_cpu":500,"request_memory_bytes":134217728,"limit_memory_bytes":268435456},"storage":[]}`)),
			resourceStack(kubernetesResource("deny-all", `{"api_version":"networking.k8s.io/v1","kind":"NetworkPolicy","name":"deny-all","network":{"default_deny":true,"allowed_egress":[]}}`)),
			resourceStack(kubernetesResource("runtime-role", `{"api_version":"rbac.authorization.k8s.io/v1","kind":"Role","name":"runtime-role","permissions":[{"api_group":"","resource":"configmaps","verbs":["get"]}]}`)),
			databaseStack(`{"database":"agent_runtime","schema":"runtime","connection_reference":"database-secret","migration_target":"postgres","migrations":[{"version":1,"upgrade_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","rollback_digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","upgrade_artifact":"migrations/v1.up.sql","rollback_artifact":"migrations/v1.down.sql"}]}`),
		}
		for _, input := range valid {
			_, err := stack.Parse(strings.NewReader(input))
			Expect(err).NotTo(HaveOccurred(), input)
		}

		invalid := []string{
			resourceStack(kubernetesResource("api", `{"api_version":"apps/v1","kind":"Deployment","name":"api","image":"registry.invalid/api:latest","service_account":"runtime-api","ports":[],"compute":{"request_milli_cpu":100,"limit_milli_cpu":500,"request_memory_bytes":134217728,"limit_memory_bytes":268435456},"storage":[]}`)),
			resourceStack(kubernetesResource("api", `{"api_version":"apps/v1","kind":"Deployment","name":"api","image":"registry.invalid/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","service_account":"runtime-api","ports":[],"compute":{"request_milli_cpu":100,"limit_milli_cpu":0,"request_memory_bytes":134217728,"limit_memory_bytes":268435456},"storage":[]}`)),
			resourceStack(kubernetesResource("deny-all", `{"api_version":"networking.k8s.io/v1","kind":"NetworkPolicy","name":"deny-all","network":{"default_deny":false,"allowed_egress":[]}}`)),
			resourceStack(kubernetesResource("runtime-role", `{"api_version":"rbac.authorization.k8s.io/v1","kind":"Role","name":"runtime-role","permissions":[{"api_group":"*","resource":"*","verbs":["*"]}]}`)),
			databaseStack(`{"database":"agent_runtime","schema":"runtime","connection_reference":"database-secret","migration_target":"postgres","migrations":[{"version":1,"upgrade_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","rollback_digest":"","upgrade_artifact":"migrations/v1.up.sql","rollback_artifact":"migrations/v1.down.sql"}]}`),
			strings.Replace(validIdentityStack, `"version":"v1"`, `"version":"v1","value":"secret"`, 1),
		}
		for _, input := range invalid {
			_, err := stack.Parse(strings.NewReader(input))
			Expect(err).To(HaveOccurred(), input)
		}
	})
})

func resourceStack(resource string) string {
	resources := `[` + resource + `]`
	return stackDocument(resources, resources, resources)
}

func kubernetesResource(id, payload string) string {
	return fmt.Sprintf(`{"id":%q,"kind":"kubernetes","owner":"platform-operator","scope":"namespace","dependencies":[],"retention":{"policy":"ephemeral","days":0},"backup_restore_owner":"none","delete_behavior":"delete","external_controller":false,"kubernetes":%s}`, id, payload)
}

func databaseResource(payload string) string {
	return fmt.Sprintf(`{"id":"database","kind":"database","owner":"database-operator","scope":"provider","dependencies":["database-secret","postgres"],"retention":{"policy":"persistent","days":30},"backup_restore_owner":"database-operator","delete_behavior":"tombstone","external_controller":false,"database":%s}`, payload)
}

func databaseStack(payload string) string {
	secret := strings.Replace(validIdentityResourceObject, `"id":"notifier-secret"`, `"id":"database-secret"`, 1)
	postgres := kubernetesResource("postgres", `{"api_version":"apps/v1","kind":"Deployment","name":"postgres","image":"registry.invalid/postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","service_account":"runtime-api","readiness":{"command":["true"],"initial_delay_seconds":0,"period_seconds":1,"failure_threshold":1},"ports":[],"compute":{"request_milli_cpu":100,"limit_milli_cpu":500,"request_memory_bytes":134217728,"limit_memory_bytes":268435456},"storage":[]}`)
	resources := `[` + secret + `,` + postgres + `,` + databaseResource(payload) + `]`
	return stackDocument(resources, resources, resources)
}
