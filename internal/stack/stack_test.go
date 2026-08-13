package stack_test

import (
	"strings"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/stack"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestStack(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Declarative Stack Suite")
}

var _ = Describe("Stack specification", func() {
	It("accepts one explicit versioned stack identity and refuses ambiguous input", func() {
		spec, err := stack.Parse(strings.NewReader(validIdentityStack))
		Expect(err).NotTo(HaveOccurred())
		Expect(spec.Name.String()).To(Equal("feature-a"))
		Expect(spec.Namespace(stack.ProfileLocal)).To(Equal("ar-feature-a"))
		quota, err := spec.SandboxQuotaPolicy(stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		Expect(quota.Defaults.MilliCPU).To(Equal(uint32(500)))
		Expect(quota.Maximums.SnapshotBytes).To(Equal(uint64(107374182400)))

		for _, input := range []string{
			strings.Replace(validIdentityStack, `"version":1`, `"version":0`, 1),
			strings.Replace(validIdentityStack, `"name":"feature-a"`, `"name":"Feature_A"`, 1),
			strings.Replace(validIdentityStack, `"namespace":"ar-feature-a"`, `"namespace":"default"`, 1),
			strings.Replace(validIdentityStack, `"milli_cpu":500`, `"milli_cpu":0`, 1),
			strings.Replace(validIdentityStack, `"profiles":`, `"instance":"second-identity","profiles":`, 1),
			strings.Replace(validIdentityStack, `"production"`, `"not-production"`, 1),
		} {
			_, err := stack.Parse(strings.NewReader(input))
			Expect(err).To(HaveOccurred(), input)
		}
	})

	It("rejects duplicate, dangling, cyclic, and profile-divergent resource topology", func() {
		for _, input := range []string{
			stackDocument(`[`+validIdentityResourceObject+`,`+validIdentityResourceObject+`]`, validIdentityResource, validIdentityResource),
			stackDocument(strings.Replace(validIdentityResource, `"dependencies":[]`, `"dependencies":["missing"]`, 1), validIdentityResource, validIdentityResource),
			stackDocument(strings.Replace(validIdentityResource, `"dependencies":[]`, `"dependencies":["notifier-secret"]`, 1), validIdentityResource, validIdentityResource),
			stackDocument(validIdentityResource, strings.Replace(validIdentityResource, `"id":"notifier-secret"`, `"id":"other-secret"`, 1), validIdentityResource),
		} {
			_, err := stack.Parse(strings.NewReader(input))
			Expect(err).To(HaveOccurred(), input)
		}
	})

	It("accepts only unique provider-supported orchestration declarations", func() {
		valid := stackDocument(validOrchestrationResource, validOrchestrationResource, validOrchestrationResource)
		_, err := stack.Parse(strings.NewReader(valid))
		Expect(err).NotTo(HaveOccurred())

		for _, input := range []string{
			strings.Replace(valid, `"type":"Keyword"`, `"type":"MadeUp"`, 1),
			strings.Replace(valid, `"name":"TenantKey"`, `"name":"9tenant"`, 1),
			strings.Replace(valid, `[{"name":"TenantKey","type":"Keyword"}]`, `[{"name":"TenantKey","type":"Keyword"},{"name":"TenantKey","type":"Text"}]`, 1),
			strings.Replace(valid, `[{"name":"retention-sweep","cron":"0 * * * *"}]`, `[{"name":"retention-sweep","cron":"0 * * * *"},{"name":"retention-sweep","cron":"0 0 * * *"}]`, 1),
			strings.Replace(valid, `"name":"retention-sweep"`, `"name":"RetentionSweep"`, 1),
		} {
			_, err := stack.Parse(strings.NewReader(input))
			Expect(err).To(HaveOccurred(), input)
		}
	})
})

func stackDocument(local, ci, production string) string {
	return `{
  "version":1,
  "name":"feature-a",
  "profiles":{
    "local":{"namespace":"ar-feature-a","prerequisites":[],"sandbox_quota_policy":` + sandboxQuotaPolicy + `,"resources":` + local + `},
    "ci":{"namespace":"ar-ci-feature-a","prerequisites":[],"sandbox_quota_policy":` + sandboxQuotaPolicy + `,"resources":` + ci + `},
    "production":{"namespace":"feature-a","prerequisites":[],"sandbox_quota_policy":` + sandboxQuotaPolicy + `,"resources":` + production + `}
  }
}`
}

var validIdentityStack = stackDocument(validIdentityResource, validIdentityResource, validIdentityResource)

const validIdentityResource = `[` + validIdentityResourceObject + `]`

const validIdentityResourceObject = `{
    "id":"notifier-secret",
    "kind":"secret_reference",
    "owner":"release-operations",
    "scope":"namespace",
    "dependencies":[],
    "retention":{"policy":"external","days":0},
    "backup_restore_owner":"platform-operator",
    "delete_behavior":"retain",
    "external_controller":true,
    "secret_reference":{"provider":"kubernetes","reference":"ntfy-token","version":"v1"}
  }`

const validOrchestrationResource = `[
  {
    "id":"temporal-namespace",
    "kind":"orchestration",
    "owner":"orchestration-operator",
    "scope":"namespace",
    "dependencies":[],
    "retention":{"policy":"persistent","days":30},
    "backup_restore_owner":"platform-operator",
    "delete_behavior":"retain",
    "external_controller":false,
    "orchestration":{
      "namespace":"feature-a",
      "task_queue_prefix":"feature-a-",
      "retention_days":30,
      "search_attributes":[{"name":"TenantKey","type":"Keyword"}],
      "schedules":[{"name":"retention-sweep","cron":"0 * * * *"}]
    }
  }
]`

const sandboxQuotaPolicy = `{
  "defaults":{"milli_cpu":500,"memory_bytes":536870912,"root_disk_bytes":4294967296,"tmpfs_bytes":268435456,"pids":128,"process_count":64,"open_files":1024,"inodes":100000,"files":50000,"lifetime_seconds":3600,"produced_output_bytes":67108864,"retained_output_bytes":16777216,"transfer_bytes":1073741824,"network_connections":64,"volume_bytes":10737418240,"snapshot_bytes":10737418240},
  "maximums":{"milli_cpu":4000,"memory_bytes":4294967296,"root_disk_bytes":34359738368,"tmpfs_bytes":2147483648,"pids":1024,"process_count":512,"open_files":8192,"inodes":1000000,"files":500000,"lifetime_seconds":86400,"produced_output_bytes":1073741824,"retained_output_bytes":268435456,"transfer_bytes":10737418240,"network_connections":1024,"volume_bytes":107374182400,"snapshot_bytes":107374182400}
}`
