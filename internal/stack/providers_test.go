package stack_test

import (
	"context"
	"fmt"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/stack"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type providerCommand struct{ arguments []string }

type fakeProviderRunner struct {
	commands []providerCommand
	extraKey bool
}

func (runner *fakeProviderRunner) Run(_ context.Context, _ string, arguments []string, _ []byte) (stack.KubectlCommandResult, error) {
	runner.commands = append(runner.commands, providerCommand{arguments: append([]string(nil), arguments...)})
	joined := strings.Join(arguments, " ")
	switch {
	case strings.Contains(joined, "get Secret/blob-creds"):
		data := `{"data":{"MINIO_ROOT_PASSWORD":"redacted","MINIO_ROOT_USER":"redacted"}}`
		if runner.extraKey {
			data = `{"data":{"EXCESS_AUTHORITY":"redacted","MINIO_ROOT_PASSWORD":"redacted","MINIO_ROOT_USER":"redacted"}}`
		}
		return stack.KubectlCommandResult{Output: []byte(data)}, nil
	case strings.Contains(joined, "get Secret/db-creds"):
		return stack.KubectlCommandResult{Output: []byte(`{"data":{"POSTGRES_PASSWORD":"redacted"}}`)}, nil
	case strings.Contains(joined, "psql"):
		return stack.KubectlCommandResult{Output: []byte("1\n")}, nil
	case strings.Contains(joined, "get Endpoints/telemetry"):
		return stack.KubectlCommandResult{Output: []byte(`{"subsets":[{"addresses":[{"ip":"10.0.0.1"}],"ports":[{"name":"otlp"}]}]}`)}, nil
	default:
		return stack.KubectlCommandResult{}, nil
	}
}

var _ = Describe("Declared provider reconciliation", func() {
	It("reconciles the exact blob prefix and verifies database, telemetry, and secret declarations", func() {
		rendered := renderProviderStack("delete")
		runner := &fakeProviderRunner{}
		adapter, err := stack.NewKubectlDeclaredProviderAdapter(runner)
		Expect(err).NotTo(HaveOccurred())

		ids, err := adapter.ReconcileDeclared(context.Background(), stack.OperatorTarget{Kubeconfig: "/explicit/kubeconfig", Context: "smoke"}, rendered)
		Expect(err).NotTo(HaveOccurred())
		Expect(ids).To(Equal([]stack.ResourceID{"blob-creds", "blob-prefix", "db-creds", "runtime-database", "telemetry-pipeline"}))
		Expect(joinedProviderCommands(runner.commands)).To(ContainSubstring("provider-blob smoke-bucket smoke/payloads http://blob:9000"))
		Expect(joinedProviderCommands(runner.commands)).NotTo(ContainSubstring("redacted"))
	})

	It("rejects undeclared secret keys instead of widening workload authority", func() {
		runner := &fakeProviderRunner{extraKey: true}
		adapter, err := stack.NewKubectlDeclaredProviderAdapter(runner)
		Expect(err).NotTo(HaveOccurred())

		_, err = adapter.ReconcileDeclared(context.Background(), stack.OperatorTarget{Kubeconfig: "/explicit/kubeconfig", Context: "smoke"}, renderProviderStack("delete"))
		Expect(err).To(MatchError(ContainSubstring("key inventory differs")))
	})

	It("removes only the declared blob prefix before its Kubernetes reconciler", func() {
		runner := &fakeProviderRunner{}
		adapter, err := stack.NewKubectlDeclaredProviderAdapter(runner)
		Expect(err).NotTo(HaveOccurred())

		ids, err := adapter.TeardownDeclared(context.Background(), stack.OperatorTarget{Kubeconfig: "/explicit/kubeconfig", Context: "smoke"}, renderProviderStack("delete"))
		Expect(err).NotTo(HaveOccurred())
		Expect(ids).To(Equal([]stack.ResourceID{"blob-creds", "blob-prefix", "db-creds", "runtime-database", "telemetry-pipeline"}))
		commands := joinedProviderCommands(runner.commands)
		Expect(commands).To(ContainSubstring("provider-blob smoke-bucket smoke/payloads http://blob:9000"))
		Expect(commands).To(ContainSubstring("mc rb --force"))
	})
})

func joinedProviderCommands(commands []providerCommand) string {
	var parts []string
	for _, command := range commands {
		parts = append(parts, strings.Join(command.arguments, " "))
	}
	return strings.Join(parts, "\n")
}

func renderProviderStack(deleteBehavior string) stack.Rendered {
	retention := `{"policy":"ephemeral","days":0}`
	if deleteBehavior == "retain" {
		retention = `{"policy":"persistent","days":30}`
	}
	resources := fmt.Sprintf(`[
{"id":"blob-creds","kind":"secret_reference","owner":"security-operator","scope":"namespace","dependencies":[],"retention":{"policy":"external","days":0},"backup_restore_owner":"none","delete_behavior":"retain","external_controller":true,"secret_reference":{"provider":"local-generated","reference":"blob-creds","version":"v1","keys":["MINIO_ROOT_PASSWORD","MINIO_ROOT_USER"]}},
{"id":"db-creds","kind":"secret_reference","owner":"security-operator","scope":"namespace","dependencies":[],"retention":{"policy":"external","days":0},"backup_restore_owner":"none","delete_behavior":"retain","external_controller":true,"secret_reference":{"provider":"local-generated","reference":"db-creds","version":"v1","keys":["POSTGRES_PASSWORD"]}},
{"id":"runtime-account","kind":"kubernetes","owner":"platform-operator","scope":"namespace","dependencies":[],"retention":%[1]s,"backup_restore_owner":"none","delete_behavior":"%[2]s","external_controller":false,"kubernetes":{"api_version":"v1","kind":"ServiceAccount","name":"runtime-account"}},
{"id":"blob","kind":"kubernetes","owner":"blob-operator","scope":"namespace","dependencies":["blob-creds","runtime-account"],"retention":%[1]s,"backup_restore_owner":"none","delete_behavior":"%[2]s","external_controller":false,"kubernetes":{"api_version":"apps/v1","kind":"Deployment","name":"blob","image":"registry.invalid/blob@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","service_account":"runtime-account","secret_environment":[{"name":"MINIO_ROOT_USER","secret":"blob-creds","key":"MINIO_ROOT_USER"},{"name":"MINIO_ROOT_PASSWORD","secret":"blob-creds","key":"MINIO_ROOT_PASSWORD"}],"ports":[{"name":"http","number":9000,"protocol":"TCP"}],"compute":{"request_milli_cpu":100,"limit_milli_cpu":500,"request_memory_bytes":134217728,"limit_memory_bytes":268435456},"storage":[]}},
{"id":"blob-service","kind":"kubernetes","owner":"blob-operator","scope":"namespace","dependencies":["blob"],"retention":%[1]s,"backup_restore_owner":"none","delete_behavior":"%[2]s","external_controller":false,"kubernetes":{"api_version":"v1","kind":"Service","name":"blob","selector":"blob","ports":[{"name":"http","number":9000,"protocol":"TCP"}]}},
{"id":"blob-reconciler","kind":"kubernetes","owner":"blob-operator","scope":"namespace","dependencies":["blob-creds","blob-service","runtime-account"],"retention":%[1]s,"backup_restore_owner":"none","delete_behavior":"%[2]s","external_controller":false,"kubernetes":{"api_version":"apps/v1","kind":"Deployment","name":"blob-reconciler","image":"registry.invalid/mc@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","service_account":"runtime-account","secret_environment":[{"name":"MINIO_ROOT_USER","secret":"blob-creds","key":"MINIO_ROOT_USER"},{"name":"MINIO_ROOT_PASSWORD","secret":"blob-creds","key":"MINIO_ROOT_PASSWORD"}],"ports":[],"compute":{"request_milli_cpu":25,"limit_milli_cpu":100,"request_memory_bytes":33554432,"limit_memory_bytes":134217728},"storage":[]}},
{"id":"blob-prefix","kind":"blob","owner":"blob-operator","scope":"namespace","dependencies":["blob-creds","blob-reconciler","blob-service"],"retention":%[1]s,"backup_restore_owner":"none","delete_behavior":"%[2]s","external_controller":false,"blob":{"bucket":"smoke-bucket","prefix":"smoke/payloads","endpoint_reference":"blob-service","endpoint_port_name":"http","credential_reference":"blob-creds","reconciler_reference":"blob-reconciler"}},
{"id":"state","kind":"kubernetes","owner":"database-operator","scope":"namespace","dependencies":["db-creds","runtime-account"],"retention":%[1]s,"backup_restore_owner":"none","delete_behavior":"%[2]s","external_controller":false,"kubernetes":{"api_version":"apps/v1","kind":"Deployment","name":"state","image":"registry.invalid/postgres@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","service_account":"runtime-account","secret_environment":[{"name":"POSTGRES_PASSWORD","secret":"db-creds","key":"POSTGRES_PASSWORD"}],"readiness":{"command":["pg_isready"],"initial_delay_seconds":1,"period_seconds":1,"failure_threshold":3},"ports":[],"compute":{"request_milli_cpu":100,"limit_milli_cpu":500,"request_memory_bytes":134217728,"limit_memory_bytes":268435456},"storage":[]}},
{"id":"runtime-database","kind":"database","owner":"database-operator","scope":"namespace","dependencies":["db-creds","state"],"retention":%[1]s,"backup_restore_owner":"none","delete_behavior":"%[2]s","external_controller":true,"database":{"database":"runtime","schema":"runtime","connection_reference":"db-creds","migration_target":"state","migrations":[]}},
{"id":"telemetry","kind":"kubernetes","owner":"telemetry-operator","scope":"namespace","dependencies":["runtime-account"],"retention":%[1]s,"backup_restore_owner":"none","delete_behavior":"%[2]s","external_controller":false,"kubernetes":{"api_version":"apps/v1","kind":"Deployment","name":"telemetry","image":"registry.invalid/telemetry@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","service_account":"runtime-account","ports":[{"name":"otlp","number":4318,"protocol":"TCP"}],"compute":{"request_milli_cpu":100,"limit_milli_cpu":500,"request_memory_bytes":134217728,"limit_memory_bytes":268435456},"storage":[]}},
{"id":"telemetry-service","kind":"kubernetes","owner":"telemetry-operator","scope":"namespace","dependencies":["telemetry"],"retention":%[1]s,"backup_restore_owner":"none","delete_behavior":"%[2]s","external_controller":false,"kubernetes":{"api_version":"v1","kind":"Service","name":"telemetry","selector":"telemetry","ports":[{"name":"otlp","number":4318,"protocol":"TCP"}]}},
{"id":"telemetry-pipeline","kind":"telemetry","owner":"telemetry-operator","scope":"namespace","dependencies":["telemetry-service"],"retention":%[1]s,"backup_restore_owner":"none","delete_behavior":"%[2]s","external_controller":false,"telemetry":{"collector_service":"telemetry-service","port_name":"otlp","retention_days":1}}
]`, retention, deleteBehavior)
	limits := `{"milli_cpu":500,"memory_bytes":536870912,"root_disk_bytes":1073741824,"tmpfs_bytes":268435456,"pids":128,"process_count":64,"open_files":1024,"inodes":100000,"files":50000,"lifetime_seconds":3600,"produced_output_bytes":67108864,"retained_output_bytes":16777216,"transfer_bytes":1073741824,"network_connections":64,"volume_bytes":10737418240,"snapshot_bytes":10737418240}`
	quota := `{"defaults":` + limits + `,"maximums":` + limits + `}`
	document := `{"version":1,"name":"feature-a","profiles":{"local":{"namespace":"ar-feature-a","prerequisites":[],"sandbox_quota_policy":` + quota + `,"resources":` + resources + `},"ci":{"namespace":"ar-ci-feature-a","prerequisites":[],"sandbox_quota_policy":` + quota + `,"resources":` + resources + `},"production":{"namespace":"feature-a","prerequisites":[],"sandbox_quota_policy":` + quota + `,"resources":` + resources + `}}}`
	spec, err := stack.Parse(strings.NewReader(document))
	Expect(err).NotTo(HaveOccurred())
	rendered, err := stack.Render(spec, stack.ProfileLocal)
	Expect(err).NotTo(HaveOccurred())
	return rendered
}
