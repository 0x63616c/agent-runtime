package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/stack"
	"github.com/cockroachdb/errors"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestStackctl(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Stack Operator CLI Suite")
}

var _ = Describe("render and check", func() {
	It("uses one --stack document and refuses modified rendered state", func() {
		directory := GinkgoT().TempDir()
		stackPath := filepath.Join(directory, "stack.json")
		Expect(os.WriteFile(stackPath, []byte(stackDocument), 0o600)).To(Succeed())
		var output bytes.Buffer
		Expect(run(context.Background(), []string{"render", "--stack-file", stackPath, "--profile", "local"}, &output)).To(Succeed())
		Expect(output.String()).To(ContainSubstring(`"agent-runtime.dev/stack": "feature-a"`))
		renderedPath := filepath.Join(directory, "rendered.json")
		Expect(os.WriteFile(renderedPath, output.Bytes(), 0o600)).To(Succeed())
		Expect(run(context.Background(), []string{"check", "--stack-file", stackPath, "--profile", "local", "--observed", renderedPath}, &bytes.Buffer{})).To(Succeed())

		tampered := bytes.Replace(output.Bytes(), []byte("ntfy-token"), []byte("other-token"), 1)
		Expect(os.WriteFile(renderedPath, tampered, 0o600)).To(Succeed())
		Expect(run(context.Background(), []string{"check", "--stack-file", stackPath, "--profile", "local", "--observed", renderedPath}, &bytes.Buffer{})).To(MatchError(ContainSubstring("digest")))

		output.Reset()
		probe := &cliProbe{context: "disposable"}
		Expect(runWithProbe(context.Background(), []string{"preflight", "--stack-file", stackPath, "--profile", "local", "--kubeconfig", "/explicit/kubeconfig", "--context", "disposable"}, &output, probe)).To(Succeed())
		Expect(output.String()).To(Equal("{\"results\":[]}\n"))
		Expect(probe.target).To(Equal(stack.OperatorTarget{Kubeconfig: "/explicit/kubeconfig", Context: "disposable"}))
	})

	It("requires the same explicit Kubernetes target shape for preflight as mutation", func() {
		directory := GinkgoT().TempDir()
		stackPath := filepath.Join(directory, "stack.json")
		Expect(os.WriteFile(stackPath, []byte(stackDocument), 0o600)).To(Succeed())
		for _, arguments := range [][]string{
			{"preflight", "--stack-file", stackPath, "--profile", "local"},
			{"preflight", "--stack-file", stackPath, "--profile", "local", "--kubeconfig", "relative", "--context", "disposable"},
			{"preflight", "--stack-file", stackPath, "--profile", "local", "--kubeconfig", "/explicit/kubeconfig"},
		} {
			Expect(run(context.Background(), arguments, &bytes.Buffer{})).To(MatchError(ContainSubstring("explicit absolute kubeconfig and context are required")))
		}
	})

	It("requires the full explicit audited target for namespace bootstrap", func() {
		_, _, _, _, _, err := parseOperatorArguments("bootstrap", []string{"--stack-file", "/stack.json", "--stack", "agent-runtime", "--profile", "local"})
		Expect(err).To(MatchError(ContainSubstring("absolute --bootstrap-capability-file are required")))

		request, stackPath, profile, rollbackPath, auditPath, err := parseOperatorArguments("bootstrap", []string{
			"--stack-file", "/stack.json", "--stack", "agent-runtime", "--profile", "local",
			"--kubeconfig", "/kubeconfig", "--context", "disposable", "--actor", "smoke-bootstrap",
			"--audit-file", "/audit.jsonl", "--migration-root", "/migrations", "--bootstrap-capability-file", "/bootstrap-capability.json",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(stackPath).To(Equal("/stack.json"))
		Expect(profile).To(Equal(stack.ProfileLocal))
		Expect(rollbackPath).To(BeEmpty())
		Expect(auditPath).To(Equal("/audit.jsonl"))
		Expect(request.Target).To(Equal(stack.OperatorTarget{Kubeconfig: "/kubeconfig", Context: "disposable", MigrationRoot: "/migrations"}))
	})

	It("requires one absolute bootstrap capability file for every operator command", func() {
		base := []string{
			"--stack-file", "/stack.json", "--stack", "agent-runtime", "--profile", "local",
			"--kubeconfig", "/kubeconfig", "--context", "disposable", "--actor", "smoke-bootstrap",
			"--audit-file", "/audit.jsonl", "--migration-root", "/migrations",
		}
		for _, command := range []string{"bootstrap", "apply", "reconcile", "teardown"} {
			_, _, _, _, _, err := parseOperatorArguments(command, base)
			Expect(err).To(MatchError(ContainSubstring("absolute --bootstrap-capability-file are required")))
		}

		request, _, _, _, _, err := parseOperatorArguments("apply", append(base, "--bootstrap-capability-file", "/bootstrap-capability.json"))
		Expect(err).NotTo(HaveOccurred())
		Expect(request.CapabilityFile).To(Equal("/bootstrap-capability.json"))
	})

	It("retains the bootstrap capability until namespace deletion succeeds on retry", func() {
		directory := GinkgoT().TempDir()
		stackPath := filepath.Join(directory, "stack.json")
		capabilityPath := filepath.Join(directory, "bootstrap-capability.json")
		auditPath := filepath.Join(directory, "audit.jsonl")
		migrationRoot := filepath.Join(directory, "migrations")
		Expect(os.WriteFile(stackPath, []byte(stackDocument), 0o600)).To(Succeed())
		Expect(os.Mkdir(migrationRoot, 0o700)).To(Succeed())

		rendered, err := loadAndRenderNamed(stackPath, "feature-a", stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		authority, err := stack.NewBootstrapAuthority(rendered, "uid-bootstrap")
		Expect(err).NotTo(HaveOccurred())
		Expect(stack.WriteBootstrapAuthority(capabilityPath, authority)).To(Succeed())
		initialCapability, err := os.ReadFile(capabilityPath)
		Expect(err).NotTo(HaveOccurred())

		operator := &retryingTeardownOperator{errors: []error{errors.New("wait for Namespace/ar-feature-a deletion: timeout")}}
		factory := func(string) (stackOperator, error) { return operator, nil }
		arguments := []string{
			"teardown", "--stack-file", stackPath, "--stack", "feature-a", "--profile", "local",
			"--kubeconfig", "/explicit/kubeconfig", "--context", "disposable", "--actor", "test-operator",
			"--audit-file", auditPath, "--migration-root", migrationRoot, "--bootstrap-capability-file", capabilityPath,
		}

		Expect(runWithProbeAndOperator(context.Background(), arguments, &bytes.Buffer{}, systemProbe{}, factory)).To(MatchError(ContainSubstring("wait for Namespace/ar-feature-a deletion: timeout")))
		retainedCapability, err := os.ReadFile(capabilityPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(retainedCapability).To(Equal(initialCapability))

		Expect(runWithProbeAndOperator(context.Background(), arguments, &bytes.Buffer{}, systemProbe{}, factory)).To(Succeed())
		_, err = os.Stat(capabilityPath)
		Expect(os.IsNotExist(err)).To(BeTrue())
		Expect(operator.teardowns).To(Equal(2))
	})

	It("emits canonical role configurations from Stack desired state without a second file source", func() {
		resources := []stack.Resource{
			{ID: "api", Kubernetes: &stack.KubernetesResource{Environment: []stack.EnvironmentVariable{{Name: "RUNTIME_ROLE_CONFIG", Value: `{"version":1,"role":"api","namespace":"runtime","listen_address":"127.0.0.1:8080","dependencies":[{"name":"state","endpoint":"http://state:8080"},{"name":"telemetry","endpoint":"http://telemetry:4318"}]}`}}}},
			{ID: "tool", Kubernetes: &stack.KubernetesResource{Environment: []stack.EnvironmentVariable{{Name: "RUNTIME_ROLE_CONFIG", Value: `{"version":1,"role":"tool","namespace":"runtime","listen_address":"127.0.0.1:8081","dependencies":[{"name":"sandbox-control","endpoint":"https://sandbox:8443","secret_environment":"SANDBOX_CONTROL_TOKEN"},{"name":"telemetry","endpoint":"http://telemetry:4318"},{"name":"tool-broker","endpoint":"http://broker:8080","secret_environment":"TOOL_BROKER_TOKEN"}]}`}}}},
		}

		configurations, err := extractRoleConfigurations(resources)
		Expect(err).NotTo(HaveOccurred())
		encoded, err := json.Marshal(configurations)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(encoded)).To(Equal(`{"api":{"version":1,"role":"api","namespace":"runtime","listen_address":"127.0.0.1:8080","dependencies":[{"name":"state","endpoint":"http://state:8080"},{"name":"telemetry","endpoint":"http://telemetry:4318"}]},"tool":{"version":1,"role":"tool","namespace":"runtime","listen_address":"127.0.0.1:8081","dependencies":[{"name":"sandbox-control","endpoint":"https://sandbox:8443","secret_environment":"SANDBOX_CONTROL_TOKEN"},{"name":"telemetry","endpoint":"http://telemetry:4318"},{"name":"tool-broker","endpoint":"http://broker:8080","secret_environment":"TOOL_BROKER_TOKEN"}]}}`))
	})
})

type cliProbe struct {
	context string
	target  stack.OperatorTarget
}

func (*cliProbe) Executable(context.Context, string) (bool, error) { return true, nil }
func (probe *cliProbe) KubernetesContext(_ context.Context, target stack.OperatorTarget) (string, error) {
	probe.target = target
	return probe.context, nil
}
func (*cliProbe) Architecture(context.Context) (string, error) { return runtime.GOARCH, nil }
func (*cliProbe) FreeDiskBytes(context.Context) (int64, error) { return 1 << 40, nil }

type retryingTeardownOperator struct {
	errors    []error
	teardowns int
}

func (*retryingTeardownOperator) Bootstrap(context.Context, stack.OperatorRequest, stack.Rendered) (stack.KubernetesNamespaceObservation, error) {
	return stack.KubernetesNamespaceObservation{}, nil
}

func (*retryingTeardownOperator) Apply(context.Context, stack.OperatorRequest, stack.Rendered) (stack.KubernetesObservation, error) {
	return stack.KubernetesObservation{}, nil
}

func (*retryingTeardownOperator) Observe(context.Context, stack.OperatorRequest, stack.Rendered) (stack.KubernetesObservation, error) {
	return stack.KubernetesObservation{}, nil
}

func (*retryingTeardownOperator) Diff(context.Context, stack.OperatorRequest, stack.Rendered) (stack.KubernetesDifference, error) {
	return stack.KubernetesDifference{}, nil
}

func (*retryingTeardownOperator) Reconcile(context.Context, stack.OperatorRequest, stack.Rendered) (stack.ReconcileResult, error) {
	return stack.ReconcileResult{}, nil
}

func (*retryingTeardownOperator) Rollback(context.Context, stack.OperatorRequest, stack.Rendered, stack.Rendered) (stack.KubernetesObservation, error) {
	return stack.KubernetesObservation{}, nil
}

func (operator *retryingTeardownOperator) Teardown(context.Context, stack.OperatorRequest, stack.Rendered) error {
	defer func() { operator.teardowns++ }()
	if operator.teardowns < len(operator.errors) {
		return operator.errors[operator.teardowns]
	}
	return nil
}

var stackDocument = strings.ReplaceAll(`{"version":1,"name":"feature-a","profiles":{
"local":{"namespace":"ar-feature-a","prerequisites":[],"sandbox_quota_policy":POLICY,"resources":[{"id":"notifier-secret","kind":"secret_reference","owner":"release-operations","scope":"namespace","dependencies":[],"retention":{"policy":"external","days":0},"backup_restore_owner":"platform-operator","delete_behavior":"retain","external_controller":true,"secret_reference":{"provider":"kubernetes","reference":"ntfy-token","version":"v1"}}]},
"ci":{"namespace":"ar-ci-feature-a","prerequisites":[],"sandbox_quota_policy":POLICY,"resources":[{"id":"notifier-secret","kind":"secret_reference","owner":"release-operations","scope":"namespace","dependencies":[],"retention":{"policy":"external","days":0},"backup_restore_owner":"platform-operator","delete_behavior":"retain","external_controller":true,"secret_reference":{"provider":"kubernetes","reference":"ntfy-token","version":"v1"}}]},
"production":{"namespace":"feature-a","prerequisites":[],"sandbox_quota_policy":POLICY,"resources":[{"id":"notifier-secret","kind":"secret_reference","owner":"release-operations","scope":"namespace","dependencies":[],"retention":{"policy":"external","days":0},"backup_restore_owner":"platform-operator","delete_behavior":"retain","external_controller":true,"secret_reference":{"provider":"kubernetes","reference":"ntfy-token","version":"v1"}}]}}}`, "POLICY", testSandboxQuotaPolicy)

const testSandboxQuotaPolicy = `{"defaults":{"milli_cpu":500,"memory_bytes":536870912,"root_disk_bytes":4294967296,"tmpfs_bytes":268435456,"pids":128,"process_count":64,"open_files":1024,"inodes":100000,"files":50000,"lifetime_seconds":3600,"produced_output_bytes":67108864,"retained_output_bytes":16777216,"transfer_bytes":1073741824,"network_connections":64,"volume_bytes":10737418240,"snapshot_bytes":10737418240},"maximums":{"milli_cpu":4000,"memory_bytes":4294967296,"root_disk_bytes":34359738368,"tmpfs_bytes":2147483648,"pids":1024,"process_count":512,"open_files":8192,"inodes":1000000,"files":500000,"lifetime_seconds":86400,"produced_output_bytes":1073741824,"retained_output_bytes":268435456,"transfer_bytes":10737418240,"network_connections":1024,"volume_bytes":107374182400,"snapshot_bytes":107374182400}}`
