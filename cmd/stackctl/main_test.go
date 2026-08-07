package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/stack"
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

var stackDocument = strings.ReplaceAll(`{"version":1,"name":"feature-a","profiles":{
"local":{"namespace":"ar-feature-a","prerequisites":[],"sandbox_quota_policy":POLICY,"resources":[{"id":"notifier-secret","kind":"secret_reference","owner":"release-operations","scope":"namespace","dependencies":[],"retention":{"policy":"external","days":0},"backup_restore_owner":"platform-operator","delete_behavior":"retain","external_controller":true,"secret_reference":{"provider":"kubernetes","reference":"ntfy-token","version":"v1"}}]},
"ci":{"namespace":"ar-ci-feature-a","prerequisites":[],"sandbox_quota_policy":POLICY,"resources":[{"id":"notifier-secret","kind":"secret_reference","owner":"release-operations","scope":"namespace","dependencies":[],"retention":{"policy":"external","days":0},"backup_restore_owner":"platform-operator","delete_behavior":"retain","external_controller":true,"secret_reference":{"provider":"kubernetes","reference":"ntfy-token","version":"v1"}}]},
"production":{"namespace":"feature-a","prerequisites":[],"sandbox_quota_policy":POLICY,"resources":[{"id":"notifier-secret","kind":"secret_reference","owner":"release-operations","scope":"namespace","dependencies":[],"retention":{"policy":"external","days":0},"backup_restore_owner":"platform-operator","delete_behavior":"retain","external_controller":true,"secret_reference":{"provider":"kubernetes","reference":"ntfy-token","version":"v1"}}]}}}`, "POLICY", testSandboxQuotaPolicy)

const testSandboxQuotaPolicy = `{"defaults":{"milli_cpu":500,"memory_bytes":536870912,"root_disk_bytes":4294967296,"tmpfs_bytes":268435456,"pids":128,"process_count":64,"open_files":1024,"inodes":100000,"files":50000,"lifetime_seconds":3600,"produced_output_bytes":67108864,"retained_output_bytes":16777216,"transfer_bytes":1073741824,"network_connections":64,"volume_bytes":10737418240,"snapshot_bytes":10737418240},"maximums":{"milli_cpu":4000,"memory_bytes":4294967296,"root_disk_bytes":34359738368,"tmpfs_bytes":2147483648,"pids":1024,"process_count":512,"open_files":8192,"inodes":1000000,"files":500000,"lifetime_seconds":86400,"produced_output_bytes":1073741824,"retained_output_bytes":268435456,"transfer_bytes":10737418240,"network_connections":1024,"volume_bytes":107374182400,"snapshot_bytes":107374182400}}`
