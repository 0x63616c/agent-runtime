package stack_test

import (
	"context"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/stack"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type hostProbe struct {
	executables   map[string]bool
	context       string
	architecture  string
	freeDiskBytes int64
}

func (probe hostProbe) Executable(_ context.Context, name string) (bool, error) {
	return probe.executables[name], nil
}

func (probe hostProbe) KubernetesContext(context.Context) (string, error) { return probe.context, nil }
func (probe hostProbe) Architecture(context.Context) (string, error)      { return probe.architecture, nil }
func (probe hostProbe) FreeDiskBytes(context.Context) (int64, error)      { return probe.freeDiskBytes, nil }

var _ = Describe("Read-only prerequisite checks", func() {
	It("returns direct repairs without mutating host configuration", func() {
		declarations := `[
          {"name":"tilt","kind":"executable","expected":"present","minimum_bytes":0,"repair":"Install the pinned Tilt version from the operator guide."},
          {"name":"kubernetes-context","kind":"kubernetes_context","expected":"orbstack","minimum_bytes":0,"repair":"Start OrbStack Kubernetes; do not change the current context."},
          {"name":"host-architecture","kind":"architecture","expected":"arm64","minimum_bytes":0,"repair":"Use the declared arm64 local profile."},
          {"name":"free-disk","kind":"free_disk","expected":"","minimum_bytes":1073741824,"repair":"Free at least 1 GiB without deleting stack state."}
        ]`
		document := strings.Replace(validIdentityStack, `"prerequisites":[]`, `"prerequisites":`+declarations, 3)
		spec, err := stack.Parse(strings.NewReader(document))
		Expect(err).NotTo(HaveOccurred())

		report, err := stack.Preflight(context.Background(), spec, stack.ProfileLocal, hostProbe{
			executables: map[string]bool{"tilt": false}, context: "admin@prod", architecture: "arm64", freeDiskBytes: 512 << 20,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(report.Passed()).To(BeFalse())
		Expect(report.Results).To(ConsistOf(
			stack.PrerequisiteResult{Name: "tilt", Passed: false, Repair: "Install the pinned Tilt version from the operator guide."},
			stack.PrerequisiteResult{Name: "kubernetes-context", Passed: false, Repair: "Start OrbStack Kubernetes; do not change the current context."},
			stack.PrerequisiteResult{Name: "host-architecture", Passed: true},
			stack.PrerequisiteResult{Name: "free-disk", Passed: false, Repair: "Free at least 1 GiB without deleting stack state."},
		))
	})
})
