package stack_test

import (
	"context"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/stack"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type bootstrapCommand struct {
	arguments []string
	input     []byte
}

type bootstrapRunner struct {
	results  []stack.KubectlCommandResult
	commands []bootstrapCommand
}

func (runner *bootstrapRunner) Run(_ context.Context, program string, arguments []string, input []byte) (stack.KubectlCommandResult, error) {
	Expect(program).To(Equal("kubectl"))
	runner.commands = append(runner.commands, bootstrapCommand{arguments: append([]string(nil), arguments...), input: append([]byte(nil), input...)})
	result := runner.results[0]
	runner.results = runner.results[1:]
	return result, nil
}

var _ = Describe("Kubectl namespace bootstrap", func() {
	It("atomically creates only an absent rendered Namespace and re-observes its owned identity", func() {
		rendered := renderIdentityStack()
		manifests, err := stack.RenderKubernetes(rendered)
		Expect(err).NotTo(HaveOccurred())
		runner := &bootstrapRunner{results: []stack.KubectlCommandResult{
			{ExitCode: 0},
			{ExitCode: 0},
			{ExitCode: 0, Output: []byte(`{"metadata":{"uid":"uid-new","labels":{"app.kubernetes.io/part-of":"agent-runtime","agent-runtime.dev/stack":"feature-a","agent-runtime.dev/profile":"local"},"annotations":{"agent-runtime.dev/bootstrap-nonce-sha256":"sha256:nonce"}}}`)},
		}}
		adapter, err := stack.NewKubectlAdapter(runner)
		Expect(err).NotTo(HaveOccurred())
		target := stack.OperatorTarget{Kubeconfig: "/explicit/kubeconfig", Context: "disposable"}

		observation, err := adapter.BootstrapNamespace(context.Background(), target, manifests, "sha256:nonce")

		Expect(err).NotTo(HaveOccurred())
		Expect(observation.Namespace).To(Equal("ar-feature-a"))
		Expect(observation.UID).To(Equal(stack.ObservedUID("uid-new")))
		Expect(runner.commands).To(HaveLen(3))
		Expect(runner.commands[0].arguments).To(Equal([]string{"--kubeconfig", "/explicit/kubeconfig", "--context", "disposable", "get", "Namespace/ar-feature-a", "--ignore-not-found=true", "-o", "json"}))
		Expect(runner.commands[1].arguments).To(Equal([]string{"--kubeconfig", "/explicit/kubeconfig", "--context", "disposable", "create", "--field-manager=agent-runtime-stackctl", "-f", "-"}))
		Expect(string(runner.commands[1].input)).To(Equal("{\"apiVersion\":\"v1\",\"kind\":\"Namespace\",\"metadata\":{\"name\":\"ar-feature-a\",\"labels\":{\"agent-runtime.dev/profile\":\"local\",\"agent-runtime.dev/stack\":\"feature-a\",\"app.kubernetes.io/part-of\":\"agent-runtime\"},\"annotations\":{\"agent-runtime.dev/bootstrap-nonce-sha256\":\"sha256:nonce\"}}}\n"))
	})

	It("refuses a pre-existing namespace without applying or relabeling it", func() {
		rendered := renderIdentityStack()
		manifests, err := stack.RenderKubernetes(rendered)
		Expect(err).NotTo(HaveOccurred())
		runner := &bootstrapRunner{results: []stack.KubectlCommandResult{{ExitCode: 0, Output: []byte(`{"metadata":{"uid":"uid-foreign"}}`)}}}
		adapter, err := stack.NewKubectlAdapter(runner)
		Expect(err).NotTo(HaveOccurred())

		_, err = adapter.BootstrapNamespace(context.Background(), stack.OperatorTarget{Kubeconfig: "/explicit/kubeconfig", Context: "disposable"}, manifests, "sha256:nonce")

		Expect(err).To(MatchError(ContainSubstring("refuse pre-existing Namespace")))
		Expect(runner.commands).To(HaveLen(1))
	})

	It("refuses standalone apply before it can adopt a same-UID labelled namespace without the bootstrap capability", func() {
		rendered := renderIdentityStack()
		manifests, err := stack.RenderKubernetes(rendered)
		Expect(err).NotTo(HaveOccurred())
		authority := stack.BootstrapAuthority{Stack: "feature-a", Profile: stack.ProfileLocal, Namespace: "ar-feature-a", NamespaceUID: "uid-visible-on-foreign-namespace", RenderDigest: rendered.Digest(), Nonce: "private-bootstrap-nonce"}
		runner := &bootstrapRunner{results: []stack.KubectlCommandResult{{
			ExitCode: 0,
			Output:   []byte(`{"metadata":{"uid":"uid-visible-on-foreign-namespace","labels":{"app.kubernetes.io/part-of":"agent-runtime","agent-runtime.dev/stack":"feature-a","agent-runtime.dev/profile":"local"},"annotations":{"agent-runtime.dev/bootstrap-nonce-sha256":"sha256:copied-or-forged"}}}`),
		}}}
		adapter, err := stack.NewKubectlAdapter(runner)
		Expect(err).NotTo(HaveOccurred())

		_, err = adapter.Apply(context.Background(), stack.OperatorTarget{Kubeconfig: "/explicit/kubeconfig", Context: "disposable"}, manifests, authority)

		Expect(err).To(MatchError(ContainSubstring("Namespace is absent, replaced, or not owned")))
		Expect(runner.commands).To(HaveLen(1))
		Expect(runner.commands[0].arguments).To(ContainElements("get", "Namespace/ar-feature-a"))
		Expect(runner.commands[0].arguments).NotTo(ContainElement("apply"))
	})
})

func renderIdentityStack() stack.Rendered {
	spec, err := stack.Parse(strings.NewReader(validIdentityStack))
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	rendered, err := stack.Render(spec, stack.ProfileLocal)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return rendered
}
