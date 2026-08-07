package stack_test

import (
	"context"
	"os"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/stack"
	"github.com/cockroachdb/errors"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type temporalRunnerResult struct {
	result stack.KubectlCommandResult
	err    error
}

type fakeTemporalRunner struct {
	results   []temporalRunnerResult
	arguments [][]string
}

func (runner *fakeTemporalRunner) Run(ctx context.Context, program string, arguments []string, _ []byte) (stack.KubectlCommandResult, error) {
	if err := ctx.Err(); err != nil {
		return stack.KubectlCommandResult{}, err
	}
	Expect(program).To(Equal("kubectl"))
	if containsArguments(arguments, "get", "Namespace/agent-runtime") {
		return stack.KubectlCommandResult{Output: []byte(`{"metadata":{"uid":"uid-bootstrap","labels":{"app.kubernetes.io/part-of":"agent-runtime","agent-runtime.dev/stack":"agent-runtime","agent-runtime.dev/profile":"production"},"annotations":{"agent-runtime.dev/bootstrap-nonce-sha256":"sha256:ed04c4e9ea6c49cf9ceb39098787c5b9842524f96b07ef45305476a11caec9b4"}}}`)}, nil
	}
	runner.arguments = append(runner.arguments, append([]string(nil), arguments...))
	if containsArguments(arguments, "rollout", "status") {
		return stack.KubectlCommandResult{ExitCode: 0}, nil
	}
	if len(runner.results) == 0 {
		return stack.KubectlCommandResult{}, errors.New("unexpected Temporal CLI invocation")
	}
	result := runner.results[0]
	runner.results = runner.results[1:]
	return result.result, result.err
}

func containsArguments(arguments []string, expected ...string) bool {
	for _, value := range expected {
		found := false
		for _, argument := range arguments {
			if argument == value {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

const matchingTemporalNamespace = `{"config":{"workflowExecutionRetentionTtl":"2592000s"}}`

func productionRenderedStack() stack.Rendered {
	file, err := os.Open("../../deploy/production/stack.json")
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(file.Close)
	spec, err := stack.Parse(file)
	Expect(err).NotTo(HaveOccurred())
	rendered, err := stack.Render(spec, stack.ProfileProduction)
	Expect(err).NotTo(HaveOccurred())
	return rendered
}

func orchestrationAuthority(rendered stack.Rendered) stack.BootstrapAuthority {
	return stack.BootstrapAuthority{Stack: "agent-runtime", Profile: stack.ProfileProduction, Namespace: "agent-runtime", NamespaceUID: "uid-bootstrap", RenderDigest: rendered.Digest(), Nonce: "test-nonce"}
}

var _ = Describe("Temporal orchestration adapter", func() {
	target := stack.OperatorTarget{Kubeconfig: "/explicit/kubeconfig", Context: "disposable"}

	It("leaves an existing declared namespace unchanged", func() {
		runner := &fakeTemporalRunner{results: []temporalRunnerResult{{result: stack.KubectlCommandResult{ExitCode: 0, Output: []byte(matchingTemporalNamespace)}}}}
		adapter, err := stack.NewTemporalCLIAdapter(runner)
		Expect(err).NotTo(HaveOccurred())

		ids, err := adapter.ReconcileOrchestration(context.Background(), target, productionRenderedStack(), orchestrationAuthority(productionRenderedStack()))
		Expect(err).NotTo(HaveOccurred())
		Expect(ids).To(Equal([]stack.ResourceID{"temporal-namespace"}))
		Expect(runner.arguments).To(HaveLen(2))
		Expect(runner.arguments[0]).To(ContainElements("rollout", "status"))
		Expect(runner.arguments[1]).To(ContainElements("describe", "agent-runtime", "--output", "json"))
	})

	It("creates only after Temporal positively reports namespace not found", func() {
		runner := &fakeTemporalRunner{results: []temporalRunnerResult{
			{result: stack.KubectlCommandResult{ExitCode: 1, Output: []byte("Namespace agent-runtime is not found.")}},
			{result: stack.KubectlCommandResult{ExitCode: 0}},
		}}
		adapter, err := stack.NewTemporalCLIAdapter(runner)
		Expect(err).NotTo(HaveOccurred())

		_, err = adapter.ReconcileOrchestration(context.Background(), target, productionRenderedStack(), orchestrationAuthority(productionRenderedStack()))
		Expect(err).NotTo(HaveOccurred())
		Expect(runner.arguments).To(HaveLen(3))
		Expect(runner.arguments[2]).To(ContainElements("create", "--retention", "720h"))
	})

	It("retries transport failures without misclassifying them as absence", func() {
		runner := &fakeTemporalRunner{results: []temporalRunnerResult{
			{result: stack.KubectlCommandResult{ExitCode: 1, Output: []byte("service unavailable")}},
			{result: stack.KubectlCommandResult{ExitCode: 1, Output: []byte("service unavailable")}},
			{result: stack.KubectlCommandResult{ExitCode: 1, Output: []byte("service unavailable")}},
		}}
		adapter, err := stack.NewTemporalCLIAdapter(runner)
		Expect(err).NotTo(HaveOccurred())

		_, err = adapter.ReconcileOrchestration(context.Background(), target, productionRenderedStack(), orchestrationAuthority(productionRenderedStack()))
		Expect(err).To(MatchError(ContainSubstring("after 3 attempts: service unavailable")))
		Expect(runner.arguments).To(HaveLen(4))
		for _, arguments := range runner.arguments[1:] {
			Expect(arguments).To(ContainElement("describe"))
			Expect(arguments).NotTo(ContainElement("create"))
		}
	})

	It("redacts unsafe CLI output from create failures", func() {
		runner := &fakeTemporalRunner{results: []temporalRunnerResult{
			{result: stack.KubectlCommandResult{ExitCode: 1, Output: []byte("Namespace agent-runtime is not found.")}},
			{result: stack.KubectlCommandResult{ExitCode: 1, Output: []byte("password fixture-password rejected")}},
		}}
		adapter, err := stack.NewTemporalCLIAdapter(runner)
		Expect(err).NotTo(HaveOccurred())

		_, err = adapter.ReconcileOrchestration(context.Background(), target, productionRenderedStack(), orchestrationAuthority(productionRenderedStack()))
		Expect(err).To(MatchError(ContainSubstring("output redacted")))
		Expect(err.Error()).NotTo(ContainSubstring("fixture-password"))
	})

	It("honors cancellation before invoking the command boundary", func() {
		runner := &fakeTemporalRunner{}
		adapter, err := stack.NewTemporalCLIAdapter(runner)
		Expect(err).NotTo(HaveOccurred())
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err = adapter.ReconcileOrchestration(ctx, target, productionRenderedStack(), orchestrationAuthority(productionRenderedStack()))
		Expect(errors.Is(err, context.Canceled)).To(BeTrue())
		Expect(runner.arguments).To(BeEmpty())
	})

	It("accepts an already-created namespace during a create race", func() {
		runner := &fakeTemporalRunner{results: []temporalRunnerResult{
			{result: stack.KubectlCommandResult{ExitCode: 1, Output: []byte("Namespace agent-runtime is not found.")}},
			{result: stack.KubectlCommandResult{ExitCode: 1, Output: []byte("Namespace agent-runtime already exists.")}},
			{result: stack.KubectlCommandResult{ExitCode: 0}},
		}}
		adapter, err := stack.NewTemporalCLIAdapter(runner)
		Expect(err).NotTo(HaveOccurred())

		ids, err := adapter.ReconcileOrchestration(context.Background(), target, productionRenderedStack(), orchestrationAuthority(productionRenderedStack()))
		Expect(err).NotTo(HaveOccurred())
		Expect(ids).To(Equal([]stack.ResourceID{"temporal-namespace"}))
		Expect(runner.arguments[3]).To(ContainElements("update", "--retention", "720h"))
	})

	It("updates retention when the observed structured value drifts", func() {
		runner := &fakeTemporalRunner{results: []temporalRunnerResult{
			{result: stack.KubectlCommandResult{ExitCode: 0, Output: []byte(`{"config":{"workflowExecutionRetentionTtl":"86400s"}}`)}},
			{result: stack.KubectlCommandResult{ExitCode: 0}},
		}}
		adapter, err := stack.NewTemporalCLIAdapter(runner)
		Expect(err).NotTo(HaveOccurred())

		_, err = adapter.ReconcileOrchestration(context.Background(), target, productionRenderedStack(), orchestrationAuthority(productionRenderedStack()))
		Expect(err).NotTo(HaveOccurred())
		Expect(runner.arguments).To(HaveLen(3))
		Expect(runner.arguments[2]).To(ContainElements("update", "--retention", "720h"))
	})

	It("rejects malformed structured namespace observations", func() {
		runner := &fakeTemporalRunner{results: []temporalRunnerResult{{result: stack.KubectlCommandResult{ExitCode: 0, Output: []byte(`not-json`)}}}}
		adapter, err := stack.NewTemporalCLIAdapter(runner)
		Expect(err).NotTo(HaveOccurred())

		_, err = adapter.ReconcileOrchestration(context.Background(), target, productionRenderedStack(), orchestrationAuthority(productionRenderedStack()))
		Expect(err).To(MatchError(ContainSubstring("decode declared Temporal namespace description")))
	})

	It("does not classify unrelated not-found output as a missing namespace", func() {
		runner := &fakeTemporalRunner{results: []temporalRunnerResult{
			{result: stack.KubectlCommandResult{ExitCode: 1, Output: []byte("deployment temporal not found")}},
			{result: stack.KubectlCommandResult{ExitCode: 1, Output: []byte("deployment temporal not found")}},
			{result: stack.KubectlCommandResult{ExitCode: 1, Output: []byte("deployment temporal not found")}},
		}}
		adapter, err := stack.NewTemporalCLIAdapter(runner)
		Expect(err).NotTo(HaveOccurred())

		_, err = adapter.ReconcileOrchestration(context.Background(), target, productionRenderedStack(), orchestrationAuthority(productionRenderedStack()))
		Expect(err).To(HaveOccurred())
		Expect(strings.ToLower(err.Error())).To(ContainSubstring("deployment temporal not found"))
		Expect(runner.arguments).To(HaveLen(4))
	})
})
