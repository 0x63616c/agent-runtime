package stack_test

import (
	"context"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/stack"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type recordedAudit struct{ records []stack.OperatorAuditRecord }

func (audit *recordedAudit) Append(_ context.Context, record stack.OperatorAuditRecord) error {
	audit.records = append(audit.records, record)
	return nil
}

type fakeKubernetesOperator struct {
	changes   []stack.Change
	applies   int
	observes  int
	teardowns int
}

func (operator *fakeKubernetesOperator) Apply(_ context.Context, _ stack.OperatorTarget, _ stack.KubernetesManifests) (stack.KubernetesObservation, error) {
	operator.applies++
	return stack.KubernetesObservation{ObjectIDs: []stack.ResourceID{"api"}}, nil
}

func (operator *fakeKubernetesOperator) Observe(_ context.Context, _ stack.OperatorTarget, _ stack.KubernetesManifests) (stack.KubernetesObservation, error) {
	operator.observes++
	return stack.KubernetesObservation{ObjectIDs: []stack.ResourceID{"api"}}, nil
}

func (operator *fakeKubernetesOperator) Diff(_ context.Context, _ stack.OperatorTarget, _ stack.KubernetesManifests) (stack.KubernetesDifference, error) {
	return stack.KubernetesDifference{Changes: operator.changes}, nil
}

func (operator *fakeKubernetesOperator) Teardown(_ context.Context, _ stack.OperatorTarget, _ stack.Rendered, _ stack.KubernetesManifests) error {
	operator.teardowns++
	return nil
}

var _ = Describe("Audited Kubernetes operator", func() {
	It("reconciles only declared drift and retains the actor, target, digest, and bounded affected resources", func() {
		spec, err := stack.Parse(strings.NewReader(stackDocument(kubernetesManifestResources, kubernetesManifestResources, kubernetesManifestResources)))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileCI)
		Expect(err).NotTo(HaveOccurred())
		adapter := &fakeKubernetesOperator{changes: []stack.Change{{Resource: "api", Kind: stack.ChangeModified}}}
		audit := &recordedAudit{}
		operator, err := stack.NewKubernetesOperator(adapter, audit)
		Expect(err).NotTo(HaveOccurred())

		result, err := operator.Reconcile(context.Background(), stack.OperatorRequest{Actor: "platform-operator", Target: stack.OperatorTarget{Kubeconfig: "/explicit/kubeconfig", Context: "disposable-ci"}}, rendered)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Applied).To(BeTrue())
		Expect(adapter.applies).To(Equal(1))
		Expect(audit.records).To(HaveLen(1))
		Expect(audit.records[0].Action).To(Equal(stack.OperatorActionReconcile))
		Expect(audit.records[0].Actor).To(Equal("platform-operator"))
		Expect(audit.records[0].Context).To(Equal("disposable-ci"))
		Expect(audit.records[0].Digest).To(Equal(rendered.Digest()))
		Expect(audit.records[0].Result).To(Equal("applied"))
		Expect(audit.records[0].Resources).To(Equal([]stack.ResourceID{"api"}))
	})

	It("does not mutate when observed state already matches the rendered manifests", func() {
		spec, err := stack.Parse(strings.NewReader(stackDocument(kubernetesManifestResources, kubernetesManifestResources, kubernetesManifestResources)))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileCI)
		Expect(err).NotTo(HaveOccurred())
		adapter := &fakeKubernetesOperator{}
		audit := &recordedAudit{}
		operator, err := stack.NewKubernetesOperator(adapter, audit)
		Expect(err).NotTo(HaveOccurred())

		result, err := operator.Reconcile(context.Background(), stack.OperatorRequest{Actor: "platform-operator", Target: stack.OperatorTarget{Kubeconfig: "/explicit/kubeconfig", Context: "disposable-ci"}}, rendered)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Applied).To(BeFalse())
		Expect(adapter.applies).To(Equal(0))
		Expect(audit.records[0].Result).To(Equal("unchanged"))
	})
})
