package stack_test

import (
	"context"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/stack"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type bootstrapOperatorAdapter struct {
	observation stack.KubernetesNamespaceObservation
	bootstraps  int
}

func (adapter *bootstrapOperatorAdapter) BootstrapNamespace(context.Context, stack.OperatorTarget, stack.KubernetesManifests, string) (stack.KubernetesNamespaceObservation, error) {
	adapter.bootstraps++
	return adapter.observation, nil
}

func (*bootstrapOperatorAdapter) Apply(context.Context, stack.OperatorTarget, stack.KubernetesManifests, stack.BootstrapAuthority) (stack.KubernetesObservation, error) {
	return stack.KubernetesObservation{}, nil
}
func (*bootstrapOperatorAdapter) Observe(context.Context, stack.OperatorTarget, stack.KubernetesManifests) (stack.KubernetesObservation, error) {
	return stack.KubernetesObservation{}, nil
}
func (*bootstrapOperatorAdapter) Diff(context.Context, stack.OperatorTarget, stack.KubernetesManifests) (stack.KubernetesDifference, error) {
	return stack.KubernetesDifference{}, nil
}
func (*bootstrapOperatorAdapter) Teardown(context.Context, stack.OperatorTarget, stack.Rendered, stack.KubernetesManifests, stack.BootstrapAuthority) error {
	return nil
}

var _ = Describe("Audited namespace bootstrap", func() {
	It("records the newly created namespace identity, containment labels, and desired-state digest", func() {
		spec, err := stack.Parse(strings.NewReader(validIdentityStack))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		labels := stack.OwnershipLabels{PartOf: "agent-runtime", Stack: "feature-a", Profile: stack.ProfileLocal}
		adapter := &bootstrapOperatorAdapter{observation: stack.KubernetesNamespaceObservation{
			Namespace: "ar-feature-a", UID: "uid-new", Labels: labels, RenderDigest: rendered.Digest(),
		}}
		audit := &recordedAudit{}
		operator, err := stack.NewKubernetesOperator(adapter, audit)
		Expect(err).NotTo(HaveOccurred())
		authority, err := stack.NewBootstrapAuthority(rendered, "")
		Expect(err).NotTo(HaveOccurred())

		observation, err := operator.Bootstrap(context.Background(), stack.OperatorRequest{
			Actor: "smoke-bootstrap", Target: stack.OperatorTarget{Kubeconfig: "/explicit/kubeconfig", Context: "disposable", MigrationRoot: "/migrations"}, BootstrapAuthority: authority,
		}, rendered)

		Expect(err).NotTo(HaveOccurred())
		Expect(observation.UID).To(Equal(stack.ObservedUID("uid-new")))
		Expect(adapter.bootstraps).To(Equal(1))
		Expect(audit.records).To(ConsistOf(stack.OperatorAuditRecord{
			Action: stack.OperatorActionBootstrap, Actor: "smoke-bootstrap", Context: "disposable",
			Stack: "feature-a", Profile: stack.ProfileLocal, Digest: rendered.Digest(), Result: "bootstrapped",
			Resources: []stack.ResourceID{"namespace"}, NamespaceUID: "uid-new", NamespaceLabels: &labels,
		}))
	})

	It("rejects an adapter observation not bound to the rendered namespace", func() {
		spec, err := stack.Parse(strings.NewReader(validIdentityStack))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		adapter := &bootstrapOperatorAdapter{observation: stack.KubernetesNamespaceObservation{
			Namespace: "foreign", UID: "uid-foreign", Labels: stack.OwnershipLabels{PartOf: "agent-runtime", Stack: "feature-a", Profile: stack.ProfileLocal}, RenderDigest: rendered.Digest(),
		}}
		operator, err := stack.NewKubernetesOperator(adapter, &recordedAudit{})
		Expect(err).NotTo(HaveOccurred())
		authority, err := stack.NewBootstrapAuthority(rendered, "")
		Expect(err).NotTo(HaveOccurred())

		_, err = operator.Bootstrap(context.Background(), stack.OperatorRequest{Actor: "smoke-bootstrap", Target: stack.OperatorTarget{Kubeconfig: "/explicit/kubeconfig", Context: "disposable", MigrationRoot: "/migrations"}, BootstrapAuthority: authority}, rendered)
		Expect(err).To(MatchError(ContainSubstring("namespace observation does not match rendered desired state")))
	})
})
