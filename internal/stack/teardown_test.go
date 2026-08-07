package stack_test

import (
	"strings"

	"github.com/0x63616c/agent-runtime/internal/stack"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Containment-safe teardown planning", func() {
	It("plans Kubernetes authority without pretending provider resources have Kubernetes UIDs", func() {
		spec, err := stack.Parse(strings.NewReader(stackDocument(kubernetesManifestResources, kubernetesManifestResources, kubernetesManifestResources)))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		labels := stack.OwnershipLabels{PartOf: "agent-runtime", Stack: "feature-a", Profile: stack.ProfileLocal}
		observed := make([]stack.ObservedResource, 0, 7)
		for _, resource := range rendered.Resources() {
			if resource.Kind == stack.ResourceKubernetes {
				observed = append(observed, stack.ObservedResource{ID: resource.ID, UID: stack.ObservedUID("uid-" + string(resource.ID)), Labels: labels})
			}
		}
		state := stack.ObservedState{
			Stack: "feature-a", Profile: stack.ProfileLocal, Namespace: "ar-feature-a",
			NamespaceUID: "uid-namespace-1", RenderDigest: rendered.Digest(), Labels: labels,
			Resources: observed,
		}

		plan, err := stack.PlanKubernetesTeardown(rendered, state)
		Expect(err).NotTo(HaveOccurred())
		Expect(plan.Actions).To(HaveLen(7))
		Expect(plan.Actions).To(ContainElement(stack.TeardownAction{Resource: "api", UID: "uid-api", Behavior: stack.DeleteOwned}))
	})

	It("requires rendered identity, ownership labels, and observed UIDs before planning actions", func() {
		spec, err := stack.Parse(strings.NewReader(validIdentityStack))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		state := stack.ObservedState{
			Stack: "feature-a", Profile: stack.ProfileLocal, Namespace: "ar-feature-a",
			NamespaceUID: "uid-namespace-1", RenderDigest: rendered.Digest(),
			Labels: stack.OwnershipLabels{PartOf: "agent-runtime", Stack: "feature-a", Profile: stack.ProfileLocal},
			Resources: []stack.ObservedResource{{
				ID: "notifier-secret", UID: "uid-secret-1",
				Labels: stack.OwnershipLabels{PartOf: "agent-runtime", Stack: "feature-a", Profile: stack.ProfileLocal},
			}},
		}
		plan, err := stack.PlanTeardown(rendered, state)
		Expect(err).NotTo(HaveOccurred())
		Expect(plan.NamespaceUID).To(Equal(stack.ObservedUID("uid-namespace-1")))
		Expect(plan.Actions).To(Equal([]stack.TeardownAction{{Resource: "notifier-secret", UID: "uid-secret-1", Behavior: stack.DeleteRetain}}))

		wrongLabel := state
		wrongLabel.Labels.Stack = "sibling"
		_, err = stack.PlanTeardown(rendered, wrongLabel)
		Expect(err).To(HaveOccurred())

		missingUID := state
		missingUID.Resources = append([]stack.ObservedResource(nil), state.Resources...)
		missingUID.Resources[0].UID = ""
		_, err = stack.PlanTeardown(rendered, missingUID)
		Expect(err).To(HaveOccurred())

		foreign := state
		foreign.Resources = append(append([]stack.ObservedResource(nil), state.Resources...), stack.ObservedResource{ID: "foreign", UID: "uid-foreign", Labels: state.Labels})
		_, err = stack.PlanTeardown(rendered, foreign)
		Expect(err).To(HaveOccurred())
	})
})
