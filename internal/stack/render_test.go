package stack_test

import (
	"bytes"
	"os"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/stack"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Deterministic rendering", func() {
	It("canonicalizes resource order and binds the digest to stack, profile, and explicit namespace", func() {
		resourceA := strings.Replace(validIdentityResourceObject, `"id":"notifier-secret"`, `"id":"a-secret"`, 1)
		resourceB := strings.Replace(validIdentityResourceObject, `"id":"notifier-secret"`, `"id":"b-secret"`, 1)
		ordered := `[` + resourceA + `,` + resourceB + `]`
		reversed := `[` + resourceB + `,` + resourceA + `]`

		first, err := stack.Parse(strings.NewReader(stackDocument(ordered, ordered, ordered)))
		Expect(err).NotTo(HaveOccurred())
		second, err := stack.Parse(strings.NewReader(stackDocument(reversed, reversed, reversed)))
		Expect(err).NotTo(HaveOccurred())

		firstRender, err := stack.Render(first, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		secondRender, err := stack.Render(second, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		Expect(firstRender.Digest()).To(MatchRegexp(`^sha256:[a-f0-9]{64}$`))
		Expect(firstRender.Digest()).To(Equal(secondRender.Digest()))
		Expect(firstRender.Resources()[0].ID).To(Equal(stack.ResourceID("a-secret")))
		Expect(bytes.Equal(firstRender.JSON(), secondRender.JSON())).To(BeTrue())
		Expect(string(firstRender.JSON())).To(ContainSubstring(`"namespace": "ar-feature-a"`))
		Expect(string(firstRender.JSON())).NotTo(ContainSubstring(`"dependencies": null`))

		ciRender, err := stack.Render(first, stack.ProfileCI)
		Expect(err).NotTo(HaveOccurred())
		Expect(ciRender.Digest()).NotTo(Equal(firstRender.Digest()))
		_, err = stack.Render(first, stack.Profile("unknown"))
		Expect(err).To(HaveOccurred())
	})

	It("keeps reviewed local, CI, and production render goldens stable", func() {
		spec, err := stack.Parse(strings.NewReader(validIdentityStack))
		Expect(err).NotTo(HaveOccurred())
		var actual []string
		for _, profile := range []stack.Profile{stack.ProfileLocal, stack.ProfileCI, stack.ProfileProduction} {
			rendered, renderErr := stack.Render(spec, profile)
			Expect(renderErr).NotTo(HaveOccurred())
			actual = append(actual, rendered.Digest())
		}
		Expect(actual).To(Equal([]string{
			"sha256:d33252340bf94dbb4c0c85d0559873f5f9ebda537349459c02eff0b8676b340e",
			"sha256:e1bd1ad686f105b2af84c733c5c9a1e07810b897bc2af14a0e97aa9c2268d31f",
			"sha256:8a604040da4f80381be6b19df0d3b5a31b2b21e337a7404a146df3c12ec91d24",
		}))
	})

	It("renders every profile in the checked-in contract example", func() {
		input, err := os.Open("../../deploy/stacks/contract-example.json")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(input.Close)
		spec, err := stack.Parse(input)
		Expect(err).NotTo(HaveOccurred())
		for _, profile := range []stack.Profile{stack.ProfileLocal, stack.ProfileCI, stack.ProfileProduction} {
			_, err := stack.Render(spec, profile)
			Expect(err).NotTo(HaveOccurred(), profile)
		}
	})

	It("binds two Stack identities to disjoint rendered namespaces and labels", func() {
		first, err := stack.Parse(strings.NewReader(validIdentityStack))
		Expect(err).NotTo(HaveOccurred())
		secondDocument := strings.NewReplacer(
			`"name":"feature-a"`, `"name":"feature-b"`,
			`"namespace":"ar-feature-a"`, `"namespace":"ar-feature-b"`,
			`"namespace":"ar-ci-feature-a"`, `"namespace":"ar-ci-feature-b"`,
			`"namespace":"feature-a"`, `"namespace":"feature-b"`,
		).Replace(validIdentityStack)
		second, err := stack.Parse(strings.NewReader(secondDocument))
		Expect(err).NotTo(HaveOccurred())
		firstRender, err := stack.Render(first, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		secondRender, err := stack.Render(second, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		Expect(firstRender.Digest()).NotTo(Equal(secondRender.Digest()))
		Expect(string(firstRender.JSON())).To(ContainSubstring(`"namespace": "ar-feature-a"`))
		Expect(string(secondRender.JSON())).To(ContainSubstring(`"namespace": "ar-feature-b"`))
	})
})
