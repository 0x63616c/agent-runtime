package stack_test

import (
	"bytes"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/stack"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Rendered desired-state drift", func() {
	It("checks canonical provenance and reports bounded resource changes", func() {
		expectedSpec, err := stack.Parse(strings.NewReader(validIdentityStack))
		Expect(err).NotTo(HaveOccurred())
		expected, err := stack.Render(expectedSpec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		Expect(stack.Check(expected, bytes.NewReader(expected.JSON()))).To(Succeed())

		changedDocument := strings.ReplaceAll(validIdentityStack, `"version":"v1"`, `"version":"v2"`)
		changedSpec, err := stack.Parse(strings.NewReader(changedDocument))
		Expect(err).NotTo(HaveOccurred())
		changed, err := stack.Render(changedSpec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		difference, err := stack.Diff(expected, bytes.NewReader(changed.JSON()))
		Expect(err).NotTo(HaveOccurred())
		Expect(difference.Changes).To(Equal([]stack.Change{{Resource: "notifier-secret", Kind: stack.ChangeModified}}))

		tampered := bytes.Replace(expected.JSON(), []byte(`"reference": "ntfy-token"`), []byte(`"reference": "other-token"`), 1)
		Expect(stack.Check(expected, bytes.NewReader(tampered))).To(MatchError(ContainSubstring("digest")))
	})
})
