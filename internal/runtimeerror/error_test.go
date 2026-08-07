package runtimeerror_test

import (
	stderrors "errors"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/runtimeerror"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestRuntimeError(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Runtime Error Suite")
}

type sentinelError struct{}

func (sentinelError) Error() string { return "dependency unavailable" }

var _ = Describe("Boundary errors", func() {
	It("preserves errors.Is and errors.As while adding a safe operation context", func() {
		cause := sentinelError{}
		identity, err := runtimeerror.NewSafeIdentity("milestone_m0")
		Expect(err).NotTo(HaveOccurred())
		err = runtimeerror.Wrap("publish milestone evidence", identity, cause)

		Expect(err).To(MatchError(ContainSubstring("publish milestone evidence milestone_m0")))
		Expect(stderrors.Is(err, cause)).To(BeTrue())

		var target sentinelError
		Expect(stderrors.As(err, &target)).To(BeTrue())
	})

	It("refuses unsafe identity text before it reaches an error", func() {
		_, err := runtimeerror.NewSafeIdentity("Authorization: Bearer secret")
		Expect(err).To(MatchError("create safe error identity: invalid value"))
	})
})
