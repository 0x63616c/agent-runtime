package clock_test

import (
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestClock(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Clock Suite")
}

var _ = Describe("Fake clock", func() {
	It("advances UTC logical time without waiting", func() {
		fake, err := clock.NewFake(time.Date(2026, 8, 6, 12, 0, 0, 0, time.FixedZone("PDT", -7*60*60)))
		Expect(err).NotTo(HaveOccurred())

		Expect(fake.Advance(90 * time.Second)).To(Succeed())
		Expect(fake.Now()).To(Equal(time.Date(2026, 8, 6, 19, 1, 30, 0, time.UTC)))
	})
})
