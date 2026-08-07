package nowait_test

import (
	"context"
	"errors"
	"testing"
	"testing/fstest"

	"github.com/0x63616c/agent-runtime/internal/nowait"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"
)

func TestNoWait(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "No Real Wait Suite")
}

var _ = Describe("Source check", func() {
	It("accepts server loops and rejects aliased or dot-imported real-time waits", func() {
		sources := fstest.MapFS{
			"safe.go":        {Data: []byte("package fixture\nfunc serve(){for { break }}\n")},
			"unsafe.go":      {Data: []byte("package fixture\nimport tm \"time\"\nfunc wait(){tm.Sleep(1)}\n")},
			"unsafe_test.go": {Data: []byte("package fixture\nimport . \"time\"\nfunc waitTest(){<-After(1)}\n")},
		}
		violations, err := nowait.CheckFS(context.Background(), sources)
		Expect(err).NotTo(HaveOccurred())
		Expect(violations).To(ConsistOf(
			gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Rule": Equal("real-time Sleep")}),
			gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Rule": Equal("real-time After")}),
		))
	})

	It("stops before reading source after cancellation", func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := nowait.CheckFS(ctx, fstest.MapFS{"source.go": {Data: []byte("not Go")}})
		Expect(errors.Is(err, context.Canceled)).To(BeTrue())
	})
})
