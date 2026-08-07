package roles_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/roles"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Role startup", func() {
	It("serves a secret-safe readiness record without creating infrastructure", func() {
		config, err := roles.Parse(strings.NewReader(orchestrationConfig))
		Expect(err).NotTo(HaveOccurred())
		plan, err := roles.Prepare(context.Background(), config, fakeSecrets{
			"TEMPORAL_AUTH_TOKEN": "temporal-secret",
			"STATE_DATABASE_DSN":  "postgres-secret",
		})
		Expect(err).NotTo(HaveOccurred())

		listener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		context, cancel := context.WithCancel(context.Background())
		finished := make(chan error, 1)
		go func() { finished <- roles.Serve(context, plan, listener) }()
		DeferCleanup(func() {
			cancel()
			Expect(<-finished).To(Succeed())
		})

		response, err := http.Get("http://" + listener.Addr().String() + "/readyz") // #nosec G107 -- listener is local test state.
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(response.Body.Close)
		body, err := io.ReadAll(response.Body)
		Expect(err).NotTo(HaveOccurred())
		Expect(response.StatusCode).To(Equal(http.StatusOK))
		Expect(string(body)).To(ContainSubstring(`"role":"orchestration"`))
		Expect(string(body)).NotTo(ContainSubstring("temporal-secret"))
		Expect(string(body)).NotTo(ContainSubstring("postgres-secret"))
	})
})
