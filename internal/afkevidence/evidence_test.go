package afkevidence_test

import (
	"strings"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/afkevidence"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestAFKEvidence(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "AFK Evidence Suite")
}

var _ = Describe("AFK evidence logs", func() {
	It("accepts a bounded local record without upgrading it to immutable proof", func() {
		log, err := afkevidence.Parse(strings.NewReader(`{"version":1,"records":[{"event":"local_check","requirement_ids":["MON-004","MON-005"],"seams":["S12"],"documentation":["AGENTS.md"],"revision":"working-tree","source_ref":"local","utc_time":"2026-08-07T03:30:00Z","proof_level":"unit","command_id":"just-check","artifact_ref":"m0-local-check","result":"passed","limitations":["immutable-main-ci-pending"]}]}`))
		Expect(err).NotTo(HaveOccurred())
		Expect(log.Records).To(HaveLen(1))
		Expect(log.Records[0].Event).To(Equal(afkevidence.EventLocalCheck))
		Expect(log.Records[0].Immutable()).To(BeFalse())
	})

	It("accepts immutable main CI and rejects unsafe or contradictory records", func() {
		log, err := afkevidence.Parse(strings.NewReader(`{"version":1,"records":[{"event":"main_ci","requirement_ids":["MON-004"],"seams":["S12"],"documentation":["AGENTS.md"],"revision":"0123456789abcdef0123456789abcdef01234567","source_ref":"refs/heads/main","utc_time":"2026-08-07T03:30:00Z","proof_level":"main_ci","command_id":"just-check","artifact_ref":"gha-123-1","result":"passed","limitations":["release-proof-pending"]}]}`))
		Expect(err).NotTo(HaveOccurred())
		Expect(log.Records[0].Immutable()).To(BeTrue())

		_, err = afkevidence.Parse(strings.NewReader(`{"version":1,"records":[{"event":"main_ci","requirement_ids":["MON-004"],"seams":["S12"],"documentation":["AGENTS.md"],"revision":"working-tree","source_ref":"refs/heads/main","utc_time":"2026-08-07T03:30:00Z","proof_level":"main_ci","command_id":"just-check","artifact_ref":"Authorization:Bearer-secret","result":"passed","limitations":["none"]}]}`))
		Expect(err).To(MatchError(ContainSubstring("validate AFK evidence record")))
	})

	It("rejects unknown fields, unknown requirements, and trailing JSON", func() {
		for _, input := range []string{
			`{"version":1,"records":[{"event":"local_check","requirement_ids":["UNKNOWN-001"],"seams":["S12"],"documentation":["AGENTS.md"],"revision":"working-tree","source_ref":"local","utc_time":"2026-08-07T03:30:00Z","proof_level":"unit","command_id":"just-check","artifact_ref":"m0-local-check","result":"passed","limitations":["pending"]}]}`,
			`{"version":1,"records":[],"secret":"value"}`,
			`{"version":1,"records":[]} {}`,
		} {
			_, err := afkevidence.Parse(strings.NewReader(input))
			Expect(err).To(HaveOccurred())
		}
	})
})
