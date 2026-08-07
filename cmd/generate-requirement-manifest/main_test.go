package main

import (
	"testing"

	"github.com/0x63616c/agent-runtime/internal/milestone"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestGenerator(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Requirement Generator Suite")
}

var _ = Describe("canonical evidence generation", func() {
	It("derives ownership from the work map and never generates the durable ledger", func() {
		workMap := `| M0 | issue | deps | MON-001–002, OPS-STAT-001 | summary |
| M1 | issue | deps | INF-001–002 | summary |`
		owners, err := parseOwnership(workMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(owners["MON-001"]).To(Equal(milestone.MilestoneID("M0")))
		Expect(owners["OPS-STAT-001"]).To(Equal(milestone.MilestoneID("M0")))
		Expect(owners["INF-002"]).To(Equal(milestone.MilestoneID("M1")))

		generated, err := render([]string{"INF-001", "INF-002", "MON-001", "MON-002", "OPS-STAT-001"}, owners)
		Expect(err).NotTo(HaveOccurred())
		Expect(generated).To(HaveLen(2))
		Expect(generated[0].path).To(Equal("internal/milestone/manifest.go"))
		Expect(generated[1].path).To(Equal("evidence/requirements-catalog.json"))
	})

	It("refuses a requirement with no explicit work-map owner", func() {
		_, err := render([]string{"MON-001", "TST-001"}, map[string]milestone.MilestoneID{"MON-001": "M0"})
		Expect(err).To(MatchError(ContainSubstring("requirement has no work-map owner")))
	})

	It("refuses duplicate terminal ownership and identifies both owner rows", func() {
		workMap := `| M0 | issue | deps | MON-001–002 | summary |
| M1 | issue | deps | MON-002, INF-001 | summary |`
		_, err := parseOwnership(workMap)
		Expect(err).To(MatchError("requirement MON-002 has multiple terminal owners: M0 (row 1) and M1 (row 2)"))
	})

	It("excludes explicit non-terminal contribution rows from ownership", func() {
		workMap := `| M0 | issue | deps | MON-001 | summary |
| Contributing issue | Contribution | Terminal evidence owner |
| #18 | contributes fixtures for MON-001 | M1 |`
		owners, err := parseOwnership(workMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(owners).To(Equal(map[string]milestone.MilestoneID{"MON-001": "M0"}))
	})
})
