package main

import (
	"bytes"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/milestone"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestLedgerReport(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Ledger Report Suite")
}

var _ = Describe("completion reports", func() {
	It("names every required row and its evidence in the exact JSON schema", func() {
		var output bytes.Buffer
		report := result{
			Ledger:   "evidence/requirements-ledger.json",
			Required: []milestone.RequirementID{"API-001", "TST-009"},
			Requirements: []milestone.Requirement{
				{ID: "API-001", Status: milestone.RequirementNotStarted},
				{ID: "TST-009", Status: milestone.RequirementBlocked},
			},
			Result: "required-requirements-not-completed",
		}
		Expect(encodeResult(&output, report)).To(Succeed())
		const expected = `{"ledger":"evidence/requirements-ledger.json","required":["API-001","TST-009"],"requirements":[{"id":"API-001","status":"not_started"},{"id":"TST-009","status":"blocked"}],"result":"required-requirements-not-completed"}` + "\n"
		Expect(output.String()).To(Equal(expected))
	})

	It("groups formal evidence gaps by milestone without claiming source readiness", func() {
		catalog := milestone.Catalog{Requirements: []milestone.CatalogRequirement{
			{ID: "API-001", Milestone: "M5", Weight: 2},
			{ID: "API-002", Milestone: "M5", Weight: 1},
			{ID: "SBX-001", Milestone: "M3", Weight: 1},
		}}
		ledger := milestone.Ledger{Requirements: []milestone.Requirement{
			{ID: "API-001", Status: milestone.RequirementCompleted},
			{ID: "API-002", Status: milestone.RequirementInProgress},
			{ID: "SBX-001", Status: milestone.RequirementNotStarted},
		}}

		Expect(buildReadiness(catalog, ledger)).To(Equal([]milestoneReadiness{
			{Milestone: "M3", Total: 1, NotStarted: 1, TotalWeight: 1, EvidenceGaps: []milestone.RequirementID{"SBX-001"}},
			{Milestone: "M5", Total: 2, Completed: 1, InProgress: 1, TotalWeight: 3, CompletedWeight: 2, EstimatedCompletionPercent: 67, EvidenceGaps: []milestone.RequirementID{"API-002"}},
		}))
	})

	It("writes an explicit formal-ledger readiness result", func() {
		var output bytes.Buffer
		report := readinessResult{
			Catalog: "evidence/requirements-catalog.json",
			Ledger:  "evidence/requirements-ledger.json",
			Milestones: []milestoneReadiness{{
				Milestone:                  "M5",
				Total:                      2,
				Completed:                  1,
				InProgress:                 1,
				TotalWeight:                2,
				CompletedWeight:            1,
				EstimatedCompletionPercent: 50,
				EvidenceGaps:               []milestone.RequirementID{"API-002"},
			}},
			Result: "formal-ledger-readiness",
		}
		Expect(encodeReadinessResult(&output, report)).To(Succeed())
		const expected = `{"catalog":"evidence/requirements-catalog.json","ledger":"evidence/requirements-ledger.json","milestones":[{"milestone":"M5","total":2,"completed":1,"in_progress":1,"blocked":0,"not_started":0,"total_weight":2,"completed_weight":1,"estimated_completion_percent":50,"evidence_gaps":["API-002"]}],"result":"formal-ledger-readiness"}` + "\n"
		Expect(output.String()).To(Equal(expected))
	})
})
