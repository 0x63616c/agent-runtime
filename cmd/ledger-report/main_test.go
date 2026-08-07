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
})
