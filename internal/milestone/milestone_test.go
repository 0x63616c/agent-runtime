package milestone_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/milestone"
	"github.com/0x63616c/agent-runtime/internal/runtimeconfig"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestMilestone(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Milestone Evidence Suite")
}

func validLedger() string {
	return `{"version":1,"requirements":[` +
		`{"id":"ENG-001","status":"completed","evidence":[{"revision":"4439138","utc_time":"2026-08-06T20:00:00Z","proof_level":"unit","command_id":"go-test-all","artifact_ref":"evidence-unit-001","result":"passed"}]},` +
		`{"id":"OPS-STAT-001","status":"in_progress"},` +
		`{"id":"TST-009","status":"blocked"}` +
		`]}`
}

func catalog() milestone.Catalog {
	requirements := make([]milestone.CatalogRequirement, 0, len(milestone.AcceptedRequirementIDs()))
	for _, id := range milestone.AcceptedRequirementIDs() {
		weight := 1
		if id == "ENG-001" {
			weight = 40
		}
		if id == "OPS-STAT-001" {
			weight = 35
		}
		if id == "TST-009" {
			weight = 25
		}
		requirements = append(requirements, milestone.CatalogRequirement{ID: milestone.RequirementID(id), Milestone: "M0", Weight: weight})
	}
	return milestone.Catalog{Version: 1, Requirements: requirements}
}

func fullLedger() milestone.Ledger {
	requirements := make([]milestone.Requirement, 0, len(milestone.AcceptedRequirementIDs()))
	for _, id := range milestone.AcceptedRequirementIDs() {
		requirements = append(requirements, milestone.Requirement{ID: milestone.RequirementID(id), Status: milestone.RequirementNotStarted})
	}
	for index := range requirements {
		switch requirements[index].ID {
		case "ENG-001":
			requirements[index].Status = milestone.RequirementCompleted
			requirements[index].Evidence = []milestone.Proof{{Revision: "4439138", UTCTime: time.Date(2026, 8, 6, 20, 0, 0, 0, time.UTC), Level: milestone.ProofUnit, CommandID: "go-test-all", ArtifactRef: "evidence-unit-001", Result: "passed"}}
		case "OPS-STAT-001":
			requirements[index].Status = milestone.RequirementInProgress
		case "TST-009":
			requirements[index].Status = milestone.RequirementBlocked
		}
	}
	return milestone.Ledger{Version: 1, Requirements: requirements}
}

var _ = Describe("Milestone evidence", func() {
	It("parses a weighted ledger deterministically and creates a safe estimate", func() {
		ledger, err := milestone.ParseLedger(strings.NewReader(validLedger()))
		Expect(err).NotTo(HaveOccurred())
		Expect(ledger.Requirements).To(HaveLen(3))

		record, err := milestone.BuildRecord(catalog(), fullLedger(), reportInput())
		Expect(err).NotTo(HaveOccurred())
		Expect(record.Report.EstimatedOverallPercent).To(Equal(14))
		Expect(record.Report.Status).To(Equal(milestone.StatusBlocked))
		Expect(record.Estimate.Completed).To(Equal([]milestone.RequirementID{"ENG-001"}))
		Expect(record.Estimate.InProgress).To(ContainElement(milestone.RequirementID("OPS-STAT-001")))
		Expect(record.Estimate.Blocked).To(Equal([]milestone.RequirementID{"TST-009"}))
		Expect(record.Report.EvidenceSummary).To(ContainElements(
			milestone.EvidenceReference{Kind: milestone.EvidenceCompleted, Reference: "ENG-001"},
			milestone.EvidenceReference{Kind: milestone.EvidenceInProgress, Reference: "OPS-STAT-001"},
			milestone.EvidenceReference{Kind: milestone.EvidenceBlocked, Reference: "TST-009"},
			milestone.EvidenceReference{Kind: milestone.EvidenceUncertainty, Reference: "main-ci-pending"},
		))
	})

	It("serializes the exact transport schema and rejects unsafe evidence text", func() {
		ledger, err := milestone.ParseLedger(strings.NewReader(validLedger()))
		Expect(err).NotTo(HaveOccurred())
		Expect(ledger.Requirements).To(HaveLen(3))
		record, err := milestone.BuildRecord(catalog(), fullLedger(), reportInput())
		Expect(err).NotTo(HaveOccurred())
		encoded, err := json.Marshal(record.Report)
		Expect(err).NotTo(HaveOccurred())
		var fields map[string]json.RawMessage
		Expect(json.Unmarshal(encoded, &fields)).To(Succeed())
		Expect(fields).To(HaveLen(7))
		for _, key := range []string{"milestone", "estimated_overall_percent", "evidence_summary", "next_milestone", "commit_or_revision", "utc_time", "status"} {
			Expect(fields).To(HaveKey(key))
		}

		unsafe := reportInput()
		unsafe.Uncertainty = []milestone.EvidenceReference{{Kind: milestone.EvidenceUncertainty, Reference: "Authorization:Bearer top-secret-token"}}
		_, err = milestone.BuildRecord(catalog(), fullLedger(), unsafe)
		Expect(err).To(MatchError(ContainSubstring("invalid uncertainty reference")))
	})

	It("refuses incomplete, duplicate, and unknown ledger input", func() {
		_, err := milestone.ParseLedger(strings.NewReader(`{"version":1,"requirements":[{"id":"ENG-001","status":"unknown"}]}`))
		Expect(err).To(MatchError(ContainSubstring("unknown requirement status")))

		_, err = milestone.ParseLedger(strings.NewReader(`{"version":1,"requirements":[{"id":"ENG-001","status":"completed","evidence":[{"revision":"4439138","utc_time":"2026-08-06T20:00:00Z","proof_level":"unit","command_id":"go-test-all","artifact_ref":"evidence-unit-001","result":"passed"}]},{"id":"ENG-001","status":"completed","evidence":[{"revision":"4439138","utc_time":"2026-08-06T20:00:00Z","proof_level":"unit","command_id":"go-test-all","artifact_ref":"evidence-unit-001","result":"passed"}]}]}`))
		Expect(err).To(MatchError(ContainSubstring("duplicate requirement")))

		_, err = milestone.ParseLedger(strings.NewReader(`{"version":1,"requirements":[{"id":"ENG-001","status":"completed"}]}`))
		Expect(err).To(MatchError(ContainSubstring("completed requirement requires evidence")))
	})

	It("retains complementary proof scopes and refuses an unknown scope", func() {
		ledgerJSON := `{"version":1,"requirements":[{"id":"TST-001","status":"completed","evidence":[` +
			`{"revision":"4439138","utc_time":"2026-08-06T20:00:00Z","proof_level":"unit","command_id":"unit-suite","artifact_ref":"unit-proof","result":"passed"},` +
			`{"revision":"4439138","utc_time":"2026-08-06T20:01:00Z","proof_level":"workflow","command_id":"workflow-suite","artifact_ref":"workflow-proof","result":"passed"},` +
			`{"revision":"4439138","utc_time":"2026-08-06T20:02:00Z","proof_level":"integration","command_id":"integration-suite","artifact_ref":"integration-proof","result":"passed"},` +
			`{"revision":"4439138","utc_time":"2026-08-06T20:03:00Z","proof_level":"local_tilt_e2e","command_id":"local-e2e","artifact_ref":"local-proof","result":"passed"},` +
			`{"revision":"4439138","utc_time":"2026-08-06T20:04:00Z","proof_level":"linux_kvm_e2e","command_id":"kvm-e2e","artifact_ref":"kvm-proof","result":"passed"},` +
			`{"revision":"4439138","utc_time":"2026-08-06T20:05:00Z","proof_level":"documentation","command_id":"docs-check","artifact_ref":"docs-proof","result":"passed"},` +
			`{"revision":"4439138","utc_time":"2026-08-06T20:06:00Z","proof_level":"independent_review","command_id":"review-check","artifact_ref":"review-proof","result":"passed"},` +
			`{"revision":"4439138","utc_time":"2026-08-06T20:07:00Z","proof_level":"release","command_id":"release-check","artifact_ref":"release-proof","result":"passed"},` +
			`{"revision":"4439138","utc_time":"2026-08-06T20:08:00Z","proof_level":"main_ci","command_id":"main-ci","artifact_ref":"gha-123-1","result":"passed"}` +
			`]}]}`
		ledger, err := milestone.ParseLedger(strings.NewReader(ledgerJSON))
		Expect(err).NotTo(HaveOccurred())
		Expect(ledger.Requirements[0].Evidence).To(HaveLen(9))

		invalid := strings.Replace(ledgerJSON, `"proof_level":"workflow"`, `"proof_level":"ambient_ci"`, 1)
		_, err = milestone.ParseLedger(strings.NewReader(invalid))
		Expect(err).To(MatchError(ContainSubstring("invalid proof reference")))
	})

	It("rejects missing and non-green requirements requested by verification", func() {
		ledger := fullLedger()
		Expect(milestone.VerifyRequired(catalog(), ledger, []milestone.RequirementID{"ENG-001"})).To(Succeed())
		Expect(milestone.VerifyRequired(catalog(), ledger, []milestone.RequirementID{"MISSING-001"})).To(MatchError(ContainSubstring("requirement is missing")))
		Expect(milestone.VerifyRequired(catalog(), ledger, []milestone.RequirementID{"OPS-STAT-001"})).To(MatchError(ContainSubstring("requirement is in_progress, not completed")))
		Expect(milestone.VerifyRequired(catalog(), ledger, []milestone.RequirementID{"TST-009"})).To(MatchError(ContainSubstring("requirement is blocked, not completed")))
		Expect(milestone.VerifyRequired(catalog(), ledger, []milestone.RequirementID{"API-001"})).To(MatchError(ContainSubstring("requirement is not_started, not completed")))

		missing := fullLedger()
		missing.Requirements = missing.Requirements[:len(missing.Requirements)-1]
		Expect(milestone.ValidateCatalog(catalog(), missing)).To(MatchError(ContainSubstring("requirement is missing")))

		unknown := fullLedger()
		unknown.Requirements = append(unknown.Requirements, milestone.Requirement{ID: "UNKNOWN-001", Status: milestone.RequirementNotStarted})
		Expect(milestone.ValidateCatalog(catalog(), unknown)).To(MatchError(ContainSubstring("requirement is unknown")))

		incomplete := catalog()
		incomplete.Requirements = append(incomplete.Requirements, milestone.CatalogRequirement{ID: "MON-001", Milestone: "M0", Weight: 1})
		_, err := milestone.BuildRecord(incomplete, ledger, reportInput())
		Expect(err).To(MatchError(ContainSubstring("canonical catalog must contain exactly 183")))
	})

	It("retains evidence before delivery and retains a failed delivery for deterministic retry", func() {
		_, err := milestone.ParseLedger(strings.NewReader(validLedger()))
		Expect(err).NotTo(HaveOccurred())
		config, err := runtimeconfig.New(runtimeconfig.Input{Version: 1})
		Expect(err).NotTo(HaveOccurred())
		fakeClock, err := clock.NewFake(time.Date(2026, 8, 6, 20, 0, 0, 0, time.UTC))
		Expect(err).NotTo(HaveOccurred())
		store := milestone.NewMemoryStore()
		notifier := milestone.NewFakeNotifier(milestone.NewDeliveryFailure(milestone.FailureUnavailable))
		service, err := milestone.NewService(config.Notifier, fakeClock, store, notifier)
		Expect(err).NotTo(HaveOccurred())

		record, err := service.Publish(context.Background(), catalog(), fullLedger(), reportInput())
		Expect(err).To(MatchError(ContainSubstring("deliver milestone status")))
		Expect(record.Delivery).To(Equal(milestone.DeliveryFailed))
		Expect(store.Events()).To(Equal([]string{"retained:M0 foundation", "failed:M0 foundation"}))
		Expect(notifier.Deliveries()).To(HaveLen(1))
		Expect(notifier.Deliveries()[0].Topic).To(Equal(runtimeconfig.NtfyTopic))
		Expect(notifier.Deliveries()[0].Report.EvidenceSummary).To(ContainElements(
			milestone.EvidenceReference{Kind: milestone.EvidenceCompleted, Reference: "ENG-001"},
			milestone.EvidenceReference{Kind: milestone.EvidenceInProgress, Reference: "OPS-STAT-001"},
			milestone.EvidenceReference{Kind: milestone.EvidenceBlocked, Reference: "TST-009"},
			milestone.EvidenceReference{Kind: milestone.EvidenceUncertainty, Reference: "main-ci-pending"},
		))
		Expect(record.Failure).To(Equal(milestone.FailureUnavailable))

		notifier.SetFailures()
		record, err = service.Retry(context.Background(), "M0 foundation")
		Expect(err).NotTo(HaveOccurred())
		Expect(record.Delivery).To(Equal(milestone.DeliverySent))
		Expect(store.Events()).To(Equal([]string{"retained:M0 foundation", "failed:M0 foundation", "sent:M0 foundation"}))
		Expect(notifier.Deliveries()).To(HaveLen(2))
	})

	It("does not mutate retained evidence when the caller has cancelled", func() {
		config, err := runtimeconfig.New(runtimeconfig.Input{Version: 1})
		Expect(err).NotTo(HaveOccurred())
		fakeClock, err := clock.NewFake(time.Date(2026, 8, 6, 20, 0, 0, 0, time.UTC))
		Expect(err).NotTo(HaveOccurred())
		store := milestone.NewMemoryStore()
		notifier := milestone.NewFakeNotifier()
		service, err := milestone.NewService(config.Notifier, fakeClock, store, notifier)
		Expect(err).NotTo(HaveOccurred())
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = service.Publish(ctx, catalog(), fullLedger(), reportInput())
		Expect(err).To(MatchError(context.Canceled))
		Expect(store.Events()).To(BeEmpty())
		Expect(notifier.Deliveries()).To(BeEmpty())
	})

	It("refuses unknown notifier failure codes before persistence", func() {
		failure := milestone.NewDeliveryFailure(milestone.FailureCode("provider-secret"))
		Expect(failure).To(MatchError(ContainSubstring("unsupported failure code")))
	})
})

func reportInput() milestone.ReportInput {
	return milestone.ReportInput{
		Milestone:     "M0 foundation",
		NextMilestone: "M0 CI proof",
		Revision:      "4439138",
		Uncertainty:   []milestone.EvidenceReference{{Kind: milestone.EvidenceUncertainty, Reference: "main-ci-pending"}},
	}
}
