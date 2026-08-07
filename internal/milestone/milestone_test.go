package milestone_test

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
		milestoneID := milestone.MilestoneID("Later")
		if isM0Requirement(milestone.RequirementID(id)) {
			milestoneID = "M0"
		}
		requirements = append(requirements, milestone.CatalogRequirement{ID: milestone.RequirementID(id), Milestone: milestoneID, Weight: weight})
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
		default:
			if isM0Requirement(requirements[index].ID) {
				requirements[index].Status = milestone.RequirementCompleted
				requirements[index].Evidence = []milestone.Proof{{Revision: "4439138", UTCTime: time.Date(2026, 8, 6, 20, 0, 0, 0, time.UTC), Level: milestone.ProofUnit, CommandID: "m0-foundation-check", ArtifactRef: "m0-foundation-proof", Result: "passed"}}
			}
		}
	}
	return milestone.Ledger{Version: 1, Requirements: requirements}
}

var _ = Describe("Milestone evidence", func() {
	It("reports a completed M0 from its terminal rows while retaining the full project estimate", func() {
		ledger, err := milestone.ParseLedger(strings.NewReader(validLedger()))
		Expect(err).NotTo(HaveOccurred())
		Expect(ledger.Requirements).To(HaveLen(3))

		record, err := milestone.BuildRecord(catalog(), fullLedger(), reportInput())
		Expect(err).NotTo(HaveOccurred())
		Expect(record.Report.EstimatedOverallPercent).To(Equal(17))
		Expect(record.Report.Status).To(Equal(milestone.StatusCompleted))
		Expect(record.Estimate.Completed).To(ContainElements(
			milestone.RequirementID("ENG-001"),
			milestone.RequirementID("DOC-005"),
			milestone.RequirementID("DOC-008"),
			milestone.RequirementID("MON-004"),
			milestone.RequirementID("MON-005"),
			milestone.RequirementID("MON-006"),
			milestone.RequirementID("MON-007"),
			milestone.RequirementID("MON-008"),
		))
		Expect(record.Estimate.InProgress).To(ContainElement(milestone.RequirementID("OPS-STAT-001")))
		Expect(record.Estimate.Blocked).To(Equal([]milestone.RequirementID{"TST-009"}))
		Expect(len(record.Estimate.Completed) + len(record.Estimate.InProgress) + len(record.Estimate.Blocked)).To(Equal(len(milestone.AcceptedRequirementIDs())))
		Expect(record.Report.EvidenceSummary).To(Equal([]milestone.EvidenceReference{
			{Kind: milestone.EvidenceCompleted, Reference: "DOC-005"},
			{Kind: milestone.EvidenceCompleted, Reference: "DOC-008"},
			{Kind: milestone.EvidenceCompleted, Reference: "MON-004"},
			{Kind: milestone.EvidenceCompleted, Reference: "MON-005"},
			{Kind: milestone.EvidenceCompleted, Reference: "MON-006"},
			{Kind: milestone.EvidenceCompleted, Reference: "MON-007"},
			{Kind: milestone.EvidenceCompleted, Reference: "MON-008"},
		}))
	})

	It("requires explicit known unique terminal rows and reports their uncertainty honestly", func() {
		input := reportInput()
		input.Uncertainty = []milestone.EvidenceReference{{Kind: milestone.EvidenceUncertainty, Reference: "main-ci-pending"}}
		record, err := milestone.BuildRecord(catalog(), fullLedger(), input)
		Expect(err).NotTo(HaveOccurred())
		Expect(record.Report.Status).To(Equal(milestone.StatusInProgress))
		Expect(record.Report.EvidenceSummary).To(HaveLen(8))
		Expect(record.Report.EvidenceSummary).To(ContainElement(milestone.EvidenceReference{Kind: milestone.EvidenceUncertainty, Reference: "main-ci-pending"}))

		input.TerminalRequirementIDs = nil
		_, err = milestone.BuildRecord(catalog(), fullLedger(), input)
		Expect(err).To(MatchError(ContainSubstring("terminal requirement list is required")))
		input.TerminalRequirementIDs = []milestone.RequirementID{"DOC-005", "DOC-005"}
		_, err = milestone.BuildRecord(catalog(), fullLedger(), input)
		Expect(err).To(MatchError(ContainSubstring("duplicate terminal requirement")))
		input.TerminalRequirementIDs = []milestone.RequirementID{"UNKNOWN-001"}
		_, err = milestone.BuildRecord(catalog(), fullLedger(), input)
		Expect(err).To(MatchError(ContainSubstring("unknown terminal requirement")))
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
		Expect(notifier.Deliveries()[0].Report.EvidenceSummary).To(HaveLen(7))
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

	It("posts the exact report through the fixed ntfy topic without exposing its authorization", func() {
		client := &recordingHTTPClient{statusCode: http.StatusServiceUnavailable}
		notifier, err := milestone.NewNtfyNotifier(client)
		Expect(err).NotTo(HaveOccurred())
		config, err := runtimeconfig.New(runtimeconfig.Input{Version: 1, Notifier: runtimeconfig.NotifierInput{AccessToken: "actual-secret"}})
		Expect(err).NotTo(HaveOccurred())
		config.Notifier.ApplyAuthorization(notifier)

		record, err := milestone.BuildRecord(catalog(), fullLedger(), reportInput())
		Expect(err).NotTo(HaveOccurred())
		record.Report.UTCTime = time.Date(2026, 8, 6, 20, 0, 0, 0, time.UTC)
		err = notifier.Deliver(context.Background(), milestone.Notification{Topic: runtimeconfig.NtfyTopic, Report: record.Report})
		Expect(err).To(MatchError("notifier delivery unavailable"))
		Expect(err.Error()).NotTo(ContainSubstring("actual-secret"))
		Expect(client.requests).To(HaveLen(1))
		Expect(client.requests[0].Method).To(Equal(http.MethodPost))
		Expect(client.requests[0].URL.String()).To(Equal(runtimeconfig.NtfyTopic))
		Expect(client.requests[0].URL.Path).To(Equal("/0x63616c-ai-agant"))
		Expect(client.requests[0].Header.Get("Authorization")).To(Equal("Bearer actual-secret"))
		Expect(client.requests[0].Header.Get("Content-Type")).To(Equal("text/plain"))
		Expect(client.requests[0].Header.Get("X-Sequence-ID")).To(Equal("milestone-639bccdea2c38354866f1e600aee9588"))
		const expected = `{"milestone":"M0 foundation","estimated_overall_percent":17,"evidence_summary":[{"kind":"completed","reference":"DOC-005"},{"kind":"completed","reference":"DOC-008"},{"kind":"completed","reference":"MON-004"},{"kind":"completed","reference":"MON-005"},{"kind":"completed","reference":"MON-006"},{"kind":"completed","reference":"MON-007"},{"kind":"completed","reference":"MON-008"}],"next_milestone":"M0 CI proof","commit_or_revision":"4439138","utc_time":"2026-08-06T20:00:00Z","status":"completed"}`
		Expect(string(client.bodies[0])).To(Equal(expected))
	})

	It("persists a failed delivery on disk before a later retry succeeds", func() {
		directory := GinkgoT().TempDir()
		store, err := milestone.NewFileStore(directory)
		Expect(err).NotTo(HaveOccurred())
		config, err := runtimeconfig.New(runtimeconfig.Input{Version: 1})
		Expect(err).NotTo(HaveOccurred())
		fakeClock, err := clock.NewFake(time.Date(2026, 8, 6, 20, 0, 0, 0, time.UTC))
		Expect(err).NotTo(HaveOccurred())
		notifier := milestone.NewFakeNotifier(milestone.NewDeliveryFailure(milestone.FailureUnavailable))
		service, err := milestone.NewService(config.Notifier, fakeClock, store, notifier)
		Expect(err).NotTo(HaveOccurred())

		failed, err := service.Publish(context.Background(), catalog(), fullLedger(), reportInput())
		Expect(err).To(MatchError(ContainSubstring("deliver milestone status")))
		Expect(failed.Delivery).To(Equal(milestone.DeliveryFailed))
		entries, err := os.ReadDir(directory)
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(HaveLen(1))
		encoded, err := os.ReadFile(filepath.Join(directory, entries[0].Name()))
		Expect(err).NotTo(HaveOccurred())
		var retained milestone.Record
		Expect(json.Unmarshal(encoded, &retained)).To(Succeed())
		Expect(retained.Delivery).To(Equal(milestone.DeliveryFailed))
		Expect(retained.Failure).To(Equal(milestone.FailureUnavailable))

		notifier.SetFailures()
		sent, err := service.Retry(context.Background(), "M0 foundation")
		Expect(err).NotTo(HaveOccurred())
		Expect(sent.Delivery).To(Equal(milestone.DeliverySent))
	})

	It("hardens an existing evidence directory and durably replaces private records", func() {
		directory := GinkgoT().TempDir()
		Expect(os.Chmod(directory, 0o755)).To(Succeed())
		store, err := milestone.NewFileStore(directory)
		Expect(err).NotTo(HaveOccurred())
		directoryInfo, err := os.Stat(directory)
		Expect(err).NotTo(HaveOccurred())
		Expect(directoryInfo.Mode().Perm()).To(Equal(os.FileMode(0o700)))

		record, err := milestone.BuildRecord(catalog(), fullLedger(), reportInput())
		Expect(err).NotTo(HaveOccurred())
		Expect(store.Retain(context.Background(), record)).To(Succeed())
		entries, err := os.ReadDir(directory)
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(HaveLen(1))
		recordInfo, err := entries[0].Info()
		Expect(err).NotTo(HaveOccurred())
		Expect(recordInfo.Mode().Perm()).To(Equal(os.FileMode(0o600)))
		_, err = store.MarkFailed(context.Background(), "M0 foundation", milestone.FailureUnavailable)
		Expect(err).NotTo(HaveOccurred())
		reopened, err := milestone.NewFileStore(directory)
		Expect(err).NotTo(HaveOccurred())
		retained, err := reopened.Lookup(context.Background(), "M0 foundation")
		Expect(err).NotTo(HaveOccurred())
		Expect(retained.Delivery).To(Equal(milestone.DeliveryFailed))
	})

	It("allows a pending record to recover with the same report after sent-state retention fails", func() {
		config, err := runtimeconfig.New(runtimeconfig.Input{Version: 1})
		Expect(err).NotTo(HaveOccurred())
		fakeClock, err := clock.NewFake(time.Date(2026, 8, 6, 20, 0, 0, 0, time.UTC))
		Expect(err).NotTo(HaveOccurred())
		backing := milestone.NewMemoryStore()
		store := &failOnceMarkSentStore{EvidenceStore: backing}
		notifier := milestone.NewFakeNotifier()
		service, err := milestone.NewService(config.Notifier, fakeClock, store, notifier)
		Expect(err).NotTo(HaveOccurred())

		pending, err := service.Publish(context.Background(), catalog(), fullLedger(), reportInput())
		Expect(err).To(MatchError(ContainSubstring("retain milestone delivery success")))
		Expect(pending.Delivery).To(Equal(milestone.DeliveryPending))
		retained, err := backing.Lookup(context.Background(), "M0 foundation")
		Expect(err).NotTo(HaveOccurred())
		Expect(retained.Delivery).To(Equal(milestone.DeliveryPending))

		sent, err := service.Retry(context.Background(), "M0 foundation")
		Expect(err).NotTo(HaveOccurred())
		Expect(sent.Delivery).To(Equal(milestone.DeliverySent))
		Expect(notifier.Deliveries()).To(HaveLen(2))
	})

	It("allows only one process to retry a retained delivery claim", func() {
		directory := GinkgoT().TempDir()
		firstStore, err := milestone.NewFileStore(directory)
		Expect(err).NotTo(HaveOccurred())
		secondStore, err := milestone.NewFileStore(directory)
		Expect(err).NotTo(HaveOccurred())
		record, err := milestone.BuildRecord(catalog(), fullLedger(), reportInput())
		Expect(err).NotTo(HaveOccurred())
		Expect(firstStore.Retain(context.Background(), record)).To(Succeed())
		_, err = firstStore.MarkFailed(context.Background(), "M0 foundation", milestone.FailureUnavailable)
		Expect(err).NotTo(HaveOccurred())
		config, err := runtimeconfig.New(runtimeconfig.Input{Version: 1})
		Expect(err).NotTo(HaveOccurred())
		fakeClock, err := clock.NewFake(time.Date(2026, 8, 6, 20, 0, 0, 0, time.UTC))
		Expect(err).NotTo(HaveOccurred())
		notifier := newBlockingNotifier()
		first, err := milestone.NewService(config.Notifier, fakeClock, firstStore, notifier)
		Expect(err).NotTo(HaveOccurred())
		second, err := milestone.NewService(config.Notifier, fakeClock, secondStore, notifier)
		Expect(err).NotTo(HaveOccurred())

		firstResult := make(chan error, 1)
		go func() {
			_, retryErr := first.Retry(context.Background(), "M0 foundation")
			firstResult <- retryErr
		}()
		<-notifier.firstEntered
		released := false
		defer func() {
			if !released {
				close(notifier.releaseFirst)
			}
		}()

		_, err = second.Retry(context.Background(), "M0 foundation")
		Expect(err).To(MatchError(ContainSubstring("claim milestone delivery")))
		Expect(notifier.Calls()).To(Equal(1))
		close(notifier.releaseFirst)
		released = true
		Expect(<-firstResult).To(Succeed())
	})

	It("reuses one ntfy sequence when the first transport result is ambiguous", func() {
		directory := GinkgoT().TempDir()
		store, err := milestone.NewFileStore(directory)
		Expect(err).NotTo(HaveOccurred())
		config, err := runtimeconfig.New(runtimeconfig.Input{Version: 1})
		Expect(err).NotTo(HaveOccurred())
		fakeClock, err := clock.NewFake(time.Date(2026, 8, 6, 20, 0, 0, 0, time.UTC))
		Expect(err).NotTo(HaveOccurred())
		client := &recordingHTTPClient{statusCode: http.StatusOK, failures: []error{stderrors.New("connection result unknown")}}
		notifier, err := milestone.NewNtfyNotifier(client)
		Expect(err).NotTo(HaveOccurred())
		service, err := milestone.NewService(config.Notifier, fakeClock, store, notifier)
		Expect(err).NotTo(HaveOccurred())

		_, err = service.Publish(context.Background(), catalog(), fullLedger(), reportInput())
		Expect(err).To(MatchError("deliver milestone status: notifier delivery unavailable"))
		_, err = service.Retry(context.Background(), "M0 foundation")
		Expect(err).NotTo(HaveOccurred())
		Expect(client.requests).To(HaveLen(2))
		Expect(client.requests[1].URL.String()).To(Equal(client.requests[0].URL.String()))
		Expect(client.requests[1].Header.Get("X-Sequence-ID")).To(Equal(client.requests[0].Header.Get("X-Sequence-ID")))
		Expect(client.bodies[1]).To(Equal(client.bodies[0]))
	})
})

func reportInput() milestone.ReportInput {
	return milestone.ReportInput{
		Milestone:              "M0 foundation",
		NextMilestone:          "M0 CI proof",
		Revision:               "4439138",
		TerminalRequirementIDs: []milestone.RequirementID{"DOC-005", "DOC-008", "MON-004", "MON-005", "MON-006", "MON-007", "MON-008"},
	}
}

func isM0Requirement(id milestone.RequirementID) bool {
	switch id {
	case "DOC-005", "DOC-008", "MON-004", "MON-005", "MON-006", "MON-007", "MON-008":
		return true
	default:
		return false
	}
}

type recordingHTTPClient struct {
	statusCode int
	failures   []error
	requests   []*http.Request
	bodies     [][]byte
}

type failOnceMarkSentStore struct {
	milestone.EvidenceStore
	fail bool
}

func (store *failOnceMarkSentStore) MarkSent(ctx context.Context, milestoneID milestone.MilestoneID) (milestone.Record, error) {
	if !store.fail {
		store.fail = true
		return milestone.Record{}, stderrors.New("simulated sent-state persistence failure")
	}
	return store.EvidenceStore.MarkSent(ctx, milestoneID)
}

type blockingNotifier struct {
	mu           sync.Mutex
	calls        int
	firstEntered chan struct{}
	releaseFirst chan struct{}
}

func newBlockingNotifier() *blockingNotifier {
	return &blockingNotifier{firstEntered: make(chan struct{}), releaseFirst: make(chan struct{})}
}

func (notifier *blockingNotifier) Deliver(context.Context, milestone.Notification) error {
	notifier.mu.Lock()
	notifier.calls++
	call := notifier.calls
	notifier.mu.Unlock()
	if call == 1 {
		close(notifier.firstEntered)
		<-notifier.releaseFirst
		return nil
	}
	return stderrors.New("second notifier delivery must not occur")
}

func (notifier *blockingNotifier) Calls() int {
	notifier.mu.Lock()
	defer notifier.mu.Unlock()
	return notifier.calls
}

func (client *recordingHTTPClient) Do(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	client.requests = append(client.requests, request)
	client.bodies = append(client.bodies, body)
	if len(client.failures) > 0 {
		failure := client.failures[0]
		client.failures = client.failures[1:]
		return nil, failure
	}
	return &http.Response{StatusCode: client.statusCode, Body: io.NopCloser(strings.NewReader("unavailable")), Header: make(http.Header)}, nil
}
