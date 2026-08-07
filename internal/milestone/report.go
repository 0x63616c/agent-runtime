package milestone

import (
	"sort"

	"github.com/cockroachdb/errors"
)

// BuildRecord calculates an estimate only from a complete canonical catalog.
func BuildRecord(catalog Catalog, ledger Ledger, input ReportInput) (Record, error) {
	if err := ValidateCatalog(catalog, ledger); err != nil {
		return Record{}, errors.Wrap(err, "build milestone status")
	}
	if err := validateReportInput(input, catalog); err != nil {
		return Record{}, errors.Wrap(err, "build milestone status")
	}
	weights := make(map[RequirementID]int, len(catalog.Requirements))
	for _, entry := range catalog.Requirements {
		weights[entry.ID] = entry.Weight
	}
	terminal := make(map[RequirementID]struct{}, len(input.TerminalRequirementIDs))
	for _, id := range input.TerminalRequirementIDs {
		terminal[id] = struct{}{}
	}
	record := Record{
		Report:   Report{Milestone: input.Milestone, NextMilestone: input.NextMilestone, CommitOrRevision: input.Revision},
		Estimate: Estimate{Uncertainty: cloneEvidence(input.Uncertainty)},
		Delivery: DeliveryPending,
	}
	var totalWeight, completedWeight int
	var terminalInProgress, terminalBlocked int
	for _, entry := range ledger.Requirements {
		totalWeight += weights[entry.ID]
		switch entry.Status {
		case RequirementCompleted:
			completedWeight += weights[entry.ID]
			record.Estimate.Completed = append(record.Estimate.Completed, entry.ID)
			if _, included := terminal[entry.ID]; included {
				record.Report.EvidenceSummary = append(record.Report.EvidenceSummary, evidence(EvidenceCompleted, entry.ID))
			}
		case RequirementBlocked:
			record.Estimate.Blocked = append(record.Estimate.Blocked, entry.ID)
			if _, included := terminal[entry.ID]; included {
				terminalBlocked++
				record.Report.EvidenceSummary = append(record.Report.EvidenceSummary, evidence(EvidenceBlocked, entry.ID))
			}
		default:
			record.Estimate.InProgress = append(record.Estimate.InProgress, entry.ID)
			if _, included := terminal[entry.ID]; included {
				terminalInProgress++
				record.Report.EvidenceSummary = append(record.Report.EvidenceSummary, evidence(EvidenceInProgress, entry.ID))
			}
		}
	}
	record.Report.EvidenceSummary = append(record.Report.EvidenceSummary, input.Uncertainty...)
	sort.Slice(record.Estimate.Completed, func(i, j int) bool { return record.Estimate.Completed[i] < record.Estimate.Completed[j] })
	sort.Slice(record.Estimate.InProgress, func(i, j int) bool { return record.Estimate.InProgress[i] < record.Estimate.InProgress[j] })
	sort.Slice(record.Estimate.Blocked, func(i, j int) bool { return record.Estimate.Blocked[i] < record.Estimate.Blocked[j] })
	sort.Slice(record.Report.EvidenceSummary, func(i, j int) bool {
		if record.Report.EvidenceSummary[i].Kind == record.Report.EvidenceSummary[j].Kind {
			return record.Report.EvidenceSummary[i].Reference < record.Report.EvidenceSummary[j].Reference
		}
		return record.Report.EvidenceSummary[i].Kind < record.Report.EvidenceSummary[j].Kind
	})
	record.Report.EstimatedOverallPercent = (completedWeight*100 + totalWeight/2) / totalWeight
	switch {
	case terminalBlocked > 0:
		record.Report.Status = StatusBlocked
	case terminalInProgress > 0 || len(record.Estimate.Uncertainty) > 0:
		record.Report.Status = StatusInProgress
	default:
		record.Report.Status = StatusCompleted
	}
	if record.Report.Status != StatusCompleted && len(record.Estimate.Uncertainty) == 0 {
		return Record{}, errors.New("build milestone status: unfinished report requires uncertainty")
	}
	return record, nil
}

func validateReportInput(input ReportInput, catalog Catalog) error {
	if !validText(string(input.Milestone)) || !validText(string(input.NextMilestone)) || !validReference(string(input.Revision)) {
		return errors.New("invalid report identity")
	}
	if len(input.TerminalRequirementIDs) == 0 {
		return errors.New("terminal requirement list is required")
	}
	known := make(map[RequirementID]struct{}, len(catalog.Requirements))
	for _, requirement := range catalog.Requirements {
		known[requirement.ID] = struct{}{}
	}
	seen := make(map[RequirementID]struct{}, len(input.TerminalRequirementIDs))
	for _, id := range input.TerminalRequirementIDs {
		if _, duplicate := seen[id]; duplicate {
			return errors.New("duplicate terminal requirement")
		}
		seen[id] = struct{}{}
		if _, exists := known[id]; !exists {
			return errors.New("unknown terminal requirement")
		}
	}
	for _, reference := range input.Uncertainty {
		if reference.Kind != EvidenceUncertainty || !validReference(string(reference.Reference)) {
			return errors.New("invalid uncertainty reference")
		}
	}
	return nil
}

func evidence(kind EvidenceKind, id RequirementID) EvidenceReference {
	return EvidenceReference{Kind: kind, Reference: EvidenceRef(id)}
}

func cloneEvidence(input []EvidenceReference) []EvidenceReference {
	return append([]EvidenceReference(nil), input...)
}
