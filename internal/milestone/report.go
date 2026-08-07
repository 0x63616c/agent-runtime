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
	if err := validateReportInput(input); err != nil {
		return Record{}, errors.Wrap(err, "build milestone status")
	}
	weights := make(map[RequirementID]int, len(catalog.Requirements))
	for _, entry := range catalog.Requirements {
		weights[entry.ID] = entry.Weight
	}
	record := Record{
		Report:   Report{Milestone: input.Milestone, NextMilestone: input.NextMilestone, CommitOrRevision: input.Revision},
		Estimate: Estimate{Uncertainty: cloneEvidence(input.Uncertainty)},
		Delivery: DeliveryPending,
	}
	var totalWeight, completedWeight int
	for _, entry := range ledger.Requirements {
		totalWeight += weights[entry.ID]
		switch entry.Status {
		case RequirementCompleted:
			completedWeight += weights[entry.ID]
			record.Estimate.Completed = append(record.Estimate.Completed, entry.ID)
			record.Report.EvidenceSummary = append(record.Report.EvidenceSummary, evidence(EvidenceCompleted, entry.ID))
		case RequirementBlocked:
			record.Estimate.Blocked = append(record.Estimate.Blocked, entry.ID)
			record.Report.EvidenceSummary = append(record.Report.EvidenceSummary, evidence(EvidenceBlocked, entry.ID))
		default:
			record.Estimate.InProgress = append(record.Estimate.InProgress, entry.ID)
			record.Report.EvidenceSummary = append(record.Report.EvidenceSummary, evidence(EvidenceInProgress, entry.ID))
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
	case len(record.Estimate.Blocked) > 0:
		record.Report.Status = StatusBlocked
	case len(record.Estimate.InProgress) > 0:
		record.Report.Status = StatusInProgress
	default:
		record.Report.Status = StatusCompleted
	}
	if record.Report.Status != StatusCompleted && len(record.Estimate.Uncertainty) == 0 {
		return Record{}, errors.New("build milestone status: unfinished report requires uncertainty")
	}
	return record, nil
}

func validateReportInput(input ReportInput) error {
	if !validText(string(input.Milestone)) || !validText(string(input.NextMilestone)) || !validReference(string(input.Revision)) {
		return errors.New("invalid report identity")
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
