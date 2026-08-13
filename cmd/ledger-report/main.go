// Command ledger-report validates a machine-readable weighted evidence ledger.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/milestone"
)

type result struct {
	Ledger       string                    `json:"ledger"`
	Required     []milestone.RequirementID `json:"required,omitempty"`
	Requirements []milestone.Requirement   `json:"requirements,omitempty"`
	Result       string                    `json:"result"`
}

// readinessResult reports the formal ledger state grouped by milestone. It does
// not assess current source code, rerun evidence, or turn an in-progress row
// into a completion claim.
type readinessResult struct {
	Catalog    string               `json:"catalog"`
	Ledger     string               `json:"ledger"`
	Milestones []milestoneReadiness `json:"milestones"`
	Result     string               `json:"result"`
}

// milestoneReadiness is one weighted requirement group from the canonical
// catalog and its matching formal-ledger state.
type milestoneReadiness struct {
	Milestone                  milestone.MilestoneID     `json:"milestone"`
	Total                      int                       `json:"total"`
	Completed                  int                       `json:"completed"`
	InProgress                 int                       `json:"in_progress"`
	Blocked                    int                       `json:"blocked"`
	NotStarted                 int                       `json:"not_started"`
	TotalWeight                int                       `json:"total_weight"`
	CompletedWeight            int                       `json:"completed_weight"`
	EstimatedCompletionPercent int                       `json:"estimated_completion_percent"`
	EvidenceGaps               []milestone.RequirementID `json:"evidence_gaps"`
}

func main() {
	var ledgerPath string
	var catalogPath string
	var required string
	var complete bool
	var readiness bool
	flag.StringVar(&ledgerPath, "ledger", "", "path to a version-one evidence ledger JSON file")
	flag.StringVar(&catalogPath, "catalog", "", "path to the complete canonical requirement catalog JSON file")
	flag.StringVar(&required, "require", "", "optional comma-separated requirement IDs that must be completed")
	flag.BoolVar(&complete, "complete", false, "require every canonical requirement to have completed evidence")
	flag.BoolVar(&readiness, "readiness", false, "report formal requirement status and evidence gaps by milestone")
	flag.Parse()
	if ledgerPath == "" || catalogPath == "" {
		fail(fmt.Errorf("validate ledger report arguments: -catalog and -ledger are required"))
	}

	ledgerData, err := os.ReadFile(ledgerPath)
	if err != nil {
		fail(fmt.Errorf("read ledger: %w", err))
	}
	ledger, err := milestone.ParseLedger(bytes.NewReader(ledgerData))
	if err != nil {
		fail(err)
	}
	catalogData, err := os.ReadFile(catalogPath)
	if err != nil {
		fail(fmt.Errorf("read catalog: %w", err))
	}
	catalog, err := milestone.ParseCatalog(bytes.NewReader(catalogData))
	if err != nil {
		fail(err)
	}
	if readiness {
		if required != "" || complete {
			fail(fmt.Errorf("report readiness: -readiness cannot be combined with -require or -complete"))
		}
		if err := milestone.ValidateCatalog(catalog, ledger); err != nil {
			fail(fmt.Errorf("validate formal readiness inputs: %w", err))
		}
		if err := writeReadinessResult(readinessResult{
			Catalog:    catalogPath,
			Ledger:     ledgerPath,
			Milestones: buildReadiness(catalog, ledger),
			Result:     "formal-ledger-readiness",
		}); err != nil {
			fail(err)
		}
		return
	}
	var requiredIDs []milestone.RequirementID
	resultName := "complete-catalog-valid"
	if required == "" && !complete {
		if err := milestone.ValidateCatalog(catalog, ledger); err != nil {
			fail(fmt.Errorf("validate complete ledger report: %w", err))
		}
	} else {
		if complete {
			for _, id := range milestone.AcceptedRequirementIDs() {
				requiredIDs = append(requiredIDs, milestone.RequirementID(id))
			}
		} else {
			for _, id := range strings.Split(required, ",") {
				requiredIDs = append(requiredIDs, milestone.RequirementID(id))
			}
		}
		completionErr := milestone.VerifyRequired(catalog, ledger, requiredIDs)
		resultName = "required-requirements-completed"
		if completionErr != nil {
			resultName = "required-requirements-not-completed"
		}
		if err := writeResult(result{Ledger: ledgerPath, Required: requiredIDs, Requirements: ledger.Requirements, Result: resultName}); err != nil {
			fail(err)
		}
		if completionErr != nil {
			fail(fmt.Errorf("check completion ledger report: %w", completionErr))
		}
		return
	}
	if err := writeResult(result{Ledger: ledgerPath, Result: resultName}); err != nil {
		fail(err)
	}
}

func writeResult(report result) error {
	return encodeResult(os.Stdout, report)
}

func writeReadinessResult(report readinessResult) error {
	return encodeReadinessResult(os.Stdout, report)
}

func encodeResult(output io.Writer, report result) error {
	if err := json.NewEncoder(output).Encode(report); err != nil {
		return fmt.Errorf("write ledger report result: %w", err)
	}
	return nil
}

func encodeReadinessResult(output io.Writer, report readinessResult) error {
	if err := json.NewEncoder(output).Encode(report); err != nil {
		return fmt.Errorf("write readiness report result: %w", err)
	}
	return nil
}

func buildReadiness(catalog milestone.Catalog, ledger milestone.Ledger) []milestoneReadiness {
	ledgerByID := make(map[milestone.RequirementID]milestone.Requirement, len(ledger.Requirements))
	for _, requirement := range ledger.Requirements {
		ledgerByID[requirement.ID] = requirement
	}
	byMilestone := make(map[milestone.MilestoneID]*milestoneReadiness)
	for _, requirement := range catalog.Requirements {
		entry := byMilestone[requirement.Milestone]
		if entry == nil {
			entry = &milestoneReadiness{
				Milestone:    requirement.Milestone,
				EvidenceGaps: make([]milestone.RequirementID, 0),
			}
			byMilestone[requirement.Milestone] = entry
		}
		entry.Total++
		entry.TotalWeight += requirement.Weight
		status := ledgerByID[requirement.ID].Status
		switch status {
		case milestone.RequirementCompleted:
			entry.Completed++
			entry.CompletedWeight += requirement.Weight
		case milestone.RequirementInProgress:
			entry.InProgress++
			entry.EvidenceGaps = append(entry.EvidenceGaps, requirement.ID)
		case milestone.RequirementBlocked:
			entry.Blocked++
			entry.EvidenceGaps = append(entry.EvidenceGaps, requirement.ID)
		case milestone.RequirementNotStarted:
			entry.NotStarted++
			entry.EvidenceGaps = append(entry.EvidenceGaps, requirement.ID)
		}
	}
	result := make([]milestoneReadiness, 0, len(byMilestone))
	for _, entry := range byMilestone {
		entry.EstimatedCompletionPercent = (entry.CompletedWeight*100 + entry.TotalWeight/2) / entry.TotalWeight
		sort.Slice(entry.EvidenceGaps, func(i, j int) bool { return entry.EvidenceGaps[i] < entry.EvidenceGaps[j] })
		result = append(result, *entry)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Milestone < result[j].Milestone })
	return result
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
