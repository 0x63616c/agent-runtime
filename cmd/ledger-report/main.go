// Command ledger-report validates a machine-readable weighted evidence ledger.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/milestone"
)

type result struct {
	Ledger       string                    `json:"ledger"`
	Required     []milestone.RequirementID `json:"required,omitempty"`
	Requirements []milestone.Requirement   `json:"requirements,omitempty"`
	Result       string                    `json:"result"`
}

func main() {
	var ledgerPath string
	var catalogPath string
	var required string
	var complete bool
	flag.StringVar(&ledgerPath, "ledger", "", "path to a version-one evidence ledger JSON file")
	flag.StringVar(&catalogPath, "catalog", "", "path to the complete canonical requirement catalog JSON file")
	flag.StringVar(&required, "require", "", "optional comma-separated requirement IDs that must be completed")
	flag.BoolVar(&complete, "complete", false, "require every canonical requirement to have completed evidence")
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

func encodeResult(output io.Writer, report result) error {
	if err := json.NewEncoder(output).Encode(report); err != nil {
		return fmt.Errorf("write ledger report result: %w", err)
	}
	return nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
