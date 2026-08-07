package milestone

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/cockroachdb/errors"
)

// ParseLedger decodes and validates a version-one evidence ledger.
func ParseLedger(input io.Reader) (Ledger, error) {
	if input == nil {
		return Ledger{}, errors.New("parse evidence ledger: input is required")
	}
	var ledger Ledger
	if err := decodeOne(input, &ledger); err != nil {
		return Ledger{}, errors.Wrap(err, "parse evidence ledger")
	}
	if err := validateLedger(ledger); err != nil {
		return Ledger{}, errors.Wrap(err, "validate evidence ledger")
	}
	sort.Slice(ledger.Requirements, func(i, j int) bool { return ledger.Requirements[i].ID < ledger.Requirements[j].ID })
	return ledger, nil
}

// ParseCatalog decodes and validates the accepted 183-row weighted catalog.
func ParseCatalog(input io.Reader) (Catalog, error) {
	if input == nil {
		return Catalog{}, errors.New("parse requirement catalog: input is required")
	}
	var catalog Catalog
	if err := decodeOne(input, &catalog); err != nil {
		return Catalog{}, errors.Wrap(err, "parse requirement catalog")
	}
	if err := validateCatalog(catalog); err != nil {
		return Catalog{}, errors.Wrap(err, "validate requirement catalog")
	}
	sort.Slice(catalog.Requirements, func(i, j int) bool { return catalog.Requirements[i].ID < catalog.Requirements[j].ID })
	return catalog, nil
}

func decodeOne(input io.Reader, destination any) error {
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.Wrap(err, "decode JSON document")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == io.EOF {
		return nil
	} else if err == nil {
		return errors.New("decode JSON document: multiple JSON values")
	} else {
		return errors.Wrap(err, "decode trailing JSON content")
	}
}

func validateLedger(ledger Ledger) error {
	if ledger.Version != 1 {
		return errors.Newf("unsupported ledger version %d", ledger.Version)
	}
	if len(ledger.Requirements) == 0 {
		return errors.New("requirements are required")
	}
	seen := map[RequirementID]struct{}{}
	for _, requirement := range ledger.Requirements {
		if !validReference(string(requirement.ID)) {
			return errors.New("invalid requirement ID")
		}
		if _, duplicate := seen[requirement.ID]; duplicate {
			return errors.New("duplicate requirement ID")
		}
		seen[requirement.ID] = struct{}{}
		if !validRequirementStatus(requirement.Status) {
			return errors.New("unknown requirement status")
		}
		if requirement.Status == RequirementCompleted && len(requirement.Evidence) == 0 {
			return errors.New("completed requirement requires evidence")
		}
		for _, proof := range requirement.Evidence {
			if err := validateProof(proof); err != nil {
				return errors.Wrap(err, "validate requirement evidence")
			}
		}
	}
	return nil
}

func validRequirementStatus(status RequirementStatus) bool {
	switch status {
	case RequirementCompleted, RequirementInProgress, RequirementBlocked, RequirementNotStarted:
		return true
	default:
		return false
	}
}

func validateProof(proof Proof) error {
	if !validReference(string(proof.Revision)) || proof.UTCTime.IsZero() || !validProofLevel(proof.Level) || !validReference(string(proof.CommandID)) || !validReference(string(proof.ArtifactRef)) || proof.Result != "passed" {
		return errors.New("invalid proof reference")
	}
	return nil
}

func validProofLevel(level ProofLevel) bool {
	switch level {
	case ProofUnit, ProofWorkflow, ProofContract, ProofIntegration, ProofLocalTiltE2E, ProofLinuxKVME2E, ProofManual, ProofDocumentation, ProofIndependentReview, ProofRelease, ProofMainCI:
		return true
	default:
		return false
	}
}

func validateCatalog(catalog Catalog) error {
	if catalog.Version != 1 {
		return errors.Newf("unsupported catalog version %d", catalog.Version)
	}
	if len(catalog.Requirements) != len(acceptedRequirementIDs) {
		return errors.Newf("canonical catalog must contain exactly %d requirements", len(acceptedRequirementIDs))
	}
	expected := make(map[RequirementID]struct{}, len(acceptedRequirementIDs))
	for _, id := range acceptedRequirementIDs {
		expected[RequirementID(id)] = struct{}{}
	}
	seen := map[RequirementID]struct{}{}
	for _, requirement := range catalog.Requirements {
		if !validReference(string(requirement.ID)) || !validReference(string(requirement.Milestone)) || requirement.Weight <= 0 {
			return errors.New("invalid catalog requirement")
		}
		if _, duplicate := seen[requirement.ID]; duplicate {
			return errors.New("duplicate catalog requirement")
		}
		seen[requirement.ID] = struct{}{}
		if _, known := expected[requirement.ID]; !known {
			return errors.New("unknown accepted requirement")
		}
	}
	return nil
}

// ValidateCatalog rejects a partial, unknown, or otherwise non-canonical ledger.
func ValidateCatalog(catalog Catalog, ledger Ledger) error {
	if err := validateCatalog(catalog); err != nil {
		return errors.Wrap(err, "validate canonical catalog")
	}
	if err := validateLedger(ledger); err != nil {
		return errors.Wrap(err, "validate canonical ledger")
	}
	ledgerByID := map[RequirementID]struct{}{}
	for _, requirement := range ledger.Requirements {
		ledgerByID[requirement.ID] = struct{}{}
	}
	for _, requirement := range catalog.Requirements {
		if _, exists := ledgerByID[requirement.ID]; !exists {
			return errors.New("validate canonical ledger: requirement is missing")
		}
	}
	catalogByID := map[RequirementID]struct{}{}
	for _, requirement := range catalog.Requirements {
		catalogByID[requirement.ID] = struct{}{}
	}
	for _, requirement := range ledger.Requirements {
		if _, exists := catalogByID[requirement.ID]; !exists {
			return errors.New("validate canonical ledger: requirement is unknown")
		}
	}
	return nil
}

// VerifyRequired validates completeness before requiring named entries to be green.
func VerifyRequired(catalog Catalog, ledger Ledger, required []RequirementID) error {
	if err := ValidateCatalog(catalog, ledger); err != nil {
		return errors.Wrap(err, "verify required evidence")
	}
	if len(required) == 0 {
		return errors.New("verify required evidence: requirement list is required")
	}
	entries := map[RequirementID]Requirement{}
	for _, entry := range ledger.Requirements {
		entries[entry.ID] = entry
	}
	for _, id := range required {
		entry, exists := entries[id]
		if !exists {
			return errors.New("verify required evidence: requirement is missing")
		}
		if entry.Status != RequirementCompleted {
			return errors.Newf("verify required evidence: requirement is %s, not completed", entry.Status)
		}
	}
	return nil
}

func validReference(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !referenceCharacter(character) {
			return false
		}
	}
	return true
}

func validText(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !referenceCharacter(character) && character != ' ' {
			return false
		}
	}
	return true
}

func referenceCharacter(character rune) bool {
	return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.'
}
