// Command generate-requirement-manifest renders canonical evidence metadata.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/milestone"
)

var (
	requirementID    = regexp.MustCompile(`\*\*([A-Z]+(?:-[A-Z]+)*-[0-9]{3})\*\*`)
	qualifiedRange   = regexp.MustCompile(`^([A-Z]+(?:-[A-Z]+)*)-([0-9]{3})(?:–([0-9]{3}))?`)
	unqualifiedRange = regexp.MustCompile(`^([0-9]{3})(?:–([0-9]{3}))?`)
)

type output struct {
	path string
	data []byte
}

func main() {
	check := flag.Bool("check", false, "fail when generated evidence metadata differs")
	source := flag.String("source", "docs/planning/requirements/master-requirements.md", "binding requirements source")
	workMapPath := flag.String("work-map", "docs/planning/work-map.md", "explicit milestone ownership source")
	ledgerPath := flag.String("ledger", "evidence/requirements-ledger.json", "curated durable evidence ledger")
	flag.Parse()

	requirements, err := os.ReadFile(*source)
	if err != nil {
		fail(fmt.Errorf("read binding requirements: %w", err))
	}
	ids := unique(requirementID.FindAllStringSubmatch(string(requirements), -1))
	if len(ids) != 183 {
		fail(fmt.Errorf("validate binding requirements: expected 183 requirement IDs, found %d", len(ids)))
	}
	workMap, err := os.ReadFile(*workMapPath)
	if err != nil {
		fail(fmt.Errorf("read requirement ownership map: %w", err))
	}
	owners, err := parseOwnership(string(workMap))
	if err != nil {
		fail(fmt.Errorf("parse requirement ownership map: %w", err))
	}
	outputs, err := render(ids, owners)
	if err != nil {
		fail(fmt.Errorf("render canonical evidence metadata: %w", err))
	}
	for _, generated := range outputs {
		if *check {
			if err := checkOutput(generated); err != nil {
				fail(err)
			}
			continue
		}
		if err := writeAtomic(generated.path, generated.data); err != nil {
			fail(fmt.Errorf("write generated output %s: %w", generated.path, err))
		}
	}
	if err := validateCuratedLedger(outputs[1].data, *ledgerPath); err != nil {
		fail(err)
	}
}

func parseOwnership(workMap string) (map[string]milestone.MilestoneID, error) {
	owners := map[string]milestone.MilestoneID{}
	ownerRows := map[string]int{}
	for lineIndex, line := range strings.Split(workMap, "\n") {
		columns := strings.Split(line, "|")
		if len(columns) < 6 {
			continue
		}
		milestoneName := strings.TrimSpace(columns[1])
		if !regexp.MustCompile(`^M[0-9]+$`).MatchString(milestoneName) {
			continue
		}
		prefix := ""
		for _, rawPart := range strings.Split(columns[4], ",") {
			part := strings.TrimSpace(rawPart)
			if strings.Contains(part, "design gate only") {
				continue
			}
			ids, nextPrefix, err := expandRange(part, prefix)
			if err != nil {
				return nil, err
			}
			prefix = nextPrefix
			for _, id := range ids {
				if existingOwner, alreadyOwned := owners[id]; alreadyOwned {
					return nil, fmt.Errorf(
						"requirement %s has multiple terminal owners: %s (row %d) and %s (row %d)",
						id, existingOwner, ownerRows[id], milestoneName, lineIndex+1,
					)
				}
				owners[id] = milestone.MilestoneID(milestoneName)
				ownerRows[id] = lineIndex + 1
			}
		}
	}
	return owners, nil
}

func expandRange(part string, inheritedPrefix string) ([]string, string, error) {
	prefix := inheritedPrefix
	match := qualifiedRange.FindStringSubmatch(part)
	if len(match) != 0 {
		prefix = match[1]
	} else {
		match = unqualifiedRange.FindStringSubmatch(part)
	}
	if len(match) == 0 || prefix == "" {
		return nil, prefix, fmt.Errorf("parse ownership range: invalid value")
	}
	startIndex := 2
	endIndex := 3
	if qualifiedRange.FindStringSubmatch(part) == nil {
		startIndex = 1
		endIndex = 2
	}
	start, err := strconv.Atoi(match[startIndex])
	if err != nil {
		return nil, prefix, fmt.Errorf("parse ownership range start: %w", err)
	}
	end := start
	if match[endIndex] != "" {
		end, err = strconv.Atoi(match[endIndex])
		if err != nil {
			return nil, prefix, fmt.Errorf("parse ownership range end: %w", err)
		}
	}
	if end < start {
		return nil, prefix, fmt.Errorf("parse ownership range: end precedes start")
	}
	ids := make([]string, 0, end-start+1)
	for number := start; number <= end; number++ {
		ids = append(ids, fmt.Sprintf("%s-%03d", prefix, number))
	}
	return ids, prefix, nil
}

func render(ids []string, owners map[string]milestone.MilestoneID) ([]output, error) {
	manifest := "// Code generated from docs/planning/requirements/master-requirements.md; DO NOT EDIT.\n\npackage milestone\n\nimport \"strings\"\n\nvar acceptedRequirementIDs = strings.Fields(`" + strings.Join(ids, " ") + "`)\n\n// AcceptedRequirementIDs returns a copy of the binding 183-ID requirement manifest.\nfunc AcceptedRequirementIDs() []string {\n\treturn append([]string(nil), acceptedRequirementIDs...)\n}\n"
	catalog := milestone.Catalog{Version: 1}
	for _, id := range ids {
		owner, exists := owners[id]
		if !exists {
			return nil, fmt.Errorf("requirement has no work-map owner")
		}
		catalog.Requirements = append(catalog.Requirements, milestone.CatalogRequirement{ID: milestone.RequirementID(id), Milestone: owner, Weight: 1})
	}
	catalogJSON, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode requirement catalog: %w", err)
	}
	return []output{
		{path: "internal/milestone/manifest.go", data: []byte(manifest)},
		{path: "evidence/requirements-catalog.json", data: append(catalogJSON, '\n')},
	}, nil
}

func validateCuratedLedger(catalogData []byte, ledgerPath string) error {
	catalog, err := milestone.ParseCatalog(bytes.NewReader(catalogData))
	if err != nil {
		return fmt.Errorf("validate generated catalog: %w", err)
	}
	ledgerData, err := os.ReadFile(ledgerPath)
	if err != nil {
		return fmt.Errorf("read curated evidence ledger: %w", err)
	}
	ledger, err := milestone.ParseLedger(bytes.NewReader(ledgerData))
	if err != nil {
		return fmt.Errorf("validate curated evidence ledger schema: %w", err)
	}
	if err := milestone.ValidateCatalog(catalog, ledger); err != nil {
		return fmt.Errorf("validate curated evidence ledger completeness: %w", err)
	}
	return nil
}

func checkOutput(generated output) error {
	existing, err := os.ReadFile(generated.path)
	if err != nil {
		return fmt.Errorf("read generated output %s: %w", generated.path, err)
	}
	if !bytes.Equal(existing, generated.data) {
		return fmt.Errorf("check generated output %s: stale; run go run ./cmd/generate-requirement-manifest", generated.path)
	}
	return nil
}

func writeAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".generate-*")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set temporary output permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary output: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary output: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary output: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace generated output: %w", err)
	}
	return nil
}

func unique(matches [][]string) []string {
	seen := map[string]struct{}{}
	for _, match := range matches {
		seen[match[1]] = struct{}{}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
