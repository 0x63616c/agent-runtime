// Command afk-evidence creates and validates bounded direct-main evidence logs.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/0x63616c/agent-runtime/internal/afkevidence"
	"github.com/0x63616c/agent-runtime/internal/milestone"
)

func main() {
	mode := flag.String("mode", "validate", "validate or record")
	path := flag.String("file", "", "evidence log to validate")
	event := flag.String("event", "", "record event")
	requirements := flag.String("requirements", "", "comma-separated requirement IDs")
	seams := flag.String("seams", "", "comma-separated seam IDs")
	documentation := flag.String("documentation", "", "comma-separated documentation paths")
	revision := flag.String("revision", "", "working-tree or immutable source revision")
	sourceRef := flag.String("source-ref", "", "local or refs/heads/main")
	utcTime := flag.String("utc-time", "", "RFC3339 UTC completion time")
	proofLevel := flag.String("proof-level", "unit", "proof scope")
	commandID := flag.String("command-id", "", "reviewed command ID")
	artifactRef := flag.String("artifact-ref", "", "bounded artifact reference")
	result := flag.String("result", "", "passed or failed")
	limitations := flag.String("limitations", "", "comma-separated bounded limitations")
	flag.Parse()

	switch *mode {
	case "validate":
		if *path == "" {
			fail(fmt.Errorf("validate AFK evidence: -file is required"))
		}
		input, err := os.Open(*path)
		if err != nil {
			fail(fmt.Errorf("open AFK evidence: %w", err))
		}
		defer func() { _ = input.Close() }()
		if _, err := afkevidence.Parse(input); err != nil {
			fail(err)
		}
	case "record":
		completedAt, err := time.Parse(time.RFC3339, *utcTime)
		if err != nil {
			fail(fmt.Errorf("parse AFK evidence UTC time: %w", err))
		}
		record := afkevidence.Record{
			Event:          afkevidence.Event(*event),
			RequirementIDs: requirementIDs(*requirements),
			Seams:          fields(*seams),
			Documentation:  fields(*documentation),
			Revision:       milestone.RevisionRef(*revision),
			SourceRef:      *sourceRef,
			UTCTime:        completedAt,
			ProofLevel:     milestone.ProofLevel(*proofLevel),
			CommandID:      milestone.CommandID(*commandID),
			ArtifactRef:    milestone.ArtifactRef(*artifactRef),
			Result:         *result,
			Limitations:    fields(*limitations),
		}
		encoded, err := json.Marshal(afkevidence.Log{Version: 1, Records: []afkevidence.Record{record}})
		if err != nil {
			fail(fmt.Errorf("encode AFK evidence: %w", err))
		}
		if _, err := afkevidence.Parse(strings.NewReader(string(encoded))); err != nil {
			fail(err)
		}
		fmt.Println(string(encoded))
	default:
		fail(fmt.Errorf("AFK evidence mode must be validate or record"))
	}
}

func fields(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

func requirementIDs(value string) []milestone.RequirementID {
	values := fields(value)
	ids := make([]milestone.RequirementID, 0, len(values))
	for _, value := range values {
		ids = append(ids, milestone.RequirementID(value))
	}
	return ids
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
