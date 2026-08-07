// Package afkevidence validates bounded, secret-safe direct-main evidence logs.
package afkevidence

import (
	"encoding/json"
	"io"
	"regexp"
	"time"

	"github.com/0x63616c/agent-runtime/internal/milestone"
	"github.com/cockroachdb/errors"
)

// Event classifies the direct-main checkpoint represented by a record.
type Event string

const (
	// EventLocalCheck records mutable working-tree evidence only.
	EventLocalCheck Event = "local_check"
	// EventPrePush records a check against the immutable revision about to be pushed.
	EventPrePush Event = "pre_push"
	// EventMainCI records a main-branch CI result for an immutable revision.
	EventMainCI Event = "main_ci"
	// EventRedMainHalt records that delivery stopped after a failed main check.
	EventRedMainHalt Event = "red_main_halt"
)

// Log is the versioned machine-readable AFK evidence document.
type Log struct {
	Version int      `json:"version"`
	Records []Record `json:"records"`
}

// Record contains only bounded references; command output and secrets are external.
type Record struct {
	Event          Event                     `json:"event"`
	RequirementIDs []milestone.RequirementID `json:"requirement_ids"`
	Seams          []string                  `json:"seams"`
	Documentation  []string                  `json:"documentation"`
	Revision       milestone.RevisionRef     `json:"revision"`
	SourceRef      string                    `json:"source_ref"`
	UTCTime        time.Time                 `json:"utc_time"`
	ProofLevel     milestone.ProofLevel      `json:"proof_level"`
	CommandID      milestone.CommandID       `json:"command_id"`
	ArtifactRef    milestone.ArtifactRef     `json:"artifact_ref"`
	Result         string                    `json:"result"`
	Limitations    []string                  `json:"limitations"`
}

var immutableRevision = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Parse decodes exactly one AFK evidence document and validates every record.
func Parse(input io.Reader) (Log, error) {
	if input == nil {
		return Log{}, errors.New("parse AFK evidence log: input is required")
	}
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	var log Log
	if err := decoder.Decode(&log); err != nil {
		return Log{}, errors.Wrap(err, "parse AFK evidence log")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Log{}, errors.New("parse AFK evidence log: multiple JSON values")
		}
		return Log{}, errors.Wrap(err, "parse AFK evidence log trailing content")
	}
	if log.Version != 1 || len(log.Records) == 0 {
		return Log{}, errors.New("validate AFK evidence log: version 1 and records are required")
	}
	for _, record := range log.Records {
		if err := validateRecord(record); err != nil {
			return Log{}, errors.Wrap(err, "validate AFK evidence record")
		}
	}
	return log, nil
}

// Immutable reports whether the record refers to a full immutable revision.
func (r Record) Immutable() bool {
	return immutableRevision.MatchString(string(r.Revision))
}

func validateRecord(record Record) error {
	if !validEvent(record.Event) || len(record.RequirementIDs) == 0 || len(record.Seams) == 0 || len(record.Documentation) == 0 || len(record.Limitations) == 0 {
		return errors.New("required bounded fields are missing")
	}
	accepted := make(map[milestone.RequirementID]struct{}, len(milestone.AcceptedRequirementIDs()))
	for _, id := range milestone.AcceptedRequirementIDs() {
		accepted[milestone.RequirementID(id)] = struct{}{}
	}
	for _, id := range record.RequirementIDs {
		if _, exists := accepted[id]; !exists {
			return errors.New("unknown requirement ID")
		}
	}
	for _, values := range [][]string{record.Seams, record.Documentation, record.Limitations} {
		for _, value := range values {
			if !safeReference(value) {
				return errors.New("unsafe reference")
			}
		}
	}
	if record.UTCTime.IsZero() || record.UTCTime.Location() != time.UTC || !safeReference(string(record.CommandID)) || !safeReference(string(record.ArtifactRef)) || !validProofLevel(record.ProofLevel) {
		return errors.New("invalid proof fields")
	}
	if record.Result != "passed" && record.Result != "failed" {
		return errors.New("invalid result")
	}
	if record.Event == EventLocalCheck {
		if record.Revision != "working-tree" || record.SourceRef != "local" || record.Result != "passed" || record.ProofLevel == milestone.ProofMainCI {
			return errors.New("invalid local check identity")
		}
		return nil
	}
	if !record.Immutable() || record.SourceRef != "refs/heads/main" {
		return errors.New("immutable main revision is required")
	}
	if record.Event == EventRedMainHalt && record.Result != "failed" {
		return errors.New("red main halt must be failed")
	}
	if (record.Event == EventMainCI || record.Event == EventRedMainHalt) && record.ProofLevel != milestone.ProofMainCI {
		return errors.New("main CI proof level is required")
	}
	return nil
}

func validEvent(event Event) bool {
	switch event {
	case EventLocalCheck, EventPrePush, EventMainCI, EventRedMainHalt:
		return true
	default:
		return false
	}
}

func validProofLevel(level milestone.ProofLevel) bool {
	switch level {
	case milestone.ProofUnit, milestone.ProofWorkflow, milestone.ProofContract, milestone.ProofIntegration, milestone.ProofLocalTiltE2E, milestone.ProofLinuxKVME2E, milestone.ProofManual, milestone.ProofDocumentation, milestone.ProofIndependentReview, milestone.ProofRelease, milestone.ProofMainCI:
		return true
	default:
		return false
	}
}

func safeReference(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' || character == '/' {
			continue
		}
		return false
	}
	return true
}
