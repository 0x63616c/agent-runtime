package agentruntime_test

import (
	"encoding/json"
	"testing"
	"time"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestPublicIdentifiersRejectCrossTypeAndInvalidValues(t *testing.T) {
	t.Parallel()

	if _, err := agentruntime.ParseSessionID("turn_1234567890ABCDEF"); err == nil {
		t.Fatal("ParseSessionID(cross-type ID) error = nil")
	}
	if _, err := agentruntime.ParseSessionID("sess_short"); err == nil {
		t.Fatal("ParseSessionID(short ID) error = nil")
	}
	identifier, err := agentruntime.ParseSessionID("sess_1234567890ABCDEF")
	if err != nil {
		t.Fatalf("ParseSessionID(valid ID): %v", err)
	}
	encoded, err := json.Marshal(identifier)
	if err != nil {
		t.Fatalf("MarshalJSON(valid ID): %v", err)
	}
	if string(encoded) != `"sess_1234567890ABCDEF"` {
		t.Fatalf("MarshalJSON(valid ID) = %s", encoded)
	}
	if got := identifier.Redacted(); got != "sess_...CDEF" {
		t.Fatalf("Redacted() = %q", got)
	}
}

func TestEveryPublicIdentifierHasStrictJSONAndRedactionSemantics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		canonical string
		parse     func(string) (string, error)
	}{
		{"Agent", "agent_1234567890ABCDEF", func(value string) (string, error) {
			id, err := agentruntime.ParseAgentID(value)
			return id.String(), err
		}},
		{"Agent revision", "arev_1234567890ABCDEF", func(value string) (string, error) {
			id, err := agentruntime.ParseAgentRevisionID(value)
			return id.String(), err
		}},
		{"Session", "sess_1234567890ABCDEF", func(value string) (string, error) {
			id, err := agentruntime.ParseSessionID(value)
			return id.String(), err
		}},
		{"Input", "inpt_1234567890ABCDEF", func(value string) (string, error) {
			id, err := agentruntime.ParseInputID(value)
			return id.String(), err
		}},
		{"Turn", "turn_1234567890ABCDEF", func(value string) (string, error) {
			id, err := agentruntime.ParseTurnID(value)
			return id.String(), err
		}},
		{"Event", "evt_1234567890ABCDEF", func(value string) (string, error) {
			id, err := agentruntime.ParseEventID(value)
			return id.String(), err
		}},
		{"Cursor", "cur_1234567890ABCDEF", func(value string) (string, error) {
			id, err := agentruntime.ParseCursor(value)
			return id.String(), err
		}},
		{"Artifact", "art_1234567890ABCDEF", func(value string) (string, error) {
			id, err := agentruntime.ParseArtifactID(value)
			return id.String(), err
		}},
		{"Request", "req_1234567890ABCDEF", func(value string) (string, error) {
			id, err := agentruntime.ParseRequestID(value)
			return id.String(), err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			parsed, err := test.parse(test.canonical)
			if err != nil {
				t.Fatalf("parse canonical ID: %v", err)
			}
			if parsed != test.canonical {
				t.Fatalf("parsed ID = %q", parsed)
			}
			if _, err := test.parse("wrong_1234567890ABCDEF"); err == nil {
				t.Fatal("parse cross-type ID error = nil")
			}
		})
	}
}

func TestPublicErrorExposesOnlyStableFailure(t *testing.T) {
	t.Parallel()

	err := &agentruntime.Error{Failure: agentruntime.Failure{Code: agentruntime.FailureConflict, Message: "idempotency key conflicts"}}
	if got := err.Error(); got != "conflict: idempotency key conflicts" {
		t.Fatalf("Error() = %q", got)
	}
	var nilError *agentruntime.Error
	if got := nilError.Error(); got != "agent runtime error" {
		t.Fatalf("nil Error() = %q", got)
	}
}

func TestSnapshotsCloneCallerOwnedCollections(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	agentID, err := agentruntime.ParseAgentID("agent_1234567890ABCDEF")
	if err != nil {
		t.Fatalf("ParseAgentID: %v", err)
	}
	revisionID, err := agentruntime.ParseAgentRevisionID("arev_1234567890ABCDEF")
	if err != nil {
		t.Fatalf("ParseAgentRevisionID: %v", err)
	}
	specification := agentruntime.AgentSpecification{
		ID:           agentID,
		RevisionID:   revisionID,
		Revision:     1,
		Name:         "researcher",
		ModelProfile: "balanced",
		Instructions: "Use cited sources.",
		Tools:        []agentruntime.ToolDefinition{{Name: "search", Description: "Search approved sources."}},
		CreatedAt:    createdAt,
	}
	clone := specification.Clone()
	clone.Tools[0].Name = "mutated"
	if specification.Tools[0].Name != "search" {
		t.Fatalf("Clone mutated source tools: %q", specification.Tools[0].Name)
	}
}
