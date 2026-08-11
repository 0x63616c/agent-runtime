package agentruntime

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
)

// AgentID identifies an Agent without carrying tenancy or routing information.
type AgentID string

// AgentRevisionID identifies one immutable Agent specification revision.
type AgentRevisionID string

// SessionID identifies a durable Session.
type SessionID string

// InputID identifies one accepted Input.
type InputID string

// TurnID identifies one durable Turn.
type TurnID string

// EventID identifies one Product event.
type EventID string

// Cursor identifies an opaque Product-event replay position.
type Cursor string

// ArtifactID identifies an authorized immutable Artifact reference.
type ArtifactID string

// ApprovalID identifies one owner-actionable Approval request.
type ApprovalID string

// RequestID correlates one HTTP attempt without identifying durable work.
type RequestID string

const (
	agentPrefix         = "agent_"
	agentRevisionPrefix = "arev_"
	sessionPrefix       = "sess_"
	inputPrefix         = "inpt_"
	turnPrefix          = "turn_"
	eventPrefix         = "evt_"
	cursorPrefix        = "cur_"
	artifactPrefix      = "art_"
	approvalPrefix      = "appr_"
	requestPrefix       = "req_"
)

// ParseAgentID validates an externally supplied Agent ID.
func ParseAgentID(value string) (AgentID, error) { return parseID[AgentID](value, agentPrefix) }

// ParseAgentRevisionID validates an externally supplied Agent revision ID.
func ParseAgentRevisionID(value string) (AgentRevisionID, error) {
	return parseID[AgentRevisionID](value, agentRevisionPrefix)
}

// ParseSessionID validates an externally supplied Session ID.
func ParseSessionID(value string) (SessionID, error) { return parseID[SessionID](value, sessionPrefix) }

// ParseInputID validates an externally supplied Input ID.
func ParseInputID(value string) (InputID, error) { return parseID[InputID](value, inputPrefix) }

// ParseTurnID validates an externally supplied Turn ID.
func ParseTurnID(value string) (TurnID, error) { return parseID[TurnID](value, turnPrefix) }

// ParseEventID validates an externally supplied Product-event ID.
func ParseEventID(value string) (EventID, error) { return parseID[EventID](value, eventPrefix) }

// ParseCursor validates an externally supplied Product-event Cursor.
func ParseCursor(value string) (Cursor, error) { return parseID[Cursor](value, cursorPrefix) }

// ParseArtifactID validates an externally supplied Artifact ID.
func ParseArtifactID(value string) (ArtifactID, error) {
	return parseID[ArtifactID](value, artifactPrefix)
}

// ParseApprovalID validates an externally supplied Approval ID.
func ParseApprovalID(value string) (ApprovalID, error) {
	return parseID[ApprovalID](value, approvalPrefix)
}

// ParseRequestID validates an externally supplied request correlation ID.
func ParseRequestID(value string) (RequestID, error) { return parseID[RequestID](value, requestPrefix) }

type opaqueID interface {
	~string
}

func parseID[T opaqueID](value, prefix string) (T, error) {
	if !strings.HasPrefix(value, prefix) || !validPayload(strings.TrimPrefix(value, prefix)) {
		return "", fmt.Errorf("invalid %s identifier", strings.TrimSuffix(prefix, "_"))
	}
	return T(value), nil
}

func validPayload(payload string) bool {
	if len(payload) != 16 {
		return false
	}
	for _, character := range payload {
		if !asciiAlphaNumeric(character) {
			return false
		}
	}
	return true
}

func asciiAlphaNumeric(character rune) bool {
	return (character >= 'a' && character <= 'z') ||
		(character >= 'A' && character <= 'Z') ||
		(character >= '0' && character <= '9')
}

func marshalID[T opaqueID](id T, prefix string) ([]byte, error) {
	if _, err := parseID[T](string(id), prefix); err != nil {
		return nil, err
	}
	return json.Marshal(string(id))
}

func unmarshalID[T opaqueID](data []byte, target *T, prefix string) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("decode %s identifier: %w", strings.TrimSuffix(prefix, "_"), err)
	}
	parsed, err := parseID[T](value, prefix)
	if err != nil {
		return fmt.Errorf("decode %s identifier: %w", strings.TrimSuffix(prefix, "_"), err)
	}
	*target = parsed
	return nil
}

func redactID[T opaqueID](id T, prefix string) string {
	value := string(id)
	if _, err := parseID[T](value, prefix); err != nil {
		return "[INVALID ID]"
	}
	return prefix + "..." + value[len(value)-4:]
}

// String returns the canonical Agent ID.
func (id AgentID) String() string { return string(id) }

// Redacted returns a safe diagnostic Agent ID.
func (id AgentID) Redacted() string { return redactID(id, agentPrefix) }

// LogValue returns a redacted Agent ID for structured logs.
func (id AgentID) LogValue() slog.Value { return slog.StringValue(id.Redacted()) }

// MarshalJSON encodes a validated Agent ID.
func (id AgentID) MarshalJSON() ([]byte, error) { return marshalID(id, agentPrefix) }

// UnmarshalJSON decodes and validates an Agent ID.
func (id *AgentID) UnmarshalJSON(data []byte) error { return unmarshalID(data, id, agentPrefix) }

// String returns the canonical Agent revision ID.
func (id AgentRevisionID) String() string { return string(id) }

// Redacted returns a safe diagnostic Agent revision ID.
func (id AgentRevisionID) Redacted() string { return redactID(id, agentRevisionPrefix) }

// LogValue returns a redacted Agent revision ID for structured logs.
func (id AgentRevisionID) LogValue() slog.Value { return slog.StringValue(id.Redacted()) }

// MarshalJSON encodes a validated Agent revision ID.
func (id AgentRevisionID) MarshalJSON() ([]byte, error) { return marshalID(id, agentRevisionPrefix) }

// UnmarshalJSON decodes and validates an Agent revision ID.
func (id *AgentRevisionID) UnmarshalJSON(data []byte) error {
	return unmarshalID(data, id, agentRevisionPrefix)
}

// String returns the canonical Session ID.
func (id SessionID) String() string { return string(id) }

// Redacted returns a safe diagnostic Session ID.
func (id SessionID) Redacted() string { return redactID(id, sessionPrefix) }

// LogValue returns a redacted Session ID for structured logs.
func (id SessionID) LogValue() slog.Value { return slog.StringValue(id.Redacted()) }

// MarshalJSON encodes a validated Session ID.
func (id SessionID) MarshalJSON() ([]byte, error) { return marshalID(id, sessionPrefix) }

// UnmarshalJSON decodes and validates a Session ID.
func (id *SessionID) UnmarshalJSON(data []byte) error { return unmarshalID(data, id, sessionPrefix) }

// String returns the canonical Input ID.
func (id InputID) String() string { return string(id) }

// Redacted returns a safe diagnostic Input ID.
func (id InputID) Redacted() string { return redactID(id, inputPrefix) }

// LogValue returns a redacted Input ID for structured logs.
func (id InputID) LogValue() slog.Value { return slog.StringValue(id.Redacted()) }

// MarshalJSON encodes a validated Input ID.
func (id InputID) MarshalJSON() ([]byte, error) { return marshalID(id, inputPrefix) }

// UnmarshalJSON decodes and validates an Input ID.
func (id *InputID) UnmarshalJSON(data []byte) error { return unmarshalID(data, id, inputPrefix) }

// String returns the canonical Turn ID.
func (id TurnID) String() string { return string(id) }

// Redacted returns a safe diagnostic Turn ID.
func (id TurnID) Redacted() string { return redactID(id, turnPrefix) }

// LogValue returns a redacted Turn ID for structured logs.
func (id TurnID) LogValue() slog.Value { return slog.StringValue(id.Redacted()) }

// MarshalJSON encodes a validated Turn ID.
func (id TurnID) MarshalJSON() ([]byte, error) { return marshalID(id, turnPrefix) }

// UnmarshalJSON decodes and validates a Turn ID.
func (id *TurnID) UnmarshalJSON(data []byte) error { return unmarshalID(data, id, turnPrefix) }

// String returns the canonical Product-event ID.
func (id EventID) String() string { return string(id) }

// Redacted returns a safe diagnostic Product-event ID.
func (id EventID) Redacted() string { return redactID(id, eventPrefix) }

// LogValue returns a redacted Product-event ID for structured logs.
func (id EventID) LogValue() slog.Value { return slog.StringValue(id.Redacted()) }

// MarshalJSON encodes a validated Product-event ID.
func (id EventID) MarshalJSON() ([]byte, error) { return marshalID(id, eventPrefix) }

// UnmarshalJSON decodes and validates a Product-event ID.
func (id *EventID) UnmarshalJSON(data []byte) error { return unmarshalID(data, id, eventPrefix) }

// String returns the canonical Product-event Cursor.
func (id Cursor) String() string { return string(id) }

// Redacted returns a safe diagnostic Product-event Cursor.
func (id Cursor) Redacted() string { return redactID(id, cursorPrefix) }

// LogValue returns a redacted Product-event Cursor for structured logs.
func (id Cursor) LogValue() slog.Value { return slog.StringValue(id.Redacted()) }

// MarshalJSON encodes a validated Product-event Cursor.
func (id Cursor) MarshalJSON() ([]byte, error) { return marshalID(id, cursorPrefix) }

// UnmarshalJSON decodes and validates a Product-event Cursor.
func (id *Cursor) UnmarshalJSON(data []byte) error { return unmarshalID(data, id, cursorPrefix) }

// String returns the canonical Artifact ID.
func (id ArtifactID) String() string { return string(id) }

// Redacted returns a safe diagnostic Artifact ID.
func (id ArtifactID) Redacted() string { return redactID(id, artifactPrefix) }

// LogValue returns a redacted Artifact ID for structured logs.
func (id ArtifactID) LogValue() slog.Value { return slog.StringValue(id.Redacted()) }

// MarshalJSON encodes a validated Artifact ID.
func (id ArtifactID) MarshalJSON() ([]byte, error) { return marshalID(id, artifactPrefix) }

// UnmarshalJSON decodes and validates an Artifact ID.
func (id *ArtifactID) UnmarshalJSON(data []byte) error { return unmarshalID(data, id, artifactPrefix) }

// String returns the canonical Approval ID.
func (id ApprovalID) String() string { return string(id) }

// Redacted returns a safe diagnostic Approval ID.
func (id ApprovalID) Redacted() string { return redactID(id, approvalPrefix) }

// LogValue returns a redacted Approval ID for structured logs.
func (id ApprovalID) LogValue() slog.Value { return slog.StringValue(id.Redacted()) }

// MarshalJSON encodes a validated Approval ID.
func (id ApprovalID) MarshalJSON() ([]byte, error) { return marshalID(id, approvalPrefix) }

// UnmarshalJSON decodes and validates an Approval ID.
func (id *ApprovalID) UnmarshalJSON(data []byte) error { return unmarshalID(data, id, approvalPrefix) }

// String returns the canonical request correlation ID.
func (id RequestID) String() string { return string(id) }

// Redacted returns a safe diagnostic request correlation ID.
func (id RequestID) Redacted() string { return redactID(id, requestPrefix) }

// LogValue returns a redacted request correlation ID for structured logs.
func (id RequestID) LogValue() slog.Value { return slog.StringValue(id.Redacted()) }

// MarshalJSON encodes a validated request correlation ID.
func (id RequestID) MarshalJSON() ([]byte, error) { return marshalID(id, requestPrefix) }

// UnmarshalJSON decodes and validates a request correlation ID.
func (id *RequestID) UnmarshalJSON(data []byte) error { return unmarshalID(data, id, requestPrefix) }
