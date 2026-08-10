package agentruntime

import "time"

const (
	// MaxIdempotencyKeyBytes bounds one public idempotency key before transport-specific limits apply.
	MaxIdempotencyKeyBytes = 128
	// MaxInputParts bounds the number of public Input parts accepted in one request.
	MaxInputParts = 32
	// MaxTextPartBytes bounds one public text Input part.
	MaxTextPartBytes = 64 * 1024
	// MaxSessionViewQueuedTurns bounds the queued Turns included in one Session inspection.
	MaxSessionViewQueuedTurns = 100
)

// ToolDefinition describes model-visible intent without granting execution authority.
type ToolDefinition struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// CreateAgentRequest registers the first immutable revision of an Agent specification.
type CreateAgentRequest struct {
	IdempotencyKey string           `json:"idempotency_key"`
	Name           string           `json:"name"`
	ModelProfile   string           `json:"model_profile"`
	Instructions   string           `json:"instructions"`
	Tools          []ToolDefinition `json:"tools,omitempty"`
}

// ReviseAgentRequest creates another immutable revision of an existing Agent.
type ReviseAgentRequest struct {
	AgentID        AgentID          `json:"agent_id"`
	IdempotencyKey string           `json:"idempotency_key"`
	ModelProfile   string           `json:"model_profile"`
	Instructions   string           `json:"instructions"`
	Tools          []ToolDefinition `json:"tools,omitempty"`
}

// AgentSpecification is one immutable, versioned definition of Agent behavior.
type AgentSpecification struct {
	ID           AgentID          `json:"id"`
	RevisionID   AgentRevisionID  `json:"revision_id"`
	Revision     uint64           `json:"revision"`
	Name         string           `json:"name"`
	ModelProfile string           `json:"model_profile"`
	Instructions string           `json:"instructions"`
	Tools        []ToolDefinition `json:"tools,omitempty"`
	CreatedAt    time.Time        `json:"created_at"`
}

// Clone returns an independent Agent specification snapshot.
func (specification AgentSpecification) Clone() AgentSpecification {
	clone := specification
	clone.Tools = append([]ToolDefinition(nil), specification.Tools...)
	return clone
}

// SessionState is the durable lifecycle state of a Session.
type SessionState string

const (
	// SessionOpen accepts Input and may run a Turn.
	SessionOpen SessionState = "open"
	// SessionClosing drains already accepted Input and rejects new Input.
	SessionClosing SessionState = "closing"
	// SessionCompleted has drained its accepted work.
	SessionCompleted SessionState = "completed"
	// SessionCancelled ended through explicit cancellation.
	SessionCancelled SessionState = "cancelled"
	// SessionFailed ended because the runtime could not safely continue.
	SessionFailed SessionState = "failed"
)

// TurnState is the durable lifecycle state of one Turn.
type TurnState string

const (
	// TurnQueued is durably ordered behind an active Turn.
	TurnQueued TurnState = "queued"
	// TurnRunning is the only Turn currently allowed to progress a Session.
	TurnRunning TurnState = "running"
	// TurnSucceeded completed successfully.
	TurnSucceeded TurnState = "succeeded"
	// TurnFailed completed with a safe Failure.
	TurnFailed TurnState = "failed"
	// TurnCancelled completed after explicit cancellation.
	TurnCancelled TurnState = "cancelled"
)

// CreateSessionRequest creates a Session pinned to one exact Agent revision.
type CreateSessionRequest struct {
	IdempotencyKey string          `json:"idempotency_key"`
	AgentRevision  AgentRevisionID `json:"agent_revision_id"`
}

// Session is an immutable caller snapshot of a durable Session.
type Session struct {
	ID            SessionID       `json:"id"`
	AgentID       AgentID         `json:"agent_id"`
	AgentRevision AgentRevisionID `json:"agent_revision_id"`
	State         SessionState    `json:"state"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

// ContentPartKind identifies one bounded Input content representation.
type ContentPartKind string

const (
	// ContentText contains bounded UTF-8 text.
	ContentText ContentPartKind = "text"
	// ContentArtifact refers to authorized immutable content by metadata.
	ContentArtifact ContentPartKind = "artifact"
)

// ArtifactReference identifies immutable content without exposing a storage URL.
type ArtifactReference struct {
	ID        ArtifactID `json:"id"`
	MediaType string     `json:"media_type"`
	SizeBytes int64      `json:"size_bytes"`
	SHA256    string     `json:"sha256"`
}

// ArtifactDownload is one authorized immutable artifact read.  It contains
// metadata chosen by runtime state and bounded bytes, never a storage URL.
type ArtifactDownload struct {
	Artifact ArtifactReference `json:"artifact"`
	Body     []byte            `json:"body"`
}

// Clone returns an independent authorized artifact read.
func (download ArtifactDownload) Clone() ArtifactDownload {
	download.Body = append([]byte(nil), download.Body...)
	return download
}

// IdempotencyStatus is the safe durable outcome lookup for one exact caller
// scope and idempotency key.  It never exposes request bytes or backend IDs.
type IdempotencyStatus struct {
	OperationID string     `json:"operation_id"`
	Command     string     `json:"command"`
	SessionID   SessionID  `json:"session_id,omitempty"`
	TurnID      TurnID     `json:"turn_id,omitempty"`
	ArtifactID  ArtifactID `json:"artifact_id,omitempty"`
	AcceptedAt  time.Time  `json:"accepted_at"`
}

// ContentPart carries either bounded text or an Artifact reference.
type ContentPart struct {
	Kind     ContentPartKind    `json:"kind"`
	Text     string             `json:"text,omitempty"`
	Artifact *ArtifactReference `json:"artifact,omitempty"`
}

// Clone returns an independent content snapshot.
func (part ContentPart) Clone() ContentPart {
	clone := part
	if part.Artifact != nil {
		artifact := *part.Artifact
		clone.Artifact = &artifact
	}
	return clone
}

// SendInputRequest idempotently submits bounded content to a Session.
type SendInputRequest struct {
	SessionID      SessionID     `json:"session_id"`
	IdempotencyKey string        `json:"idempotency_key"`
	Parts          []ContentPart `json:"parts"`
}

// Input is an immutable accepted Input snapshot.
type Input struct {
	ID         InputID       `json:"id"`
	Parts      []ContentPart `json:"parts"`
	AcceptedAt time.Time     `json:"accepted_at"`
}

// Clone returns an independent Input snapshot.
func (input Input) Clone() Input {
	clone := input
	clone.Parts = make([]ContentPart, len(input.Parts))
	for index := range input.Parts {
		clone.Parts[index] = input.Parts[index].Clone()
	}
	return clone
}

// FailureCode is a stable runtime-owned failure classification.
type FailureCode string

const (
	// FailureInvalidInput means a request violated the public contract.
	FailureInvalidInput FailureCode = "invalid_input"
	// FailureConflict means an idempotency key or state transition conflicted.
	FailureConflict FailureCode = "conflict"
	// FailureNotFound safely covers absent or unauthorized resources.
	FailureNotFound FailureCode = "not_found"
	// FailureUnavailable means durable progress may be retried later.
	FailureUnavailable FailureCode = "unavailable"
	// FailureInternal means the runtime failed without exposing backend details.
	FailureInternal FailureCode = "internal"
)

// Failure is a bounded, provider-neutral terminal Turn failure.
type Failure struct {
	Code      FailureCode       `json:"code"`
	Message   string            `json:"message"`
	Retryable bool              `json:"retryable"`
	Details   map[string]string `json:"details,omitempty"`
}

// Clone returns an independent Failure snapshot.
func (failure *Failure) Clone() *Failure {
	if failure == nil {
		return nil
	}
	clone := *failure
	clone.Details = make(map[string]string, len(failure.Details))
	for key, value := range failure.Details {
		clone.Details[key] = value
	}
	return &clone
}

// Turn is an immutable snapshot of one durable progression from Input to outcome.
type Turn struct {
	ID          TurnID     `json:"id"`
	InputID     InputID    `json:"input_id"`
	Position    uint64     `json:"position"`
	State       TurnState  `json:"state"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Failure     *Failure   `json:"failure,omitempty"`
}

// Clone returns an independent Turn snapshot.
func (turn Turn) Clone() Turn {
	clone := turn
	clone.Failure = turn.Failure.Clone()
	if turn.StartedAt != nil {
		value := *turn.StartedAt
		clone.StartedAt = &value
	}
	if turn.CompletedAt != nil {
		value := *turn.CompletedAt
		clone.CompletedAt = &value
	}
	return clone
}

// SendInputResult identifies both the accepted Input and its exactly-one Turn.
type SendInputResult struct {
	Input Input `json:"input"`
	Turn  Turn  `json:"turn"`
}

// SessionView contains only runtime-owned public Session state and references.
type SessionView struct {
	Session              Session `json:"session"`
	ActiveTurn           *Turn   `json:"active_turn,omitempty"`
	QueuedTurns          []Turn  `json:"queued_turns,omitempty"`
	QueuedTurnCount      uint64  `json:"queued_turn_count"`
	QueuedTurnsTruncated bool    `json:"queued_turns_truncated"`
	RecentEvents         []Event `json:"recent_events,omitempty"`
}

// Clone returns an independent Session inspection snapshot.
func (view SessionView) Clone() SessionView {
	clone := view
	if view.ActiveTurn != nil {
		turn := view.ActiveTurn.Clone()
		clone.ActiveTurn = &turn
	}
	clone.QueuedTurns = cloneTurns(view.QueuedTurns)
	clone.RecentEvents = append([]Event(nil), view.RecentEvents...)
	return clone
}

func cloneTurns(turns []Turn) []Turn {
	clones := make([]Turn, len(turns))
	for index := range turns {
		clones[index] = turns[index].Clone()
	}
	return clones
}

// EventKind identifies a stable Product-event vocabulary entry.
type EventKind string

const (
	// EventSessionCreated reports durable Session creation.
	EventSessionCreated EventKind = "session.created"
	// EventInputAccepted reports durable idempotent Input admission.
	EventInputAccepted EventKind = "input.accepted"
	// EventTurnQueued reports a Turn ordered behind active work.
	EventTurnQueued EventKind = "turn.queued"
	// EventTurnStarted reports that a Turn became active.
	EventTurnStarted EventKind = "turn.started"
	// EventTurnSucceeded reports one terminal successful outcome.
	EventTurnSucceeded EventKind = "turn.succeeded"
	// EventTurnFailed reports one terminal safe Failure outcome.
	EventTurnFailed EventKind = "turn.failed"
	// EventTurnCancelled reports one terminal cancelled outcome.
	EventTurnCancelled EventKind = "turn.cancelled"
	// EventSessionClosing reports that no new Input is accepted while queued work drains.
	EventSessionClosing EventKind = "session.closing"
	// EventSessionCompleted reports a terminal drained Session.
	EventSessionCompleted EventKind = "session.completed"
)

// Event is a bounded, ordered, caller-safe Product event.
type Event struct {
	ID         EventID   `json:"id"`
	Cursor     Cursor    `json:"cursor"`
	Sequence   uint64    `json:"sequence"`
	Kind       EventKind `json:"kind"`
	SessionID  SessionID `json:"session_id"`
	InputID    InputID   `json:"input_id,omitempty"`
	TurnID     TurnID    `json:"turn_id,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}

// EventGap explicitly says a requested replay position is no longer available.
type EventGap struct {
	RequestedAfter Cursor `json:"requested_after"`
	Earliest       Cursor `json:"earliest_available,omitempty"`
	InspectSession bool   `json:"inspect_session"`
}

// EventPage is one bounded replay page and its next opaque position.
type EventPage struct {
	Events     []Event   `json:"events"`
	NextCursor Cursor    `json:"next_cursor,omitempty"`
	Gap        *EventGap `json:"gap,omitempty"`
}

// CancelTurnRequest explicitly cancels one active or queued Turn.
type CancelTurnRequest struct {
	SessionID      SessionID `json:"session_id"`
	TurnID         TurnID    `json:"turn_id"`
	IdempotencyKey string    `json:"idempotency_key"`
}

// CloseSessionRequest stops new admission and drains already accepted Input.
type CloseSessionRequest struct {
	SessionID      SessionID `json:"session_id"`
	IdempotencyKey string    `json:"idempotency_key"`
}
