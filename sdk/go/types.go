package agentruntime

import (
	"io"
	"time"
)

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

// MaxToolCallsPerTurn bounds one public Tool-call inspection response.
const MaxToolCallsPerTurn = 64

// ToolCallState is the safe public lifecycle of one model Tool intent.
type ToolCallState string

const (
	// ToolCallIntent records model intent without execution authority.
	ToolCallIntent ToolCallState = "intent"
	// ToolCallAwaitingApproval awaits a permitted human decision.
	ToolCallAwaitingApproval ToolCallState = "awaiting_approval"
	// ToolCallAuthorized has a bounded capability grant but no execution outcome.
	ToolCallAuthorized ToolCallState = "authorized"
	// ToolCallExecuting has committed a capability-bound execution intent.
	ToolCallExecuting ToolCallState = "executing"
	// ToolCallSucceeded has a durable terminal successful observation.
	ToolCallSucceeded ToolCallState = "succeeded"
	// ToolCallFailed has a durable terminal safe failure.
	ToolCallFailed ToolCallState = "failed"
	// ToolCallUncertain has an unresolved external-effect outcome.
	ToolCallUncertain ToolCallState = "uncertain"
)

// CapabilityGrant is a caller-safe projection of bounded grant consumption.
// It deliberately omits capability bytes, policy digests, and grant identity.
type CapabilityGrant struct {
	MaximumUses uint32    `json:"maximum_uses"`
	Uses        uint32    `json:"uses"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// ToolExecution is a caller-safe terminal or in-progress tool observation.
type ToolExecution struct {
	State       ToolCallState `json:"state"`
	Failure     *Failure      `json:"failure,omitempty"`
	CreatedAt   time.Time     `json:"created_at"`
	CompletedAt *time.Time    `json:"completed_at,omitempty"`
}

// Clone returns an independent ToolExecution snapshot.
func (execution *ToolExecution) Clone() *ToolExecution {
	if execution == nil {
		return nil
	}
	clone := *execution
	clone.Failure = execution.Failure.Clone()
	if execution.CompletedAt != nil {
		value := *execution.CompletedAt
		clone.CompletedAt = &value
	}
	return &clone
}

// ToolCall is a caller-safe model intent and its derived authorization/execution state.
type ToolCall struct {
	ID        string           `json:"id"`
	Name      string           `json:"name"`
	State     ToolCallState    `json:"state"`
	Approval  *Approval        `json:"approval,omitempty"`
	Grant     *CapabilityGrant `json:"grant,omitempty"`
	Execution *ToolExecution   `json:"execution,omitempty"`
	CreatedAt time.Time        `json:"created_at"`
}

// Clone returns an independent ToolCall snapshot.
func (call ToolCall) Clone() ToolCall {
	clone := call
	if call.Approval != nil {
		value := call.Approval.Clone()
		clone.Approval = &value
	}
	clone.Execution = call.Execution.Clone()
	return clone
}

// ToolCallPage is one bounded owner-scoped Tool-call inspection result.
type ToolCallPage struct {
	Calls     []ToolCall `json:"calls"`
	Truncated bool       `json:"truncated"`
}

// Clone returns an independent ToolCallPage snapshot.
func (page ToolCallPage) Clone() ToolCallPage {
	clone := page
	clone.Calls = make([]ToolCall, len(page.Calls))
	for index := range page.Calls {
		clone.Calls[index] = page.Calls[index].Clone()
	}
	return clone
}

// ToolDefinition describes model-visible intent without granting execution authority.
type ToolDefinition struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// PolicyDecision is the closed disposition an immutable Policy revision gives
// one named Tool. It conveys no credential or executable capability.
type PolicyDecision string

const (
	// PolicyDenied prevents the named Tool from receiving execution authority.
	PolicyDenied PolicyDecision = "denied"
	// PolicyRequiresApproval requires a later durable human decision before the
	// named Tool can receive a bounded capability grant.
	PolicyRequiresApproval PolicyDecision = "requires_approval"
)

// PolicyRule is one bounded, model-independent authorization rule for a named Tool.
type PolicyRule struct {
	ToolName string         `json:"tool_name"`
	Decision PolicyDecision `json:"decision"`
}

// Policy is one immutable, versioned tenant authorization policy. Tool
// execution consumes its durable revision digest; it never receives policy
// administration authority.
type Policy struct {
	Name      string       `json:"name"`
	Revision  uint64       `json:"revision"`
	Digest    string       `json:"digest"`
	Rules     []PolicyRule `json:"rules"`
	CreatedAt time.Time    `json:"created_at"`
}

// Clone returns an independent immutable Policy snapshot.
func (policy Policy) Clone() Policy {
	policy.Rules = append([]PolicyRule(nil), policy.Rules...)
	return policy
}

// CreatePolicyRequest creates the first immutable revision of a named Policy.
type CreatePolicyRequest struct {
	IdempotencyKey string       `json:"idempotency_key"`
	Name           string       `json:"name"`
	Rules          []PolicyRule `json:"rules"`
}

// RevisePolicyRequest creates the next immutable revision of one named Policy.
type RevisePolicyRequest struct {
	IdempotencyKey   string       `json:"idempotency_key"`
	Name             string       `json:"name"`
	ExpectedRevision uint64       `json:"expected_revision"`
	Rules            []PolicyRule `json:"rules"`
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

// ArtifactStream is an authorized immutable Artifact transfer. Callers must
// Close it; reading to EOF verifies the HTTP Digest trailer and exact size.
type ArtifactStream struct {
	Artifact ArtifactReference
	Body     io.ReadCloser
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

// ApprovalState is the public lifecycle state of one human decision request.
type ApprovalState string

const (
	// ApprovalPending awaits an owner decision before any tool execution may be authorized.
	ApprovalPending ApprovalState = "pending"
	// ApprovalApproved records an owner decision that created a bounded internal grant.
	ApprovalApproved ApprovalState = "approved"
	// ApprovalDenied records an owner decision that forbids the requested effect.
	ApprovalDenied ApprovalState = "denied"
	// ApprovalExpired records that the decision window elapsed before a decision.
	ApprovalExpired ApprovalState = "expired"
)

// Approval is a caller-safe immutable projection of a pending or terminal human decision.
type Approval struct {
	ID        ApprovalID    `json:"id"`
	SessionID SessionID     `json:"session_id"`
	TurnID    TurnID        `json:"turn_id"`
	State     ApprovalState `json:"state"`
	ExpiresAt time.Time     `json:"expires_at"`
	DecidedAt *time.Time    `json:"decided_at,omitempty"`
}

// Clone returns an independent Approval snapshot.
func (approval Approval) Clone() Approval {
	clone := approval
	if approval.DecidedAt != nil {
		value := *approval.DecidedAt
		clone.DecidedAt = &value
	}
	return clone
}

// DecideApprovalRequest idempotently records one owner decision for a pending Approval.
type DecideApprovalRequest struct {
	ApprovalID     ApprovalID    `json:"approval_id"`
	Decision       ApprovalState `json:"decision"`
	IdempotencyKey string        `json:"idempotency_key"`
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

// ModelUsage retains provider-neutral token accounting for the latest recorded
// model invocation. Nil values remain unknown; they are never coerced to zero.
type ModelUsage struct {
	InputTokens  *uint64 `json:"input_tokens,omitempty"`
	OutputTokens *uint64 `json:"output_tokens,omitempty"`
}

// Clone returns an independent ModelUsage snapshot.
func (usage *ModelUsage) Clone() *ModelUsage {
	if usage == nil {
		return nil
	}
	clone := *usage
	if usage.InputTokens != nil {
		value := *usage.InputTokens
		clone.InputTokens = &value
	}
	if usage.OutputTokens != nil {
		value := *usage.OutputTokens
		clone.OutputTokens = &value
	}
	return &clone
}

// Turn is an immutable snapshot of one durable progression from Input to outcome.
type Turn struct {
	ID          TurnID      `json:"id"`
	InputID     InputID     `json:"input_id"`
	Position    uint64      `json:"position"`
	State       TurnState   `json:"state"`
	StartedAt   *time.Time  `json:"started_at,omitempty"`
	CompletedAt *time.Time  `json:"completed_at,omitempty"`
	Failure     *Failure    `json:"failure,omitempty"`
	Usage       *ModelUsage `json:"usage,omitempty"`
	// Output is the owner-readable immutable finalized model output, when the
	// model invocation reached a durable successful terminal outcome.
	Output *ArtifactReference `json:"output,omitempty"`
}

// Clone returns an independent Turn snapshot.
func (turn Turn) Clone() Turn {
	clone := turn
	clone.Failure = turn.Failure.Clone()
	clone.Usage = turn.Usage.Clone()
	if turn.Output != nil {
		output := *turn.Output
		clone.Output = &output
	}
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
	// EventProducerGap reports that a producer outcome could not be recovered
	// and the following terminal event is the durable finalization boundary.
	EventProducerGap EventKind = "producer.gap"
	// EventApprovalResolved reports a terminal approved, denied, or expired
	// approval without exposing an action or capability value.
	EventApprovalResolved EventKind = "approval.resolved"
	// EventSandboxOperationFinalized reports that a sandbox-backed operation
	// reached a durable terminal outcome. Backend handles remain private.
	EventSandboxOperationFinalized EventKind = "sandbox_operation.finalized"
	// EventSessionClosing reports that no new Input is accepted while queued work drains.
	EventSessionClosing EventKind = "session.closing"
	// EventSessionCompleted reports a terminal drained Session.
	EventSessionCompleted EventKind = "session.completed"
	// EventSessionCancelled reports a terminal caller-requested Session cancellation.
	EventSessionCancelled EventKind = "session.cancelled"
	// EventSessionFailed reports a terminal runtime-owned Session failure.
	EventSessionFailed EventKind = "session.failed"
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

// CancelSessionRequest terminally cancels a drained Session.
type CancelSessionRequest struct {
	SessionID      SessionID `json:"session_id"`
	IdempotencyKey string    `json:"idempotency_key"`
}
