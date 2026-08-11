// Package runtimestate defines the metadata-only S2/S7 runtime lifecycle authority.
//
// It deliberately contains neither a storage implementation nor raw Agent, Input,
// model, tool, or sandbox bytes. Implementations validate a runtimecontent handoff
// before persisting only the committed Reference metadata.
package runtimestate

import (
	"context"
	"errors"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

// Store failures are deliberately storage-neutral. Implementations must not
// return a database, object-store, Temporal, or provider error through this boundary.
var (
	// ErrConflict reports a legal request that cannot apply to the current authoritative state.
	ErrConflict = errors.New("runtime state conflict")
	// ErrNotFoundOrDenied prevents resource enumeration across authorization boundaries.
	ErrNotFoundOrDenied = errors.New("runtime state not found or denied")
	// ErrUnavailable reports a transient authority failure without exposing its adapter.
	ErrUnavailable = errors.New("runtime state unavailable")
	// ErrIntegrity reports a detected metadata, receipt, or reference commitment mismatch.
	ErrIntegrity = errors.New("runtime state integrity failure")
	// ErrReceiptExpired reports a retained idempotency key whose result can no longer be replayed.
	ErrReceiptExpired = errors.New("runtime state idempotency receipt expired")
)

// Authority identifies the narrow authority with which a command or query is made.
type Authority string

const (
	// AuthorityTenantAdministrator may mutate tenant-catalog Agent revision metadata.
	AuthorityTenantAdministrator Authority = "tenant_administrator"
	// AuthoritySessionOwner may operate on one principal-owned Session.
	AuthoritySessionOwner Authority = "session_owner"
	// AuthorityRuntimeWorker may record fenced runtime invocation work.
	AuthorityRuntimeWorker Authority = "runtime_worker"
	// AuthorityAuditReader may read retained audit metadata.
	AuthorityAuditReader Authority = "audit_reader"
	// AuthorityOutboxPublisher may claim or acknowledge tenant Outbox work.
	AuthorityOutboxPublisher Authority = "outbox_publisher"
)

// MutationScope is authenticated application metadata, never a caller-supplied database predicate.
type MutationScope struct {
	Tenant    runtimecontent.TenantID
	Principal runtimecontent.PrincipalID
	Authority Authority
}

// RequestDigest commits the compiler-canonical, identity-free command request used for idempotency.
type RequestDigest string

// OperationID is the durable external-effect key owned by the runtime.
type OperationID string

// InvocationID identifies one invocation attempt without exposing a provider handle.
type InvocationID string

// AuditFactID identifies one append-only audit metadata record.
type AuditFactID string

// OutboxID identifies one durable publication/reconciliation work record.
type OutboxID string

// AgentRevisionRecord is persisted revision metadata; the behavior body remains in runtimecontent.
type AgentRevisionRecord struct {
	Tenant        runtimecontent.TenantID
	AgentID       agentruntime.AgentID         `json:",omitempty"`
	RevisionID    agentruntime.AgentRevisionID `json:",omitempty"`
	Revision      uint64
	Name          string
	ModelProfile  string
	Specification runtimecontent.Reference
	CreatedAt     time.Time
	RetainUntil   time.Time
}

// PolicyRevisionRecord is immutable tenant authorization metadata. Rules are
// bounded public vocabulary; no raw secret, credential, or executable action
// is retained in state.
type PolicyRevisionRecord struct {
	Tenant      runtimecontent.TenantID
	Name        string
	Revision    uint64
	Digest      string
	Rules       []agentruntime.PolicyRule
	CreatedAt   time.Time
	RetainUntil time.Time
}

// Clone returns an independent Policy revision snapshot.
func (record PolicyRevisionRecord) Clone() PolicyRevisionRecord {
	record.Rules = append([]agentruntime.PolicyRule(nil), record.Rules...)
	return record
}

// Clone returns an independent Agent revision metadata snapshot.
func (record AgentRevisionRecord) Clone() AgentRevisionRecord { return record }

// SessionRecord is the revision-pinned, metadata-only Session aggregate projection.
type SessionRecord struct {
	Tenant      runtimecontent.TenantID
	Principal   runtimecontent.PrincipalID
	SessionID   agentruntime.SessionID       `json:",omitempty"`
	AgentID     agentruntime.AgentID         `json:",omitempty"`
	RevisionID  agentruntime.AgentRevisionID `json:",omitempty"`
	State       agentruntime.SessionState
	Version     uint64
	CreatedAt   time.Time
	UpdatedAt   time.Time
	RetainUntil time.Time
}

// Clone returns an independent Session metadata snapshot.
func (record SessionRecord) Clone() SessionRecord { return record }

// InputRecord refers to the immutable canonical Input envelope; it never contains parts or text.
type InputRecord struct {
	Tenant         runtimecontent.TenantID
	Principal      runtimecontent.PrincipalID
	SessionID      agentruntime.SessionID `json:",omitempty"`
	InputID        agentruntime.InputID   `json:",omitempty"`
	Content        runtimecontent.Reference
	AcceptedAt     time.Time
	RetentionUntil time.Time
}

// Clone returns an independent Input metadata snapshot.
func (record InputRecord) Clone() InputRecord { return record }

// ArtifactRecord is immutable state metadata for one principal-readable blob.
// Its reference never contains a bucket/key or content bytes.
type ArtifactRecord struct {
	Tenant      runtimecontent.TenantID
	Principal   runtimecontent.PrincipalID
	ArtifactID  agentruntime.ArtifactID `json:",omitempty"`
	SessionID   agentruntime.SessionID  `json:",omitempty"`
	TurnID      agentruntime.TurnID     `json:",omitempty"`
	Reference   runtimecontent.Reference
	CreatedAt   time.Time
	RetainUntil time.Time
}

// Clone returns an independent Artifact metadata snapshot.
func (record ArtifactRecord) Clone() ArtifactRecord { return record }

// ConversationRecord is one immutable semantic-context entry in a
// session-owned, optimistic-versioned sequence.
type ConversationRecord struct {
	Tenant      runtimecontent.TenantID
	Principal   runtimecontent.PrincipalID
	SessionID   agentruntime.SessionID `json:",omitempty"`
	Version     uint64
	Reference   runtimecontent.Reference
	CreatedAt   time.Time
	RetainUntil time.Time
}

// Clone returns an independent conversation metadata snapshot.
func (record ConversationRecord) Clone() ConversationRecord { return record }

// ToolIntentRecord separates a model request from any execution authority.
type ToolIntentRecord struct {
	Tenant               runtimecontent.TenantID
	Principal            runtimecontent.PrincipalID
	SessionID            agentruntime.SessionID `json:",omitempty"`
	TurnID               agentruntime.TurnID    `json:",omitempty"`
	ToolCallID           string
	ToolName             string
	ActionDigest         string
	PolicyRevisionDigest string
	CreatedAt            time.Time
	RetainUntil          time.Time
}

func (record ToolIntentRecord) Clone() ToolIntentRecord { return record }

// CapabilityGrantRecord is bounded metadata only; secret capability material is never persisted.
type CapabilityGrantRecord struct {
	Tenant               runtimecontent.TenantID
	Principal            runtimecontent.PrincipalID
	GrantID              string
	ToolCallID           string
	CapabilityDigest     string
	MaximumUses          uint32
	Uses                 uint32
	ExpiresAt            time.Time
	PolicyRevisionDigest string
	CreatedAt            time.Time
	RetainUntil          time.Time
}

func (record CapabilityGrantRecord) Clone() CapabilityGrantRecord { return record }

// ApprovalRecord is durable bounded approval metadata governed by a Session/Turn.
type ApprovalRecord struct {
	Tenant               runtimecontent.TenantID
	Principal            runtimecontent.PrincipalID
	ApprovalID           string
	SessionID            agentruntime.SessionID `json:",omitempty"`
	TurnID               agentruntime.TurnID    `json:",omitempty"`
	ToolCallID           string
	ActionDigest         string
	PolicyRevisionDigest string
	State                string
	CapabilityDigest     string
	MaximumUses          uint32
	ExpiresAt            time.Time
	Decision             string
	DecidedAt            *time.Time
	CreatedAt            time.Time
	RetainUntil          time.Time
}

func (record ApprovalRecord) Clone() ApprovalRecord {
	clone := record
	if record.DecidedAt != nil {
		value := *record.DecidedAt
		clone.DecidedAt = &value
	}
	return clone
}

// TurnRecord is the bounded execution state for one accepted Input.
type TurnRecord struct {
	Tenant         runtimecontent.TenantID
	Principal      runtimecontent.PrincipalID
	SessionID      agentruntime.SessionID `json:",omitempty"`
	TurnID         agentruntime.TurnID    `json:",omitempty"`
	InputID        agentruntime.InputID   `json:",omitempty"`
	Position       uint64
	State          agentruntime.TurnState
	Version        uint64
	StartedAt      *time.Time
	CompletedAt    *time.Time
	Failure        *agentruntime.Failure
	RetentionUntil time.Time
}

// Clone returns an independent Turn metadata snapshot.
func (record TurnRecord) Clone() TurnRecord {
	clone := record
	clone.Failure = record.Failure.Clone()
	if record.StartedAt != nil {
		value := *record.StartedAt
		clone.StartedAt = &value
	}
	if record.CompletedAt != nil {
		value := *record.CompletedAt
		clone.CompletedAt = &value
	}
	return clone
}

// InvocationState describes durable provider-effect intent and observation, not a provider state machine.
type InvocationState string

const (
	// InvocationIntent means the external-effect intent committed before dispatch.
	InvocationIntent InvocationState = "intent"
	// InvocationSucceeded means the exact fenced operation produced a safe result reference.
	InvocationSucceeded InvocationState = "succeeded"
	// InvocationFailed means the exact fenced operation produced a safe terminal failure.
	InvocationFailed InvocationState = "failed"
	// InvocationUncertain means recovery could not prove an external-effect outcome.
	InvocationUncertain InvocationState = "uncertain"
	// InvocationCancelled means the invocation cannot produce a winning terminal outcome.
	InvocationCancelled InvocationState = "cancelled"
)

// ModelUsage retains provider-neutral token accounting. Nil fields mean the
// provider did not report that value; unknown is never coerced to zero.
type ModelUsage struct {
	InputTokens  *uint64
	OutputTokens *uint64
}

// Clone returns an independent usage snapshot.
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

// InvocationRecord retains only the external-effect identity, fence, safe references and outcome metadata.
type InvocationRecord struct {
	Tenant         runtimecontent.TenantID
	Principal      runtimecontent.PrincipalID
	SessionID      agentruntime.SessionID `json:",omitempty"`
	TurnID         agentruntime.TurnID    `json:",omitempty"`
	InvocationID   InvocationID
	OperationID    OperationID
	Ordinal        uint64
	Fence          uint64
	State          InvocationState
	Result         *runtimecontent.Reference
	Failure        *agentruntime.Failure
	Usage          *ModelUsage
	CreatedAt      time.Time
	UpdatedAt      time.Time
	RetentionUntil time.Time
}

// Clone returns an independent invocation metadata snapshot.
func (record InvocationRecord) Clone() InvocationRecord {
	clone := record
	clone.Failure = record.Failure.Clone()
	clone.Usage = record.Usage.Clone()
	if record.Result != nil {
		result := *record.Result
		clone.Result = &result
	}
	return clone
}

// ProductEventRecord is an ordered safe event with references rather than a payload body.
type ProductEventRecord struct {
	Tenant         runtimecontent.TenantID
	Principal      runtimecontent.PrincipalID
	SessionID      agentruntime.SessionID `json:",omitempty"`
	Sequence       uint64
	Cursor         agentruntime.Cursor  `json:",omitempty"`
	EventID        agentruntime.EventID `json:",omitempty"`
	Kind           agentruntime.EventKind
	InputID        agentruntime.InputID `json:",omitempty"`
	TurnID         agentruntime.TurnID  `json:",omitempty"`
	OperationID    OperationID
	OccurredAt     time.Time
	RetentionUntil time.Time
}

// Clone returns an independent product-event metadata snapshot.
func (record ProductEventRecord) Clone() ProductEventRecord { return record }

// AuditFactRecord is an append-only, redacted audit fact independent from transient logs.
type AuditFactRecord struct {
	Tenant         runtimecontent.TenantID
	AuditFactID    AuditFactID
	OperationID    OperationID
	Actor          runtimecontent.PrincipalID
	Kind           string
	SessionID      agentruntime.SessionID `json:",omitempty"`
	TurnID         agentruntime.TurnID    `json:",omitempty"`
	OccurredAt     time.Time
	RetentionUntil time.Time
}

// Clone returns an independent audit metadata snapshot.
func (record AuditFactRecord) Clone() AuditFactRecord { return record }

// OutboxState describes durable publication/reconciliation work, never exactly-once publication.
type OutboxState string

const (
	// OutboxPending is committed work not currently held by a publisher.
	OutboxPending OutboxState = "pending"
	// OutboxClaimed is work leased to one publisher for at-least-once delivery.
	OutboxClaimed OutboxState = "claimed"
	// OutboxPublished is work whose publication acknowledgement was recorded.
	OutboxPublished OutboxState = "published"
	// OutboxReconcile is work requiring explicit reconciliation before it can be finalized.
	OutboxReconcile OutboxState = "reconcile"
)

// OutboxRecord refers to a committed aggregate effect without copying its event payload.
type OutboxRecord struct {
	Tenant           runtimecontent.TenantID
	Principal        runtimecontent.PrincipalID
	OutboxID         OutboxID
	Aggregate        string
	AggregateVersion uint64
	Version          uint64
	EventID          agentruntime.EventID `json:",omitempty"`
	// EventKind is the closed product-event route. It lets a private publisher
	// select work from durable state without loading an event payload or a
	// runtime-content object.
	EventKind         agentruntime.EventKind `json:",omitempty"`
	EventSequence     uint64                 `json:",omitempty"`
	OperationID       OperationID
	SessionID         agentruntime.SessionID `json:",omitempty"`
	TurnID            agentruntime.TurnID    `json:",omitempty"`
	InvocationID      InvocationID
	InvocationOrdinal uint64
	InvocationFence   uint64
	SessionVersion    uint64
	TurnVersion       uint64
	State             OutboxState
	ClaimedBy         string
	ClaimUntil        *time.Time
	CommittedAt       time.Time
	RetentionUntil    time.Time
}

// Clone returns an independent Outbox metadata snapshot.
func (record OutboxRecord) Clone() OutboxRecord {
	clone := record
	if record.ClaimUntil != nil {
		value := *record.ClaimUntil
		clone.ClaimUntil = &value
	}
	return clone
}

// MutationReceipt records exact idempotency resolution without retaining a raw request.
type MutationReceipt struct {
	Scope               MutationScope
	IdempotencyKey      string
	OperationID         OperationID
	Command             string
	RequestDigest       RequestDigest
	AgentID             agentruntime.AgentID         `json:",omitempty"`
	RevisionID          agentruntime.AgentRevisionID `json:",omitempty"`
	SessionID           agentruntime.SessionID       `json:",omitempty"`
	InputID             agentruntime.InputID         `json:",omitempty"`
	TurnID              agentruntime.TurnID          `json:",omitempty"`
	ArtifactID          agentruntime.ArtifactID      `json:",omitempty"`
	PolicyName          string
	PolicyRevision      uint64
	ConversationVersion uint64
	AcceptedAt          time.Time
	RetentionUntil      time.Time
}

// Clone returns an independent mutation receipt snapshot.
func (receipt MutationReceipt) Clone() MutationReceipt { return receipt }

// EffectSet is atomically committed with a successful lifecycle mutation.
type EffectSet struct {
	Events []ProductEventRecord
	Audit  []AuditFactRecord
	Outbox []OutboxRecord
}

// Clone returns an independent effect set.
func (effects EffectSet) Clone() EffectSet {
	clone := EffectSet{
		Events: append([]ProductEventRecord(nil), effects.Events...),
		Audit:  append([]AuditFactRecord(nil), effects.Audit...),
		Outbox: make([]OutboxRecord, len(effects.Outbox)),
	}
	for index := range effects.Outbox {
		clone.Outbox[index] = effects.Outbox[index].Clone()
	}
	return clone
}

// RegisterAgentRevisionCommand allocates an initial Agent or next immutable revision from an opaque body handoff.
type RegisterAgentRevisionCommand struct {
	Scope            MutationScope
	IdempotencyKey   string
	AgentID          agentruntime.AgentID // empty allocates a new Agent
	ExpectedRevision uint64               // zero only when AgentID is empty
	Specification    runtimecontent.ContentHandoff
}

// RegisterPolicyRevisionCommand creates an initial or next immutable policy
// revision. It is tenant-administrator-only and is deliberately independent
// from ordinary Session commands.
type RegisterPolicyRevisionCommand struct {
	Scope            MutationScope
	IdempotencyKey   string
	Name             string
	ExpectedRevision uint64
	Rules            []agentruntime.PolicyRule
}

// Owned returns an independent policy-revision command snapshot.
func (command RegisterPolicyRevisionCommand) Owned() RegisterPolicyRevisionCommand {
	command.Rules = append([]agentruntime.PolicyRule(nil), command.Rules...)
	return command
}

// Owned returns a value-owned command. ContentHandoff is opaque and immutable to callers.
func (command RegisterAgentRevisionCommand) Owned() RegisterAgentRevisionCommand {
	return command
}

// CreateSessionCommand pins a principal-owned Session to one exact immutable revision.
type CreateSessionCommand struct {
	Scope          MutationScope
	IdempotencyKey string
	RevisionID     agentruntime.AgentRevisionID
}

// Owned returns a value-owned command.
func (command CreateSessionCommand) Owned() CreateSessionCommand {
	return command
}

// AdmitInputCommand creates exactly one Input and ordered Turn from an opaque Input-envelope handoff.
type AdmitInputCommand struct {
	Scope          MutationScope
	IdempotencyKey string
	SessionID      agentruntime.SessionID
	Input          runtimecontent.ContentHandoff
}

// RegisterArtifactCommand records a worker-produced immutable artifact only
// after the content store issued an opaque staged handoff for the same owner.
type RegisterArtifactCommand struct {
	Scope          MutationScope
	IdempotencyKey string
	SessionID      agentruntime.SessionID
	TurnID         agentruntime.TurnID
	Artifact       runtimecontent.ContentHandoff
}

// Owned returns a value-owned artifact command.
func (command RegisterArtifactCommand) Owned() RegisterArtifactCommand { return command }

// AppendConversationCommand appends one immutable entry under expected-version
// concurrency. It is worker-owned because providers/tools, not public clients,
// establish semantic context.
type AppendConversationCommand struct {
	Scope           MutationScope
	IdempotencyKey  string
	SessionID       agentruntime.SessionID
	ExpectedVersion uint64
	Entry           runtimecontent.ContentHandoff
}

// Owned returns a value-owned conversation append command.
func (command AppendConversationCommand) Owned() AppendConversationCommand { return command }

// RecordToolIntentCommand records model intent; it grants no execution authority.
type RecordToolIntentCommand struct {
	Scope                                                    MutationScope
	IdempotencyKey                                           string
	SessionID                                                agentruntime.SessionID
	TurnID                                                   agentruntime.TurnID
	ToolCallID, ToolName, ActionDigest, PolicyRevisionDigest string
}

func (command RecordToolIntentCommand) Owned() RecordToolIntentCommand { return command }

// RequestApprovalCommand creates bounded pending approval metadata for a recorded intent.
type RequestApprovalCommand struct {
	Scope                                                                        MutationScope
	IdempotencyKey                                                               string
	SessionID                                                                    agentruntime.SessionID
	TurnID                                                                       agentruntime.TurnID
	ToolCallID, ApprovalID, ActionDigest, PolicyRevisionDigest, CapabilityDigest string
	MaximumUses                                                                  uint32
	ExpiresAt                                                                    time.Time
}

func (command RequestApprovalCommand) Owned() RequestApprovalCommand {
	command.ExpiresAt = normalizeTime(command.ExpiresAt)
	return command
}

// DecideApprovalCommand is a principal-authorized, idempotent terminal decision.
type DecideApprovalCommand struct {
	Scope                                MutationScope
	IdempotencyKey, ApprovalID, Decision string
}

func (command DecideApprovalCommand) Owned() DecideApprovalCommand { return command }

// ConsumeCapabilityGrantCommand records one worker-owned use of an approved
// grant before the associated external tool execution may begin.
type ConsumeCapabilityGrantCommand struct {
	Scope                               MutationScope
	IdempotencyKey, GrantID, ToolCallID string
	PolicyRevisionDigest                string
	SessionID                           agentruntime.SessionID
	TurnID                              agentruntime.TurnID
}

// Owned returns a value-owned capability grant consumption command.
func (command ConsumeCapabilityGrantCommand) Owned() ConsumeCapabilityGrantCommand { return command }

// Owned returns a value-owned command. ContentHandoff is opaque and immutable to callers.
func (command AdmitInputCommand) Owned() AdmitInputCommand {
	return command
}

// BeginInvocationAttempt records intent before an external model effect may be dispatched.
type BeginInvocationAttemptCommand struct {
	Scope                  MutationScope
	IdempotencyKey         string
	SessionID              agentruntime.SessionID
	TurnID                 agentruntime.TurnID
	OperationID            OperationID
	ExpectedSessionVersion uint64
	ExpectedTurnVersion    uint64
	ExpectedFence          uint64
}

// Owned returns a value-owned command.
func (command BeginInvocationAttemptCommand) Owned() BeginInvocationAttemptCommand {
	return command
}

// RecordInvocationOutcomeCommand records a fenced safe outcome for one exact operation.
type RecordInvocationOutcomeCommand struct {
	Scope                  MutationScope
	IdempotencyKey         string
	SessionID              agentruntime.SessionID
	TurnID                 agentruntime.TurnID
	OperationID            OperationID
	Ordinal                uint64
	Fence                  uint64
	Outcome                InvocationState
	Result                 *runtimecontent.Reference
	Failure                *agentruntime.Failure
	Usage                  *ModelUsage
	ExpectedSessionVersion uint64
	ExpectedTurnVersion    uint64
}

// Owned returns a value-owned command and clones all caller-owned pointer metadata.
func (command RecordInvocationOutcomeCommand) Owned() RecordInvocationOutcomeCommand {
	command.Failure = command.Failure.Clone()
	command.Usage = command.Usage.Clone()
	if command.Result != nil {
		result := *command.Result
		command.Result = &result
	}
	return command
}

// TerminalOutcome binds Turn settlement to one accepted invocation outcome or explicit non-model failure.
type TerminalOutcome struct {
	OperationID OperationID
	Ordinal     uint64
	Fence       uint64
	State       agentruntime.TurnState
	Failure     *agentruntime.Failure
}

// Clone returns an independent terminal outcome.
func (outcome TerminalOutcome) Clone() TerminalOutcome {
	clone := outcome
	clone.Failure = outcome.Failure.Clone()
	return clone
}

// Owned returns a value-owned terminal outcome.
func (outcome TerminalOutcome) Owned() TerminalOutcome { return outcome.Clone() }

// SettleTurnCommand terminally settles a current running Turn and may promote one queued Turn.
type SettleTurnCommand struct {
	Scope                  MutationScope
	IdempotencyKey         string
	SessionID              agentruntime.SessionID
	TurnID                 agentruntime.TurnID
	ExpectedSessionVersion uint64
	ExpectedTurnVersion    uint64
	Outcome                TerminalOutcome
}

// Owned returns a value-owned command and terminal outcome.
func (command SettleTurnCommand) Owned() SettleTurnCommand {
	command.Outcome = command.Outcome.Owned()
	return command
}

// CancelTurnCommand terminally cancels a running or queued Turn.
type CancelTurnCommand struct {
	Scope          MutationScope
	IdempotencyKey string
	SessionID      agentruntime.SessionID
	TurnID         agentruntime.TurnID
}

// Owned returns a value-owned command.
func (command CancelTurnCommand) Owned() CancelTurnCommand {
	return command
}

// CloseSessionCommand rejects future admission and completes only after accepted work drains.
type CloseSessionCommand struct {
	Scope          MutationScope
	IdempotencyKey string
	SessionID      agentruntime.SessionID
}

// Owned returns a value-owned command.
func (command CloseSessionCommand) Owned() CloseSessionCommand {
	return command
}

// RegisterAgentRevisionResult returns the committed immutable revision and its declared effects.
type RegisterAgentRevisionResult struct {
	Revision AgentRevisionRecord
	Receipt  MutationReceipt
	Effects  EffectSet
}

// RegisterPolicyRevisionResult returns one committed immutable policy revision.
type RegisterPolicyRevisionResult struct {
	Policy  PolicyRevisionRecord
	Receipt MutationReceipt
	Effects EffectSet
}

// CreateSessionResult returns the committed revision-pinned Session and its declared effects.
type CreateSessionResult struct {
	Session SessionRecord
	Receipt MutationReceipt
	Effects EffectSet
}

// AdmitInputResult returns the accepted metadata-only Input, ordered Turn, and declared effects.
type AdmitInputResult struct {
	Input   InputRecord
	Turn    TurnRecord
	Session SessionRecord
	Receipt MutationReceipt
	Effects EffectSet
}

// RegisterArtifactResult returns one immutable artifact and its audit/outbox effects.
type RegisterArtifactResult struct {
	Artifact ArtifactRecord
	Receipt  MutationReceipt
	Effects  EffectSet
}

// AppendConversationResult returns one immutable sequence entry and derived effects.
type AppendConversationResult struct {
	Conversation ConversationRecord
	Receipt      MutationReceipt
	Effects      EffectSet
}

// BeginInvocationAttemptResult returns the committed fenced invocation intent and declared effects.
type BeginInvocationAttemptResult struct {
	Invocation InvocationRecord
	Session    SessionRecord
	Turn       TurnRecord
	Receipt    MutationReceipt
	Effects    EffectSet
}

// RecordInvocationOutcomeResult returns the committed safe invocation outcome and declared effects.
type RecordInvocationOutcomeResult struct {
	Invocation InvocationRecord
	Receipt    MutationReceipt
	Effects    EffectSet
}

// SettleTurnResult returns the terminal Turn, Session, optional promotion, and declared effects.
type SettleTurnResult struct {
	Session  SessionRecord
	Turn     TurnRecord
	Promoted *TurnRecord
	Receipt  MutationReceipt
	Effects  EffectSet
}

// CancelTurnResult returns the cancelled Turn, Session, optional promotion, and declared effects.
type CancelTurnResult struct {
	Session  SessionRecord
	Turn     TurnRecord
	Promoted *TurnRecord
	Receipt  MutationReceipt
	Effects  EffectSet
}

// CloseSessionResult returns the Session after closing or completing and its declared effects.
type CloseSessionResult struct {
	Session SessionRecord
	Receipt MutationReceipt
	Effects EffectSet
}

// ClaimOutboxResult records the exact replay-safe lease acquisition outcome.
type ClaimOutboxResult struct {
	Record  OutboxRecord
	Receipt MutationReceipt
}

// AcknowledgeOutboxResult records the exact replay-safe publication acknowledgement outcome.
type AcknowledgeOutboxResult struct {
	Record  OutboxRecord
	Receipt MutationReceipt
}

// Clone returns an independent RegisterAgentRevision result.
func (result RegisterAgentRevisionResult) Clone() RegisterAgentRevisionResult {
	result.Revision, result.Receipt, result.Effects = result.Revision.Clone(), result.Receipt.Clone(), result.Effects.Clone()
	return result
}

// Clone returns an independent policy-revision result.
func (result RegisterPolicyRevisionResult) Clone() RegisterPolicyRevisionResult {
	result.Policy, result.Receipt, result.Effects = result.Policy.Clone(), result.Receipt.Clone(), result.Effects.Clone()
	return result
}

// Clone returns an independent CreateSession result.
func (result CreateSessionResult) Clone() CreateSessionResult {
	result.Session, result.Receipt, result.Effects = result.Session.Clone(), result.Receipt.Clone(), result.Effects.Clone()
	return result
}

// Clone returns an independent AdmitInput result.
func (result AdmitInputResult) Clone() AdmitInputResult {
	result.Input, result.Turn, result.Session = result.Input.Clone(), result.Turn.Clone(), result.Session.Clone()
	result.Receipt, result.Effects = result.Receipt.Clone(), result.Effects.Clone()
	return result
}

// Clone returns an independent artifact registration result.
func (result RegisterArtifactResult) Clone() RegisterArtifactResult {
	result.Artifact, result.Receipt, result.Effects = result.Artifact.Clone(), result.Receipt.Clone(), result.Effects.Clone()
	return result
}

// Clone returns an independent conversation append result.
func (result AppendConversationResult) Clone() AppendConversationResult {
	result.Conversation, result.Receipt, result.Effects = result.Conversation.Clone(), result.Receipt.Clone(), result.Effects.Clone()
	return result
}

// Clone returns an independent BeginInvocationAttempt result.
func (result BeginInvocationAttemptResult) Clone() BeginInvocationAttemptResult {
	result.Invocation, result.Session, result.Turn = result.Invocation.Clone(), result.Session.Clone(), result.Turn.Clone()
	result.Receipt, result.Effects = result.Receipt.Clone(), result.Effects.Clone()
	return result
}

// Clone returns an independent RecordInvocationOutcome result.
func (result RecordInvocationOutcomeResult) Clone() RecordInvocationOutcomeResult {
	result.Invocation, result.Receipt, result.Effects = result.Invocation.Clone(), result.Receipt.Clone(), result.Effects.Clone()
	return result
}

// Clone returns an independent SettleTurn result.
func (result SettleTurnResult) Clone() SettleTurnResult {
	result.Session, result.Turn = result.Session.Clone(), result.Turn.Clone()
	result.Receipt, result.Effects = result.Receipt.Clone(), result.Effects.Clone()
	if result.Promoted != nil {
		promoted := result.Promoted.Clone()
		result.Promoted = &promoted
	}
	return result
}

// Clone returns an independent CancelTurn result.
func (result CancelTurnResult) Clone() CancelTurnResult {
	result.Session, result.Turn = result.Session.Clone(), result.Turn.Clone()
	result.Receipt, result.Effects = result.Receipt.Clone(), result.Effects.Clone()
	if result.Promoted != nil {
		promoted := result.Promoted.Clone()
		result.Promoted = &promoted
	}
	return result
}

// Clone returns an independent CloseSession result.
func (result CloseSessionResult) Clone() CloseSessionResult {
	result.Session, result.Receipt, result.Effects = result.Session.Clone(), result.Receipt.Clone(), result.Effects.Clone()
	return result
}

// Clone returns an independent Outbox claim result.
func (result ClaimOutboxResult) Clone() ClaimOutboxResult {
	result.Record, result.Receipt = result.Record.Clone(), result.Receipt.Clone()
	return result
}

// Clone returns an independent Outbox acknowledgement result.
func (result AcknowledgeOutboxResult) Clone() AcknowledgeOutboxResult {
	result.Record, result.Receipt = result.Record.Clone(), result.Receipt.Clone()
	return result
}

// AgentRevisionQuery is a tenant-scoped metadata query; content requires a separate runtimecontent read capability.
type AgentRevisionQuery struct {
	Scope      MutationScope
	AgentID    agentruntime.AgentID
	RevisionID agentruntime.AgentRevisionID
}

// PolicyRevisionQuery is a tenant-administrator scoped immutable policy query.
type PolicyRevisionQuery struct {
	Scope    MutationScope
	Name     string
	Revision uint64
}

// SessionViewQuery requests one bounded principal-scoped Session projection.
type SessionViewQuery struct {
	Scope            MutationScope
	SessionID        agentruntime.SessionID
	RecentEventLimit uint32
	QueuedTurnLimit  uint32
}

// TurnQuery requests one exact principal-scoped Turn projection.
type TurnQuery struct {
	Scope     MutationScope
	SessionID agentruntime.SessionID
	TurnID    agentruntime.TurnID
}

// ArtifactQuery requests one principal-authorized artifact metadata projection.
type ArtifactQuery struct {
	Scope      MutationScope
	ArtifactID agentruntime.ArtifactID
}

// InvocationQuery resolves one exact principal-scoped operation for recovery without a provider handle.
type InvocationQuery struct {
	Scope       MutationScope
	SessionID   agentruntime.SessionID
	TurnID      agentruntime.TurnID
	OperationID OperationID
}

// EventsQuery requests one bounded principal-scoped Product-event replay page.
type EventsQuery struct {
	Scope     MutationScope
	SessionID agentruntime.SessionID
	After     agentruntime.Cursor
	Limit     uint32
}

// MutationReceiptQuery requests one ownership-scoped idempotency receipt.
type MutationReceiptQuery struct {
	Scope          MutationScope
	IdempotencyKey string
}

// AuditQuery requests one bounded separately authorized audit page.
type AuditQuery struct {
	Scope MutationScope
	After AuditFactID
	Limit uint32
}

// OutboxQuery requests one bounded publisher-authorized Outbox work page.
type OutboxQuery struct {
	Scope MutationScope
	After OutboxID
	Limit uint32
}

// SessionView contains only bounded metadata projections and safe event references.
type SessionView struct {
	Session         SessionRecord
	ActiveTurn      *TurnRecord
	QueuedTurns     []TurnRecord
	QueuedTurnCount uint64
	QueuedTruncated bool
	RecentEvents    []ProductEventRecord
}

// Clone returns an independent Session view.
func (view SessionView) Clone() SessionView {
	clone := view
	if view.ActiveTurn != nil {
		turn := view.ActiveTurn.Clone()
		clone.ActiveTurn = &turn
	}
	clone.QueuedTurns = make([]TurnRecord, len(view.QueuedTurns))
	for index := range view.QueuedTurns {
		clone.QueuedTurns[index] = view.QueuedTurns[index].Clone()
	}
	clone.RecentEvents = append([]ProductEventRecord(nil), view.RecentEvents...)
	return clone
}

// EventPage reports ordered product events or an explicit retention/producer gap.
type EventPage struct {
	Events     []ProductEventRecord
	NextCursor agentruntime.Cursor
	Gap        *agentruntime.EventGap
}

// Clone returns an independent event page.
func (page EventPage) Clone() EventPage {
	clone := page
	clone.Events = append([]ProductEventRecord(nil), page.Events...)
	if page.Gap != nil {
		gap := *page.Gap
		clone.Gap = &gap
	}
	return clone
}

// AuditPage is one bounded append-only audit result page.
type AuditPage struct {
	Facts []AuditFactRecord
	Next  AuditFactID
}

// OutboxPage is one bounded ordered publication/reconciliation work page.
type OutboxPage struct {
	Records []OutboxRecord
	Next    OutboxID
}

// Clone returns an independent audit page.
func (page AuditPage) Clone() AuditPage {
	page.Facts = append([]AuditFactRecord(nil), page.Facts...)
	return page
}

// Clone returns an independent Outbox page.
func (page OutboxPage) Clone() OutboxPage {
	clone := OutboxPage{Records: make([]OutboxRecord, len(page.Records)), Next: page.Next}
	for index := range page.Records {
		clone.Records[index] = page.Records[index].Clone()
	}
	return clone
}

// ClaimOutboxCommand atomically leases one Outbox record under ownership-scoped idempotency.
type ClaimOutboxCommand struct {
	Scope           MutationScope
	IdempotencyKey  string
	OutboxID        OutboxID
	ExpectedVersion uint64
	Claimer         string
	ClaimUntil      time.Time
}

// Owned returns a value-owned command with a UTC-normalized claim expiry.
func (command ClaimOutboxCommand) Owned() ClaimOutboxCommand {
	command.ClaimUntil = normalizeTime(command.ClaimUntil)
	return command
}

// AcknowledgeOutboxCommand atomically acknowledges one owned Outbox lease under idempotency.
type AcknowledgeOutboxCommand struct {
	Scope           MutationScope
	IdempotencyKey  string
	OutboxID        OutboxID
	ExpectedVersion uint64
	Claimer         string
	PublishedAt     time.Time
}

// Owned returns a value-owned command with a UTC-normalized publication time.
func (command AcknowledgeOutboxCommand) Owned() AcknowledgeOutboxCommand {
	command.PublishedAt = normalizeTime(command.PublishedAt)
	return command
}

// RuntimeStateStore is the plans-only internal lifecycle persistence authority.
// Command construction belongs exclusively to Compiler and lifecycle decisions
// exclusively to RuntimeStatePlanner; an adapter may read authorized metadata
// state and atomically persist a validated TransitionPlan, but it cannot accept
// a caller command or manufacture a MutationReceipt.
type RuntimeStateStore interface {
	LoadRuntimeState(context.Context, MutationScope) (RuntimeState, error)
	PersistTransitionPlan(context.Context, TransitionPlan) error
	GetAgentRevision(context.Context, AgentRevisionQuery) (AgentRevisionRecord, error)
	GetPolicyRevision(context.Context, PolicyRevisionQuery) (PolicyRevisionRecord, error)
	GetSessionView(context.Context, SessionViewQuery) (SessionView, error)
	GetTurn(context.Context, TurnQuery) (TurnRecord, error)
	GetArtifact(context.Context, ArtifactQuery) (ArtifactRecord, error)
	GetInvocation(context.Context, InvocationQuery) (InvocationRecord, error)
	ReadEvents(context.Context, EventsQuery) (EventPage, error)
	GetMutationReceipt(context.Context, MutationReceiptQuery) (MutationReceipt, error)
	ReadAudit(context.Context, AuditQuery) (AuditPage, error)
	ReadOutbox(context.Context, OutboxQuery) (OutboxPage, error)
	AuthorizeAgentSpecificationBodyRead(context.Context, CompiledReadAuthorization) (runtimecontent.AgentSpecificationBodyRecord, error)
	AuthorizeInputEnvelopeRead(context.Context, CompiledReadAuthorization) (runtimecontent.InputEnvelopeRecord, error)
	AuthorizeArtifactRead(context.Context, CompiledReadAuthorization) (runtimecontent.ArtifactRecord, error)
}

// OutboxTenantSource is the deliberately narrow discovery capability used by
// a private outbox publisher. It exposes tenant identifiers only; it is not a
// public runtime query and it never grants content-read authority.
type OutboxTenantSource interface {
	ListOutboxTenants(context.Context) ([]runtimecontent.TenantID, error)
}

// ContentHandoffValidator is supplied to a state-store composition so a command cannot persist a forgeable reference.
type ContentHandoffValidator = runtimecontent.ContentHandoffValidator

func normalizeTime(value time.Time) time.Time {
	if value.IsZero() {
		return value
	}
	return value.Round(0).UTC()
}
