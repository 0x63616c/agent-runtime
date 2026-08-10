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
	ErrConflict         = errors.New("runtime state conflict")
	ErrNotFoundOrDenied = errors.New("runtime state not found or denied")
	ErrUnavailable      = errors.New("runtime state unavailable")
	ErrIntegrity        = errors.New("runtime state integrity failure")
	ErrReceiptExpired   = errors.New("runtime state idempotency receipt expired")
)

// Authority identifies the narrow authority with which a command or query is made.
type Authority string

const (
	AuthorityTenantAdministrator Authority = "tenant_administrator"
	AuthoritySessionOwner        Authority = "session_owner"
	AuthorityRuntimeWorker       Authority = "runtime_worker"
	AuthorityAuditReader         Authority = "audit_reader"
	AuthorityOutboxPublisher     Authority = "outbox_publisher"
)

// MutationScope is authenticated application metadata, never a caller-supplied database predicate.
type MutationScope struct {
	Tenant    runtimecontent.TenantID
	Principal runtimecontent.PrincipalID
	Authority Authority
}

// RequestDigest commits the canonical, identity-free command request used for idempotency.
type RequestDigest string

// OperationID is the durable external-effect key owned by the runtime.
type OperationID string

// InvocationID identifies one invocation attempt without exposing a provider handle.
type InvocationID string

// AuditFactID and OutboxID identify append-only metadata records.
type AuditFactID string
type OutboxID string

// Mutation is shared by every lifecycle command. Implementations resolve its
// idempotency receipt before allocating identifiers, sequence positions, or effects.
type Mutation struct {
	Scope          MutationScope
	IdempotencyKey string
	RequestDigest  RequestDigest
}

func (mutation Mutation) CommandScope() MutationScope           { return mutation.Scope }
func (mutation Mutation) CanonicalRequestDigest() RequestDigest { return mutation.RequestDigest }

// AgentRevisionRecord is persisted revision metadata; the behavior body remains in runtimecontent.
type AgentRevisionRecord struct {
	Tenant        runtimecontent.TenantID
	AgentID       agentruntime.AgentID
	RevisionID    agentruntime.AgentRevisionID
	Revision      uint64
	Name          string
	ModelProfile  string
	Specification runtimecontent.Reference
	CreatedAt     time.Time
	RetainUntil   time.Time
}

// Clone returns an independent Agent revision metadata snapshot.
func (record AgentRevisionRecord) Clone() AgentRevisionRecord { return record }

// SessionRecord is the revision-pinned, metadata-only Session aggregate projection.
type SessionRecord struct {
	Tenant      runtimecontent.TenantID
	Principal   runtimecontent.PrincipalID
	SessionID   agentruntime.SessionID
	AgentID     agentruntime.AgentID
	RevisionID  agentruntime.AgentRevisionID
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
	SessionID      agentruntime.SessionID
	InputID        agentruntime.InputID
	Content        runtimecontent.Reference
	AcceptedAt     time.Time
	RetentionUntil time.Time
}

// Clone returns an independent Input metadata snapshot.
func (record InputRecord) Clone() InputRecord { return record }

// TurnRecord is the bounded execution state for one accepted Input.
type TurnRecord struct {
	Tenant         runtimecontent.TenantID
	Principal      runtimecontent.PrincipalID
	SessionID      agentruntime.SessionID
	TurnID         agentruntime.TurnID
	InputID        agentruntime.InputID
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
	InvocationIntent    InvocationState = "intent"
	InvocationSucceeded InvocationState = "succeeded"
	InvocationFailed    InvocationState = "failed"
	InvocationUncertain InvocationState = "uncertain"
	InvocationCancelled InvocationState = "cancelled"
)

// InvocationRecord retains only the external-effect identity, fence, safe references and outcome metadata.
type InvocationRecord struct {
	Tenant         runtimecontent.TenantID
	Principal      runtimecontent.PrincipalID
	SessionID      agentruntime.SessionID
	TurnID         agentruntime.TurnID
	InvocationID   InvocationID
	OperationID    OperationID
	Ordinal        uint64
	Fence          uint64
	State          InvocationState
	Result         *runtimecontent.Reference
	Failure        *agentruntime.Failure
	CreatedAt      time.Time
	UpdatedAt      time.Time
	RetentionUntil time.Time
}

// Clone returns an independent invocation metadata snapshot.
func (record InvocationRecord) Clone() InvocationRecord {
	clone := record
	clone.Failure = record.Failure.Clone()
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
	SessionID      agentruntime.SessionID
	Sequence       uint64
	Cursor         agentruntime.Cursor
	EventID        agentruntime.EventID
	Kind           agentruntime.EventKind
	InputID        agentruntime.InputID
	TurnID         agentruntime.TurnID
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
	SessionID      agentruntime.SessionID
	TurnID         agentruntime.TurnID
	OccurredAt     time.Time
	RetentionUntil time.Time
}

// Clone returns an independent audit metadata snapshot.
func (record AuditFactRecord) Clone() AuditFactRecord { return record }

// OutboxState describes durable publication/reconciliation work, never exactly-once publication.
type OutboxState string

const (
	OutboxPending   OutboxState = "pending"
	OutboxClaimed   OutboxState = "claimed"
	OutboxPublished OutboxState = "published"
	OutboxReconcile OutboxState = "reconcile"
)

// OutboxRecord refers to a committed aggregate effect without copying its event payload.
type OutboxRecord struct {
	Tenant           runtimecontent.TenantID
	OutboxID         OutboxID
	Aggregate        string
	AggregateVersion uint64
	Version          uint64
	EventID          agentruntime.EventID
	OperationID      OperationID
	State            OutboxState
	ClaimedBy        string
	ClaimUntil       *time.Time
	CommittedAt      time.Time
	RetentionUntil   time.Time
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
	Scope          MutationScope
	IdempotencyKey string
	OperationID    OperationID
	Command        string
	RequestDigest  RequestDigest
	AgentID        agentruntime.AgentID
	RevisionID     agentruntime.AgentRevisionID
	SessionID      agentruntime.SessionID
	InputID        agentruntime.InputID
	TurnID         agentruntime.TurnID
	AcceptedAt     time.Time
	RetentionUntil time.Time
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
	Mutation
	AgentID          agentruntime.AgentID // empty allocates a new Agent
	ExpectedRevision uint64               // zero only when AgentID is empty
	Specification    runtimecontent.ContentHandoff
}

// CreateSessionCommand pins a principal-owned Session to one exact immutable revision.
type CreateSessionCommand struct {
	Mutation
	RevisionID agentruntime.AgentRevisionID
}

// AdmitInputCommand creates exactly one Input and ordered Turn from an opaque Input-envelope handoff.
type AdmitInputCommand struct {
	Mutation
	SessionID agentruntime.SessionID
	Input     runtimecontent.ContentHandoff
}

// BeginInvocationAttempt records intent before an external model effect may be dispatched.
type BeginInvocationAttemptCommand struct {
	Mutation
	SessionID              agentruntime.SessionID
	TurnID                 agentruntime.TurnID
	OperationID            OperationID
	ExpectedSessionVersion uint64
	ExpectedTurnVersion    uint64
	ExpectedFence          uint64
}

// RecordInvocationOutcomeCommand records a fenced safe outcome for one exact operation.
type RecordInvocationOutcomeCommand struct {
	Mutation
	SessionID              agentruntime.SessionID
	TurnID                 agentruntime.TurnID
	OperationID            OperationID
	Ordinal                uint64
	Fence                  uint64
	Outcome                InvocationState
	Result                 *runtimecontent.Reference
	Failure                *agentruntime.Failure
	ExpectedSessionVersion uint64
	ExpectedTurnVersion    uint64
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

// SettleTurnCommand terminally settles a current running Turn and may promote one queued Turn.
type SettleTurnCommand struct {
	Mutation
	SessionID              agentruntime.SessionID
	TurnID                 agentruntime.TurnID
	ExpectedSessionVersion uint64
	ExpectedTurnVersion    uint64
	Outcome                TerminalOutcome
}

// CancelTurnCommand terminally cancels a running or queued Turn.
type CancelTurnCommand struct {
	Mutation
	SessionID agentruntime.SessionID
	TurnID    agentruntime.TurnID
}

// CloseSessionCommand rejects future admission and completes only after accepted work drains.
type CloseSessionCommand struct {
	Mutation
	SessionID agentruntime.SessionID
}

type RegisterAgentRevisionResult struct {
	Revision AgentRevisionRecord
	Receipt  MutationReceipt
	Effects  EffectSet
}
type CreateSessionResult struct {
	Session SessionRecord
	Receipt MutationReceipt
	Effects EffectSet
}
type AdmitInputResult struct {
	Input   InputRecord
	Turn    TurnRecord
	Session SessionRecord
	Receipt MutationReceipt
	Effects EffectSet
}
type BeginInvocationAttemptResult struct {
	Invocation InvocationRecord
	Session    SessionRecord
	Turn       TurnRecord
	Receipt    MutationReceipt
	Effects    EffectSet
}
type RecordInvocationOutcomeResult struct {
	Invocation InvocationRecord
	Receipt    MutationReceipt
	Effects    EffectSet
}
type SettleTurnResult struct {
	Session  SessionRecord
	Turn     TurnRecord
	Promoted *TurnRecord
	Receipt  MutationReceipt
	Effects  EffectSet
}
type CancelTurnResult struct {
	Session  SessionRecord
	Turn     TurnRecord
	Promoted *TurnRecord
	Receipt  MutationReceipt
	Effects  EffectSet
}
type CloseSessionResult struct {
	Session SessionRecord
	Receipt MutationReceipt
	Effects EffectSet
}

// Clone returns an independent RegisterAgentRevision result.
func (result RegisterAgentRevisionResult) Clone() RegisterAgentRevisionResult {
	result.Revision, result.Receipt, result.Effects = result.Revision.Clone(), result.Receipt.Clone(), result.Effects.Clone()
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

// AgentRevisionQuery is a tenant-scoped metadata query; content requires a separate runtimecontent read capability.
type AgentRevisionQuery struct {
	Scope      MutationScope
	AgentID    agentruntime.AgentID
	RevisionID agentruntime.AgentRevisionID
}
type SessionViewQuery struct {
	Scope            MutationScope
	SessionID        agentruntime.SessionID
	RecentEventLimit uint32
	QueuedTurnLimit  uint32
}
type TurnQuery struct {
	Scope     MutationScope
	SessionID agentruntime.SessionID
	TurnID    agentruntime.TurnID
}
type EventsQuery struct {
	Scope     MutationScope
	SessionID agentruntime.SessionID
	After     agentruntime.Cursor
	Limit     uint32
}
type MutationReceiptQuery struct {
	Scope          MutationScope
	IdempotencyKey string
}
type AuditQuery struct {
	Scope MutationScope
	After AuditFactID
	Limit uint32
}
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

type AuditPage struct {
	Facts []AuditFactRecord
	Next  AuditFactID
}
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

type ClaimOutboxCommand struct {
	Scope           MutationScope
	OutboxID        OutboxID
	ExpectedVersion uint64
	Claimer         string
	ClaimUntil      time.Time
}
type AcknowledgeOutboxCommand struct {
	Scope           MutationScope
	OutboxID        OutboxID
	ExpectedVersion uint64
	Claimer         string
	PublishedAt     time.Time
}

// RuntimeStateStore is the closed internal lifecycle authority. Its production implementation is PostgreSQL;
// neither this contract nor a memory conformance adapter claims durable public composition.
type RuntimeStateStore interface {
	RegisterAgentRevision(context.Context, RegisterAgentRevisionCommand) (RegisterAgentRevisionResult, error)
	CreateSession(context.Context, CreateSessionCommand) (CreateSessionResult, error)
	AdmitInput(context.Context, AdmitInputCommand) (AdmitInputResult, error)
	BeginInvocationAttempt(context.Context, BeginInvocationAttemptCommand) (BeginInvocationAttemptResult, error)
	RecordInvocationOutcome(context.Context, RecordInvocationOutcomeCommand) (RecordInvocationOutcomeResult, error)
	SettleTurn(context.Context, SettleTurnCommand) (SettleTurnResult, error)
	CancelTurn(context.Context, CancelTurnCommand) (CancelTurnResult, error)
	CloseSession(context.Context, CloseSessionCommand) (CloseSessionResult, error)
	GetAgentRevision(context.Context, AgentRevisionQuery) (AgentRevisionRecord, error)
	GetSessionView(context.Context, SessionViewQuery) (SessionView, error)
	GetTurn(context.Context, TurnQuery) (TurnRecord, error)
	ReadEvents(context.Context, EventsQuery) (EventPage, error)
	GetMutationReceipt(context.Context, MutationReceiptQuery) (MutationReceipt, error)
	ReadAudit(context.Context, AuditQuery) (AuditPage, error)
	ReadOutbox(context.Context, OutboxQuery) (OutboxPage, error)
	ClaimOutbox(context.Context, ClaimOutboxCommand) (OutboxRecord, error)
	AcknowledgeOutbox(context.Context, AcknowledgeOutboxCommand) (OutboxRecord, error)
}

// ContentHandoffValidator is supplied to a state-store composition so a command cannot persist a forgeable reference.
type ContentHandoffValidator = runtimecontent.ContentHandoffValidator
