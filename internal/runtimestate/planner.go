package runtimestate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

// IdentifierKind identifies the exact opaque identifier allocated by a planner.
type IdentifierKind string

const (
	IdentifierAgent      IdentifierKind = "agent"
	IdentifierRevision   IdentifierKind = "arev"
	IdentifierSession    IdentifierKind = "sess"
	IdentifierInput      IdentifierKind = "inpt"
	IdentifierArtifact   IdentifierKind = "art"
	IdentifierTurn       IdentifierKind = "turn"
	IdentifierInvocation IdentifierKind = "invocation"
	IdentifierEvent      IdentifierKind = "evt"
	IdentifierCursor     IdentifierKind = "cur"
	IdentifierAudit      IdentifierKind = "audit"
	IdentifierOutbox     IdentifierKind = "outbox"
	IdentifierGrant      IdentifierKind = "grant"
)

// IdentifierSource supplies planner-owned opaque IDs. It is injected so plans are deterministic in tests.
type IdentifierSource interface {
	NextIdentifier(IdentifierKind) (string, error)
}

// DataClass identifies an independently governed durable-data lifecycle.
// Classes intentionally describe persisted data rather than process roles, so
// operators can set different retention and collection policies without
// coupling public event replay to audit or idempotency retention.
type DataClass string

const (
	DataClassAgentRevision DataClass = "agent_revision"
	DataClassPolicy        DataClass = "policy"
	DataClassSession       DataClass = "session"
	DataClassInput         DataClass = "input"
	DataClassTurn          DataClass = "turn"
	DataClassArtifact      DataClass = "artifact"
	DataClassConversation  DataClass = "conversation"
	DataClassAuthorization DataClass = "authorization"
	DataClassInvocation    DataClass = "invocation"
	DataClassEvent         DataClass = "product_event"
	DataClassAudit         DataClass = "audit"
	DataClassOutbox        DataClass = "outbox"
	DataClassReceipt       DataClass = "idempotency_receipt"
)

// RetentionPolicy declares the fallback metadata retention at the transition boundary.
type RetentionPolicy interface{ RetainUntil(time.Time) time.Time }

// ClassRetentionPolicy optionally supplies independent retention horizons for
// individual durable data classes. The fallback RetentionPolicy remains
// supported so existing operator configuration has stable behavior.
type ClassRetentionPolicy interface {
	RetentionPolicy
	RetainClassUntil(DataClass, time.Time) time.Time
}
type defaultRetention struct{}

func (defaultRetention) RetainUntil(now time.Time) time.Time { return now.Add(24 * time.Hour) }

// PlannerOption configures one RuntimeStatePlanner.
type PlannerOption func(*RuntimeStatePlanner) error

// WithRetentionPolicy injects the retention authority used for planner-owned records.
func WithRetentionPolicy(policy RetentionPolicy) PlannerOption {
	return func(planner *RuntimeStatePlanner) error {
		if policy == nil {
			return errors.New("runtime state retention policy is required")
		}
		planner.retention = policy
		return nil
	}
}

// RuntimeState is the complete bounded metadata prior state consumed by RuntimeStatePlanner.
// It intentionally contains no raw Agent/Input bytes and is cloned at every boundary.
type RuntimeState struct {
	Revisions      []AgentRevisionRecord
	Policies       []PolicyRevisionRecord
	Sessions       []SessionRecord
	Inputs         []InputRecord
	Artifacts      []ArtifactRecord
	Conversations  []ConversationRecord
	ToolIntents    []ToolIntentRecord
	Grants         []CapabilityGrantRecord
	ToolExecutions []ToolExecutionRecord
	Approvals      []ApprovalRecord
	Turns          []TurnRecord
	Invocations    []InvocationRecord
	Receipts       []MutationReceipt
	Events         []ProductEventRecord
	Audit          []AuditFactRecord
	Outbox         []OutboxRecord
}

// Clone returns an independent prior-state snapshot.
func (state RuntimeState) Clone() RuntimeState {
	clone := RuntimeState{}
	clone.Revisions = append([]AgentRevisionRecord(nil), state.Revisions...)
	clone.Policies = make([]PolicyRevisionRecord, len(state.Policies))
	for i := range state.Policies {
		clone.Policies[i] = state.Policies[i].Clone()
	}
	clone.Sessions = append([]SessionRecord(nil), state.Sessions...)
	clone.Inputs = append([]InputRecord(nil), state.Inputs...)
	clone.Artifacts = append([]ArtifactRecord(nil), state.Artifacts...)
	clone.Conversations = append([]ConversationRecord(nil), state.Conversations...)
	clone.ToolIntents = append([]ToolIntentRecord(nil), state.ToolIntents...)
	clone.Grants = append([]CapabilityGrantRecord(nil), state.Grants...)
	clone.ToolExecutions = make([]ToolExecutionRecord, len(state.ToolExecutions))
	for index := range state.ToolExecutions {
		clone.ToolExecutions[index] = state.ToolExecutions[index].Clone()
	}
	clone.Approvals = make([]ApprovalRecord, len(state.Approvals))
	for i := range state.Approvals {
		clone.Approvals[i] = state.Approvals[i].Clone()
	}
	clone.Turns = make([]TurnRecord, len(state.Turns))
	for i := range state.Turns {
		clone.Turns[i] = state.Turns[i].Clone()
	}
	clone.Invocations = make([]InvocationRecord, len(state.Invocations))
	for i := range state.Invocations {
		clone.Invocations[i] = state.Invocations[i].Clone()
	}
	clone.Receipts = append([]MutationReceipt(nil), state.Receipts...)
	clone.Events = append([]ProductEventRecord(nil), state.Events...)
	clone.Audit = append([]AuditFactRecord(nil), state.Audit...)
	clone.Outbox = make([]OutboxRecord, len(state.Outbox))
	for i := range state.Outbox {
		clone.Outbox[i] = state.Outbox[i].Clone()
	}
	return clone
}

// PlanResult is the safe result of a planned transition. Exactly the records applicable to Kind are present.
type PlanResult struct {
	Kind         CommandKind
	Revision     AgentRevisionRecord
	Policy       PolicyRevisionRecord
	Session      SessionRecord
	Input        InputRecord
	Artifact     ArtifactRecord
	Conversation ConversationRecord
	Turn         TurnRecord
	Promoted     *TurnRecord
	Invocation   InvocationRecord
	Outbox       OutboxRecord
	Receipt      MutationReceipt
}

// Clone returns an independent transition result.
func (result PlanResult) Clone() PlanResult {
	result.Revision = result.Revision.Clone()
	result.Policy = result.Policy.Clone()
	result.Session = result.Session.Clone()
	result.Input = result.Input.Clone()
	result.Artifact = result.Artifact.Clone()
	result.Conversation = result.Conversation.Clone()
	result.Turn = result.Turn.Clone()
	result.Invocation = result.Invocation.Clone()
	result.Outbox = result.Outbox.Clone()
	result.Receipt = result.Receipt.Clone()
	if result.Promoted != nil {
		promoted := result.Promoted.Clone()
		result.Promoted = &promoted
	}
	return result
}

// TransitionPlan is a centrally-produced atomic state replacement and its ordered derived effects.
type TransitionPlan struct {
	base    RuntimeState
	kind    CommandKind
	state   RuntimeState
	effects EffectSet
	result  PlanResult
}

// Kind returns the planned closed command kind.
func (plan TransitionPlan) Kind() CommandKind { return plan.kind }

// State returns the complete metadata state to persist atomically.
func (plan TransitionPlan) State() RuntimeState { return plan.state.Clone() }

// BaseState returns the exact metadata snapshot against which this sealed plan was derived.
// Persistence adapters use it only for atomic compare-and-set; it contains no raw content.
func (plan TransitionPlan) BaseState() RuntimeState { return plan.base.Clone() }

// Effects returns the ordered effects included in State.
func (plan TransitionPlan) Effects() EffectSet { return plan.effects.Clone() }

// Result returns the safe command result derived from State.
func (plan TransitionPlan) Result() PlanResult { return plan.result.Clone() }

// Validate confirms the plan's effects and result are included in the replacement state.
func (plan TransitionPlan) Validate() error {
	if plan.kind == "" || plan.result.Kind != plan.kind || plan.result.Receipt.Command != string(plan.kind) {
		return ErrIntegrity
	}
	if !containsReceipt(plan.state, plan.result.Receipt) {
		return ErrIntegrity
	}
	for _, event := range plan.effects.Events {
		if !containsEvent(plan.state, event) {
			return ErrIntegrity
		}
	}
	for _, fact := range plan.effects.Audit {
		if !containsAudit(plan.state, fact) {
			return ErrIntegrity
		}
	}
	for _, outbox := range plan.effects.Outbox {
		if !containsOutbox(plan.state, outbox) {
			return ErrIntegrity
		}
	}
	return nil
}

// RuntimeStatePlanner deterministically interprets compiler-sealed mutations over metadata-only state.
type RuntimeStatePlanner struct {
	clock     clock.Clock
	ids       IdentifierSource
	retention RetentionPolicy
}

// NewRuntimeStatePlanner constructs the pure lifecycle interpreter.
func NewRuntimeStatePlanner(source clock.Clock, ids IdentifierSource, options ...PlannerOption) (*RuntimeStatePlanner, error) {
	if source == nil || ids == nil {
		return nil, errors.New("create runtime state planner: clock and identifier source are required")
	}
	planner := &RuntimeStatePlanner{clock: source, ids: ids, retention: defaultRetention{}}
	for _, option := range options {
		if option == nil {
			return nil, errors.New("create runtime state planner: nil option")
		}
		if err := option(planner); err != nil {
			return nil, err
		}
	}
	return planner, nil
}

// Plan returns the complete atomic replacement for a compiler-sealed command.
func (planner *RuntimeStatePlanner) Plan(ctx context.Context, prior RuntimeState, mutation CompiledMutation) (TransitionPlan, error) {
	if err := ctx.Err(); err != nil {
		return TransitionPlan{}, err
	}
	if planner == nil || planner.clock == nil || planner.ids == nil || planner.retention == nil || mutation.mutation.kind == "" || mutation.mutation.receipt.Command != mutation.mutation.kind {
		return TransitionPlan{}, ErrIntegrity
	}
	now := normalizeTime(planner.clock.Now())
	if now.IsZero() {
		return TransitionPlan{}, ErrIntegrity
	}
	state := prior.Clone()
	if err := validateState(state); err != nil {
		return TransitionPlan{}, err
	}
	if receipt, ok := findReceipt(state, mutation.mutation.receipt); ok {
		if receiptExpired(receipt, now) {
			return TransitionPlan{}, ErrReceiptExpired
		}
		if receipt.Command != string(mutation.mutation.kind) || receipt.RequestDigest != mutation.mutation.receipt.RequestDigest {
			return TransitionPlan{}, ErrConflict
		}
		return planner.replayPlan(state, mutation.mutation.kind, receipt)
	}
	var result PlanResult
	var effects EffectSet
	var err error
	switch command := mutation.mutation.command.(type) {
	case compiledRegister:
		result, effects, err = planner.register(&state, mutation.mutation.receipt, command, now)
	case RegisterPolicyRevisionCommand:
		result, effects, err = planner.registerPolicy(&state, mutation.mutation.receipt, command, now)
	case CreateSessionCommand:
		result, effects, err = planner.createSession(&state, mutation.mutation.receipt, command, now)
	case compiledAdmit:
		result, effects, err = planner.admit(&state, mutation.mutation.receipt, command, now)
	case compiledArtifact:
		result, effects, err = planner.registerArtifact(&state, mutation.mutation.receipt, command, now)
	case compiledConversation:
		result, effects, err = planner.appendConversation(&state, mutation.mutation.receipt, command, now)
	case compiledToolApproval:
		result, effects, err = planner.admitToolApproval(&state, mutation.mutation.receipt, command, now)
	case compiledToolIntent:
		result, effects, err = planner.recordToolIntent(&state, mutation.mutation.receipt, command, now)
	case RequestApprovalCommand:
		result, effects, err = planner.requestApproval(&state, mutation.mutation.receipt, command, now)
	case DecideApprovalCommand:
		result, effects, err = planner.decideApproval(&state, mutation.mutation.receipt, command, now)
	case ConsumeCapabilityGrantCommand:
		result, effects, err = planner.consumeCapabilityGrant(&state, mutation.mutation.receipt, command, now)
	case RevokeCapabilityGrantCommand:
		result, effects, err = planner.revokeCapabilityGrant(&state, mutation.mutation.receipt, command, now)
	case ExpireCapabilityGrantCommand:
		result, effects, err = planner.expireCapabilityGrant(&state, mutation.mutation.receipt, command, now)
	case DenyToolAdmissionCommand:
		result, effects, err = planner.denyToolAdmission(&state, mutation.mutation.receipt, command, now)
	case BeginToolExecutionCommand:
		result, effects, err = planner.beginToolExecution(&state, mutation.mutation.receipt, command, now)
	case RecordToolExecutionOutcomeCommand:
		result, effects, err = planner.recordToolExecutionOutcome(&state, mutation.mutation.receipt, command, now)
	case BeginInvocationAttemptCommand:
		result, effects, err = planner.begin(&state, mutation.mutation.receipt, command, now)
	case RecordInvocationOutcomeCommand:
		result, effects, err = planner.recordOutcome(&state, mutation.mutation.receipt, command, now)
	case SettleTurnCommand:
		result, effects, err = planner.settle(&state, mutation.mutation.receipt, command, now, false)
	case CancelTurnCommand:
		result, effects, err = planner.cancel(&state, mutation.mutation.receipt, command, now)
	case CloseSessionCommand:
		result, effects, err = planner.close(&state, mutation.mutation.receipt, command, now)
	case ClaimOutboxCommand:
		result, effects, err = planner.claim(&state, mutation.mutation.receipt, command, now)
	case AcknowledgeOutboxCommand:
		result, effects, err = planner.acknowledge(&state, mutation.mutation.receipt, command, now)
	default:
		return TransitionPlan{}, ErrIntegrity
	}
	if err != nil {
		return TransitionPlan{}, err
	}
	result.Kind = mutation.mutation.kind
	result.Receipt = planner.receipt(mutation.mutation.receipt, result, now)
	state.Receipts = append(state.Receipts, result.Receipt)
	if err := validateState(state); err != nil {
		return TransitionPlan{}, err
	}
	plan := TransitionPlan{base: prior.Clone(), kind: mutation.mutation.kind, state: state, effects: effects, result: result}
	if err := plan.Validate(); err != nil {
		return TransitionPlan{}, err
	}
	return plan, nil
}

func (planner *RuntimeStatePlanner) registerPolicy(state *RuntimeState, binding ReceiptBinding, command RegisterPolicyRevisionCommand, now time.Time) (PlanResult, EffectSet, error) {
	latest := uint64(0)
	for _, record := range state.Policies {
		if record.Tenant == binding.Scope.Tenant && record.Name == command.Name && record.Revision > latest {
			latest = record.Revision
		}
	}
	if latest != command.ExpectedRevision {
		return PlanResult{}, EffectSet{}, ErrConflict
	}
	rules := append([]agentruntime.PolicyRule(nil), command.Rules...)
	digest, err := policyDigest(command.Name, latest+1, rules)
	if err != nil {
		return PlanResult{}, EffectSet{}, ErrIntegrity
	}
	until := planner.retain(now, DataClassPolicy)
	record := PolicyRevisionRecord{Tenant: binding.Scope.Tenant, Name: command.Name, Revision: latest + 1, Digest: digest, Rules: rules, CreatedAt: now, RetainUntil: until}
	state.Policies = append(state.Policies, record)
	effects, err := planner.auditOnly(state, binding, "policy_revision.registered", "", "", now)
	if err != nil {
		return PlanResult{}, EffectSet{}, err
	}
	return PlanResult{Policy: record}, effects, nil
}

func policyDigest(name string, revision uint64, rules []agentruntime.PolicyRule) (string, error) {
	encoded, err := json.Marshal(struct {
		Version  string                    `json:"version"`
		Name     string                    `json:"name"`
		Revision uint64                    `json:"revision"`
		Rules    []agentruntime.PolicyRule `json:"rules"`
	}{"runtime-policy/v1", name, revision, rules})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (planner *RuntimeStatePlanner) register(state *RuntimeState, binding ReceiptBinding, compiled compiledRegister, now time.Time) (PlanResult, EffectSet, error) {
	command := compiled.command
	revision := uint64(1)
	agentID := command.AgentID
	if agentID == "" {
		var err error
		agentID, err = planner.agentID()
		if err != nil {
			return PlanResult{}, EffectSet{}, err
		}
	} else {
		latest := uint64(0)
		for _, record := range state.Revisions {
			if record.Tenant == binding.Scope.Tenant && record.AgentID == agentID && record.Revision > latest {
				latest = record.Revision
			}
		}
		if latest != command.ExpectedRevision {
			return PlanResult{}, EffectSet{}, ErrConflict
		}
		revision = latest + 1
	}
	revisionID, err := planner.revisionID()
	if err != nil {
		return PlanResult{}, EffectSet{}, err
	}
	until := planner.retain(now, DataClassAgentRevision)
	record := AgentRevisionRecord{Tenant: binding.Scope.Tenant, AgentID: agentID, RevisionID: revisionID, Revision: revision, Name: compiled.commitment.Name, ModelProfile: compiled.commitment.ModelProfile, Specification: compiled.commitment.Reference, CreatedAt: now, RetainUntil: until}
	state.Revisions = append(state.Revisions, record)
	effects, err := planner.auditOnly(state, binding, "agent_revision.registered", "", "", now)
	if err != nil {
		return PlanResult{}, EffectSet{}, err
	}
	outbox, err := planner.catalogOutbox(binding, record, now, planner.retain(now, DataClassOutbox))
	if err != nil {
		return PlanResult{}, EffectSet{}, err
	}
	state.Outbox = append(state.Outbox, outbox)
	effects.Outbox = append(effects.Outbox, outbox)
	return PlanResult{Revision: record}, effects, nil
}

func (planner *RuntimeStatePlanner) createSession(state *RuntimeState, binding ReceiptBinding, command CreateSessionCommand, now time.Time) (PlanResult, EffectSet, error) {
	var revision AgentRevisionRecord
	found := false
	for _, candidate := range state.Revisions {
		if candidate.Tenant == binding.Scope.Tenant && candidate.RevisionID == command.RevisionID {
			revision, found = candidate, true
			break
		}
	}
	if !found {
		return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
	}
	id, err := planner.sessionID()
	if err != nil {
		return PlanResult{}, EffectSet{}, err
	}
	until := planner.retain(now, DataClassSession)
	session := SessionRecord{Tenant: binding.Scope.Tenant, Principal: binding.Scope.Principal, SessionID: id, AgentID: revision.AgentID, RevisionID: revision.RevisionID, State: agentruntime.SessionOpen, Version: 1, CreatedAt: now, UpdatedAt: now, RetainUntil: until}
	state.Sessions = append(state.Sessions, session)
	effects, err := planner.effects(state, binding, session, TurnRecord{}, InvocationRecord{}, []agentruntime.EventKind{agentruntime.EventSessionCreated}, now)
	if err != nil {
		return PlanResult{}, EffectSet{}, err
	}
	return PlanResult{Session: session}, effects, nil
}

func (planner *RuntimeStatePlanner) admit(state *RuntimeState, binding ReceiptBinding, compiled compiledAdmit, now time.Time) (PlanResult, EffectSet, error) {
	command := compiled.command
	sessionIndex := findSession(state, binding.Scope, command.SessionID)
	if sessionIndex < 0 {
		return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
	}
	session := state.Sessions[sessionIndex]
	if session.State != agentruntime.SessionOpen {
		return PlanResult{}, EffectSet{}, ErrConflict
	}
	inputID, err := planner.inputID()
	if err != nil {
		return PlanResult{}, EffectSet{}, err
	}
	turnID, err := planner.turnID()
	if err != nil {
		return PlanResult{}, EffectSet{}, err
	}
	inputUntil := planner.retain(now, DataClassInput)
	turnUntil := planner.retain(now, DataClassTurn)
	input := InputRecord{Tenant: session.Tenant, Principal: session.Principal, SessionID: session.SessionID, InputID: inputID, Content: compiled.commitment.Reference, AcceptedAt: now, RetentionUntil: inputUntil}
	state.Inputs = append(state.Inputs, input)
	position := uint64(1)
	active := false
	for _, turn := range state.Turns {
		if turn.SessionID == session.SessionID {
			if turn.Position >= position {
				position = turn.Position + 1
			}
			if turn.State == agentruntime.TurnRunning {
				active = true
			}
		}
	}
	turnState := agentruntime.TurnRunning
	kinds := []agentruntime.EventKind{agentruntime.EventInputAccepted, agentruntime.EventTurnStarted}
	started := &now
	if active {
		turnState, kinds, started = agentruntime.TurnQueued, []agentruntime.EventKind{agentruntime.EventInputAccepted, agentruntime.EventTurnQueued}, nil
	}
	turn := TurnRecord{Tenant: session.Tenant, Principal: session.Principal, SessionID: session.SessionID, TurnID: turnID, InputID: inputID, Position: position, State: turnState, Version: 1, StartedAt: started, RetentionUntil: turnUntil}
	state.Turns = append(state.Turns, turn)
	session.Version++
	session.UpdatedAt = now
	state.Sessions[sessionIndex] = session
	effects, err := planner.effects(state, binding, session, turn, InvocationRecord{}, kinds, now)
	if err != nil {
		return PlanResult{}, EffectSet{}, err
	}
	return PlanResult{Input: input, Turn: turn, Session: session}, effects, nil
}

func (planner *RuntimeStatePlanner) registerArtifact(state *RuntimeState, binding ReceiptBinding, compiled compiledArtifact, now time.Time) (PlanResult, EffectSet, error) {
	command := compiled.command
	if findTurn(state, binding.Scope, command.SessionID, command.TurnID) < 0 {
		return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
	}
	id, err := planner.artifactID()
	if err != nil {
		return PlanResult{}, EffectSet{}, err
	}
	until := planner.retain(now, DataClassArtifact)
	record := ArtifactRecord{Tenant: binding.Scope.Tenant, Principal: binding.Scope.Principal, ArtifactID: id, SessionID: command.SessionID, TurnID: command.TurnID, Reference: compiled.commitment.Reference, CreatedAt: now, RetainUntil: until}
	state.Artifacts = append(state.Artifacts, record)
	effects, err := planner.auditOnly(state, binding, "artifact.registered", command.SessionID, command.TurnID, now)
	if err != nil {
		return PlanResult{}, EffectSet{}, err
	}
	outbox, err := planner.artifactOutbox(binding, record, now, planner.retain(now, DataClassOutbox))
	if err != nil {
		return PlanResult{}, EffectSet{}, err
	}
	state.Outbox = append(state.Outbox, outbox)
	effects.Outbox = append(effects.Outbox, outbox)
	return PlanResult{Artifact: record}, effects, nil
}

func (planner *RuntimeStatePlanner) appendConversation(state *RuntimeState, binding ReceiptBinding, compiled compiledConversation, now time.Time) (PlanResult, EffectSet, error) {
	command := compiled.command
	if findSession(state, binding.Scope, command.SessionID) < 0 {
		return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
	}
	version := uint64(0)
	for _, record := range state.Conversations {
		if record.SessionID == command.SessionID && record.Version > version {
			version = record.Version
		}
	}
	if command.ExpectedVersion != version {
		return PlanResult{}, EffectSet{}, ErrConflict
	}
	until := planner.retain(now, DataClassConversation)
	record := ConversationRecord{Tenant: binding.Scope.Tenant, Principal: binding.Scope.Principal, SessionID: command.SessionID, Version: version + 1, Reference: compiled.commitment.Reference, CreatedAt: now, RetainUntil: until}
	state.Conversations = append(state.Conversations, record)
	effects, err := planner.auditOnly(state, binding, "conversation.appended", command.SessionID, "", now)
	if err != nil {
		return PlanResult{}, EffectSet{}, err
	}
	outbox, err := planner.conversationOutbox(binding, record, now, planner.retain(now, DataClassOutbox))
	if err != nil {
		return PlanResult{}, EffectSet{}, err
	}
	state.Outbox = append(state.Outbox, outbox)
	effects.Outbox = append(effects.Outbox, outbox)
	return PlanResult{Conversation: record}, effects, nil
}

func (planner *RuntimeStatePlanner) recordToolIntent(state *RuntimeState, binding ReceiptBinding, compiled compiledToolIntent, now time.Time) (PlanResult, EffectSet, error) {
	c := compiled.command
	if findTurn(state, binding.Scope, c.SessionID, c.TurnID) < 0 {
		return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
	}
	r := ToolIntentRecord{Tenant: binding.Scope.Tenant, Principal: binding.Scope.Principal, SessionID: c.SessionID, TurnID: c.TurnID, ToolCallID: c.ToolCallID, ToolName: c.ToolName, ActionDigest: c.ActionDigest, ActionDescriptor: compiled.descriptor, PolicyRevisionDigest: c.PolicyRevisionDigest, CreatedAt: now, RetainUntil: planner.retain(now, DataClassAuthorization)}
	state.ToolIntents = append(state.ToolIntents, r)
	e, err := planner.auditOnly(state, binding, "tool.intent_recorded", c.SessionID, c.TurnID, now)
	return PlanResult{}, e, err
}

type compiledToolApproval struct {
	command    AdmitToolApprovalCommand
	descriptor runtimecontent.Reference
}

// admitToolApproval prevents an intent-without-approval crash window. The
// policy decision is already sealed by the worker before this state mutation;
// the planner confirms only durable ownership and exact correlation.
func (planner *RuntimeStatePlanner) admitToolApproval(state *RuntimeState, binding ReceiptBinding, compiled compiledToolApproval, now time.Time) (PlanResult, EffectSet, error) {
	c := compiled.command
	turnIndex := findTurn(state, binding.Scope, c.SessionID, c.TurnID)
	if !c.ExpiresAt.After(now) || turnIndex < 0 || state.Turns[turnIndex].State != agentruntime.TurnRunning {
		return PlanResult{}, EffectSet{}, ErrConflict
	}
	for _, intent := range state.ToolIntents {
		if intent.ToolCallID == c.ToolCallID && intent.SessionID == c.SessionID && intent.TurnID == c.TurnID {
			return PlanResult{}, EffectSet{}, ErrConflict
		}
	}
	for _, approval := range state.Approvals {
		if approval.ApprovalID == c.ApprovalID {
			return PlanResult{}, EffectSet{}, ErrConflict
		}
	}
	// The active turn is explicitly paused before the public approval becomes
	// visible. A pending approval is never represented as a terminal Turn.
	state.Turns[turnIndex].State = agentruntime.TurnWaitingForApproval
	state.Turns[turnIndex].Version++
	state.ToolIntents = append(state.ToolIntents, ToolIntentRecord{Tenant: binding.Scope.Tenant, Principal: binding.Scope.Principal, SessionID: c.SessionID, TurnID: c.TurnID, ToolCallID: c.ToolCallID, ToolName: c.ToolName, ActionDigest: c.ActionDigest, ActionDescriptor: compiled.descriptor, PolicyRevisionDigest: c.PolicyRevisionDigest, CreatedAt: now, RetainUntil: planner.retain(now, DataClassAuthorization)})
	state.Approvals = append(state.Approvals, ApprovalRecord{Tenant: binding.Scope.Tenant, Principal: binding.Scope.Principal, ApprovalID: c.ApprovalID, SessionID: c.SessionID, TurnID: c.TurnID, ToolCallID: c.ToolCallID, ActionDigest: c.ActionDigest, PolicyRevisionDigest: c.PolicyRevisionDigest, State: "pending", CapabilityDigest: c.CapabilityDigest, ActionVerb: c.ActionVerb, ActionTarget: c.ActionTarget, MaximumUses: c.MaximumUses, ExpiresAt: c.ExpiresAt, CreatedAt: now, RetainUntil: planner.retain(now, DataClassAuthorization)})
	effects, err := planner.auditOnly(state, binding, "tool.approval_requested", c.SessionID, c.TurnID, now)
	return PlanResult{}, effects, err
}
func (planner *RuntimeStatePlanner) requestApproval(state *RuntimeState, binding ReceiptBinding, c RequestApprovalCommand, now time.Time) (PlanResult, EffectSet, error) {
	if !c.ExpiresAt.After(now) {
		return PlanResult{}, EffectSet{}, ErrConflict
	}
	found := false
	for _, i := range state.ToolIntents {
		if i.ToolCallID == c.ToolCallID && i.SessionID == c.SessionID && i.TurnID == c.TurnID {
			found = true
		}
	}
	if !found {
		return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
	}
	turnIndex := findTurn(state, binding.Scope, c.SessionID, c.TurnID)
	if turnIndex < 0 || state.Turns[turnIndex].State != agentruntime.TurnRunning {
		return PlanResult{}, EffectSet{}, ErrConflict
	}
	for _, a := range state.Approvals {
		if a.ApprovalID == c.ApprovalID {
			return PlanResult{}, EffectSet{}, ErrConflict
		}
	}
	r := ApprovalRecord{Tenant: binding.Scope.Tenant, Principal: binding.Scope.Principal, ApprovalID: c.ApprovalID, SessionID: c.SessionID, TurnID: c.TurnID, ToolCallID: c.ToolCallID, ActionDigest: c.ActionDigest, PolicyRevisionDigest: c.PolicyRevisionDigest, State: "pending", CapabilityDigest: c.CapabilityDigest, MaximumUses: c.MaximumUses, ExpiresAt: c.ExpiresAt, CreatedAt: now, RetainUntil: planner.retain(now, DataClassAuthorization)}
	state.Turns[turnIndex].State = agentruntime.TurnWaitingForApproval
	state.Turns[turnIndex].Version++
	state.Approvals = append(state.Approvals, r)
	e, err := planner.auditOnly(state, binding, "approval.requested", c.SessionID, c.TurnID, now)
	return PlanResult{}, e, err
}
func (planner *RuntimeStatePlanner) decideApproval(state *RuntimeState, binding ReceiptBinding, c DecideApprovalCommand, now time.Time) (PlanResult, EffectSet, error) {
	for n := range state.Approvals {
		a := state.Approvals[n]
		if a.ApprovalID != c.ApprovalID || a.Tenant != binding.Scope.Tenant || a.Principal != binding.Scope.Principal {
			continue
		}
		if a.State != "pending" {
			return PlanResult{}, EffectSet{}, ErrConflict
		}
		if !now.Before(a.ExpiresAt) {
			a.State = "expired"
			state.Approvals[n] = a
			effects, err := planner.approvalEffects(state, binding, a, now)
			return PlanResult{}, effects, err
		}
		a.State = c.Decision
		a.Decision = c.Decision
		a.DecidedAt = &now
		state.Approvals[n] = a
		if c.Decision == "approved" {
			grantID, err := planner.grantID()
			if err != nil {
				return PlanResult{}, EffectSet{}, err
			}
			state.Grants = append(state.Grants, CapabilityGrantRecord{
				Tenant:               a.Tenant,
				Principal:            a.Principal,
				GrantID:              grantID,
				ToolCallID:           a.ToolCallID,
				CapabilityDigest:     a.CapabilityDigest,
				MaximumUses:          a.MaximumUses,
				ExpiresAt:            a.ExpiresAt,
				PolicyRevisionDigest: a.PolicyRevisionDigest,
				CreatedAt:            now,
				RetainUntil:          a.RetainUntil,
			})
			// The approved capability is the only transition that resumes the
			// paused turn. Execution still requires the separate grant-consume
			// and operation-intent transitions.
			turnIndex := findTurn(state, binding.Scope, a.SessionID, a.TurnID)
			if turnIndex < 0 || state.Turns[turnIndex].State != agentruntime.TurnWaitingForApproval {
				return PlanResult{}, EffectSet{}, ErrConflict
			}
			state.Turns[turnIndex].State = agentruntime.TurnRunning
			state.Turns[turnIndex].Version++
		}
		e, err := planner.approvalEffects(state, binding, a, now)
		return PlanResult{}, e, err
	}
	return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
}

func (planner *RuntimeStatePlanner) approvalEffects(state *RuntimeState, binding ReceiptBinding, approval ApprovalRecord, now time.Time) (EffectSet, error) {
	sessionIndex := findSession(state, binding.Scope, approval.SessionID)
	turnIndex := findTurn(state, binding.Scope, approval.SessionID, approval.TurnID)
	if sessionIndex < 0 || turnIndex < 0 {
		return EffectSet{}, ErrNotFoundOrDenied
	}
	effects, err := planner.effects(state, binding, state.Sessions[sessionIndex], state.Turns[turnIndex], InvocationRecord{}, []agentruntime.EventKind{agentruntime.EventApprovalResolved}, now)
	if err != nil || len(effects.Audit) == 0 || len(state.Audit) == 0 {
		return effects, err
	}
	kind := "approval." + approval.State
	effects.Audit[0].Kind = kind
	state.Audit[len(state.Audit)-1].Kind = kind
	return effects, nil
}

func (planner *RuntimeStatePlanner) consumeCapabilityGrant(state *RuntimeState, binding ReceiptBinding, c ConsumeCapabilityGrantCommand, now time.Time) (PlanResult, EffectSet, error) {
	turnIndex := findTurn(state, binding.Scope, c.SessionID, c.TurnID)
	// An approval may resume a Turn, but a grant never outlives that Turn's
	// executable phase. This check is deliberately in the deterministic state
	// transition rather than the worker so a cancellation/replay race cannot
	// consume a capability after the owner has withdrawn the work.
	if turnIndex < 0 {
		return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
	}
	if state.Turns[turnIndex].State != agentruntime.TurnRunning {
		return PlanResult{}, EffectSet{}, ErrConflict
	}
	for index := range state.Grants {
		grant := state.Grants[index]
		if grant.GrantID != c.GrantID || grant.Tenant != binding.Scope.Tenant || grant.Principal != binding.Scope.Principal {
			continue
		}
		if grant.ToolCallID != c.ToolCallID || grant.PolicyRevisionDigest != c.PolicyRevisionDigest || grant.RevokedAt != nil || !now.Before(grant.ExpiresAt) || grant.Uses >= grant.MaximumUses {
			return PlanResult{}, EffectSet{}, ErrConflict
		}
		grant.Uses++
		state.Grants[index] = grant
		effects, err := planner.auditOnly(state, binding, "capability_grant.consumed", c.SessionID, c.TurnID, now)
		return PlanResult{}, effects, err
	}
	return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
}

func (planner *RuntimeStatePlanner) revokeCapabilityGrant(state *RuntimeState, binding ReceiptBinding, c RevokeCapabilityGrantCommand, now time.Time) (PlanResult, EffectSet, error) {
	turnIndex := findTurn(state, binding.Scope, c.SessionID, c.TurnID)
	if turnIndex < 0 {
		return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
	}
	for index := range state.Grants {
		grant := state.Grants[index]
		if grant.GrantID != c.GrantID || grant.Tenant != binding.Scope.Tenant || grant.Principal != binding.Scope.Principal {
			continue
		}
		if grant.ToolCallID != c.ToolCallID || grant.Uses != 0 || grant.RevokedAt != nil || !now.Before(grant.ExpiresAt) {
			return PlanResult{}, EffectSet{}, ErrConflict
		}
		for _, execution := range state.ToolExecutions {
			if execution.GrantID == grant.GrantID {
				return PlanResult{}, EffectSet{}, ErrConflict
			}
		}
		value := now
		grant.RevokedAt = &value
		state.Grants[index] = grant
		effects, err := planner.auditOnly(state, binding, "capability_grant.revoked", c.SessionID, c.TurnID, now)
		return PlanResult{}, effects, err
	}
	return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
}

func (planner *RuntimeStatePlanner) expireCapabilityGrant(state *RuntimeState, binding ReceiptBinding, c ExpireCapabilityGrantCommand, now time.Time) (PlanResult, EffectSet, error) {
	if findTurn(state, binding.Scope, c.SessionID, c.TurnID) < 0 {
		return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
	}
	for index := range state.Grants {
		grant := state.Grants[index]
		if grant.GrantID != c.GrantID || grant.Tenant != binding.Scope.Tenant || grant.Principal != binding.Scope.Principal {
			continue
		}
		if grant.ToolCallID != c.ToolCallID || grant.RevokedAt != nil || now.Before(grant.ExpiresAt) {
			return PlanResult{}, EffectSet{}, ErrConflict
		}
		value := now
		grant.RevokedAt = &value
		state.Grants[index] = grant
		effects, err := planner.auditOnly(state, binding, "capability_grant.expired", c.SessionID, c.TurnID, now)
		return PlanResult{}, effects, err
	}
	return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
}

func (planner *RuntimeStatePlanner) denyToolAdmission(state *RuntimeState, binding ReceiptBinding, c DenyToolAdmissionCommand, now time.Time) (PlanResult, EffectSet, error) {
	if findTurn(state, binding.Scope, c.SessionID, c.TurnID) < 0 {
		return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
	}
	effects, err := planner.auditOnly(state, binding, "tool.admission_denied", c.SessionID, c.TurnID, now)
	return PlanResult{}, effects, err
}

func (planner *RuntimeStatePlanner) beginToolExecution(state *RuntimeState, binding ReceiptBinding, c BeginToolExecutionCommand, now time.Time) (PlanResult, EffectSet, error) {
	turnIndex := findTurn(state, binding.Scope, c.SessionID, c.TurnID)
	// Keep the second half of consume->intent fenced by the same durable Turn
	// phase. A worker restart between the two transitions may resume safely,
	// whereas cancellation, expiry, or a terminal result must never create a
	// new external-effect intent.
	if turnIndex < 0 {
		return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
	}
	if state.Turns[turnIndex].State != agentruntime.TurnRunning {
		return PlanResult{}, EffectSet{}, ErrConflict
	}
	for _, execution := range state.ToolExecutions {
		if execution.OperationID == c.OperationID {
			return PlanResult{}, EffectSet{}, ErrConflict
		}
	}
	for _, grant := range state.Grants {
		if grant.GrantID != c.GrantID || grant.Tenant != binding.Scope.Tenant || grant.Principal != binding.Scope.Principal {
			continue
		}
		if grant.ToolCallID != c.ToolCallID || grant.Uses == 0 || !now.Before(grant.ExpiresAt) {
			return PlanResult{}, EffectSet{}, ErrConflict
		}
		record := ToolExecutionRecord{Tenant: binding.Scope.Tenant, Principal: binding.Scope.Principal, SessionID: c.SessionID, TurnID: c.TurnID, ToolCallID: c.ToolCallID, GrantID: c.GrantID, OperationID: c.OperationID, State: ToolExecutionIntent, CreatedAt: now, UpdatedAt: now, RetentionUntil: planner.retain(now, DataClassAuthorization)}
		state.ToolExecutions = append(state.ToolExecutions, record)
		effects, err := planner.auditOnly(state, binding, "tool.execution_intended", c.SessionID, c.TurnID, now)
		if err != nil {
			return PlanResult{}, effects, err
		}
		outbox, err := planner.toolExecutionOutbox(record, now, planner.retain(now, DataClassOutbox))
		if err != nil {
			return PlanResult{}, EffectSet{}, err
		}
		state.Outbox = append(state.Outbox, outbox)
		effects.Outbox = append(effects.Outbox, outbox)
		return PlanResult{}, effects, nil
	}
	return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
}

func (planner *RuntimeStatePlanner) recordToolExecutionOutcome(state *RuntimeState, binding ReceiptBinding, c RecordToolExecutionOutcomeCommand, now time.Time) (PlanResult, EffectSet, error) {
	sessionIndex := findSession(state, binding.Scope, c.SessionID)
	turnIndex := findTurn(state, binding.Scope, c.SessionID, c.TurnID)
	if sessionIndex < 0 || turnIndex < 0 {
		return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
	}
	for index := range state.ToolExecutions {
		record := state.ToolExecutions[index]
		if record.OperationID != c.OperationID || record.ToolCallID != c.ToolCallID || record.Tenant != binding.Scope.Tenant || record.Principal != binding.Scope.Principal || record.SessionID != c.SessionID || record.TurnID != c.TurnID {
			continue
		}
		if record.State != ToolExecutionIntent {
			return PlanResult{}, EffectSet{}, ErrConflict
		}
		record.State, record.Result, record.Failure, record.UpdatedAt = c.Outcome, c.Result, c.Failure.Clone(), now
		state.ToolExecutions[index] = record
		for grantIndex := range state.Grants {
			grant := state.Grants[grantIndex]
			if grant.GrantID == record.GrantID && grant.RevokedAt == nil {
				value := now
				grant.RevokedAt = &value
				state.Grants[grantIndex] = grant
				break
			}
		}
		effects, err := planner.effects(state, binding, state.Sessions[sessionIndex], state.Turns[turnIndex], InvocationRecord{OperationID: record.OperationID}, []agentruntime.EventKind{agentruntime.EventSandboxOperationFinalized}, now)
		if err != nil {
			return PlanResult{}, effects, err
		}
		for _, grant := range state.Grants {
			if grant.GrantID == record.GrantID && grant.Uses >= grant.MaximumUses {
				extra, auditErr := planner.auditOnly(state, binding, "capability_grant.exhausted", c.SessionID, c.TurnID, now)
				if auditErr != nil {
					return PlanResult{}, effects, auditErr
				}
				effects.Audit = append(effects.Audit, extra.Audit...)
				effects.Outbox = append(effects.Outbox, extra.Outbox...)
				break
			}
		}
		return PlanResult{}, effects, nil
	}
	return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
}

func (planner *RuntimeStatePlanner) begin(state *RuntimeState, binding ReceiptBinding, command BeginInvocationAttemptCommand, now time.Time) (PlanResult, EffectSet, error) {
	sessionIndex := findSession(state, binding.Scope, command.SessionID)
	turnIndex := findTurn(state, binding.Scope, command.SessionID, command.TurnID)
	if sessionIndex < 0 || turnIndex < 0 {
		return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
	}
	session, turn := state.Sessions[sessionIndex], state.Turns[turnIndex]
	if session.Version != command.ExpectedSessionVersion || turn.Version != command.ExpectedTurnVersion || turn.State != agentruntime.TurnRunning {
		return PlanResult{}, EffectSet{}, ErrConflict
	}
	for _, invocation := range state.Invocations {
		if invocation.OperationID == command.OperationID {
			return PlanResult{}, EffectSet{}, ErrConflict
		}
	}
	ordinal, fence := uint64(1), uint64(1)
	for _, invocation := range state.Invocations {
		if invocation.TurnID == turn.TurnID {
			if invocation.Ordinal >= ordinal {
				ordinal = invocation.Ordinal + 1
			}
			if invocation.Fence >= fence {
				fence = invocation.Fence + 1
			}
		}
	}
	if command.ExpectedFence != 0 && command.ExpectedFence != fence-1 {
		return PlanResult{}, EffectSet{}, ErrConflict
	}
	id, err := planner.invocationID()
	if err != nil {
		return PlanResult{}, EffectSet{}, err
	}
	until := planner.retain(now, DataClassInvocation)
	invocation := InvocationRecord{Tenant: session.Tenant, Principal: session.Principal, SessionID: session.SessionID, TurnID: turn.TurnID, InvocationID: id, OperationID: command.OperationID, Ordinal: ordinal, Fence: fence, State: InvocationIntent, CreatedAt: now, UpdatedAt: now, RetentionUntil: until}
	state.Invocations = append(state.Invocations, invocation)
	turn.Version++
	session.Version++
	session.UpdatedAt = now
	state.Turns[turnIndex], state.Sessions[sessionIndex] = turn, session
	effects, err := planner.effects(state, binding, session, turn, invocation, nil, now)
	if err != nil {
		return PlanResult{}, EffectSet{}, err
	}
	return PlanResult{Invocation: invocation, Session: session, Turn: turn}, effects, nil
}

func (planner *RuntimeStatePlanner) recordOutcome(state *RuntimeState, binding ReceiptBinding, command RecordInvocationOutcomeCommand, now time.Time) (PlanResult, EffectSet, error) {
	sessionIndex := findSession(state, binding.Scope, command.SessionID)
	turnIndex := findTurn(state, binding.Scope, command.SessionID, command.TurnID)
	invocationIndex := findInvocation(state, binding.Scope, command.SessionID, command.TurnID, command.OperationID)
	if sessionIndex < 0 || turnIndex < 0 || invocationIndex < 0 {
		return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
	}
	session, turn, invocation := state.Sessions[sessionIndex], state.Turns[turnIndex], state.Invocations[invocationIndex]
	if session.Version != command.ExpectedSessionVersion || turn.Version != command.ExpectedTurnVersion || invocation.Ordinal != command.Ordinal || invocation.Fence != command.Fence || invocation.State != InvocationIntent || turn.State != agentruntime.TurnRunning {
		return PlanResult{}, EffectSet{}, ErrConflict
	}
	invocation.State, invocation.Result, invocation.Failure, invocation.Usage, invocation.UpdatedAt = command.Outcome, command.Result, command.Failure.Clone(), command.Usage.Clone(), now
	state.Invocations[invocationIndex] = invocation
	effects, err := planner.effects(state, binding, session, turn, invocation, nil, now)
	if err != nil {
		return PlanResult{}, EffectSet{}, err
	}
	return PlanResult{Invocation: invocation}, effects, nil
}

func (planner *RuntimeStatePlanner) settle(state *RuntimeState, binding ReceiptBinding, command SettleTurnCommand, now time.Time, cancelled bool) (PlanResult, EffectSet, error) {
	sessionIndex := findSession(state, binding.Scope, command.SessionID)
	turnIndex := findTurn(state, binding.Scope, command.SessionID, command.TurnID)
	if sessionIndex < 0 || turnIndex < 0 {
		return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
	}
	session, turn := state.Sessions[sessionIndex], state.Turns[turnIndex]
	if session.Version != command.ExpectedSessionVersion || turn.Version != command.ExpectedTurnVersion || turn.State != agentruntime.TurnRunning {
		return PlanResult{}, EffectSet{}, ErrConflict
	}
	if command.Outcome.OperationID != "" {
		index := findInvocation(state, binding.Scope, command.SessionID, command.TurnID, command.Outcome.OperationID)
		if index < 0 || state.Invocations[index].Ordinal != command.Outcome.Ordinal || state.Invocations[index].Fence != command.Outcome.Fence || (state.Invocations[index].State != InvocationSucceeded && state.Invocations[index].State != InvocationFailed && state.Invocations[index].State != InvocationUncertain) {
			return PlanResult{}, EffectSet{}, ErrConflict
		}
	}
	turn.State, turn.Failure = command.Outcome.State, command.Outcome.Failure.Clone()
	turn.Version++
	turn.CompletedAt = &now
	state.Turns[turnIndex] = turn
	session.Version++
	session.UpdatedAt = now
	kind := terminalEvent(turn.State)
	kinds := []agentruntime.EventKind{kind}
	if command.Outcome.OperationID != "" {
		invocation := state.Invocations[findInvocation(state, binding.Scope, command.SessionID, command.TurnID, command.Outcome.OperationID)]
		if invocation.State == InvocationUncertain {
			kinds = []agentruntime.EventKind{agentruntime.EventProducerGap, kind}
		}
	}
	promoted := planner.promote(state, session.SessionID, now)
	if promoted != nil {
		kinds = append(kinds, agentruntime.EventTurnStarted)
	} else if session.State == agentruntime.SessionClosing {
		session.State = agentruntime.SessionCompleted
		kinds = append(kinds, agentruntime.EventSessionCompleted)
	}
	state.Sessions[sessionIndex] = session
	effects, err := planner.effects(state, binding, session, turn, InvocationRecord{}, kinds, now)
	if err != nil {
		return PlanResult{}, EffectSet{}, err
	}
	return PlanResult{Session: session, Turn: turn, Promoted: promoted}, effects, nil
}

func (planner *RuntimeStatePlanner) cancel(state *RuntimeState, binding ReceiptBinding, command CancelTurnCommand, now time.Time) (PlanResult, EffectSet, error) {
	sessionIndex := findSession(state, binding.Scope, command.SessionID)
	turnIndex := findTurn(state, binding.Scope, command.SessionID, command.TurnID)
	if sessionIndex < 0 || turnIndex < 0 {
		return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
	}
	session, turn := state.Sessions[sessionIndex], state.Turns[turnIndex]
	if turn.State != agentruntime.TurnRunning && turn.State != agentruntime.TurnWaitingForApproval && turn.State != agentruntime.TurnQueued {
		return PlanResult{}, EffectSet{}, ErrConflict
	}
	priorState := turn.State
	turn.State, turn.Version, turn.CompletedAt = agentruntime.TurnCancelled, turn.Version+1, &now
	state.Turns[turnIndex] = turn
	cancelledApprovals := 0
	for index := range state.Approvals {
		approval := state.Approvals[index]
		if approval.SessionID == command.SessionID && approval.TurnID == command.TurnID && approval.Tenant == binding.Scope.Tenant && approval.Principal == binding.Scope.Principal && approval.State == "pending" {
			approval.State = string(agentruntime.ApprovalCancelled)
			state.Approvals[index] = approval
			cancelledApprovals++
		}
	}
	// A cancellation withdraws any still-unused authority for this Turn before
	// the worker can commit an execution intent. A consumed grant has already
	// crossed that boundary and must instead reconcile its exact operation.
	toolCalls := map[string]struct{}{}
	for _, intent := range state.ToolIntents {
		if intent.SessionID == command.SessionID && intent.TurnID == command.TurnID && intent.Tenant == binding.Scope.Tenant && intent.Principal == binding.Scope.Principal {
			toolCalls[intent.ToolCallID] = struct{}{}
		}
	}
	revokedGrants := 0
	for index := range state.Grants {
		grant := state.Grants[index]
		if grant.Tenant != binding.Scope.Tenant || grant.Principal != binding.Scope.Principal || grant.Uses != 0 || grant.RevokedAt != nil {
			continue
		}
		if _, belongsToCancelledTurn := toolCalls[grant.ToolCallID]; !belongsToCancelledTurn {
			continue
		}
		value := now
		grant.RevokedAt = &value
		state.Grants[index] = grant
		revokedGrants++
	}
	session.Version++
	session.UpdatedAt = now
	kinds := []agentruntime.EventKind{agentruntime.EventTurnCancelled}
	promoted := (*TurnRecord)(nil)
	if priorState == agentruntime.TurnRunning || priorState == agentruntime.TurnWaitingForApproval {
		promoted = planner.promote(state, session.SessionID, now)
	}
	if promoted != nil {
		kinds = append(kinds, agentruntime.EventTurnStarted)
	} else if session.State == agentruntime.SessionClosing && !hasPending(state, session.SessionID) {
		session.State = agentruntime.SessionCompleted
		kinds = append(kinds, agentruntime.EventSessionCompleted)
	}
	state.Sessions[sessionIndex] = session
	effects, err := planner.effects(state, binding, session, turn, InvocationRecord{}, kinds, now)
	if err != nil {
		return PlanResult{}, EffectSet{}, err
	}
	for range cancelledApprovals {
		approvalEffects, auditErr := planner.auditOnly(state, binding, "approval.cancelled", command.SessionID, command.TurnID, now)
		if auditErr != nil {
			return PlanResult{}, EffectSet{}, auditErr
		}
		effects.Audit = append(effects.Audit, approvalEffects.Audit...)
		effects.Outbox = append(effects.Outbox, approvalEffects.Outbox...)
	}
	for range revokedGrants {
		revocationEffects, auditErr := planner.auditOnly(state, binding, "capability_grant.revoked", command.SessionID, command.TurnID, now)
		if auditErr != nil {
			return PlanResult{}, EffectSet{}, auditErr
		}
		effects.Audit = append(effects.Audit, revocationEffects.Audit...)
		effects.Outbox = append(effects.Outbox, revocationEffects.Outbox...)
	}
	return PlanResult{Session: session, Turn: turn, Promoted: promoted}, effects, nil
}

func (planner *RuntimeStatePlanner) close(state *RuntimeState, binding ReceiptBinding, command CloseSessionCommand, now time.Time) (PlanResult, EffectSet, error) {
	index := findSession(state, binding.Scope, command.SessionID)
	if index < 0 {
		return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
	}
	session := state.Sessions[index]
	if session.State != agentruntime.SessionOpen {
		return PlanResult{}, EffectSet{}, ErrConflict
	}
	session.State, session.Version, session.UpdatedAt = agentruntime.SessionClosing, session.Version+1, now
	kinds := []agentruntime.EventKind{agentruntime.EventSessionClosing}
	if !hasPending(state, session.SessionID) {
		session.State = agentruntime.SessionCompleted
		kinds = append(kinds, agentruntime.EventSessionCompleted)
	}
	state.Sessions[index] = session
	effects, err := planner.effects(state, binding, session, TurnRecord{}, InvocationRecord{}, kinds, now)
	if err != nil {
		return PlanResult{}, EffectSet{}, err
	}
	return PlanResult{Session: session}, effects, nil
}
func (planner *RuntimeStatePlanner) claim(state *RuntimeState, binding ReceiptBinding, command ClaimOutboxCommand, now time.Time) (PlanResult, EffectSet, error) {
	index := findOutbox(state, binding.Scope.Tenant, command.OutboxID)
	if index < 0 {
		return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
	}
	record := state.Outbox[index]
	claimable := record.State == OutboxPending || (record.State == OutboxClaimed && record.ClaimUntil != nil && !record.ClaimUntil.After(now))
	if record.Version != command.ExpectedVersion || !claimable || !command.ClaimUntil.After(now) {
		return PlanResult{}, EffectSet{}, ErrConflict
	}
	record.State, record.ClaimedBy, record.ClaimUntil, record.Version = OutboxClaimed, command.Claimer, &command.ClaimUntil, record.Version+1
	state.Outbox[index] = record
	// Audit-export routes are already lifecycle facts. Auditing their own claim
	// would create an unbounded audit-outbox recursion, so they are the one
	// deliberately terminal bookkeeping exception.
	if record.Aggregate == "audit_fact" {
		return PlanResult{Outbox: record}, EffectSet{}, nil
	}
	effects, err := planner.auditOnly(state, binding, "outbox.claimed", record.SessionID, record.TurnID, now)
	return PlanResult{Outbox: record}, effects, err
}
func (planner *RuntimeStatePlanner) acknowledge(state *RuntimeState, binding ReceiptBinding, command AcknowledgeOutboxCommand, now time.Time) (PlanResult, EffectSet, error) {
	index := findOutbox(state, binding.Scope.Tenant, command.OutboxID)
	if index < 0 {
		return PlanResult{}, EffectSet{}, ErrNotFoundOrDenied
	}
	record := state.Outbox[index]
	if record.Version != command.ExpectedVersion || record.State != OutboxClaimed || record.ClaimedBy != command.Claimer || record.ClaimUntil == nil || !record.ClaimUntil.After(now) {
		return PlanResult{}, EffectSet{}, ErrConflict
	}
	record.State, record.Version, record.ClaimUntil = OutboxPublished, record.Version+1, nil
	state.Outbox[index] = record
	if record.Aggregate == "audit_fact" {
		return PlanResult{Outbox: record}, EffectSet{}, nil
	}
	effects, err := planner.auditOnly(state, binding, "outbox.published", record.SessionID, record.TurnID, now)
	return PlanResult{Outbox: record}, effects, err
}

func (planner *RuntimeStatePlanner) promote(state *RuntimeState, sessionID agentruntime.SessionID, now time.Time) *TurnRecord {
	var index = -1
	var position uint64
	for i := range state.Turns {
		turn := state.Turns[i]
		if turn.SessionID == sessionID && turn.State == agentruntime.TurnQueued && (index < 0 || turn.Position < position) {
			index, position = i, turn.Position
		}
	}
	if index < 0 {
		return nil
	}
	state.Turns[index].State, state.Turns[index].Version, state.Turns[index].StartedAt = agentruntime.TurnRunning, state.Turns[index].Version+1, &now
	result := state.Turns[index].Clone()
	return &result
}
func (planner *RuntimeStatePlanner) effects(state *RuntimeState, binding ReceiptBinding, session SessionRecord, turn TurnRecord, invocation InvocationRecord, kinds []agentruntime.EventKind, now time.Time) (EffectSet, error) {
	effects := EffectSet{}
	for _, kind := range kinds {
		event, err := planner.event(state, session, turn, invocation, binding, kind, now, planner.retain(now, DataClassEvent))
		if err != nil {
			return EffectSet{}, err
		}
		state.Events = append(state.Events, event)
		effects.Events = append(effects.Events, event)
		outbox, err := planner.outbox(session, turn, invocation, event.EventID, kind, event.Sequence, now, planner.retain(now, DataClassOutbox))
		if err != nil {
			return EffectSet{}, err
		}
		state.Outbox = append(state.Outbox, outbox)
		effects.Outbox = append(effects.Outbox, outbox)
	}
	fact, err := planner.fact(binding, session, turn, now, planner.retain(now, DataClassAudit))
	if err != nil {
		return EffectSet{}, err
	}
	state.Audit = append(state.Audit, fact)
	effects.Audit = append(effects.Audit, fact)
	// One semantic route carries the compatibility fact. Additional semantic
	// events must not redeliver it; every phase below has its own audit route.
	if len(effects.Outbox) > 0 {
		effects.Outbox[0].AuditFactID = fact.AuditFactID
		state.Outbox[len(state.Outbox)-len(effects.Outbox)].AuditFactID = fact.AuditFactID
	}
	if len(kinds) == 0 {
		outbox, err := planner.outbox(session, turn, invocation, agentruntime.EventID(""), "", 0, now, planner.retain(now, DataClassOutbox))
		if err != nil {
			return EffectSet{}, err
		}
		outbox.AuditFactID = fact.AuditFactID
		state.Outbox = append(state.Outbox, outbox)
		effects.Outbox = append(effects.Outbox, outbox)
	}
	if err := planner.appendAuditLifecycle(state, &effects, binding, session.SessionID, turn.TurnID, now); err != nil {
		return EffectSet{}, err
	}
	return effects, nil
}
func (planner *RuntimeStatePlanner) auditOnly(state *RuntimeState, binding ReceiptBinding, kind string, sessionID agentruntime.SessionID, turnID agentruntime.TurnID, now time.Time) (EffectSet, error) {
	fact, err := planner.factKind(binding, kind, sessionID, turnID, now, planner.retain(now, DataClassAudit))
	if err != nil {
		return EffectSet{}, err
	}
	state.Audit = append(state.Audit, fact)
	effects := EffectSet{Audit: []AuditFactRecord{fact}}
	outbox, err := planner.auditOutbox(fact, now, planner.retain(now, DataClassOutbox))
	if err != nil {
		return EffectSet{}, err
	}
	state.Outbox = append(state.Outbox, outbox)
	effects.Outbox = append(effects.Outbox, outbox)
	if err := planner.appendAuditLifecycle(state, &effects, binding, sessionID, turnID, now); err != nil {
		return EffectSet{}, err
	}
	return effects, nil
}

// appendAuditLifecycle persists the redacted audit phases alongside a mutation
// and gives every phase an independent durable-export route. Compilation has
// already sealed authorization when this runs; all facts become visible only
// with the same committed state replacement. Terminal and reconciliation
// phases are emitted only for the closed mutation vocabulary that owns them.
func (planner *RuntimeStatePlanner) appendAuditLifecycle(state *RuntimeState, effects *EffectSet, binding ReceiptBinding, sessionID agentruntime.SessionID, turnID agentruntime.TurnID, now time.Time) error {
	if effects == nil {
		return ErrIntegrity
	}
	for _, kind := range auditLifecycleKinds(binding.Command) {
		fact, err := planner.factKind(binding, kind, sessionID, turnID, now, planner.retain(now, DataClassAudit))
		if err != nil {
			return err
		}
		state.Audit = append(state.Audit, fact)
		effects.Audit = append(effects.Audit, fact)
		outbox, err := planner.auditOutbox(fact, now, planner.retain(now, DataClassOutbox))
		if err != nil {
			return err
		}
		state.Outbox = append(state.Outbox, outbox)
		effects.Outbox = append(effects.Outbox, outbox)
	}
	return nil
}

func auditLifecycleKinds(command CommandKind) []string {
	prefix := string(command)
	kinds := []string{prefix + ".attempted", prefix + ".authorized", prefix + ".committed"}
	switch command {
	case CommandRecordToolOutcome, CommandRecordOutcome, CommandSettleTurn, CommandCancelTurn, CommandCloseSession, CommandRevokeCapabilityGrant, CommandExpireCapabilityGrant:
		return append(kinds, prefix+".terminal")
	case CommandClaimOutbox, CommandAcknowledgeOutbox:
		return append(kinds, prefix+".reconciled")
	default:
		return kinds
	}
}
func (planner *RuntimeStatePlanner) event(state *RuntimeState, session SessionRecord, turn TurnRecord, invocation InvocationRecord, binding ReceiptBinding, kind agentruntime.EventKind, now, until time.Time) (ProductEventRecord, error) {
	sequence := uint64(1)
	for _, event := range state.Events {
		if event.SessionID == session.SessionID && event.Sequence >= sequence {
			sequence = event.Sequence + 1
		}
	}
	id, err := planner.eventID()
	if err != nil {
		return ProductEventRecord{}, err
	}
	cursor, err := planner.cursor()
	if err != nil {
		return ProductEventRecord{}, err
	}
	operationID := invocation.OperationID
	if operationID == "" {
		operationID = OperationID(binding.IdempotencyKey)
	}
	return ProductEventRecord{Tenant: session.Tenant, Principal: session.Principal, SessionID: session.SessionID, Sequence: sequence, Cursor: cursor, EventID: id, Kind: kind, InputID: turn.InputID, TurnID: turn.TurnID, OperationID: operationID, OccurredAt: now, RetentionUntil: until}, nil
}
func (planner *RuntimeStatePlanner) fact(binding ReceiptBinding, session SessionRecord, turn TurnRecord, now, until time.Time) (AuditFactRecord, error) {
	return planner.factKind(binding, string(binding.Command), session.SessionID, turn.TurnID, now, until)
}
func (planner *RuntimeStatePlanner) factKind(binding ReceiptBinding, kind string, sessionID agentruntime.SessionID, turnID agentruntime.TurnID, now, until time.Time) (AuditFactRecord, error) {
	id, err := planner.auditID()
	if err != nil {
		return AuditFactRecord{}, err
	}
	return AuditFactRecord{Tenant: binding.Scope.Tenant, AuditFactID: id, OperationID: OperationID(binding.IdempotencyKey), Actor: binding.Scope.Principal, Kind: kind, SessionID: sessionID, TurnID: turnID, OccurredAt: now, RetentionUntil: until}, nil
}
func (planner *RuntimeStatePlanner) outbox(session SessionRecord, turn TurnRecord, invocation InvocationRecord, eventID agentruntime.EventID, eventKind agentruntime.EventKind, eventSequence uint64, now, until time.Time) (OutboxRecord, error) {
	id, err := planner.outboxID()
	if err != nil {
		return OutboxRecord{}, err
	}
	return OutboxRecord{Tenant: session.Tenant, Principal: session.Principal, OutboxID: id, Aggregate: "session", AggregateVersion: session.Version, Version: 1, EventID: eventID, EventKind: eventKind, EventSequence: eventSequence, OperationID: invocation.OperationID, SessionID: session.SessionID, TurnID: turn.TurnID, InvocationID: invocation.InvocationID, InvocationOrdinal: invocation.Ordinal, InvocationFence: invocation.Fence, SessionVersion: session.Version, TurnVersion: turn.Version, State: OutboxPending, CommittedAt: now, RetentionUntil: until}, nil
}
func (planner *RuntimeStatePlanner) auditOutbox(fact AuditFactRecord, now, until time.Time) (OutboxRecord, error) {
	id, err := planner.outboxID()
	if err != nil {
		return OutboxRecord{}, err
	}
	return OutboxRecord{Tenant: fact.Tenant, Principal: fact.Actor, OutboxID: id, Aggregate: "audit_fact", AggregateVersion: 1, Version: 1, AuditFactID: fact.AuditFactID, OperationID: fact.OperationID, SessionID: fact.SessionID, TurnID: fact.TurnID, State: OutboxPending, CommittedAt: now, RetentionUntil: until}, nil
}
func (planner *RuntimeStatePlanner) catalogOutbox(binding ReceiptBinding, revision AgentRevisionRecord, now, until time.Time) (OutboxRecord, error) {
	id, err := planner.outboxID()
	if err != nil {
		return OutboxRecord{}, err
	}
	return OutboxRecord{Tenant: binding.Scope.Tenant, Principal: binding.Scope.Principal, OutboxID: id, Aggregate: "agent_revision", AggregateVersion: revision.Revision, Version: 1, OperationID: OperationID(binding.IdempotencyKey), State: OutboxPending, CommittedAt: now, RetentionUntil: until}, nil
}
func (planner *RuntimeStatePlanner) artifactOutbox(binding ReceiptBinding, artifact ArtifactRecord, now, until time.Time) (OutboxRecord, error) {
	id, err := planner.outboxID()
	if err != nil {
		return OutboxRecord{}, err
	}
	return OutboxRecord{Tenant: artifact.Tenant, Principal: artifact.Principal, OutboxID: id, Aggregate: "artifact", AggregateVersion: 1, Version: 1, OperationID: OperationID(binding.IdempotencyKey), SessionID: artifact.SessionID, TurnID: artifact.TurnID, State: OutboxPending, CommittedAt: now, RetentionUntil: until}, nil
}

func (planner *RuntimeStatePlanner) toolExecutionOutbox(execution ToolExecutionRecord, now, until time.Time) (OutboxRecord, error) {
	id, err := planner.outboxID()
	if err != nil {
		return OutboxRecord{}, err
	}
	return OutboxRecord{Tenant: execution.Tenant, Principal: execution.Principal, OutboxID: id, Aggregate: "tool_execution", AggregateVersion: 1, Version: 1, OperationID: execution.OperationID, ToolCallID: execution.ToolCallID, SessionID: execution.SessionID, TurnID: execution.TurnID, State: OutboxPending, CommittedAt: now, RetentionUntil: until}, nil
}
func (planner *RuntimeStatePlanner) conversationOutbox(binding ReceiptBinding, conversation ConversationRecord, now, until time.Time) (OutboxRecord, error) {
	id, err := planner.outboxID()
	if err != nil {
		return OutboxRecord{}, err
	}
	return OutboxRecord{Tenant: conversation.Tenant, Principal: conversation.Principal, OutboxID: id, Aggregate: "conversation", AggregateVersion: conversation.Version, Version: 1, OperationID: OperationID(binding.IdempotencyKey), SessionID: conversation.SessionID, State: OutboxPending, CommittedAt: now, RetentionUntil: until}, nil
}
func (planner *RuntimeStatePlanner) receipt(binding ReceiptBinding, result PlanResult, now time.Time) MutationReceipt {
	return MutationReceipt{Scope: binding.Scope, IdempotencyKey: binding.IdempotencyKey, OperationID: OperationID(binding.IdempotencyKey), Command: string(binding.Command), RequestDigest: binding.RequestDigest, AgentID: result.Revision.AgentID, RevisionID: result.Revision.RevisionID, PolicyName: result.Policy.Name, PolicyRevision: result.Policy.Revision, SessionID: firstID(firstID(firstID(result.Session.SessionID, result.Turn.SessionID), result.Artifact.SessionID), result.Conversation.SessionID), InputID: result.Input.InputID, TurnID: firstTurnID(result.Turn.TurnID, result.Artifact.TurnID), ArtifactID: result.Artifact.ArtifactID, ConversationVersion: result.Conversation.Version, AcceptedAt: now, RetentionUntil: planner.retain(now, DataClassReceipt)}
}
func firstID(left, right agentruntime.SessionID) agentruntime.SessionID {
	if left != "" {
		return left
	}
	return right
}
func firstTurnID(left, right agentruntime.TurnID) agentruntime.TurnID {
	if left != "" {
		return left
	}
	return right
}
func (planner *RuntimeStatePlanner) retain(now time.Time, class DataClass) time.Time {
	if policy, ok := planner.retention.(ClassRetentionPolicy); ok {
		return normalizeTime(policy.RetainClassUntil(class, now))
	}
	return normalizeTime(planner.retention.RetainUntil(now))
}
func (planner *RuntimeStatePlanner) raw(kind IdentifierKind) (string, error) {
	value, err := planner.ids.NextIdentifier(kind)
	if err != nil || value == "" {
		return "", fmt.Errorf("allocate runtime state %s: %w", kind, err)
	}
	return value, nil
}
func (planner *RuntimeStatePlanner) agentID() (agentruntime.AgentID, error) {
	value, err := planner.raw(IdentifierAgent)
	if err != nil {
		return "", err
	}
	return agentruntime.ParseAgentID(value)
}
func (planner *RuntimeStatePlanner) revisionID() (agentruntime.AgentRevisionID, error) {
	value, err := planner.raw(IdentifierRevision)
	if err != nil {
		return "", err
	}
	return agentruntime.ParseAgentRevisionID(value)
}
func (planner *RuntimeStatePlanner) sessionID() (agentruntime.SessionID, error) {
	value, err := planner.raw(IdentifierSession)
	if err != nil {
		return "", err
	}
	return agentruntime.ParseSessionID(value)
}
func (planner *RuntimeStatePlanner) inputID() (agentruntime.InputID, error) {
	value, err := planner.raw(IdentifierInput)
	if err != nil {
		return "", err
	}
	return agentruntime.ParseInputID(value)
}
func (planner *RuntimeStatePlanner) artifactID() (agentruntime.ArtifactID, error) {
	value, err := planner.raw(IdentifierArtifact)
	if err != nil {
		return "", err
	}
	return agentruntime.ParseArtifactID(value)
}

func (planner *RuntimeStatePlanner) grantID() (string, error) {
	value, err := planner.raw(IdentifierGrant)
	if err != nil {
		return "", err
	}
	if !validOpaque(value, 128) {
		return "", ErrIntegrity
	}
	return value, nil
}
func (planner *RuntimeStatePlanner) turnID() (agentruntime.TurnID, error) {
	value, err := planner.raw(IdentifierTurn)
	if err != nil {
		return "", err
	}
	return agentruntime.ParseTurnID(value)
}
func (planner *RuntimeStatePlanner) eventID() (agentruntime.EventID, error) {
	value, err := planner.raw(IdentifierEvent)
	if err != nil {
		return "", err
	}
	return agentruntime.ParseEventID(value)
}
func (planner *RuntimeStatePlanner) cursor() (agentruntime.Cursor, error) {
	value, err := planner.raw(IdentifierCursor)
	if err != nil {
		return "", err
	}
	return agentruntime.ParseCursor(value)
}
func (planner *RuntimeStatePlanner) invocationID() (InvocationID, error) {
	value, err := planner.raw(IdentifierInvocation)
	return InvocationID(value), err
}
func (planner *RuntimeStatePlanner) auditID() (AuditFactID, error) {
	value, err := planner.raw(IdentifierAudit)
	return AuditFactID(value), err
}
func (planner *RuntimeStatePlanner) outboxID() (OutboxID, error) {
	value, err := planner.raw(IdentifierOutbox)
	return OutboxID(value), err
}

func findSession(state *RuntimeState, scope MutationScope, id agentruntime.SessionID) int {
	for i, session := range state.Sessions {
		if session.Tenant == scope.Tenant && session.Principal == scope.Principal && session.SessionID == id {
			return i
		}
	}
	return -1
}
func findTurn(state *RuntimeState, scope MutationScope, sessionID agentruntime.SessionID, turnID agentruntime.TurnID) int {
	for i, turn := range state.Turns {
		if turn.Tenant == scope.Tenant && turn.Principal == scope.Principal && turn.SessionID == sessionID && turn.TurnID == turnID {
			return i
		}
	}
	return -1
}
func findInvocation(state *RuntimeState, scope MutationScope, sessionID agentruntime.SessionID, turnID agentruntime.TurnID, operation OperationID) int {
	for i, invocation := range state.Invocations {
		if invocation.Tenant == scope.Tenant && invocation.Principal == scope.Principal && invocation.SessionID == sessionID && invocation.TurnID == turnID && invocation.OperationID == operation {
			return i
		}
	}
	return -1
}
func findOutbox(state *RuntimeState, tenant runtimecontent.TenantID, id OutboxID) int {
	for i, record := range state.Outbox {
		if record.Tenant == tenant && record.OutboxID == id {
			return i
		}
	}
	return -1
}
func findReceipt(state RuntimeState, binding ReceiptBinding) (MutationReceipt, bool) {
	for _, receipt := range state.Receipts {
		if receipt.Scope == binding.Scope && receipt.IdempotencyKey == binding.IdempotencyKey {
			return receipt, true
		}
	}
	return MutationReceipt{}, false
}
func hasPending(state *RuntimeState, sessionID agentruntime.SessionID) bool {
	for _, turn := range state.Turns {
		if turn.SessionID == sessionID && (turn.State == agentruntime.TurnQueued || turn.State == agentruntime.TurnRunning || turn.State == agentruntime.TurnWaitingForApproval) {
			return true
		}
	}
	return false
}
func terminalEvent(state agentruntime.TurnState) agentruntime.EventKind {
	switch state {
	case agentruntime.TurnSucceeded:
		return agentruntime.EventTurnSucceeded
	case agentruntime.TurnCancelled:
		return agentruntime.EventTurnCancelled
	default:
		return agentruntime.EventTurnFailed
	}
}
func containsReceipt(state RuntimeState, receipt MutationReceipt) bool {
	for _, item := range state.Receipts {
		if item.Scope == receipt.Scope && item.IdempotencyKey == receipt.IdempotencyKey && item.RequestDigest == receipt.RequestDigest {
			return true
		}
	}
	return false
}
func containsEvent(state RuntimeState, event ProductEventRecord) bool {
	for _, item := range state.Events {
		if item.EventID == event.EventID {
			return true
		}
	}
	return false
}
func containsAudit(state RuntimeState, fact AuditFactRecord) bool {
	for _, item := range state.Audit {
		if item.AuditFactID == fact.AuditFactID {
			return true
		}
	}
	return false
}
func containsOutbox(state RuntimeState, record OutboxRecord) bool {
	for _, item := range state.Outbox {
		if item.OutboxID == record.OutboxID {
			return true
		}
	}
	return false
}
func validateState(state RuntimeState) error {
	revisions, policies, sessions, inputs, artifacts, conversations, turns, operations := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	approvals, grants := map[string]struct{}{}, map[string]struct{}{}
	events, cursors, audit, outbox, receipts := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	active, positions := map[agentruntime.SessionID]uint64{}, map[string]struct{}{}
	for _, record := range state.Revisions {
		if duplicate(revisions, record.RevisionID.String()) {
			return ErrIntegrity
		}
	}
	for _, record := range state.Policies {
		if duplicate(policies, string(record.Tenant)+"/"+record.Name+fmt.Sprintf("/%d", record.Revision)) || !validName(record.Name) || !validPolicyRules(record.Rules) || !validDigest(record.Digest) || record.Revision == 0 || record.CreatedAt.IsZero() || record.CreatedAt.Location() != time.UTC {
			return ErrIntegrity
		}
		digest, err := policyDigest(record.Name, record.Revision, record.Rules)
		if err != nil || digest != record.Digest {
			return ErrIntegrity
		}
	}
	for _, record := range state.Sessions {
		if !record.CreatedAt.IsZero() && record.CreatedAt.Location() != time.UTC || duplicate(sessions, record.SessionID.String()) {
			return ErrIntegrity
		}
	}
	for _, record := range state.Inputs {
		if duplicate(inputs, record.InputID.String()) {
			return ErrIntegrity
		}
	}
	for _, record := range state.Artifacts {
		if duplicate(artifacts, record.ArtifactID.String()) {
			return ErrIntegrity
		}
	}
	for _, record := range state.Conversations {
		if duplicate(conversations, record.SessionID.String()+fmt.Sprintf("/%d", record.Version)) {
			return ErrIntegrity
		}
	}
	for _, record := range state.Approvals {
		if duplicate(approvals, record.ApprovalID) {
			return ErrIntegrity
		}
	}
	for _, record := range state.Grants {
		if duplicate(grants, record.GrantID) || record.MaximumUses == 0 || record.Uses > record.MaximumUses || record.ExpiresAt.IsZero() || (record.RevokedAt != nil && (record.RevokedAt.IsZero() || record.RevokedAt.Location() != time.UTC)) {
			return ErrIntegrity
		}
	}
	for _, record := range state.Turns {
		if duplicate(turns, record.TurnID.String()) || duplicate(positions, record.SessionID.String()+fmt.Sprintf("/%d", record.Position)) {
			return ErrIntegrity
		}
		if record.State == agentruntime.TurnRunning {
			active[record.SessionID]++
			if active[record.SessionID] > 1 {
				return ErrIntegrity
			}
		}
	}
	for _, record := range state.Invocations {
		if duplicate(operations, string(record.OperationID)) {
			return ErrIntegrity
		}
	}
	for _, record := range state.ToolExecutions {
		if duplicate(operations, string(record.OperationID)) {
			return ErrIntegrity
		}
	}
	for _, record := range state.Events {
		if duplicate(events, record.EventID.String()) || duplicate(cursors, record.Cursor.String()) {
			return ErrIntegrity
		}
	}
	for _, record := range state.Audit {
		if duplicate(audit, string(record.AuditFactID)) {
			return ErrIntegrity
		}
	}
	for _, record := range state.Outbox {
		if duplicate(outbox, string(record.OutboxID)) {
			return ErrIntegrity
		}
	}
	for _, record := range state.Receipts {
		if duplicate(receipts, string(record.Scope.Tenant)+"/"+string(record.Scope.Principal)+"/"+string(record.Scope.Authority)+"/"+record.IdempotencyKey) {
			return ErrIntegrity
		}
	}
	return nil
}
func duplicate(seen map[string]struct{}, value string) bool {
	if value == "" {
		return false
	}
	if _, exists := seen[value]; exists {
		return true
	}
	seen[value] = struct{}{}
	return false
}
func (planner *RuntimeStatePlanner) replayPlan(state RuntimeState, kind CommandKind, receipt MutationReceipt) (TransitionPlan, error) {
	result := PlanResult{Kind: kind, Receipt: receipt}
	for _, revision := range state.Revisions {
		if revision.RevisionID == receipt.RevisionID {
			result.Revision = revision
		}
	}
	for _, policy := range state.Policies {
		if policy.Name == receipt.PolicyName && policy.Revision == receipt.PolicyRevision {
			result.Policy = policy
		}
	}
	for _, session := range state.Sessions {
		if session.SessionID == receipt.SessionID {
			result.Session = session
		}
	}
	for _, input := range state.Inputs {
		if input.InputID == receipt.InputID {
			result.Input = input
		}
	}
	for _, artifact := range state.Artifacts {
		if artifact.ArtifactID == receipt.ArtifactID {
			result.Artifact = artifact
		}
	}
	for _, conversation := range state.Conversations {
		if conversation.SessionID == receipt.SessionID && conversation.Version == receipt.ConversationVersion {
			result.Conversation = conversation
		}
	}
	for _, turn := range state.Turns {
		if turn.TurnID == receipt.TurnID {
			result.Turn = turn
		}
	}
	return TransitionPlan{base: state.Clone(), kind: kind, state: state, result: result}, nil
}
