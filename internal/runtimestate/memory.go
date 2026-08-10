package runtimestate

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

// MemoryRuntimeStateStore is the deterministic, plans-only conformance adapter.
// It is intentionally not a durable or public composition authority.
type MemoryRuntimeStateStore struct {
	mu      sync.RWMutex
	planner *RuntimeStatePlanner
	states  map[string]RuntimeState
}

var _ RuntimeStateStore = (*MemoryRuntimeStateStore)(nil)
var _ OutboxTenantSource = (*MemoryRuntimeStateStore)(nil)

// NewMemoryRuntimeStateStore constructs the complete in-memory plan persistence adapter.
func NewMemoryRuntimeStateStore(planner *RuntimeStatePlanner) (*MemoryRuntimeStateStore, error) {
	if planner == nil {
		return nil, errors.New("create memory runtime state store: planner is required")
	}
	return &MemoryRuntimeStateStore{planner: planner, states: map[string]RuntimeState{}}, nil
}

// LoadRuntimeState returns one ownership-partitioned independent metadata snapshot.
func (store *MemoryRuntimeStateStore) LoadRuntimeState(ctx context.Context, scope MutationScope) (RuntimeState, error) {
	if err := ctx.Err(); err != nil {
		return RuntimeState{}, err
	}
	if !validOpaque(string(scope.Tenant), 128) {
		return RuntimeState{}, ErrNotFoundOrDenied
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.states[string(scope.Tenant)].Clone(), nil
}

// PersistTransitionPlan atomically compares and applies one planner-sealed state replacement.
func (store *MemoryRuntimeStateStore) PersistTransitionPlan(ctx context.Context, plan TransitionPlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil || store.planner == nil || plan.Validate() != nil || plan.result.Receipt.Scope.Tenant == "" {
		return ErrIntegrity
	}
	tenant := string(plan.result.Receipt.Scope.Tenant)
	store.mu.Lock()
	defer store.mu.Unlock()
	current := store.states[tenant].Clone()
	if !reflect.DeepEqual(current, plan.base) {
		return ErrConflict
	}
	store.states[tenant] = plan.state.Clone()
	return nil
}

// Apply atomically loads, plans, and persists one compiler-sealed mutation.
func (store *MemoryRuntimeStateStore) Apply(ctx context.Context, mutation CompiledMutation) (TransitionPlan, error) {
	if err := ctx.Err(); err != nil {
		return TransitionPlan{}, err
	}
	if store == nil || store.planner == nil || mutation.ReceiptBinding().Scope.Tenant == "" {
		return TransitionPlan{}, ErrIntegrity
	}
	tenant := string(mutation.ReceiptBinding().Scope.Tenant)
	store.mu.Lock()
	defer store.mu.Unlock()
	prior := store.states[tenant].Clone()
	plan, err := store.planner.Plan(ctx, prior, mutation)
	if err != nil {
		return TransitionPlan{}, err
	}
	if !reflect.DeepEqual(prior, plan.base) || plan.Validate() != nil {
		return TransitionPlan{}, ErrIntegrity
	}
	store.states[tenant] = plan.state.Clone()
	return plan, nil
}

func (store *MemoryRuntimeStateStore) GetAgentRevision(ctx context.Context, query AgentRevisionQuery) (AgentRevisionRecord, error) {
	if err := requireScope(ctx, query.Scope, AuthorityTenantAdministrator, false); err != nil {
		return AgentRevisionRecord{}, err
	}
	state := store.snapshot(query.Scope.Tenant)
	for _, record := range state.Revisions {
		if record.AgentID == query.AgentID && record.RevisionID == query.RevisionID {
			return record.Clone(), nil
		}
	}
	return AgentRevisionRecord{}, ErrNotFoundOrDenied
}
func (store *MemoryRuntimeStateStore) GetSessionView(ctx context.Context, query SessionViewQuery) (SessionView, error) {
	if err := requireScope(ctx, query.Scope, AuthoritySessionOwner, true); err != nil {
		return SessionView{}, err
	}
	state := store.snapshot(query.Scope.Tenant)
	index := findSession(&state, query.Scope, query.SessionID)
	if index < 0 {
		return SessionView{}, ErrNotFoundOrDenied
	}
	view := SessionView{Session: state.Sessions[index].Clone()}
	for _, turn := range state.Turns {
		if turn.SessionID != query.SessionID {
			continue
		}
		if turn.State == "running" {
			copy := turn.Clone()
			view.ActiveTurn = &copy
		} else if turn.State == "queued" {
			view.QueuedTurnCount++
			if uint32(len(view.QueuedTurns)) < query.QueuedTurnLimit {
				view.QueuedTurns = append(view.QueuedTurns, turn.Clone())
			}
		}
	}
	view.QueuedTruncated = uint64(len(view.QueuedTurns)) < view.QueuedTurnCount
	for _, event := range state.Events {
		if event.SessionID == query.SessionID {
			view.RecentEvents = append(view.RecentEvents, event.Clone())
		}
	}
	if uint32(len(view.RecentEvents)) > query.RecentEventLimit {
		view.RecentEvents = view.RecentEvents[len(view.RecentEvents)-int(query.RecentEventLimit):]
	}
	return view.Clone(), nil
}
func (store *MemoryRuntimeStateStore) GetTurn(ctx context.Context, query TurnQuery) (TurnRecord, error) {
	if err := requireScope(ctx, query.Scope, AuthoritySessionOwner, true); err != nil {
		return TurnRecord{}, err
	}
	state := store.snapshot(query.Scope.Tenant)
	index := findTurn(&state, query.Scope, query.SessionID, query.TurnID)
	if index < 0 {
		return TurnRecord{}, ErrNotFoundOrDenied
	}
	return state.Turns[index].Clone(), nil
}
func (store *MemoryRuntimeStateStore) GetArtifact(ctx context.Context, query ArtifactQuery) (ArtifactRecord, error) {
	if err := requireScope(ctx, query.Scope, AuthoritySessionOwner, true); err != nil {
		return ArtifactRecord{}, err
	}
	state := store.snapshot(query.Scope.Tenant)
	for _, record := range state.Artifacts {
		if record.Principal == query.Scope.Principal && record.ArtifactID == query.ArtifactID {
			return record.Clone(), nil
		}
	}
	return ArtifactRecord{}, ErrNotFoundOrDenied
}
func (store *MemoryRuntimeStateStore) GetInvocation(ctx context.Context, query InvocationQuery) (InvocationRecord, error) {
	if err := requireScope(ctx, query.Scope, AuthorityRuntimeWorker, true); err != nil {
		return InvocationRecord{}, err
	}
	state := store.snapshot(query.Scope.Tenant)
	index := findInvocation(&state, query.Scope, query.SessionID, query.TurnID, query.OperationID)
	if index < 0 {
		return InvocationRecord{}, ErrNotFoundOrDenied
	}
	return state.Invocations[index].Clone(), nil
}
func (store *MemoryRuntimeStateStore) ReadEvents(ctx context.Context, query EventsQuery) (EventPage, error) {
	if err := requireScope(ctx, query.Scope, AuthoritySessionOwner, true); err != nil {
		return EventPage{}, err
	}
	if query.Limit == 0 || query.Limit > 1000 {
		return EventPage{}, ErrConflict
	}
	state := store.snapshot(query.Scope.Tenant)
	if findSession(&state, query.Scope, query.SessionID) < 0 {
		return EventPage{}, ErrNotFoundOrDenied
	}
	start := 0
	if query.After != "" {
		found := false
		for i, event := range state.Events {
			if event.SessionID == query.SessionID && event.Cursor == query.After {
				start, found = i+1, true
				break
			}
		}
		if !found {
			return EventPage{Gap: &agentruntime.EventGap{RequestedAfter: query.After, Earliest: earliestCursor(state, query.SessionID), InspectSession: true}}, nil
		}
	}
	page := EventPage{}
	for _, event := range state.Events[start:] {
		if event.SessionID == query.SessionID && uint32(len(page.Events)) < query.Limit {
			page.Events = append(page.Events, event.Clone())
			page.NextCursor = event.Cursor
		}
	}
	return page.Clone(), nil
}
func (store *MemoryRuntimeStateStore) GetMutationReceipt(ctx context.Context, query MutationReceiptQuery) (MutationReceipt, error) {
	if err := ctx.Err(); err != nil {
		return MutationReceipt{}, err
	}
	state := store.snapshot(query.Scope.Tenant)
	for _, receipt := range state.Receipts {
		if receipt.Scope == query.Scope && receipt.IdempotencyKey == query.IdempotencyKey {
			if receiptExpired(receipt, normalizeTime(store.planner.clock.Now())) {
				return MutationReceipt{}, ErrReceiptExpired
			}
			return receipt.Clone(), nil
		}
	}
	return MutationReceipt{}, ErrNotFoundOrDenied
}
func (store *MemoryRuntimeStateStore) ReadAudit(ctx context.Context, query AuditQuery) (AuditPage, error) {
	if err := requireScope(ctx, query.Scope, AuthorityAuditReader, false); err != nil {
		return AuditPage{}, err
	}
	state := store.snapshot(query.Scope.Tenant)
	page := AuditPage{}
	after := query.After == ""
	for _, fact := range state.Audit {
		if !after {
			if fact.AuditFactID == query.After {
				after = true
			}
			continue
		}
		if uint32(len(page.Facts)) == query.Limit {
			break
		}
		page.Facts = append(page.Facts, fact.Clone())
		page.Next = fact.AuditFactID
	}
	return page.Clone(), nil
}
func (store *MemoryRuntimeStateStore) ReadOutbox(ctx context.Context, query OutboxQuery) (OutboxPage, error) {
	if err := requireScope(ctx, query.Scope, AuthorityOutboxPublisher, false); err != nil {
		return OutboxPage{}, err
	}
	state := store.snapshot(query.Scope.Tenant)
	page := OutboxPage{}
	after := query.After == ""
	for _, record := range state.Outbox {
		if !after {
			if record.OutboxID == query.After {
				after = true
			}
			continue
		}
		if uint32(len(page.Records)) == query.Limit {
			break
		}
		page.Records = append(page.Records, record.Clone())
		page.Next = record.OutboxID
	}
	return page.Clone(), nil
}

// ListOutboxTenants returns only tenant partitions containing durable state.
// It exists solely for the private publisher scheduler, which subsequently
// performs authority-scoped outbox reads for each partition.
func (store *MemoryRuntimeStateStore) ListOutboxTenants(ctx context.Context) ([]runtimecontent.TenantID, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	tenants := make([]runtimecontent.TenantID, 0, len(store.states))
	for tenant := range store.states {
		tenants = append(tenants, runtimecontent.TenantID(tenant))
	}
	slices.Sort(tenants)
	return tenants, nil
}
func (store *MemoryRuntimeStateStore) AuthorizeAgentSpecificationBodyRead(ctx context.Context, authorization CompiledReadAuthorization) (runtimecontent.AgentSpecificationBodyRecord, error) {
	if err := requireScope(ctx, authorization.scope, AuthorityTenantAdministrator, false); err != nil {
		return runtimecontent.AgentSpecificationBodyRecord{}, err
	}
	state := store.snapshot(authorization.scope.Tenant)
	for _, record := range state.Revisions {
		if record.AgentID == authorization.agentID && record.RevisionID == authorization.revisionID {
			return runtimecontent.AgentSpecificationBodyRecord{Tenant: record.Tenant, AgentID: record.AgentID, RevisionID: record.RevisionID, Revision: record.Revision, Name: record.Name, ModelProfile: record.ModelProfile, Reference: record.Specification, CreatedAt: record.CreatedAt}, nil
		}
	}
	return runtimecontent.AgentSpecificationBodyRecord{}, ErrNotFoundOrDenied
}
func (store *MemoryRuntimeStateStore) AuthorizeInputEnvelopeRead(ctx context.Context, authorization CompiledReadAuthorization) (runtimecontent.InputEnvelopeRecord, error) {
	if err := requireScope(ctx, authorization.scope, AuthoritySessionOwner, true); err != nil {
		return runtimecontent.InputEnvelopeRecord{}, err
	}
	state := store.snapshot(authorization.scope.Tenant)
	for _, record := range state.Inputs {
		if record.Principal == authorization.scope.Principal && record.SessionID == authorization.sessionID && record.InputID == authorization.inputID {
			return runtimecontent.InputEnvelopeRecord{Tenant: record.Tenant, Principal: record.Principal, SessionID: record.SessionID, InputID: record.InputID, Reference: record.Content}, nil
		}
	}
	return runtimecontent.InputEnvelopeRecord{}, ErrNotFoundOrDenied
}
func (store *MemoryRuntimeStateStore) AuthorizeArtifactRead(ctx context.Context, authorization CompiledReadAuthorization) (runtimecontent.ArtifactRecord, error) {
	if err := requireScope(ctx, authorization.scope, AuthoritySessionOwner, true); err != nil {
		return runtimecontent.ArtifactRecord{}, err
	}
	state := store.snapshot(authorization.scope.Tenant)
	for _, record := range state.Artifacts {
		if record.Principal == authorization.scope.Principal && record.ArtifactID == authorization.artifactID {
			return runtimecontent.ArtifactRecord{Tenant: record.Tenant, Principal: record.Principal, ArtifactID: record.ArtifactID, Reference: record.Reference}, nil
		}
	}
	return runtimecontent.ArtifactRecord{}, ErrNotFoundOrDenied
}
func (store *MemoryRuntimeStateStore) snapshot(tenant runtimecontent.TenantID) RuntimeState {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.states[string(tenant)].Clone()
}
func requireScope(ctx context.Context, scope MutationScope, authority Authority, principal bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateScope(scope, authority, principal); err != nil {
		return ErrNotFoundOrDenied
	}
	return nil
}
func earliestCursor(state RuntimeState, sessionID agentruntime.SessionID) agentruntime.Cursor {
	for _, event := range state.Events {
		if event.SessionID == sessionID {
			return event.Cursor
		}
	}
	return ""
}
