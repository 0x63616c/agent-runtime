// Package runtimepostgres owns the PostgreSQL implementation of runtime-state persistence.
package runtimepostgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RuntimeStateStore is the plans-only PostgreSQL authority under construction.
// It is intentionally not wired to a public runtime until full conformance lands.
type RuntimeStateStore struct {
	pool  *pgxpool.Pool
	clock clock.Clock
}

var _ runtimestate.RuntimeStateStore = (*RuntimeStateStore)(nil)
var _ runtimestate.OutboxTenantSource = (*RuntimeStateStore)(nil)

// NewRuntimeStateStore constructs the PostgreSQL authority from explicit pool and clock dependencies.
func NewRuntimeStateStore(pool *pgxpool.Pool, timeSource clock.Clock) (*RuntimeStateStore, error) {
	if pool == nil {
		return nil, errors.New("create PostgreSQL runtime state store: pool is required")
	}
	if timeSource == nil {
		return nil, errors.New("create PostgreSQL runtime state store: clock is required")
	}
	return &RuntimeStateStore{pool: pool, clock: timeSource}, nil
}

// LoadRuntimeState returns the complete independent metadata state for one tenant.
func (store *RuntimeStateStore) LoadRuntimeState(ctx context.Context, scope runtimestate.MutationScope) (runtimestate.RuntimeState, error) {
	if err := ctx.Err(); err != nil {
		return runtimestate.RuntimeState{}, err
	}
	if store == nil || store.pool == nil || scope.Tenant == "" {
		return runtimestate.RuntimeState{}, runtimestate.ErrNotFoundOrDenied
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return runtimestate.RuntimeState{}, runtimestate.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := bindTenant(ctx, tx, scope.Tenant); err != nil {
		return runtimestate.RuntimeState{}, runtimestate.ErrUnavailable
	}
	state, err := store.load(ctx, tx, scope.Tenant)
	if err != nil {
		return runtimestate.RuntimeState{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return runtimestate.RuntimeState{}, runtimestate.ErrUnavailable
	}
	return state, nil
}

// PersistTransitionPlan atomically applies a validated planner result when its exact base is current.
func (store *RuntimeStateStore) PersistTransitionPlan(ctx context.Context, plan runtimestate.TransitionPlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil || store.pool == nil || plan.Validate() != nil || plan.Result().Receipt.Scope.Tenant == "" {
		return runtimestate.ErrIntegrity
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return runtimestate.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tenant := plan.Result().Receipt.Scope.Tenant
	if err := bindTenant(ctx, tx, tenant); err != nil {
		return runtimestate.ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, string(tenant)); err != nil {
		return runtimestate.ErrUnavailable
	}
	current, err := store.load(ctx, tx, tenant)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, plan.BaseState()) {
		return runtimestate.ErrConflict
	}
	encoded, err := json.Marshal(plan.State())
	if err != nil {
		return runtimestate.ErrIntegrity
	}
	if _, err := tx.Exec(ctx, `INSERT INTO runtime.tenants (tenant_id, created_at) VALUES ($1, now()) ON CONFLICT (tenant_id) DO NOTHING`, string(tenant)); err != nil {
		return runtimestate.ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `INSERT INTO runtime.tenant_retention_jobs (tenant_id, next_collection_at)
		VALUES ($1, now() + interval '24 hours') ON CONFLICT (tenant_id) DO NOTHING`, string(tenant)); err != nil {
		return runtimestate.ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `INSERT INTO runtime.runtime_state_snapshots (tenant_id, generation, state, updated_at)
		VALUES ($1, 1, $2::jsonb, now())
		ON CONFLICT (tenant_id) DO UPDATE SET generation = runtime.runtime_state_snapshots.generation + 1, state = EXCLUDED.state, updated_at = EXCLUDED.updated_at`, string(tenant), encoded); err != nil {
		return runtimestate.ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return runtimestate.ErrUnavailable
	}
	return nil
}

// bindTenant establishes the only database-side tenant selector. It is local
// to the transaction so a pooled connection can never carry one tenant into a
// later caller. Native RLS rejects reads and writes if this is absent.
func bindTenant(ctx context.Context, tx pgx.Tx, tenant runtimecontent.TenantID) error {
	if tenant == "" {
		return errors.New("bind PostgreSQL runtime tenant: tenant is required")
	}
	_, err := tx.Exec(ctx, `SELECT set_config('runtime.tenant_id', $1, true)`, string(tenant))
	return err
}

type stateLoader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (store *RuntimeStateStore) load(ctx context.Context, query stateLoader, tenant runtimecontent.TenantID) (runtimestate.RuntimeState, error) {
	var encoded []byte
	err := query.QueryRow(ctx, `SELECT state FROM runtime.runtime_state_snapshots WHERE tenant_id = $1`, string(tenant)).Scan(&encoded)
	if err != nil {
		// Missing tenant/snapshot is the empty pre-transition state; callers which
		// require an owned record apply their own non-enumerating lookup below.
		if errors.Is(err, pgx.ErrNoRows) {
			return (runtimestate.RuntimeState{}).Clone(), nil
		}
		return runtimestate.RuntimeState{}, runtimestate.ErrUnavailable
	}
	var state runtimestate.RuntimeState
	if json.Unmarshal(encoded, &state) != nil {
		return runtimestate.RuntimeState{}, runtimestate.ErrIntegrity
	}
	state, err = upgradeLegacyGrantScopes(state)
	if err != nil {
		return runtimestate.RuntimeState{}, runtimestate.ErrIntegrity
	}
	return state.Clone(), nil
}

// upgradeLegacyGrantScopes maps the prior grant JSON shape to the current
// exact Turn correlation. A later successful transition writes the normalized
// state in its existing tenant transaction. Ambiguous legacy records remain
// fail-closed rather than allowing a cross-Turn authority decision.
func upgradeLegacyGrantScopes(state runtimestate.RuntimeState) (runtimestate.RuntimeState, error) {
	upgraded := state.Clone()
	for index := range upgraded.Grants {
		grant := upgraded.Grants[index]
		if grant.SessionID != "" || grant.TurnID != "" {
			if grant.SessionID == "" || grant.TurnID == "" {
				return runtimestate.RuntimeState{}, errors.New("upgrade legacy grant scope: partial correlation")
			}
			continue
		}
		var match *runtimestate.ToolIntentRecord
		for _, intent := range upgraded.ToolIntents {
			if intent.Tenant != grant.Tenant || intent.Principal != grant.Principal || intent.ToolCallID != grant.ToolCallID {
				continue
			}
			if match != nil {
				return runtimestate.RuntimeState{}, errors.New("upgrade legacy grant scope: ambiguous correlation")
			}
			value := intent
			match = &value
		}
		if match == nil {
			return runtimestate.RuntimeState{}, errors.New("upgrade legacy grant scope: missing correlation")
		}
		if match.SessionID == "" || match.TurnID == "" {
			return runtimestate.RuntimeState{}, errors.New("upgrade legacy grant scope: incomplete correlation")
		}
		sessionFound, turnFound := false, false
		for _, session := range upgraded.Sessions {
			if session.Tenant == grant.Tenant && session.Principal == grant.Principal && session.SessionID == match.SessionID {
				sessionFound = true
				break
			}
		}
		for _, turn := range upgraded.Turns {
			if turn.Tenant == grant.Tenant && turn.Principal == grant.Principal && turn.SessionID == match.SessionID && turn.TurnID == match.TurnID {
				turnFound = true
				break
			}
		}
		if !sessionFound || !turnFound {
			return runtimestate.RuntimeState{}, errors.New("upgrade legacy grant scope: dangling correlation")
		}
		grant.SessionID, grant.TurnID = match.SessionID, match.TurnID
		upgraded.Grants[index] = grant
	}
	return upgraded, nil
}

func (store *RuntimeStateStore) GetAgentRevision(ctx context.Context, query runtimestate.AgentRevisionQuery) (runtimestate.AgentRevisionRecord, error) {
	if !hasScope(query.Scope, runtimestate.AuthorityTenantAdministrator, false) {
		return runtimestate.AgentRevisionRecord{}, runtimestate.ErrNotFoundOrDenied
	}
	state, err := store.LoadRuntimeState(ctx, query.Scope)
	if err != nil {
		return runtimestate.AgentRevisionRecord{}, err
	}
	for _, record := range state.Revisions {
		if record.AgentID == query.AgentID && record.RevisionID == query.RevisionID {
			return record.Clone(), nil
		}
	}
	return runtimestate.AgentRevisionRecord{}, runtimestate.ErrNotFoundOrDenied
}
func (store *RuntimeStateStore) GetPolicyRevision(ctx context.Context, query runtimestate.PolicyRevisionQuery) (runtimestate.PolicyRevisionRecord, error) {
	if !hasScope(query.Scope, runtimestate.AuthorityTenantAdministrator, false) || query.Name == "" || query.Revision == 0 {
		return runtimestate.PolicyRevisionRecord{}, runtimestate.ErrNotFoundOrDenied
	}
	state, err := store.LoadRuntimeState(ctx, query.Scope)
	if err != nil {
		return runtimestate.PolicyRevisionRecord{}, err
	}
	for _, record := range state.Policies {
		if record.Tenant == query.Scope.Tenant && record.Name == query.Name && record.Revision == query.Revision {
			return record.Clone(), nil
		}
	}
	return runtimestate.PolicyRevisionRecord{}, runtimestate.ErrNotFoundOrDenied
}
func (store *RuntimeStateStore) GetSessionView(ctx context.Context, query runtimestate.SessionViewQuery) (runtimestate.SessionView, error) {
	if !hasScope(query.Scope, runtimestate.AuthoritySessionOwner, true) {
		return runtimestate.SessionView{}, runtimestate.ErrNotFoundOrDenied
	}
	state, err := store.LoadRuntimeState(ctx, query.Scope)
	if err != nil {
		return runtimestate.SessionView{}, err
	}
	var view runtimestate.SessionView
	for _, session := range state.Sessions {
		if session.Tenant == query.Scope.Tenant && session.Principal == query.Scope.Principal && session.SessionID == query.SessionID {
			view.Session = session.Clone()
			break
		}
	}
	if view.Session.SessionID == "" {
		return runtimestate.SessionView{}, runtimestate.ErrNotFoundOrDenied
	}
	for _, turn := range state.Turns {
		if turn.SessionID != query.SessionID {
			continue
		}
		if turn.State == agentruntime.TurnRunning {
			copy := turn.Clone()
			view.ActiveTurn = &copy
		}
		if turn.State == agentruntime.TurnQueued {
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
func (store *RuntimeStateStore) GetTurn(ctx context.Context, query runtimestate.TurnQuery) (runtimestate.TurnRecord, error) {
	if !hasScope(query.Scope, runtimestate.AuthoritySessionOwner, true) {
		return runtimestate.TurnRecord{}, runtimestate.ErrNotFoundOrDenied
	}
	state, err := store.LoadRuntimeState(ctx, query.Scope)
	if err != nil {
		return runtimestate.TurnRecord{}, err
	}
	for _, record := range state.Turns {
		if record.Tenant == query.Scope.Tenant && record.Principal == query.Scope.Principal && record.SessionID == query.SessionID && record.TurnID == query.TurnID {
			return record.Clone(), nil
		}
	}
	return runtimestate.TurnRecord{}, runtimestate.ErrNotFoundOrDenied
}
func (store *RuntimeStateStore) GetArtifact(ctx context.Context, query runtimestate.ArtifactQuery) (runtimestate.ArtifactRecord, error) {
	if !hasScope(query.Scope, runtimestate.AuthoritySessionOwner, true) {
		return runtimestate.ArtifactRecord{}, runtimestate.ErrNotFoundOrDenied
	}
	state, err := store.LoadRuntimeState(ctx, query.Scope)
	if err != nil {
		return runtimestate.ArtifactRecord{}, err
	}
	for _, record := range state.Artifacts {
		if record.Tenant == query.Scope.Tenant && record.Principal == query.Scope.Principal && record.ArtifactID == query.ArtifactID {
			return record.Clone(), nil
		}
	}
	return runtimestate.ArtifactRecord{}, runtimestate.ErrNotFoundOrDenied
}
func (store *RuntimeStateStore) GetInvocation(ctx context.Context, query runtimestate.InvocationQuery) (runtimestate.InvocationRecord, error) {
	if !hasScope(query.Scope, runtimestate.AuthorityRuntimeWorker, true) {
		return runtimestate.InvocationRecord{}, runtimestate.ErrNotFoundOrDenied
	}
	state, err := store.LoadRuntimeState(ctx, query.Scope)
	if err != nil {
		return runtimestate.InvocationRecord{}, err
	}
	for _, record := range state.Invocations {
		if record.Tenant == query.Scope.Tenant && record.Principal == query.Scope.Principal && record.SessionID == query.SessionID && record.TurnID == query.TurnID && record.OperationID == query.OperationID {
			return record.Clone(), nil
		}
	}
	return runtimestate.InvocationRecord{}, runtimestate.ErrNotFoundOrDenied
}
func (store *RuntimeStateStore) ReadEvents(ctx context.Context, query runtimestate.EventsQuery) (runtimestate.EventPage, error) {
	if !hasScope(query.Scope, runtimestate.AuthoritySessionOwner, true) {
		return runtimestate.EventPage{}, runtimestate.ErrNotFoundOrDenied
	}
	if query.Limit == 0 || query.Limit > 1000 {
		return runtimestate.EventPage{}, runtimestate.ErrConflict
	}
	state, err := store.LoadRuntimeState(ctx, query.Scope)
	if err != nil {
		return runtimestate.EventPage{}, err
	}
	owned := false
	for _, session := range state.Sessions {
		if session.Tenant == query.Scope.Tenant && session.Principal == query.Scope.Principal && session.SessionID == query.SessionID {
			owned = true
		}
	}
	if !owned {
		return runtimestate.EventPage{}, runtimestate.ErrNotFoundOrDenied
	}
	start, found := 0, query.After == ""
	earliest := agentruntime.Cursor("")
	for i, event := range state.Events {
		if event.SessionID != query.SessionID {
			continue
		}
		if earliest == "" {
			earliest = event.Cursor
		}
		if event.Cursor == query.After {
			start, found = i+1, true
			break
		}
	}
	if !found {
		return runtimestate.EventPage{Gap: &agentruntime.EventGap{RequestedAfter: query.After, Earliest: earliest, InspectSession: true}}, nil
	}
	page := runtimestate.EventPage{}
	for _, event := range state.Events[start:] {
		if event.SessionID == query.SessionID && uint32(len(page.Events)) < query.Limit {
			page.Events = append(page.Events, event.Clone())
			page.NextCursor = event.Cursor
		}
	}
	return page.Clone(), nil
}
func (store *RuntimeStateStore) GetMutationReceipt(ctx context.Context, query runtimestate.MutationReceiptQuery) (runtimestate.MutationReceipt, error) {
	state, err := store.LoadRuntimeState(ctx, query.Scope)
	if err != nil {
		return runtimestate.MutationReceipt{}, err
	}
	for _, receipt := range state.Receipts {
		if receipt.Scope == query.Scope && receipt.IdempotencyKey == query.IdempotencyKey {
			if !receipt.RetentionUntil.After(store.clock.Now().UTC()) {
				return runtimestate.MutationReceipt{}, runtimestate.ErrReceiptExpired
			}
			return receipt.Clone(), nil
		}
	}
	return runtimestate.MutationReceipt{}, runtimestate.ErrNotFoundOrDenied
}
func (store *RuntimeStateStore) ReadAudit(ctx context.Context, query runtimestate.AuditQuery) (runtimestate.AuditPage, error) {
	if !hasScope(query.Scope, runtimestate.AuthorityAuditReader, false) {
		return runtimestate.AuditPage{}, runtimestate.ErrNotFoundOrDenied
	}
	state, err := store.LoadRuntimeState(ctx, query.Scope)
	if err != nil {
		return runtimestate.AuditPage{}, err
	}
	page, after := runtimestate.AuditPage{}, query.After == ""
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
func (store *RuntimeStateStore) ReadOutbox(ctx context.Context, query runtimestate.OutboxQuery) (runtimestate.OutboxPage, error) {
	if !hasScope(query.Scope, runtimestate.AuthorityOutboxPublisher, false) {
		return runtimestate.OutboxPage{}, runtimestate.ErrNotFoundOrDenied
	}
	state, err := store.LoadRuntimeState(ctx, query.Scope)
	if err != nil {
		return runtimestate.OutboxPage{}, err
	}
	page, after := runtimestate.OutboxPage{}, query.After == ""
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

// ListOutboxTenants exposes only durable state partitions to the private
// outbox publisher. Runtime-content objects remain outside this capability.
func (store *RuntimeStateStore) ListOutboxTenants(ctx context.Context) ([]runtimecontent.TenantID, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if store == nil || store.pool == nil {
		return nil, runtimestate.ErrUnavailable
	}
	// The publisher scans tenant identifiers but cannot read a snapshot unless
	// it begins a separate tenant-bound transaction. The operator group has
	// only this projection; no state mutation grant is made here.
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return nil, runtimestate.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE runtime_state_operator`); err != nil {
		return nil, runtimestate.ErrUnavailable
	}
	rows, err := tx.Query(ctx, `SELECT tenant_id FROM runtime.runtime_state_tenant_partitions ORDER BY tenant_id`)
	if err != nil {
		return nil, runtimestate.ErrUnavailable
	}
	defer rows.Close()
	tenants := []runtimecontent.TenantID{}
	for rows.Next() {
		var tenant string
		if err := rows.Scan(&tenant); err != nil {
			return nil, runtimestate.ErrUnavailable
		}
		tenants = append(tenants, runtimecontent.TenantID(tenant))
	}
	if rows.Err() != nil {
		return nil, runtimestate.ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, runtimestate.ErrUnavailable
	}
	return tenants, nil
}
func (store *RuntimeStateStore) AuthorizeAgentSpecificationBodyRead(ctx context.Context, authorization runtimestate.CompiledReadAuthorization) (runtimecontent.AgentSpecificationBodyRecord, error) {
	scope := authorization.Scope()
	agentID, revisionID := authorization.AgentRevision()
	state, err := store.LoadRuntimeState(ctx, scope)
	if err != nil {
		return runtimecontent.AgentSpecificationBodyRecord{}, err
	}
	for _, record := range state.Revisions {
		if record.Tenant == scope.Tenant && record.AgentID == agentID && record.RevisionID == revisionID {
			return runtimecontent.AgentSpecificationBodyRecord{Tenant: record.Tenant, AgentID: record.AgentID, RevisionID: record.RevisionID, Revision: record.Revision, Name: record.Name, ModelProfile: record.ModelProfile, Reference: record.Specification, CreatedAt: record.CreatedAt}, nil
		}
	}
	return runtimecontent.AgentSpecificationBodyRecord{}, runtimestate.ErrNotFoundOrDenied
}
func (store *RuntimeStateStore) AuthorizeInputEnvelopeRead(ctx context.Context, authorization runtimestate.CompiledReadAuthorization) (runtimecontent.InputEnvelopeRecord, error) {
	scope := authorization.Scope()
	sessionID, inputID := authorization.Input()
	state, err := store.LoadRuntimeState(ctx, scope)
	if err != nil {
		return runtimecontent.InputEnvelopeRecord{}, err
	}
	for _, record := range state.Inputs {
		if record.Tenant == scope.Tenant && record.Principal == scope.Principal && record.SessionID == sessionID && record.InputID == inputID {
			return runtimecontent.InputEnvelopeRecord{Tenant: record.Tenant, Principal: record.Principal, SessionID: record.SessionID, InputID: record.InputID, Reference: record.Content}, nil
		}
	}
	return runtimecontent.InputEnvelopeRecord{}, runtimestate.ErrNotFoundOrDenied
}
func (store *RuntimeStateStore) AuthorizeArtifactRead(ctx context.Context, authorization runtimestate.CompiledReadAuthorization) (runtimecontent.ArtifactRecord, error) {
	scope := authorization.Scope()
	artifactID := authorization.Artifact()
	state, err := store.LoadRuntimeState(ctx, scope)
	if err != nil {
		return runtimecontent.ArtifactRecord{}, err
	}
	for _, record := range state.Artifacts {
		if record.Tenant == scope.Tenant && record.Principal == scope.Principal && record.ArtifactID == artifactID {
			return runtimecontent.ArtifactRecord{Tenant: record.Tenant, Principal: record.Principal, ArtifactID: record.ArtifactID, Reference: record.Reference}, nil
		}
	}
	return runtimecontent.ArtifactRecord{}, runtimestate.ErrNotFoundOrDenied
}
func (store *RuntimeStateStore) AuthorizeToolActionDescriptorRead(ctx context.Context, authorization runtimestate.CompiledReadAuthorization) (runtimecontent.ToolActionDescriptorCommitment, error) {
	scope := authorization.Scope()
	session, turn, tool := authorization.ToolActionDescriptor()
	if !hasScope(scope, runtimestate.AuthorityRuntimeWorker, true) {
		return runtimecontent.ToolActionDescriptorCommitment{}, runtimestate.ErrNotFoundOrDenied
	}
	state, err := store.LoadRuntimeState(ctx, scope)
	if err != nil {
		return runtimecontent.ToolActionDescriptorCommitment{}, err
	}
	for _, v := range state.ToolIntents {
		if v.Tenant == scope.Tenant && v.Principal == scope.Principal && v.SessionID == session && v.TurnID == turn && v.ToolCallID == tool {
			return runtimecontent.ToolActionDescriptorCommitment{Tenant: v.Tenant, Reference: v.ActionDescriptor}, nil
		}
	}
	return runtimecontent.ToolActionDescriptorCommitment{}, runtimestate.ErrNotFoundOrDenied
}

func hasScope(scope runtimestate.MutationScope, authority runtimestate.Authority, principalRequired bool) bool {
	if scope.Authority != authority || scope.Tenant == "" {
		return false
	}
	return !principalRequired || scope.Principal != ""
}
