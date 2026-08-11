//go:build integration

package runtimepostgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimepostgres"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestPostgresRuntimeStateStorePersistsASealedPlanAndRejectsItsStaleBase(t *testing.T) {
	ctx := context.Background()
	pool := openRuntimePool(t)
	resetRuntimeV2(t, ctx, pool)
	applyRuntimeMigrations(t, ctx, pool)

	tenant, err := runtimecontent.ParseTenantID("state-store-tenant")
	if err != nil {
		t.Fatalf("parse tenant: %v", err)
	}
	content, err := runtimecontent.New("state-store-content", &stateStoreObjects{values: map[string][]byte{}})
	if err != nil {
		t.Fatalf("new content store: %v", err)
	}
	handoff, err := content.StageAgentSpecificationBody(ctx, tenant, runtimecontent.AgentSpecificationBody{Name: "state-store", ModelProfile: "balanced", Instructions: "content stays outside PostgreSQL"})
	if err != nil {
		t.Fatalf("stage Agent specification: %v", err)
	}
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	mutation, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "register", Specification: handoff})
	if err != nil {
		t.Fatalf("compile register: %v", err)
	}
	receiptClock, err := clock.NewFake(time.Date(2026, 8, 10, 16, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("new receipt clock: %v", err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(receiptClock, &stateStoreIDs{})
	if err != nil {
		t.Fatalf("new planner: %v", err)
	}
	store, err := runtimepostgres.NewRuntimeStateStore(pool, receiptClock)
	if err != nil {
		t.Fatalf("new PostgreSQL store: %v", err)
	}
	prior, err := store.LoadRuntimeState(ctx, mutation.ReceiptBinding().Scope)
	if err != nil {
		t.Fatalf("load initial state: %v", err)
	}
	plan, err := planner.Plan(ctx, prior, mutation)
	if err != nil {
		t.Fatalf("plan register: %v", err)
	}
	if !reflect.DeepEqual(prior, plan.BaseState()) {
		t.Fatalf("plan base = %#v, want loaded prior %#v", plan.BaseState(), prior)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("validate register plan: %v", err)
	}
	if plan.Result().Receipt.Scope.Tenant == "" {
		t.Fatalf("plan receipt has no tenant: %#v", plan.Result().Receipt)
	}
	if _, err := json.Marshal(plan.State()); err != nil {
		t.Fatalf("marshal plan state: %v", err)
	}
	if err := store.PersistTransitionPlan(ctx, plan); err != nil {
		t.Fatalf("persist plan: %v", err)
	}
	receipt, err := store.GetMutationReceipt(ctx, runtimestate.MutationReceiptQuery{Scope: mutation.ReceiptBinding().Scope, IdempotencyKey: mutation.ReceiptBinding().IdempotencyKey})
	if err != nil {
		t.Fatalf("get unexpired receipt: %v", err)
	}
	if !reflect.DeepEqual(receipt, plan.Result().Receipt) {
		t.Fatalf("receipt = %#v, want planned receipt %#v", receipt, plan.Result().Receipt)
	}
	if err := receiptClock.Advance(plan.Result().Receipt.RetentionUntil.Sub(receiptClock.Now())); err != nil {
		t.Fatalf("advance receipt clock to expiry: %v", err)
	}
	if _, err := store.GetMutationReceipt(ctx, runtimestate.MutationReceiptQuery{Scope: mutation.ReceiptBinding().Scope, IdempotencyKey: mutation.ReceiptBinding().IdempotencyKey}); !errors.Is(err, runtimestate.ErrReceiptExpired) {
		t.Fatalf("get expired receipt error = %v, want ErrReceiptExpired", err)
	}
	loaded, err := store.LoadRuntimeState(ctx, mutation.ReceiptBinding().Scope)
	if err != nil {
		t.Fatalf("load persisted state: %v", err)
	}
	if !reflect.DeepEqual(loaded, plan.State()) {
		t.Fatalf("loaded state = %#v, want %#v", loaded, plan.State())
	}
	if _, err := store.GetAgentRevision(ctx, runtimestate.AgentRevisionQuery{Scope: mutation.ReceiptBinding().Scope, AgentID: plan.Result().Revision.AgentID, RevisionID: plan.Result().Revision.RevisionID}); err != nil {
		t.Fatalf("get persisted revision: %v", err)
	}
	principal, err := runtimecontent.ParsePrincipalID("state-store-user")
	if err != nil {
		t.Fatalf("parse principal: %v", err)
	}
	_, err = store.GetAgentRevision(ctx, runtimestate.AgentRevisionQuery{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}, AgentID: plan.Result().Revision.AgentID, RevisionID: plan.Result().Revision.RevisionID})
	if !errors.Is(err, runtimestate.ErrNotFoundOrDenied) {
		t.Fatalf("owner catalog query error = %v, want non-enumerating denial", err)
	}
	if err := store.PersistTransitionPlan(ctx, plan); !errors.Is(err, runtimestate.ErrConflict) {
		t.Fatalf("persist stale plan error = %v, want conflict", err)
	}
}

func TestPostgresRuntimeStateStoreBackfillsUnambiguousLegacyGrantScopeOnRestart(t *testing.T) {
	ctx := context.Background()
	pool := openRuntimePool(t)
	resetRuntimeV2(t, ctx, pool)
	applyRuntimeMigrations(t, ctx, pool)
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	tenant, _ := runtimecontent.ParseTenantID("legacy-grant-tenant")
	principal, _ := runtimecontent.ParsePrincipalID("legacy-grant-owner")
	session, turn := agentruntime.SessionID("sess_0000000000000001"), agentruntime.TurnID("turn_0000000000000002")
	legacy := runtimestate.RuntimeState{
		Sessions:    []runtimestate.SessionRecord{{Tenant: tenant, Principal: principal, SessionID: session, State: agentruntime.SessionOpen, Version: 1, CreatedAt: now, UpdatedAt: now}},
		Turns:       []runtimestate.TurnRecord{{Tenant: tenant, Principal: principal, SessionID: session, TurnID: turn, State: agentruntime.TurnRunning}},
		ToolIntents: []runtimestate.ToolIntentRecord{{Tenant: tenant, Principal: principal, SessionID: session, TurnID: turn, ToolCallID: "tcall_1234567890ABCDEF"}},
		Grants:      []runtimestate.CapabilityGrantRecord{{Tenant: tenant, Principal: principal, GrantID: "grant_1234567890ABCDE", ToolCallID: "tcall_1234567890ABCDEF", MaximumUses: 1, ExpiresAt: now.Add(time.Hour)}},
	}
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `SELECT set_config('runtime.tenant_id', $1, true)`, string(tenant)); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO runtime.tenants (tenant_id, created_at) VALUES ($1, now())`, string(tenant)); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO runtime.runtime_state_snapshots (tenant_id, generation, state, updated_at) VALUES ($1, 1, $2::jsonb, now())`, string(tenant), encoded); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	store, err := runtimepostgres.NewRuntimeStateStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	ownerScope := runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}
	loaded, err := store.LoadRuntimeState(ctx, ownerScope)
	if err != nil || len(loaded.Grants) != 1 || loaded.Grants[0].SessionID != session || loaded.Grants[0].TurnID != turn {
		t.Fatalf("backfilled legacy grant = %#v, %v", loaded.Grants, err)
	}
	content, err := runtimecontent.New("legacy-grant-content", &stateStoreObjects{values: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(stateStoreClock{now: now}, &stateStoreIDs{})
	if err != nil {
		t.Fatal(err)
	}
	cancel, err := compiler.CompileCancelTurn(runtimestate.CancelTurnCommand{Scope: ownerScope, IdempotencyKey: "cancel-backfilled-grant", SessionID: session, TurnID: turn})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.Plan(ctx, loaded, cancel)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.PersistTransitionPlan(ctx, plan); err != nil {
		t.Fatalf("persist transactionally backfilled snapshot: %v", err)
	}
	restarted, err := runtimepostgres.NewRuntimeStateStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err = restarted.LoadRuntimeState(ctx, ownerScope)
	if err != nil || len(loaded.Grants) != 1 || loaded.Grants[0].SessionID != session || loaded.Grants[0].TurnID != turn || loaded.Grants[0].RevokedAt == nil {
		t.Fatalf("restarted upgraded grant = %#v, %v", loaded.Grants, err)
	}
}

func TestPostgresRuntimeStateStorePersistsConversationAppendReplayAndExpectedVersionConflict(t *testing.T) {
	ctx := context.Background()
	pool := openRuntimePool(t)
	resetRuntimeV2(t, ctx, pool)
	applyRuntimeMigrations(t, ctx, pool)

	tenant, err := runtimecontent.ParseTenantID("conversation-state-store-tenant")
	if err != nil {
		t.Fatalf("parse tenant: %v", err)
	}
	principal, err := runtimecontent.ParsePrincipalID("conversation-state-store-user")
	if err != nil {
		t.Fatalf("parse principal: %v", err)
	}
	objects := &stateStoreObjects{values: map[string][]byte{}}
	content, err := runtimecontent.New("conversation-state-store-content", objects)
	if err != nil {
		t.Fatalf("new content store: %v", err)
	}
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	now := time.Date(2026, 8, 12, 1, 0, 0, 0, time.UTC)
	timeSource := stateStoreClock{now: now}
	planner, err := runtimestate.NewRuntimeStatePlanner(timeSource, &stateStoreIDs{})
	if err != nil {
		t.Fatalf("new planner: %v", err)
	}
	store, err := runtimepostgres.NewRuntimeStateStore(pool, timeSource)
	if err != nil {
		t.Fatalf("new PostgreSQL store: %v", err)
	}

	registrationBody, err := content.StageAgentSpecificationBody(ctx, tenant, runtimecontent.AgentSpecificationBody{Name: "conversation-state-store", ModelProfile: "balanced", Instructions: "conversation entries remain immutable references"})
	if err != nil {
		t.Fatalf("stage agent specification: %v", err)
	}
	adminScope := runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}
	registration, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: adminScope, IdempotencyKey: "conversation-register", Specification: registrationBody})
	if err != nil {
		t.Fatalf("compile registration: %v", err)
	}
	registrationBase, err := store.LoadRuntimeState(ctx, adminScope)
	if err != nil {
		t.Fatalf("load registration base: %v", err)
	}
	registrationPlan, err := planner.Plan(ctx, registrationBase, registration)
	if err != nil {
		t.Fatalf("plan registration: %v", err)
	}
	if err := store.PersistTransitionPlan(ctx, registrationPlan); err != nil {
		t.Fatalf("persist registration: %v", err)
	}

	ownerScope := runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}
	createSession, err := compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: ownerScope, IdempotencyKey: "conversation-session", RevisionID: registrationPlan.Result().Revision.RevisionID})
	if err != nil {
		t.Fatalf("compile session: %v", err)
	}
	sessionBase, err := store.LoadRuntimeState(ctx, ownerScope)
	if err != nil {
		t.Fatalf("load session base: %v", err)
	}
	sessionPlan, err := planner.Plan(ctx, sessionBase, createSession)
	if err != nil {
		t.Fatalf("plan session: %v", err)
	}
	if err := store.PersistTransitionPlan(ctx, sessionPlan); err != nil {
		t.Fatalf("persist session: %v", err)
	}

	workerScope := runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}
	entry, err := content.StageConversationEntry(ctx, tenant, []byte("immutable model context reference"))
	if err != nil {
		t.Fatalf("stage conversation entry: %v", err)
	}
	entryCommitment, err := content.ValidateConversationEntryHandoff(entry)
	if err != nil {
		t.Fatalf("validate staged conversation entry: %v", err)
	}
	appendCommand, err := compiler.CompileAppendConversation(runtimestate.AppendConversationCommand{Scope: workerScope, IdempotencyKey: "conversation-append-1", SessionID: sessionPlan.Result().Session.SessionID, ExpectedVersion: 0, Entry: entry})
	if err != nil {
		t.Fatalf("compile conversation append: %v", err)
	}
	appendBase, err := store.LoadRuntimeState(ctx, workerScope)
	if err != nil {
		t.Fatalf("load conversation base: %v", err)
	}
	appendPlan, err := planner.Plan(ctx, appendBase, appendCommand)
	if err != nil {
		t.Fatalf("plan conversation append: %v", err)
	}
	if got := appendPlan.Result().Conversation; got.Version != 1 || got.Reference != entryCommitment.Reference {
		t.Fatalf("conversation append = %#v, want version 1 and staged immutable reference %#v", got, entryCommitment.Reference)
	}
	if err := store.PersistTransitionPlan(ctx, appendPlan); err != nil {
		t.Fatalf("persist conversation append: %v", err)
	}

	loaded, err := store.LoadRuntimeState(ctx, workerScope)
	if err != nil {
		t.Fatalf("reload persisted conversation: %v", err)
	}
	if len(loaded.Conversations) != 1 || loaded.Conversations[0] != appendPlan.Result().Conversation {
		t.Fatalf("reloaded conversations = %#v, want exactly %#v", loaded.Conversations, appendPlan.Result().Conversation)
	}
	replay, err := planner.Plan(ctx, loaded, appendCommand)
	if err != nil {
		t.Fatalf("plan exact conversation replay: %v", err)
	}
	if replay.Result().Conversation != appendPlan.Result().Conversation || !reflect.DeepEqual(replay.State(), loaded) {
		t.Fatalf("conversation replay = %#v / %#v, want original result and unchanged durable state", replay.Result(), replay.State())
	}
	if err := store.PersistTransitionPlan(ctx, replay); err != nil {
		t.Fatalf("persist exact conversation replay: %v", err)
	}
	afterReplay, err := store.LoadRuntimeState(ctx, workerScope)
	if err != nil {
		t.Fatalf("reload exact replay: %v", err)
	}
	if !reflect.DeepEqual(afterReplay, loaded) {
		t.Fatalf("exact replay changed persisted state = %#v, want %#v", afterReplay, loaded)
	}

	competingEntry, err := content.StageConversationEntry(ctx, tenant, []byte("competing stale context"))
	if err != nil {
		t.Fatalf("stage stale conversation entry: %v", err)
	}
	stale, err := compiler.CompileAppendConversation(runtimestate.AppendConversationCommand{Scope: workerScope, IdempotencyKey: "conversation-append-stale", SessionID: sessionPlan.Result().Session.SessionID, ExpectedVersion: 0, Entry: competingEntry})
	if err != nil {
		t.Fatalf("compile stale conversation append: %v", err)
	}
	if _, err := planner.Plan(ctx, afterReplay, stale); !errors.Is(err, runtimestate.ErrConflict) {
		t.Fatalf("stale persisted conversation append error = %v, want ErrConflict", err)
	}
}

func TestPostgresTenantErasureDeletesOnlyAuthorizedStateReferencedContent(t *testing.T) {
	ctx := context.Background()
	pool := openRuntimePool(t)
	resetRuntimeV2(t, ctx, pool)
	applyRuntimeMigrations(t, ctx, pool)

	tenant, err := runtimecontent.ParseTenantID("erasure-tenant")
	if err != nil {
		t.Fatalf("parse tenant: %v", err)
	}
	objects := &stateStoreObjects{values: map[string][]byte{}}
	content, err := runtimecontent.New("erasure-content", objects)
	if err != nil {
		t.Fatalf("new content store: %v", err)
	}
	handoff, err := content.StageAgentSpecificationBody(ctx, tenant, runtimecontent.AgentSpecificationBody{Name: "erasable", ModelProfile: "balanced", Instructions: "delete through explicit operator authority"})
	if err != nil {
		t.Fatalf("stage Agent specification: %v", err)
	}
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	mutation, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "register-erasable", Specification: handoff})
	if err != nil {
		t.Fatalf("compile registration: %v", err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(stateStoreClock{now: time.Date(2026, 8, 10, 17, 0, 0, 0, time.UTC)}, &stateStoreIDs{})
	if err != nil {
		t.Fatalf("new planner: %v", err)
	}
	plan, err := planner.Plan(ctx, runtimestate.RuntimeState{}, mutation)
	if err != nil {
		t.Fatalf("plan registration: %v", err)
	}
	store, err := runtimepostgres.NewRuntimeStateStore(pool, stateStoreClock{now: time.Date(2026, 8, 10, 17, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("new PostgreSQL store: %v", err)
	}
	if err := store.PersistTransitionPlan(ctx, plan); err != nil {
		t.Fatalf("persist registration: %v", err)
	}
	reference := plan.Result().Revision.Specification
	objectKey := "erasure-tenant/erasure-content/v1/sha256/" + reference.Digest[len("sha256:"):]
	controller, err := runtimecontent.NewTenantErasureController(content, erasureAuthorizer{allowed: true}, objects)
	if err != nil {
		t.Fatalf("new erasure controller: %v", err)
	}
	request := runtimepostgres.LifecycleRequest{Action: runtimepostgres.LifecycleEraseTenant, Tenant: tenant, AuthorizationID: "operator-authorization-0001"}
	if _, err := store.EraseTenantAndContent(ctx, lifecycleAuthorizer{allowed: false}, request, controller); !errors.Is(err, runtimestate.ErrNotFoundOrDenied) {
		t.Fatalf("unauthorized erasure error = %v, want non-enumerating denial", err)
	}
	if _, found := objects.values[objectKey]; !found {
		t.Fatal("unauthorized erasure deleted immutable content")
	}
	receipt, err := store.EraseTenantAndContent(ctx, lifecycleAuthorizer{allowed: true}, request, controller)
	if err != nil {
		t.Fatalf("erase tenant and content: %v", err)
	}
	if receipt.Tenant != tenant || len(receipt.Content.Deleted) != 1 || receipt.Content.Failed != nil || receipt.Content.Deleted[0] != reference {
		t.Fatalf("erasure receipt = %#v", receipt)
	}
	if _, found := objects.values[objectKey]; found {
		t.Fatal("authorized erasure retained immutable content")
	}
	var remaining int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime.tenants WHERE tenant_id = $1`, string(tenant)).Scan(&remaining); err != nil {
		t.Fatalf("count tenant: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("remaining tenant rows = %d, want 0", remaining)
	}
	if _, err := store.LoadRuntimeState(ctx, mutation.ReceiptBinding().Scope); err != nil {
		t.Fatalf("load erased tenant state: %v", err)
	}
}

func TestPostgresTenantErasureReconcilesDeletionIntentAfterAmbiguousExternalDelete(t *testing.T) {
	ctx := context.Background()
	pool := openRuntimePool(t)
	resetRuntimeV2(t, ctx, pool)
	applyRuntimeMigrations(t, ctx, pool)
	tenant, err := runtimecontent.ParseTenantID("erasure-reconcile-tenant")
	if err != nil {
		t.Fatalf("parse tenant: %v", err)
	}
	objects := &deleteAfterFaultObjects{stateStoreObjects: stateStoreObjects{values: map[string][]byte{}}, failAfterDelete: true}
	content, err := runtimecontent.New("erasure-reconcile-content", objects)
	if err != nil {
		t.Fatalf("new content store: %v", err)
	}
	handoff, err := content.StageAgentSpecificationBody(ctx, tenant, runtimecontent.AgentSpecificationBody{Name: "erasable", ModelProfile: "balanced", Instructions: "reconcile tenant deletion intent"})
	if err != nil {
		t.Fatalf("stage Agent specification: %v", err)
	}
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	clock := stateStoreClock{now: time.Date(2026, 8, 10, 17, 30, 0, 0, time.UTC)}
	planner, err := runtimestate.NewRuntimeStatePlanner(clock, &stateStoreIDs{})
	if err != nil {
		t.Fatalf("new planner: %v", err)
	}
	mutation, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "register-erasure-reconcile", Specification: handoff})
	if err != nil {
		t.Fatalf("compile registration: %v", err)
	}
	plan, err := planner.Plan(ctx, runtimestate.RuntimeState{}, mutation)
	if err != nil {
		t.Fatalf("plan registration: %v", err)
	}
	store, err := runtimepostgres.NewRuntimeStateStore(pool, clock)
	if err != nil {
		t.Fatalf("new PostgreSQL store: %v", err)
	}
	if err := store.PersistTransitionPlan(ctx, plan); err != nil {
		t.Fatalf("persist registration: %v", err)
	}
	reference := plan.Result().Revision.Specification
	erasureAuthorization := &trackingErasureAuthorizer{allowed: map[string]bool{"operator-erasure-reconcile-0001": true, "operator-erasure-reconcile-0002": true}}
	controller, err := runtimecontent.NewTenantErasureController(content, erasureAuthorization, objects)
	if err != nil {
		t.Fatalf("new erasure controller: %v", err)
	}
	request := runtimepostgres.LifecycleRequest{Action: runtimepostgres.LifecycleEraseTenant, Tenant: tenant, AuthorizationID: "operator-erasure-reconcile-0001"}
	if _, err := store.EraseTenantAndContent(ctx, lifecycleAuthorizer{allowed: true}, request, controller); !errors.Is(err, runtimecontent.ErrUnavailable) {
		t.Fatalf("erase ambiguous deletion error = %v, want ErrUnavailable", err)
	}
	state, err := store.LoadRuntimeState(ctx, mutation.ReceiptBinding().Scope)
	if err != nil {
		t.Fatalf("load erased state: %v", err)
	}
	if len(state.Revisions) != 0 {
		t.Fatalf("state still references externally deleted content: %#v", state.Revisions)
	}
	var tenants, pending int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime.tenants WHERE tenant_id = $1`, string(tenant)).Scan(&tenants); err != nil {
		t.Fatalf("count erased tenants: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime.pending_content_deletions WHERE tenant_id = $1`, string(tenant)).Scan(&pending); err != nil {
		t.Fatalf("count durable pending deletions: %v", err)
	}
	if tenants != 0 || pending != 1 {
		t.Fatalf("after ambiguous erase tenants=%d pending=%d, want tenants=0 pending=1", tenants, pending)
	}
	request.AuthorizationID = "operator-erasure-reconcile-0002"
	receipt, err := store.EraseTenantAndContent(ctx, lifecycleAuthorizer{allowed: true}, request, controller)
	if err != nil {
		t.Fatalf("reconcile erased tenant content: %v", err)
	}
	if len(receipt.Content.Deleted) != 1 || receipt.Content.Deleted[0] != reference {
		t.Fatalf("tenant erasure reconciliation receipt = %#v", receipt)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime.pending_content_deletions WHERE tenant_id = $1`, string(tenant)).Scan(&pending); err != nil {
		t.Fatalf("count acknowledged pending deletions: %v", err)
	}
	if pending != 0 {
		t.Fatalf("pending deletion records = %d, want 0 after acknowledgement", pending)
	}
	if erasureAuthorization.last != request.AuthorizationID {
		t.Fatalf("reconciled erasure authorization = %q, want current %q", erasureAuthorization.last, request.AuthorizationID)
	}
}

func TestPostgresRetentionCollectionDeletesOnlyExpiredUnpinnedContent(t *testing.T) {
	ctx := context.Background()
	pool := openRuntimePool(t)
	resetRuntimeV2(t, ctx, pool)
	applyRuntimeMigrations(t, ctx, pool)
	now := time.Date(2026, 8, 10, 18, 0, 0, 0, time.UTC)
	tenant, err := runtimecontent.ParseTenantID("retention-tenant")
	if err != nil {
		t.Fatal(err)
	}
	objects := &stateStoreObjects{values: map[string][]byte{}}
	content, err := runtimecontent.New("retention-content", objects)
	if err != nil {
		t.Fatal(err)
	}
	body, err := content.StageAgentSpecificationBody(ctx, tenant, runtimecontent.AgentSpecificationBody{Name: "expired", ModelProfile: "balanced", Instructions: "collect exactly"})
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(stateStoreClock{now: now}, &stateStoreIDs{})
	if err != nil {
		t.Fatal(err)
	}
	mutation, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "register-expired", Specification: body})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.Plan(ctx, runtimestate.RuntimeState{}, mutation)
	if err != nil {
		t.Fatal(err)
	}
	store, err := runtimepostgres.NewRuntimeStateStore(pool, stateStoreClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PersistTransitionPlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	reference := plan.Result().Revision.Specification
	objectKey := "retention-tenant/retention-content/v1/sha256/" + reference.Digest[len("sha256:"):]
	controller, err := runtimecontent.NewTenantErasureController(content, erasureAuthorizer{allowed: true}, objects)
	if err != nil {
		t.Fatal(err)
	}
	request := runtimepostgres.LifecycleRequest{Action: runtimepostgres.LifecycleCollectExpired, Tenant: tenant, AuthorizationID: "operator-authorization-0002", EvaluatedAt: now.Add(24*time.Hour + time.Nanosecond)}
	if _, err := store.CollectExpiredAndContent(ctx, lifecycleAuthorizer{allowed: false}, request, controller); !errors.Is(err, runtimestate.ErrNotFoundOrDenied) {
		t.Fatalf("unauthorized retention collection error = %v, want non-enumerating denial", err)
	}
	if _, found := objects.values[objectKey]; !found {
		t.Fatal("unauthorized retention collection deleted immutable content")
	}
	// Verify the v5 retention row remains tenant-writable before exercising
	// the composed lifecycle transaction; this keeps a future RLS regression
	// diagnosable at the exact SQL boundary.
	transaction, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = transaction.Exec(ctx, `SELECT set_config('runtime.tenant_id', $1, true)`, string(tenant)); err != nil {
		t.Fatal(err)
	}
	if _, err = transaction.Exec(ctx, `UPDATE runtime.tenant_retention_jobs SET next_collection_at = next_collection_at WHERE tenant_id = $1`, string(tenant)); err != nil {
		t.Fatalf("v5 retention row is not tenant-writable: %v", err)
	}
	if err = transaction.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	receipt, err := store.CollectExpiredAndContent(ctx, lifecycleAuthorizer{allowed: true}, request, controller)
	if err != nil {
		t.Fatalf("collect expired content: %v", err)
	}
	if receipt.RemovedMetadata != 1 || len(receipt.Content.Deleted) != 1 || receipt.Content.Deleted[0] != reference {
		t.Fatalf("retention collection receipt = %#v", receipt)
	}
	if _, found := objects.values[objectKey]; found {
		t.Fatal("expired unpinned immutable content was retained")
	}
	state, err := store.LoadRuntimeState(ctx, mutation.ReceiptBinding().Scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Revisions) != 0 {
		t.Fatalf("retained revisions = %#v, want expired metadata removed", state.Revisions)
	}
}

func TestPostgresRetentionCollectionReconcilesDeletionIntentAfterAmbiguousExternalDelete(t *testing.T) {
	ctx := context.Background()
	pool := openRuntimePool(t)
	resetRuntimeV2(t, ctx, pool)
	applyRuntimeMigrations(t, ctx, pool)
	now := time.Date(2026, 8, 10, 18, 30, 0, 0, time.UTC)
	tenant, err := runtimecontent.ParseTenantID("retention-reconcile-tenant")
	if err != nil {
		t.Fatal(err)
	}
	objects := &deleteAfterFaultObjects{stateStoreObjects: stateStoreObjects{values: map[string][]byte{}}, failAfterDelete: true}
	content, err := runtimecontent.New("retention-reconcile-content", objects)
	if err != nil {
		t.Fatal(err)
	}
	body, err := content.StageAgentSpecificationBody(ctx, tenant, runtimecontent.AgentSpecificationBody{Name: "expired", ModelProfile: "balanced", Instructions: "reconcile exact deletion intent"})
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(stateStoreClock{now: now}, &stateStoreIDs{})
	if err != nil {
		t.Fatal(err)
	}
	mutation, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "register-retention-reconcile", Specification: body})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.Plan(ctx, runtimestate.RuntimeState{}, mutation)
	if err != nil {
		t.Fatal(err)
	}
	store, err := runtimepostgres.NewRuntimeStateStore(pool, stateStoreClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PersistTransitionPlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	reference := plan.Result().Revision.Specification
	objectKey := "retention-reconcile-tenant/retention-reconcile-content/v1/sha256/" + reference.Digest[len("sha256:"):]
	erasureAuthorization := &trackingErasureAuthorizer{allowed: map[string]bool{"operator-retention-reconcile-0001": true, "operator-retention-reconcile-0002": true}}
	controller, err := runtimecontent.NewTenantErasureController(content, erasureAuthorization, objects)
	if err != nil {
		t.Fatal(err)
	}
	request := runtimepostgres.LifecycleRequest{Action: runtimepostgres.LifecycleCollectExpired, Tenant: tenant, AuthorizationID: "operator-retention-reconcile-0001", EvaluatedAt: now.Add(24*time.Hour + time.Nanosecond)}
	if _, err := store.CollectExpiredAndContent(ctx, lifecycleAuthorizer{allowed: true}, request, controller); !errors.Is(err, runtimecontent.ErrUnavailable) {
		t.Fatalf("collect ambiguous deletion error = %v, want ErrUnavailable", err)
	}
	if _, found := objects.values[objectKey]; found {
		t.Fatal("ambiguous deleter did not remove its exact object")
	}
	state, err := store.LoadRuntimeState(ctx, mutation.ReceiptBinding().Scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Revisions) != 0 {
		t.Fatalf("state still references externally deleted content: %#v", state.Revisions)
	}
	var pending int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime.pending_content_deletions WHERE tenant_id = $1`, string(tenant)).Scan(&pending); err != nil {
		t.Fatalf("count durable pending deletions: %v", err)
	}
	if pending != 1 {
		t.Fatalf("pending deletion records = %d, want 1", pending)
	}
	request.AuthorizationID = "operator-retention-reconcile-0002"
	receipt, err := store.CollectExpiredAndContent(ctx, lifecycleAuthorizer{allowed: true}, request, controller)
	if err != nil {
		t.Fatalf("reconcile pending deletion: %v", err)
	}
	if receipt.RemovedMetadata != 0 || len(receipt.Content.Deleted) != 1 || receipt.Content.Deleted[0] != reference {
		t.Fatalf("reconciliation receipt = %#v", receipt)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime.pending_content_deletions WHERE tenant_id = $1`, string(tenant)).Scan(&pending); err != nil {
		t.Fatalf("count acknowledged pending deletions: %v", err)
	}
	if pending != 0 {
		t.Fatalf("pending deletion records = %d, want 0 after acknowledgement", pending)
	}
	if erasureAuthorization.last != request.AuthorizationID {
		t.Fatalf("reconciled retention authorization = %q, want current %q", erasureAuthorization.last, request.AuthorizationID)
	}
}

func TestPostgresNoOpRetentionCollectionRecordsSchedule(t *testing.T) {
	ctx := context.Background()
	pool := openRuntimePool(t)
	resetRuntimeV2(t, ctx, pool)
	applyRuntimeMigrations(t, ctx, pool)
	now := time.Date(2026, 8, 10, 19, 0, 0, 0, time.UTC)
	tenant, err := runtimecontent.ParseTenantID("retention-noop-tenant")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO runtime.tenants (tenant_id, created_at) VALUES ($1, now())`, string(tenant)); err != nil {
		t.Fatalf("insert retention tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO runtime.runtime_state_snapshots (tenant_id, generation, state, updated_at) VALUES ($1, 0, '{}'::jsonb, now())`, string(tenant)); err != nil {
		t.Fatalf("insert empty runtime state: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO runtime.tenant_retention_jobs (tenant_id, next_collection_at) VALUES ($1, $2)`, string(tenant), now); err != nil {
		t.Fatalf("insert retention schedule: %v", err)
	}
	objects := &stateStoreObjects{values: map[string][]byte{}}
	content, err := runtimecontent.New("retention-noop-content", objects)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := runtimecontent.NewTenantErasureController(content, erasureAuthorizer{allowed: true}, objects)
	if err != nil {
		t.Fatal(err)
	}
	store, err := runtimepostgres.NewRuntimeStateStore(pool, stateStoreClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	request := runtimepostgres.LifecycleRequest{Action: runtimepostgres.LifecycleCollectExpired, Tenant: tenant, AuthorizationID: "operator-noop-retention-0001", EvaluatedAt: now}
	receipt, err := store.CollectExpiredAndContent(ctx, lifecycleAuthorizer{allowed: true}, request, controller)
	if err != nil {
		t.Fatalf("collect no-op retention state: %v", err)
	}
	if receipt.RemovedMetadata != 0 || len(receipt.Content.Deleted) != 0 || receipt.CollectionAt != now {
		t.Fatalf("no-op retention receipt = %#v", receipt)
	}
	var collectedAt, nextAt time.Time
	var authorizationID string
	if err := pool.QueryRow(ctx, `SELECT last_collection_at, last_authorization_id, next_collection_at FROM runtime.tenant_retention_jobs WHERE tenant_id = $1`, string(tenant)).Scan(&collectedAt, &authorizationID, &nextAt); err != nil {
		t.Fatalf("read no-op retention schedule: %v", err)
	}
	if !collectedAt.Equal(now) || authorizationID != request.AuthorizationID || !nextAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("no-op retention schedule collected_at=%s authorization=%q next_at=%s", collectedAt, authorizationID, nextAt)
	}
}

func TestPostgresDirectTenantErasureRemovesV5RetentionSchedule(t *testing.T) {
	ctx := context.Background()
	pool := openRuntimePool(t)
	resetRuntimeV2(t, ctx, pool)
	applyRuntimeMigrations(t, ctx, pool)
	tenant, err := runtimecontent.ParseTenantID("direct-erasure-tenant")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO runtime.tenants (tenant_id, created_at) VALUES ($1, now())`, string(tenant)); err != nil {
		t.Fatalf("insert direct erasure tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO runtime.runtime_state_snapshots (tenant_id, generation, state, updated_at) VALUES ($1, 0, '{}'::jsonb, now())`, string(tenant)); err != nil {
		t.Fatalf("insert direct erasure state: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO runtime.tenant_retention_jobs (tenant_id, next_collection_at) VALUES ($1, now())`, string(tenant)); err != nil {
		t.Fatalf("insert direct erasure schedule: %v", err)
	}
	store, err := runtimepostgres.NewRuntimeStateStore(pool, stateStoreClock{now: time.Date(2026, 8, 10, 20, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	request := runtimepostgres.LifecycleRequest{Action: runtimepostgres.LifecycleEraseTenant, Tenant: tenant, AuthorizationID: "operator-direct-erasure-0001"}
	if err := store.EraseTenant(ctx, lifecycleAuthorizer{allowed: true}, request); err != nil {
		t.Fatalf("erase direct tenant state: %v", err)
	}
	var tenants, schedules int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime.tenants WHERE tenant_id = $1`, string(tenant)).Scan(&tenants); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime.tenant_retention_jobs WHERE tenant_id = $1`, string(tenant)).Scan(&schedules); err != nil {
		t.Fatal(err)
	}
	if tenants != 0 || schedules != 0 {
		t.Fatalf("direct erasure left tenants=%d schedules=%d", tenants, schedules)
	}
}

func TestPostgresContentlessTenantErasureSucceeds(t *testing.T) {
	ctx := context.Background()
	pool := openRuntimePool(t)
	resetRuntimeV2(t, ctx, pool)
	applyRuntimeMigrations(t, ctx, pool)
	tenant, err := runtimecontent.ParseTenantID("contentless-erasure-tenant")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO runtime.tenants (tenant_id, created_at) VALUES ($1, now())`, string(tenant)); err != nil {
		t.Fatalf("insert contentless tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO runtime.runtime_state_snapshots (tenant_id, generation, state, updated_at) VALUES ($1, 0, '{}'::jsonb, now())`, string(tenant)); err != nil {
		t.Fatalf("insert contentless state: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO runtime.tenant_retention_jobs (tenant_id, next_collection_at) VALUES ($1, now())`, string(tenant)); err != nil {
		t.Fatalf("insert contentless schedule: %v", err)
	}
	objects := &stateStoreObjects{values: map[string][]byte{}}
	content, err := runtimecontent.New("contentless-erasure-content", objects)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := runtimecontent.NewTenantErasureController(content, erasureAuthorizer{allowed: true}, objects)
	if err != nil {
		t.Fatal(err)
	}
	store, err := runtimepostgres.NewRuntimeStateStore(pool, stateStoreClock{now: time.Date(2026, 8, 10, 21, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	request := runtimepostgres.LifecycleRequest{Action: runtimepostgres.LifecycleEraseTenant, Tenant: tenant, AuthorizationID: "operator-contentless-erasure-0001"}
	if _, err := store.EraseTenantAndContent(ctx, lifecycleAuthorizer{allowed: true}, request, controller); err != nil {
		t.Fatalf("erase contentless tenant: %v", err)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime.tenants WHERE tenant_id = $1`, string(tenant)).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("contentless erasure retained tenant rows=%d", remaining)
	}
}

type stateStoreClock struct{ now time.Time }

func (clock stateStoreClock) Now() time.Time { return clock.now }

type stateStoreIDs struct{ next int }

func (ids *stateStoreIDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	ids.next++
	value := fmt.Sprintf("%016d", ids.next)
	return string(kind) + "_" + value, nil
}

type stateStoreObjects struct{ values map[string][]byte }

func (objects *stateStoreObjects) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	if _, found := objects.values[key]; found {
		return false, nil
	}
	objects.values[key] = append([]byte(nil), value...)
	return true, nil
}
func (objects *stateStoreObjects) Get(_ context.Context, key string, _ int) ([]byte, error) {
	return append([]byte(nil), objects.values[key]...), nil
}

func (objects *stateStoreObjects) DeleteExact(_ context.Context, key string) error {
	delete(objects.values, key)
	return nil
}

type deleteAfterFaultObjects struct {
	stateStoreObjects
	failAfterDelete bool
}

func (objects *deleteAfterFaultObjects) DeleteExact(ctx context.Context, key string) error {
	if err := objects.stateStoreObjects.DeleteExact(ctx, key); err != nil {
		return err
	}
	if objects.failAfterDelete {
		objects.failAfterDelete = false
		return errors.New("lost deletion acknowledgement")
	}
	return nil
}

type lifecycleAuthorizer struct{ allowed bool }

func (authorizer lifecycleAuthorizer) AuthorizeLifecycle(_ context.Context, _ runtimepostgres.LifecycleRequest) error {
	if !authorizer.allowed {
		return errors.New("denied")
	}
	return nil
}

type erasureAuthorizer struct{ allowed bool }

func (authorizer erasureAuthorizer) AuthorizeErasure(_ context.Context, _ runtimecontent.ErasureRequest) error {
	if !authorizer.allowed {
		return errors.New("denied")
	}
	return nil
}

type trackingErasureAuthorizer struct {
	allowed map[string]bool
	last    string
}

func (authorizer *trackingErasureAuthorizer) AuthorizeErasure(_ context.Context, request runtimecontent.ErasureRequest) error {
	authorizer.last = request.AuthorizationID
	if !authorizer.allowed[request.AuthorizationID] {
		return errors.New("denied")
	}
	return nil
}
