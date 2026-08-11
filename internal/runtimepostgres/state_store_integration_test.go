//go:build integration

package runtimepostgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimeapi"
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
	planner, err := runtimestate.NewRuntimeStatePlanner(stateStoreClock{now: time.Date(2026, 8, 10, 16, 0, 0, 0, time.UTC)}, &stateStoreIDs{})
	if err != nil {
		t.Fatalf("new planner: %v", err)
	}
	store, err := runtimepostgres.NewRuntimeStateStore(pool)
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

func TestPostgresRuntimeStateStoreFailsClosedForLegacyApprovalOnRestartAndPublicRead(t *testing.T) {
	ctx := context.Background()
	pool := openRuntimePool(t)
	resetRuntimeV2(t, ctx, pool)
	applyRuntimeMigrations(t, ctx, pool)
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	tenant, _ := runtimecontent.ParseTenantID("legacy-approval-tenant")
	principal, _ := runtimecontent.ParsePrincipalID("legacy-approval-owner")
	legacy := runtimestate.RuntimeState{
		Sessions:  []runtimestate.SessionRecord{{Tenant: tenant, Principal: principal, SessionID: "sess_1234567890ABCDEF", State: agentruntime.SessionOpen, Version: 1, CreatedAt: now, UpdatedAt: now}},
		Turns:     []runtimestate.TurnRecord{{Tenant: tenant, Principal: principal, SessionID: "sess_1234567890ABCDEF", TurnID: "turn_1234567890ABCDEF", State: agentruntime.TurnWaitingForApproval, Version: 1}},
		Approvals: []runtimestate.ApprovalRecord{{Tenant: tenant, Principal: principal, ApprovalID: "appr_1234567890ABCDEF", SessionID: "sess_1234567890ABCDEF", TurnID: "turn_1234567890ABCDEF", ToolCallID: "tcall_1234567890ABCDEF", ActionDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", PolicyRevisionDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", State: "pending", CapabilityDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", MaximumUses: 1, ExpiresAt: now.Add(time.Hour), CreatedAt: now}},
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

	pool.Close()
	restartedPool := openRuntimePool(t)
	store, err := runtimepostgres.NewRuntimeStateStore(restartedPool)
	if err != nil {
		t.Fatal(err)
	}
	ownerScope := runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}
	if _, err = store.LoadRuntimeState(ctx, ownerScope); !errors.Is(err, runtimestate.ErrIntegrity) {
		t.Fatalf("restart loaded legacy Approval without a safe summary: %v", err)
	}
	content, err := runtimecontent.New("legacy-approval-content", &stateStoreObjects{values: map[string][]byte{}})
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
	runtime, err := runtimeapi.NewStateRuntime(runtimeapi.StateRuntimeConfig{Content: content, Compiler: compiler, Planner: planner, Store: store, ModelProfiles: []string{"balanced"}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := runtimeapi.NewHandler(runtimeapi.Config{Runtime: runtime, Authenticator: legacyApprovalAuthenticator{identity: runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}}, RequestIDs: &legacyApprovalRequestIDs{}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	credential, err := agentruntime.NewStaticBearerCredential("legacy-approval-token")
	if err != nil {
		t.Fatal(err)
	}
	client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: server.URL, HTTPClient: server.Client(), Credentials: credential, RequestIDs: &legacyApprovalRequestIDs{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.ListApprovals(ctx); err == nil {
		t.Fatal("public SDK read returned an invalid legacy Approval projection")
	} else {
		var failure *agentruntime.Error
		if !errors.As(err, &failure) || failure.Failure.Code != agentruntime.FailureInternal {
			t.Fatalf("public SDK legacy Approval read error = %v, want safe internal failure", err)
		}
	}
}

type legacyApprovalAuthenticator struct{ identity runtimeapi.Identity }

func (auth legacyApprovalAuthenticator) Authenticate(ctx context.Context, token string) (runtimeapi.Identity, error) {
	if err := ctx.Err(); err != nil {
		return runtimeapi.Identity{}, err
	}
	if token != "legacy-approval-token" {
		return runtimeapi.Identity{}, errors.New("invalid credential")
	}
	return auth.identity, nil
}

type legacyApprovalRequestIDs struct{ next uint64 }

func (source *legacyApprovalRequestIDs) NextRequestID() (agentruntime.RequestID, error) {
	source.next++
	return agentruntime.ParseRequestID(fmt.Sprintf("req_%016d", source.next))
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
	store, err := runtimepostgres.NewRuntimeStateStore(pool)
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
	store, err := runtimepostgres.NewRuntimeStateStore(pool)
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

type stateStoreClock struct{ now time.Time }

func (clock stateStoreClock) Now() time.Time { return clock.now }

type stateStoreIDs struct{ next int }

func (ids *stateStoreIDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	ids.next++
	value := fmt.Sprintf("%016d", ids.next)
	switch kind {
	case runtimestate.IdentifierAgent:
		return "agent_" + value, nil
	case runtimestate.IdentifierRevision:
		return "arev_" + value, nil
	case runtimestate.IdentifierSession:
		return "sess_" + value, nil
	case runtimestate.IdentifierInput:
		return "input_" + value, nil
	case runtimestate.IdentifierTurn:
		return "turn_" + value, nil
	case runtimestate.IdentifierInvocation:
		return "invoke_" + value, nil
	case runtimestate.IdentifierEvent:
		return "evt_" + value, nil
	case runtimestate.IdentifierCursor:
		return "cur_" + value, nil
	case runtimestate.IdentifierAudit:
		return "audit_" + value, nil
	case runtimestate.IdentifierOutbox:
		return "outbox_" + value, nil
	default:
		return "", fmt.Errorf("unknown identifier kind %q", kind)
	}
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
