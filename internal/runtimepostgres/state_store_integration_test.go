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
		return "event_" + value, nil
	case runtimestate.IdentifierCursor:
		return "cursor_" + value, nil
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
