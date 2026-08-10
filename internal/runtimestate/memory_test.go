package runtimestate_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
)

func TestMemoryRuntimeStateStoreAtomicallyAppliesASealedPlanAndRejectsAStalePlan(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	content, _, tenant, _ := testRuntimeContent(t)
	handoff, err := content.StageAgentSpecificationBody(context.Background(), tenant, runtimecontent.AgentSpecificationBody{Name: "memory", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatalf("stage body: %v", err)
	}
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(fixedPlannerClock{now: now}, &uniquePlannerIDs{})
	if err != nil {
		t.Fatalf("new planner: %v", err)
	}
	store, err := runtimestate.NewMemoryRuntimeStateStore(planner)
	if err != nil {
		t.Fatalf("new memory store: %v", err)
	}
	command, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "memory-create", Specification: handoff})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	prior, err := store.LoadRuntimeState(context.Background(), command.ReceiptBinding().Scope)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	plan, err := planner.Plan(context.Background(), prior, command)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if err := store.PersistTransitionPlan(context.Background(), plan); err != nil {
		t.Fatalf("persist: %v", err)
	}
	if err := store.PersistTransitionPlan(context.Background(), plan); !errors.Is(err, runtimestate.ErrConflict) {
		t.Fatalf("stale persist error = %v, want conflict", err)
	}
	loaded, err := store.LoadRuntimeState(context.Background(), command.ReceiptBinding().Scope)
	if err != nil {
		t.Fatalf("load after persist: %v", err)
	}
	if len(loaded.Revisions) != 1 || len(loaded.Receipts) != 1 || len(loaded.Outbox) != 1 {
		t.Fatalf("persisted state = %#v, want full atomic plan", loaded)
	}
}

func TestMemoryRuntimeStateStoreServesOnlyScopedMetadataAndCompiledContentReaders(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	content, _, tenant, principal := testRuntimeContent(t)
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(fixedPlannerClock{now: now}, &uniquePlannerIDs{})
	if err != nil {
		t.Fatalf("new planner: %v", err)
	}
	store, err := runtimestate.NewMemoryRuntimeStateStore(planner)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	body, err := content.StageAgentSpecificationBody(context.Background(), tenant, runtimecontent.AgentSpecificationBody{Name: "reader", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatalf("stage body: %v", err)
	}
	registered, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "reader-register", Specification: body})
	if err != nil {
		t.Fatalf("compile register: %v", err)
	}
	registration, err := store.Apply(context.Background(), registered)
	if err != nil {
		t.Fatalf("apply register: %v", err)
	}
	reader, err := compiler.CompileAuthorizeAgentSpecificationBodyRead(runtimestate.AgentSpecificationBodyReadCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, AgentID: registration.Result().Revision.AgentID, RevisionID: registration.Result().Revision.RevisionID})
	if err != nil {
		t.Fatalf("compile reader: %v", err)
	}
	record, err := store.AuthorizeAgentSpecificationBodyRead(context.Background(), reader)
	if err != nil || record.Reference.Digest == "" {
		t.Fatalf("authorize body read = %#v, %v", record, err)
	}
	if _, err := store.GetAgentRevision(context.Background(), runtimestate.AgentRevisionQuery{Scope: ownerScope(tenant, principal), AgentID: record.AgentID, RevisionID: record.RevisionID}); !errors.Is(err, runtimestate.ErrNotFoundOrDenied) {
		t.Fatalf("owner catalog query error = %v, want non-enumerating denial", err)
	}
}
