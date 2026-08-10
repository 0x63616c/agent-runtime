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
