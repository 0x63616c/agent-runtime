package runtimetool

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestBrokerAtomicallyAdmitsPolicyRequiredApprovalAndReplays(t *testing.T) {
	ctx, fixture := context.Background(), newBrokerFixture(t)
	request := fixture.request(t, "workspace-write", 1)
	admitted, err := fixture.broker.Admit(ctx, request)
	if err != nil {
		t.Fatalf("admit policy-required Tool = %v", err)
	}
	if admitted.ToolCallID != request.ToolCallID || admitted.ApprovalID != request.ApprovalID {
		t.Fatalf("admission correlation = %#v", admitted)
	}
	state, err := fixture.store.LoadRuntimeState(ctx, fixture.workerScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.ToolIntents) != 1 || len(state.Approvals) != 1 || len(state.Grants) != 0 || len(state.ToolExecutions) != 0 {
		t.Fatalf("atomic admission state = %#v", state)
	}
	approval := state.Approvals[0]
	if approval.State != "pending" || approval.ActionVerb != "write" || approval.ActionTarget != "workspace-service" || approval.MaximumUses != 1 || approval.ToolCallID != request.ToolCallID {
		t.Fatalf("pending approval = %#v", approval)
	}
	auditCount, outboxCount := len(state.Audit), len(state.Outbox)
	if _, err := fixture.broker.Admit(ctx, request); err != nil {
		t.Fatalf("replay same tool admission = %v", err)
	}
	replayed, err := fixture.store.LoadRuntimeState(ctx, fixture.workerScope)
	if err != nil || len(replayed.ToolIntents) != 1 || len(replayed.Approvals) != 1 || len(replayed.Audit) != auditCount || len(replayed.Outbox) != outboxCount {
		t.Fatalf("replayed admission state = %#v, %v", replayed, err)
	}
}

func TestBrokerFailsClosedWithoutExactPolicyApprovalRule(t *testing.T) {
	ctx, fixture := context.Background(), newBrokerFixture(t)
	request := fixture.request(t, "workspace-denied", 1)
	if _, err := fixture.broker.Admit(ctx, request); err != ErrDenied {
		t.Fatalf("admit denied Tool error = %v, want ErrDenied", err)
	}
	state, err := fixture.store.LoadRuntimeState(ctx, fixture.workerScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.ToolIntents) != 0 || len(state.Approvals) != 0 || len(state.Grants) != 0 || len(state.ToolExecutions) != 0 {
		t.Fatalf("denied admission mutated state = %#v", state)
	}
}

func TestBrokerRetriesAConcurrentStateConflictBeforeAdmitting(t *testing.T) {
	ctx, fixture := context.Background(), newBrokerFixture(t)
	store := &conflictOnceStore{RuntimeStateStore: fixture.store}
	broker, err := NewBroker(BrokerConfig{Store: store, Compiler: fixture.compiler, Planner: fixture.planner, Clock: fixture.clock})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Admit(ctx, fixture.request(t, "workspace-write", 1)); err != nil {
		t.Fatalf("admit after one concurrent state conflict: %v", err)
	}
	if !store.failed {
		t.Fatal("admission did not exercise the injected concurrent conflict")
	}
}

type brokerFixture struct {
	broker      *Broker
	store       *runtimestate.MemoryRuntimeStateStore
	compiler    *runtimestate.Compiler
	planner     *runtimestate.RuntimeStatePlanner
	clock       clock.Clock
	content     *runtimecontent.Store
	tenant      runtimecontent.TenantID
	principal   runtimecontent.PrincipalID
	session     agentruntime.SessionID
	turn        agentruntime.TurnID
	workerScope runtimestate.MutationScope
	now         time.Time
}

func newBrokerFixture(t *testing.T) brokerFixture {
	t.Helper()
	ctx := context.Background()
	tenant, _ := runtimecontent.ParseTenantID("broker-tenant")
	principal, _ := runtimecontent.ParsePrincipalID("broker-owner")
	content, err := runtimecontent.New("broker-test", &brokerObjects{values: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 11, 18, 0, 0, 0, time.UTC)
	clockSource, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(clockSource, &brokerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := runtimestate.NewMemoryRuntimeStateStore(planner)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	admin := runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}
	owner := runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}
	worker := runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}
	apply := func(m runtimestate.CompiledMutation, err error) runtimestate.TransitionPlan {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		state, loadErr := store.LoadRuntimeState(ctx, m.ReceiptBinding().Scope)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		plan, planErr := planner.Plan(ctx, state, m)
		if planErr != nil {
			t.Fatal(planErr)
		}
		if persistErr := store.PersistTransitionPlan(ctx, plan); persistErr != nil {
			t.Fatal(persistErr)
		}
		return plan
	}
	body, err := content.StageAgentSpecificationBody(ctx, tenant, runtimecontent.AgentSpecificationBody{Name: "workspace", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	agent := apply(compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: admin, IdempotencyKey: "broker-agent", Specification: body}))
	apply(compiler.CompileRegisterPolicyRevision(runtimestate.RegisterPolicyRevisionCommand{Scope: admin, IdempotencyKey: "broker-policy", Name: "workspace-write", Rules: []agentruntime.PolicyRule{{ToolName: "workspace.write", Decision: agentruntime.PolicyRequiresApproval}}}))
	session := apply(compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: owner, IdempotencyKey: "broker-session", RevisionID: agent.Result().Revision.RevisionID}))
	input, err := content.StageInputEnvelope(ctx, tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "write workspace file"}})
	if err != nil {
		t.Fatal(err)
	}
	turn := apply(compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: owner, IdempotencyKey: "broker-input", SessionID: session.Result().Session.SessionID, Input: input}))
	broker, err := NewBroker(BrokerConfig{Store: store, Compiler: compiler, Planner: planner, Clock: clockSource})
	if err != nil {
		t.Fatal(err)
	}
	return brokerFixture{broker: broker, store: store, compiler: compiler, planner: planner, clock: clockSource, content: content, tenant: tenant, principal: principal, session: session.Result().Session.SessionID, turn: turn.Result().Turn.TurnID, workerScope: worker, now: now}
}

type conflictOnceStore struct {
	runtimestate.RuntimeStateStore
	failed bool
}

func (store *conflictOnceStore) PersistTransitionPlan(ctx context.Context, plan runtimestate.TransitionPlan) error {
	if !store.failed {
		store.failed = true
		return runtimestate.ErrConflict
	}
	return store.RuntimeStateStore.PersistTransitionPlan(ctx, plan)
}

func (fixture brokerFixture) request(t *testing.T, policy string, revision uint64) AdmissionRequest {
	t.Helper()
	descriptor, err := fixture.content.StageToolActionDescriptor(context.Background(), fixture.tenant, []byte("canonical workspace action"))
	if err != nil {
		t.Fatal(err)
	}
	approvalID, err := agentruntime.ParseApprovalID("appr_1234567890ABCDEF")
	if err != nil {
		t.Fatal(err)
	}
	return AdmissionRequest{Tenant: fixture.tenant, Principal: fixture.principal, SessionID: fixture.session, TurnID: fixture.turn, ToolCallID: "tcall_1234567890ABCDEF", ApprovalID: approvalID, PolicyName: policy, PolicyRevision: revision, ToolName: "workspace.write", ActionDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CapabilityDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Action: agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"}, MaximumUses: 1, ExpiresAt: fixture.now.Add(time.Hour), Descriptor: descriptor, IdempotencyKey: "broker-admission"}
}

type brokerObjects struct{ values map[string][]byte }

func (objects *brokerObjects) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	if _, exists := objects.values[key]; exists {
		return false, nil
	}
	objects.values[key] = append([]byte(nil), value...)
	return true, nil
}
func (objects *brokerObjects) Get(_ context.Context, key string, _ int) ([]byte, error) {
	return append([]byte(nil), objects.values[key]...), nil
}

type brokerIDs struct{ next uint64 }

func (ids *brokerIDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	ids.next++
	return fmt.Sprintf("%s_%016d", kind, ids.next), nil
}
