package localdemoworker

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/roles"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimemodel"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	"github.com/0x63616c/agent-runtime/internal/runtimetool"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/cockroachdb/errors"
)

func TestScanLoopRetriesOnlyTypedTransientStateUnavailable(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	err := scanLoop(ctx, func(context.Context) error {
		if calls.Add(1) == 1 {
			return errors.Wrap(runtimestate.ErrUnavailable, "schema migration is still starting")
		}
		cancel()
		return nil
	}, time.Second, func(context.Context, time.Duration) error { return nil }, testLogger())
	if err != nil {
		t.Fatalf("scanLoop() error = %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("scanLoop calls = %d, want 2 (one typed retry)", got)
	}
}

func TestScanLoopTreatsLiveDeadlineAsTheNextScanBoundary(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	var waits atomic.Int32
	err := scanLoop(ctx, func(context.Context) error {
		if calls.Add(1) == 2 {
			cancel()
			return context.Canceled
		}
		return nil
	}, time.Second, func(context.Context, time.Duration) error {
		waits.Add(1)
		return context.DeadlineExceeded
	}, testLogger())
	if err != nil || calls.Load() != 2 || waits.Load() != 1 {
		t.Fatalf("scanLoop live deadline = calls=%d waits=%d error=%v, want next scan boundary", calls.Load(), waits.Load(), err)
	}
}

func TestScanLoopFailsClosedForNonTransientErrors(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("invalid local demo fixture authority")
	var calls atomic.Int32
	err := scanLoop(context.Background(), func(context.Context) error {
		calls.Add(1)
		return sentinel
	}, time.Second, func(context.Context, time.Duration) error { return nil }, testLogger())
	if !errors.Is(err, sentinel) {
		t.Fatalf("scanLoop() error = %v, want wrapped %v", err, sentinel)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("scanLoop calls = %d, want one fail-closed attempt", got)
	}
}

func TestModelFixtureUsesTheCanonicalApprovalSummaryForItsWorkspaceTool(t *testing.T) {
	source, err := clock.NewFake(time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	response, err := (modelFixture{approvalTTL: 10 * time.Minute}).Invoke(t.Context(), runtimemodel.Request{OperationID: "orchestration-invocation-outbox_1234567890ABCDEF", CreatedAt: source.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if response.Tool == nil {
		t.Fatal("fixture response has no tool request")
	}
	if response.Tool.ToolName != "workspace.write" || response.Tool.PolicyName != "workspace-write-demo" || response.Tool.PolicyRevision != 1 {
		t.Fatalf("fixture policy request = %#v, want the declared workspace demo policy", response.Tool)
	}
	if response.Tool.Action.Verb != "write" || response.Tool.Action.Target != "workspace-service" {
		t.Fatalf("fixture approval summary = %#v, want canonical workspace write", response.Tool.Action)
	}
	if _, err := agentruntime.ParseApprovalID(response.Tool.ApprovalID); err != nil {
		t.Fatalf("fixture approval ID = %q, want public identifier: %v", response.Tool.ApprovalID, err)
	}
}

func TestDeclaredFixtureScenariosHaveOnlyFiniteApprovalLifetimes(t *testing.T) {
	for _, want := range []struct {
		scenario roles.LocalDemoFixtureScenario
		ttl      time.Duration
	}{
		{scenario: "workspace-approval-reset-v1", ttl: 10 * time.Minute},
		{scenario: "workspace-approval-expiry-v1", ttl: 2 * time.Second},
	} {
		t.Run(string(want.scenario), func(t *testing.T) {
			ttl, err := approvalTTLForScenario(want.scenario)
			if err != nil || ttl != want.ttl {
				t.Fatalf("scenario approval lifetime = %s, %v", ttl, err)
			}
			now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
			source, err := clock.NewFake(now)
			if err != nil {
				t.Fatal(err)
			}
			response, err := (modelFixture{approvalTTL: ttl}).Invoke(t.Context(), runtimemodel.Request{OperationID: "orchestration-invocation-outbox_1234567890ABCDEF", CreatedAt: source.Now()})
			if err != nil || response.Tool == nil {
				t.Fatalf("invoke declared scenario = %#v, %v", response, err)
			}
			if response.Tool.ExpiresAt != now.Add(ttl) {
				t.Fatalf("tool expiry = %s, want exact %s", response.Tool.ExpiresAt, now.Add(ttl))
			}
		})
	}
	if _, err := approvalTTLForScenario("ambient"); err == nil {
		t.Fatal("undeclared fixture scenario was accepted")
	}
}

func TestModelFixtureReconcilesTheExactRecordedOperationResponse(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	source, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	request := runtimemodel.Request{OperationID: "orchestration-invocation-outbox_1234567890ABCDEF", CreatedAt: source.Now()}
	fixture := modelFixture{approvalTTL: 10 * time.Minute}
	invoked, err := fixture.Invoke(t.Context(), request)
	if err != nil || invoked.Tool == nil {
		t.Fatalf("invoke fixture = %#v, %v", invoked, err)
	}
	if err := source.Advance(2*time.Minute + time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	// Reconstructing the fixture simulates a new worker process. The durable
	// invocation creation time is part of the runtime-owned request, so the
	// normalized response has no process-local state or extra blob prefix.
	restarted := modelFixture{approvalTTL: 10 * time.Minute}
	reconciled, err := restarted.Reconcile(t.Context(), request)
	if err != nil || reconciled.Tool == nil || reconciled.Tool.ExpiresAt != invoked.Tool.ExpiresAt || string(reconciled.Tool.Descriptor) != string(invoked.Tool.Descriptor) {
		t.Fatalf("reconcile fixture = %#v, %v; want exact invoke response %#v", reconciled, err, invoked)
	}
}

// TestModelFixtureRecoveryAcknowledgesTheAlreadyAdmittedTool proves the exact
// crash boundary that used to fail: Broker.Admit has committed its idempotent
// receipt, but the model outbox acknowledgement is lost. After the claim
// expires, the worker reconciles the operation-owned fixture response and
// acknowledges the original outbox without a duplicate admission effect.
func TestModelFixtureRecoveryAcknowledgesTheAlreadyAdmittedTool(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	source, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	content, err := runtimecontent.New("local-demo-model-recovery", &fixtureObjects{values: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := runtimecontent.ParseTenantID("local-demo-model-recovery")
	principal, _ := runtimecontent.ParsePrincipalID("alice")
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(source, &fixtureIDs{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := runtimestate.NewMemoryRuntimeStateStore(planner)
	if err != nil {
		t.Fatal(err)
	}
	session, turn, invocation := createFixtureModelIntent(t, ctx, content, compiler, store, tenant, principal)
	policy, err := compiler.CompileRegisterPolicyRevision(runtimestate.RegisterPolicyRevisionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "local-demo-workspace-policy", Name: "workspace-write-demo", Rules: []agentruntime.PolicyRule{{ToolName: "workspace.write", Decision: agentruntime.PolicyRequiresApproval}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, policy); err != nil {
		t.Fatal(err)
	}
	broker, err := runtimetool.NewBroker(runtimetool.BrokerConfig{Store: store, Compiler: compiler, Planner: planner, Clock: source})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &countingFixtureAdapter{fixture: modelFixture{approvalTTL: 10 * time.Minute}}
	record := fixtureInvocationOutbox(t, ctx, store, tenant)
	claim, err := compiler.CompileClaimOutbox(runtimestate.ClaimOutboxCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher}, IdempotencyKey: "local-demo-lost-model-claim", OutboxID: record.OutboxID, ExpectedVersion: record.Version, Claimer: "lost-local-demo-model", ClaimUntil: now.Add(2 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, claim); err != nil {
		t.Fatal(err)
	}
	request := runtimemodel.Request{Tenant: tenant, SessionID: session, TurnID: turn, OperationID: invocation.OperationID, CreatedAt: invocation.CreatedAt}
	response, err := adapter.Invoke(ctx, request)
	if err != nil || response.Tool == nil {
		t.Fatalf("invoke local fixture = %#v, %v", response, err)
	}
	handoff, err := content.StageToolActionDescriptor(ctx, tenant, response.Tool.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Admit(ctx, runtimetool.AdmissionRequest{Tenant: tenant, Principal: principal, SessionID: session, TurnID: turn, ToolCallID: response.Tool.ToolCallID, ApprovalID: agentruntime.ApprovalID(response.Tool.ApprovalID), PolicyName: response.Tool.PolicyName, PolicyRevision: response.Tool.PolicyRevision, ToolName: response.Tool.ToolName, ActionDigest: response.Tool.ActionDigest, CapabilityDigest: response.Tool.CapabilityDigest, Action: response.Tool.Action, MaximumUses: response.Tool.MaximumUses, ExpiresAt: response.Tool.ExpiresAt, Descriptor: handoff, IdempotencyKey: fmt.Sprintf("model-tool-%s-%d", invocation.OperationID, invocation.Fence)}); err != nil {
		t.Fatalf("admit tool before lost acknowledgement: %v", err)
	}
	if err := source.Advance(2*time.Minute + time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	// The recovered worker has a new adapter/fixture and derives the same
	// response solely from durable invocation identity and creation time.
	recoveredAdapter := &countingFixtureAdapter{fixture: modelFixture{approvalTTL: 10 * time.Minute}}
	worker, err := runtimemodel.NewWorker(runtimemodel.WorkerConfig{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: recoveredAdapter, Broker: broker, Claimer: "recovered-local-demo-model"})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.ScanOnce(ctx); err != nil {
		t.Fatalf("recover model outbox after admission: %v", err)
	}
	state, err := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker})
	if err != nil {
		t.Fatal(err)
	}
	if adapter.invocations != 1 || recoveredAdapter.reconciliations != 1 || len(state.ToolIntents) != 1 || len(state.Approvals) != 1 || state.Approvals[0].ExpiresAt != response.Tool.ExpiresAt || len(state.Turns) != 1 || state.Turns[0].State != agentruntime.TurnWaitingForApproval {
		t.Fatalf("recovered local fixture state = original=%#v recovered=%#v intents=%#v approvals=%#v turns=%#v", adapter, recoveredAdapter, state.ToolIntents, state.Approvals, state.Turns)
	}
	if record := fixtureInvocationOutbox(t, ctx, store, tenant); record.State != runtimestate.OutboxPublished {
		t.Fatalf("recovered model outbox = %#v, want acknowledged", record)
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func createFixtureModelIntent(t *testing.T, ctx context.Context, content *runtimecontent.Store, compiler *runtimestate.Compiler, store *runtimestate.MemoryRuntimeStateStore, tenant runtimecontent.TenantID, principal runtimecontent.PrincipalID) (agentruntime.SessionID, agentruntime.TurnID, runtimestate.InvocationRecord) {
	t.Helper()
	body, err := content.StageAgentSpecificationBody(ctx, tenant, runtimecontent.AgentSpecificationBody{Name: "local-demo-model", ModelProfile: "balanced", Instructions: "recover one local fixture admission", Tools: []agentruntime.ToolDefinition{{Name: "workspace.write", Description: "write a bounded workspace fixture"}}})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "local-demo-register", Specification: body})
	if err != nil {
		t.Fatal(err)
	}
	registration, err := store.Apply(ctx, registered)
	if err != nil {
		t.Fatal(err)
	}
	created, err := compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}, IdempotencyKey: "local-demo-session", RevisionID: registration.Result().Revision.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.Apply(ctx, created)
	if err != nil {
		t.Fatal(err)
	}
	input, err := content.StageInputEnvelope(ctx, tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "recover the local fixture"}})
	if err != nil {
		t.Fatal(err)
	}
	admit, err := compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}, IdempotencyKey: "local-demo-input", SessionID: session.Result().Session.SessionID, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := store.Apply(ctx, admit)
	if err != nil {
		t.Fatal(err)
	}
	begin, err := compiler.CompileBeginInvocationAttempt(runtimestate.BeginInvocationAttemptCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "local-demo-intent", SessionID: session.Result().Session.SessionID, TurnID: accepted.Result().Turn.TurnID, OperationID: "op_local_demo_recovery_0001", ExpectedSessionVersion: accepted.Result().Session.Version, ExpectedTurnVersion: accepted.Result().Turn.Version})
	if err != nil {
		t.Fatal(err)
	}
	intent, err := store.Apply(ctx, begin)
	if err != nil {
		t.Fatal(err)
	}
	return session.Result().Session.SessionID, accepted.Result().Turn.TurnID, intent.Result().Invocation
}

func fixtureInvocationOutbox(t *testing.T, ctx context.Context, store *runtimestate.MemoryRuntimeStateStore, tenant runtimecontent.TenantID) runtimestate.OutboxRecord {
	t.Helper()
	page, err := store.ReadOutbox(ctx, runtimestate.OutboxQuery{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher}, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range page.Records {
		if record.InvocationID != "" && record.EventKind == "" {
			return record
		}
	}
	t.Fatalf("local fixture model outbox = %#v, want invocation intent", page.Records)
	return runtimestate.OutboxRecord{}
}

type countingFixtureAdapter struct {
	fixture         modelFixture
	invocations     int
	reconciliations int
}

func (adapter *countingFixtureAdapter) Invoke(ctx context.Context, request runtimemodel.Request) (runtimemodel.Response, error) {
	adapter.invocations++
	return adapter.fixture.Invoke(ctx, request)
}

func (adapter *countingFixtureAdapter) Reconcile(ctx context.Context, request runtimemodel.Request) (runtimemodel.Response, error) {
	adapter.reconciliations++
	return adapter.fixture.Reconcile(ctx, request)
}

type fixtureObjects struct{ values map[string][]byte }

func (objects *fixtureObjects) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	if _, exists := objects.values[key]; exists {
		return false, nil
	}
	objects.values[key] = append([]byte(nil), value...)
	return true, nil
}

func (objects *fixtureObjects) Get(_ context.Context, key string, _ int) ([]byte, error) {
	return append([]byte(nil), objects.values[key]...), nil
}

type fixtureIDs struct{ next uint64 }

func (ids *fixtureIDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	ids.next++
	return fmt.Sprintf("%s_%016d", kind, ids.next), nil
}

func TestRandomIDsUseThePublicIdentifierPayloadLength(t *testing.T) {
	value, err := (randomIDs{}).NextIdentifier(runtimestate.IdentifierEvent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agentruntime.ParseEventID(value); err != nil {
		t.Fatalf("fixture event ID = %q, want public identifier: %v", value, err)
	}
}
