package runtimetool_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimeorchestration"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	"github.com/0x63616c/agent-runtime/internal/runtimetool"
	"github.com/0x63616c/agent-runtime/sandbox"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestWorkerFinalizesAuthorizedToolActionsAndReconcilesLostClaims(t *testing.T) {
	for _, test := range []struct {
		name        string
		recovering  bool
		corrupt     bool
		missing     bool
		wantExecute int
		wantRecon   int
		wantState   runtimestate.ToolExecutionState
	}{
		{name: "new descriptor executes once", wantExecute: 1, wantState: runtimestate.ToolExecutionSucceeded},
		{name: "lost claim reconciles without reexecution", recovering: true, wantRecon: 1, wantState: runtimestate.ToolExecutionSucceeded},
		{name: "corrupt descriptor is refused before execution", corrupt: true, wantState: runtimestate.ToolExecutionFailed},
		{name: "missing descriptor is refused before execution", missing: true, wantState: runtimestate.ToolExecutionFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
			objects := &toolObjects{values: map[string][]byte{}}
			content, err := runtimecontent.New("runtime-content", objects)
			if err != nil {
				t.Fatal(err)
			}
			tenant, _ := runtimecontent.ParseTenantID("tenant-a")
			principal, _ := runtimecontent.ParsePrincipalID("principal-a")
			compiler, err := runtimestate.NewCompiler(content)
			if err != nil {
				t.Fatal(err)
			}
			source, err := clock.NewFake(now)
			if err != nil {
				t.Fatal(err)
			}
			planner, err := runtimestate.NewRuntimeStatePlanner(source, &toolIDs{})
			if err != nil {
				t.Fatal(err)
			}
			store, err := runtimestate.NewMemoryRuntimeStateStore(planner)
			if err != nil {
				t.Fatal(err)
			}
			session, turn, execution, descriptor := createToolExecution(t, ctx, content, compiler, store, tenant, principal, now)
			if test.corrupt {
				for key, value := range objects.values {
					if bytes.Equal(value, descriptor) {
						objects.values[key][0] ^= 0xff
						break
					}
				}
			}
			if test.missing {
				for key, value := range objects.values {
					if bytes.Equal(value, descriptor) {
						delete(objects.values, key)
						break
					}
				}
			}
			if test.recovering {
				record := toolOutbox(t, ctx, store, tenant)
				claim, err := compiler.CompileClaimOutbox(runtimestate.ClaimOutboxCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher}, IdempotencyKey: "lost-tool-claim", OutboxID: record.OutboxID, ExpectedVersion: record.Version, Claimer: "lost-tool-worker", ClaimUntil: now.Add(time.Minute)})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.Apply(ctx, claim); err != nil {
					t.Fatal(err)
				}
				if err := source.Advance(time.Minute + time.Nanosecond); err != nil {
					t.Fatal(err)
				}
			}
			adapter := &recordingAdapter{response: runtimetool.Response{Output: []byte("sandbox operation completed")}}
			worker, err := runtimetool.NewWorker(runtimetool.Config{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: adapter, Claimer: "tool-worker"})
			if err != nil {
				t.Fatal(err)
			}
			if err := worker.ScanOnce(ctx); err != nil {
				t.Fatalf("scan tool intent: %v", err)
			}
			if adapter.executes != test.wantExecute || adapter.reconciles != test.wantRecon {
				t.Fatalf("adapter calls = execute=%d reconcile=%d, want %d/%d", adapter.executes, adapter.reconciles, test.wantExecute, test.wantRecon)
			}
			if !test.corrupt && !test.missing && (!bytes.Equal(adapter.last.Descriptor, descriptor) || adapter.last.SessionID != session || adapter.last.TurnID != turn || adapter.last.OperationID != execution.OperationID) {
				t.Fatalf("adapter request = %#v, want authorized descriptor and exact operation provenance", adapter.last)
			}
			state, err := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityRuntimeWorker})
			if err != nil {
				t.Fatal(err)
			}
			if len(state.ToolExecutions) != 1 || state.ToolExecutions[0].State != test.wantState {
				t.Fatalf("tool execution state = %#v, want %s", state.ToolExecutions, test.wantState)
			}
			if test.corrupt && (state.ToolExecutions[0].Failure == nil || state.ToolExecutions[0].Failure.Message != "verified tool action descriptor is invalid") {
				t.Fatalf("corrupt descriptor outcome = %#v", state.ToolExecutions[0])
			}
			if len(state.Events) == 0 || state.Events[len(state.Events)-1].Kind != agentruntime.EventSandboxOperationFinalized {
				t.Fatalf("tool terminal event = %#v, want durable sandbox finalization", state.Events)
			}
			foundFinalizationRoute := false
			for _, record := range state.Outbox {
				if record.EventKind == agentruntime.EventSandboxOperationFinalized && record.OperationID == execution.OperationID {
					foundFinalizationRoute = true
				}
			}
			if !foundFinalizationRoute {
				t.Fatalf("tool terminal outbox = %#v, want sandbox finalization route", state.Outbox)
			}
			if record := toolOutbox(t, ctx, store, tenant); record.State != runtimestate.OutboxPublished {
				t.Fatalf("tool outbox = %#v, want acknowledged after terminal outcome", record)
			}
		})
	}
}

func TestWorkerConsumesApprovedGrantAndResumesAfterConsumeBeforeIntent(t *testing.T) {
	for _, test := range []struct {
		name             string
		consumeBeforeRun bool
	}{
		{name: "approved grant is consumed then executed"},
		{name: "restart after consume creates the missing execution intent", consumeBeforeRun: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
			objects := &toolObjects{values: map[string][]byte{}}
			content, err := runtimecontent.New("runtime-content", objects)
			if err != nil {
				t.Fatal(err)
			}
			tenant, _ := runtimecontent.ParseTenantID("tenant-a")
			principal, _ := runtimecontent.ParsePrincipalID("principal-a")
			compiler, _ := runtimestate.NewCompiler(content)
			source, _ := clock.NewFake(now)
			planner, _ := runtimestate.NewRuntimeStatePlanner(source, &toolIDs{})
			store, _ := runtimestate.NewMemoryRuntimeStateStore(planner)
			approved := createApprovedToolGrant(t, ctx, content, compiler, store, tenant, principal, now)
			if test.consumeBeforeRun {
				consume, err := compiler.CompileConsumeCapabilityGrant(runtimestate.ConsumeCapabilityGrantCommand{Scope: approved.workerScope, IdempotencyKey: "crash-consume", SessionID: approved.sessionID, TurnID: approved.turnID, ToolCallID: approved.toolCallID, GrantID: approved.grantID, PolicyRevisionDigest: approved.digest})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = store.Apply(ctx, consume); err != nil {
					t.Fatal(err)
				}
			}
			adapter := &recordingAdapter{response: runtimetool.Response{Output: []byte("one bounded result")}}
			worker, err := runtimetool.NewWorker(runtimetool.Config{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: adapter, Claimer: "tool-worker"})
			if err != nil {
				t.Fatal(err)
			}
			if err := worker.ScanOnce(ctx); err != nil {
				t.Fatalf("first scan: %v", err)
			}
			if err := worker.ScanOnce(ctx); err != nil {
				t.Fatalf("replay scan: %v", err)
			}
			if adapter.executes != 1 || adapter.reconciles != 0 {
				t.Fatalf("adapter calls = execute=%d reconcile=%d, want exactly one execution", adapter.executes, adapter.reconciles)
			}
			state, err := store.LoadRuntimeState(ctx, approved.workerScope)
			if err != nil {
				t.Fatal(err)
			}
			if len(state.Grants) != 1 || state.Grants[0].Uses != 1 {
				t.Fatalf("grant use count = %#v, want exactly one durable consumption", state.Grants)
			}
			if len(state.ToolExecutions) != 1 || state.ToolExecutions[0].OperationID != runtimestate.OperationID("op-tool-"+approved.grantID) || state.ToolExecutions[0].State != runtimestate.ToolExecutionSucceeded {
				t.Fatalf("tool executions = %#v, want one succeeded deterministic execution", state.ToolExecutions)
			}
		})
	}
}

func TestWorkerRefusesOversizedToolOutputBeforeDurablePersistence(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	content, err := runtimecontent.New("runtime-content", &toolObjects{values: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("principal-a")
	compiler, _ := runtimestate.NewCompiler(content)
	source, _ := clock.NewFake(now)
	planner, _ := runtimestate.NewRuntimeStatePlanner(source, &toolIDs{})
	store, _ := runtimestate.NewMemoryRuntimeStateStore(planner)
	_, _, _, _ = createToolExecution(t, ctx, content, compiler, store, tenant, principal, now)
	adapter := &recordingAdapter{response: runtimetool.Response{Output: bytes.Repeat([]byte("x"), 8<<20+1)}}
	worker, err := runtimetool.NewWorker(runtimetool.Config{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: adapter, Claimer: "tool-worker"})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.ScanOnce(ctx); err != nil {
		t.Fatalf("finalize oversized output: %v", err)
	}
	state, err := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker})
	if err != nil {
		t.Fatal(err)
	}
	if len(state.ToolExecutions) != 1 || state.ToolExecutions[0].State != runtimestate.ToolExecutionFailed || state.ToolExecutions[0].Failure == nil || state.ToolExecutions[0].Failure.Message != "tool output exceeds the safe retention limit" || len(state.Artifacts) != 0 {
		t.Fatalf("oversized output state = executions=%#v artifacts=%#v", state.ToolExecutions, state.Artifacts)
	}
}

func TestWorkerNeverDispatchesExpiredOrCancelledApprovedGrants(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(t *testing.T, compiler *runtimestate.Compiler, store *runtimestate.MemoryRuntimeStateStore, clock *clock.Fake, approved approvedToolGrant)
	}{
		{
			name: "expired approval is not consumed",
			prepare: func(t *testing.T, _ *runtimestate.Compiler, _ *runtimestate.MemoryRuntimeStateStore, source *clock.Fake, approved approvedToolGrant) {
				t.Helper()
				if err := source.Advance(time.Hour + time.Minute); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "cancelled turn invalidates approval before dispatch",
			prepare: func(t *testing.T, compiler *runtimestate.Compiler, store *runtimestate.MemoryRuntimeStateStore, _ *clock.Fake, approved approvedToolGrant) {
				t.Helper()
				ownerScope := approved.workerScope
				ownerScope.Authority = runtimestate.AuthoritySessionOwner
				cancel, err := compiler.CompileCancelTurn(runtimestate.CancelTurnCommand{Scope: ownerScope, IdempotencyKey: "cancel-before-tool-dispatch", SessionID: approved.sessionID, TurnID: approved.turnID})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = store.Apply(context.Background(), cancel); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "owner revocation withdraws an unused grant before dispatch",
			prepare: func(t *testing.T, compiler *runtimestate.Compiler, store *runtimestate.MemoryRuntimeStateStore, _ *clock.Fake, approved approvedToolGrant) {
				t.Helper()
				ownerScope := approved.workerScope
				ownerScope.Authority = runtimestate.AuthoritySessionOwner
				revoke, err := compiler.CompileRevokeCapabilityGrant(runtimestate.RevokeCapabilityGrantCommand{Scope: ownerScope, IdempotencyKey: "revoke-before-tool-dispatch", SessionID: approved.sessionID, TurnID: approved.turnID, ToolCallID: approved.toolCallID, GrantID: approved.grantID})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = store.Apply(context.Background(), revoke); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
			content, err := runtimecontent.New("runtime-content", &toolObjects{values: map[string][]byte{}})
			if err != nil {
				t.Fatal(err)
			}
			tenant, _ := runtimecontent.ParseTenantID("tenant-a")
			principal, _ := runtimecontent.ParsePrincipalID("principal-a")
			compiler, _ := runtimestate.NewCompiler(content)
			source, _ := clock.NewFake(now)
			planner, _ := runtimestate.NewRuntimeStatePlanner(source, &toolIDs{})
			store, _ := runtimestate.NewMemoryRuntimeStateStore(planner)
			approved := createApprovedToolGrant(t, ctx, content, compiler, store, tenant, principal, now)
			test.prepare(t, compiler, store, source, approved)
			adapter := &recordingAdapter{response: runtimetool.Response{Output: []byte("must not execute")}}
			worker, err := runtimetool.NewWorker(runtimetool.Config{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: adapter, Claimer: "tool-worker"})
			if err != nil {
				t.Fatal(err)
			}
			if err := worker.ScanOnce(ctx); err != nil {
				t.Fatalf("scan invalid grant: %v", err)
			}
			state, err := store.LoadRuntimeState(ctx, approved.workerScope)
			if err != nil {
				t.Fatal(err)
			}
			if adapter.executes != 0 || adapter.reconciles != 0 || len(state.ToolExecutions) != 0 || state.Grants[0].Uses != 0 {
				t.Fatalf("invalid grant dispatched = calls=%d/%d executions=%#v grants=%#v", adapter.executes, adapter.reconciles, state.ToolExecutions, state.Grants)
			}
		})
	}
}

func TestOwnerRevocationIsDurableIdempotentAndTerminalBeforeExecution(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	content, err := runtimecontent.New("runtime-content", &toolObjects{values: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("principal-a")
	compiler, _ := runtimestate.NewCompiler(content)
	source, _ := clock.NewFake(now)
	planner, _ := runtimestate.NewRuntimeStatePlanner(source, &toolIDs{})
	store, _ := runtimestate.NewMemoryRuntimeStateStore(planner)
	approved := createApprovedToolGrant(t, ctx, content, compiler, store, tenant, principal, now)
	ownerScope := approved.workerScope
	ownerScope.Authority = runtimestate.AuthoritySessionOwner
	revoke, err := compiler.CompileRevokeCapabilityGrant(runtimestate.RevokeCapabilityGrantCommand{Scope: ownerScope, IdempotencyKey: "revoke-approved-tool", SessionID: approved.sessionID, TurnID: approved.turnID, ToolCallID: approved.toolCallID, GrantID: approved.grantID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Apply(ctx, revoke); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Apply(ctx, revoke); err != nil {
		t.Fatalf("replay revoke: %v", err)
	}
	state, err := store.LoadRuntimeState(ctx, approved.workerScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Grants) != 1 || state.Grants[0].RevokedAt == nil || state.Grants[0].Uses != 0 || len(state.ToolExecutions) != 0 || !hasAuditKind(state.Audit, "capability_grant.revoked") || !hasAuditKind(state.Audit, "revoke_capability_grant.terminal") {
		t.Fatalf("revoked state = grants=%#v executions=%#v audit=%#v", state.Grants, state.ToolExecutions, state.Audit)
	}
	adapter := &recordingAdapter{response: runtimetool.Response{Output: []byte("must not execute")}}
	worker, err := runtimetool.NewWorker(runtimetool.Config{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: adapter, Claimer: "tool-worker"})
	if err != nil {
		t.Fatal(err)
	}
	if err = worker.ScanOnce(ctx); err != nil || adapter.executes != 0 || adapter.reconciles != 0 {
		t.Fatalf("revoked grant scan = calls=%d/%d, err=%v", adapter.executes, adapter.reconciles, err)
	}
}

func hasAuditKind(records []runtimestate.AuditFactRecord, want string) bool {
	for _, record := range records {
		if record.Kind == want {
			return true
		}
	}
	return false
}

func TestStateAuthorizationRejectsCrossScopeToolDescriptorReads(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	objects := &toolObjects{values: map[string][]byte{}}
	content, _ := runtimecontent.New("runtime-content", objects)
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("principal-a")
	other, _ := runtimecontent.ParsePrincipalID("principal-b")
	compiler, _ := runtimestate.NewCompiler(content)
	source, _ := clock.NewFake(now)
	planner, _ := runtimestate.NewRuntimeStatePlanner(source, &toolIDs{})
	store, _ := runtimestate.NewMemoryRuntimeStateStore(planner)
	session, turn, _, _ := createToolExecution(t, ctx, content, compiler, store, tenant, principal, now)
	for _, scope := range []runtimestate.MutationScope{
		{Tenant: tenant, Principal: other, Authority: runtimestate.AuthorityRuntimeWorker},
		{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner},
	} {
		authorization, err := compiler.CompileAuthorizeToolActionDescriptorRead(runtimestate.ToolActionDescriptorReadCommand{Scope: scope, SessionID: session, TurnID: turn, ToolCallID: "tcall_1234567890ABCDEF"})
		if scope.Authority != runtimestate.AuthorityRuntimeWorker {
			if err == nil {
				t.Fatalf("wrong authority compiled descriptor reader")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.AuthorizeToolActionDescriptorRead(ctx, authorization); !errors.Is(err, runtimestate.ErrNotFoundOrDenied) {
			t.Fatalf("cross-principal descriptor authorization error = %v, want ErrNotFoundOrDenied", err)
		}
	}
}

func TestToolFinalizationPublishesAStateRecheckedTemporalRoute(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	objects := &toolObjects{values: map[string][]byte{}}
	content, _ := runtimecontent.New("runtime-content", objects)
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("principal-a")
	compiler, _ := runtimestate.NewCompiler(content)
	source, _ := clock.NewFake(now)
	planner, _ := runtimestate.NewRuntimeStatePlanner(source, &toolIDs{})
	store, _ := runtimestate.NewMemoryRuntimeStateStore(planner)
	_, _, execution, _ := createToolExecution(t, ctx, content, compiler, store, tenant, principal, now)
	worker, err := runtimetool.NewWorker(runtimetool.Config{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: &recordingAdapter{response: runtimetool.Response{Output: []byte("complete")}}, Claimer: "tool-worker"})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.ScanOnce(ctx); err != nil {
		t.Fatalf("finalize tool execution: %v", err)
	}
	temporal := &temporalPublisher{}
	publisher, err := runtimeorchestration.NewPublisher(runtimeorchestration.PublisherConfig{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Publisher: temporal, Claimer: "orchestration-codec"})
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.ScanOnce(ctx); err != nil {
		t.Fatalf("publish tool finalization: %v", err)
	}
	var finalization runtimeorchestration.Command
	for _, command := range temporal.commands {
		if command.Kind == runtimeorchestration.CommandSandboxOperationFinalized {
			finalization = command
			break
		}
	}
	if finalization.OutboxID == "" || finalization.Sequence == 0 {
		t.Fatalf("Temporal commands = %#v, want sandbox finalization", temporal.commands)
	}
	dispatcher, err := runtimeorchestration.NewDurableStateDispatcher(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.Dispatch(ctx, finalization); err != nil {
		t.Fatalf("recheck published sandbox finalization route: %v", err)
	}
	state, err := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range state.Events {
		if event.Kind == agentruntime.EventSandboxOperationFinalized && event.OperationID != execution.OperationID {
			t.Fatalf("sandbox finalization correlation = %s, want %s", event.OperationID, execution.OperationID)
		}
	}
}

func TestSandboxAdapterUsesOnlyVerifiedDescriptorAndReconcilesWithoutResubmit(t *testing.T) {
	descriptor, err := sandbox.EncodeControlOperationRequest(sandbox.OperationRequest{ID: "op_tool_000000000001", Kind: sandbox.OperationCloseSandbox, CloseSandbox: &sandbox.CloseSandboxRequest{SandboxID: "sbx_tool_000000000001"}})
	if err != nil {
		t.Fatal(err)
	}
	client := &sandboxClient{operation: sandbox.Operation{Ref: sandbox.OperationRef{ID: "op_tool_000000000001"}, State: sandbox.OperationSucceeded, Result: &sandbox.OperationResult{Kind: sandbox.ResultControl, Control: &sandbox.ControlResult{Action: sandbox.ControlClosed}}}}
	adapter, err := runtimetool.NewSandboxAdapter(client)
	if err != nil {
		t.Fatal(err)
	}
	request := runtimetool.Request{OperationID: "op_tool_000000000001", Descriptor: descriptor}
	response, err := adapter.Execute(context.Background(), request)
	if err != nil || client.submits != 1 || client.waits != 1 || client.gets != 0 || response.MediaType != "application/json" || !bytes.Contains(response.Output, []byte("op_tool_000000000001")) {
		t.Fatalf("sandbox execute = %#v, calls submit=%d wait=%d get=%d, err=%v", response, client.submits, client.waits, client.gets, err)
	}
	response, err = adapter.Reconcile(context.Background(), request)
	if err != nil || client.submits != 1 || client.waits != 1 || client.gets != 1 || response.Uncertain || len(response.Output) == 0 {
		t.Fatalf("sandbox reconcile = %#v, calls submit=%d wait=%d get=%d, err=%v", response, client.submits, client.waits, client.gets, err)
	}
	for _, invalid := range []runtimetool.Request{
		{OperationID: "op_tool_000000000001", Descriptor: []byte("not sandbox.control/v1")},
		{OperationID: "op_other_000000000001", Descriptor: descriptor},
	} {
		response, err := adapter.Execute(context.Background(), invalid)
		if err != nil || response.Failure == nil || response.Failure.Code != agentruntime.FailureInvalidInput || client.submits != 1 {
			t.Fatalf("invalid descriptor execution = %#v, calls=%d, err=%v", response, client.submits, err)
		}
	}
}

func createToolExecution(t *testing.T, ctx context.Context, content *runtimecontent.Store, compiler *runtimestate.Compiler, store *runtimestate.MemoryRuntimeStateStore, tenant runtimecontent.TenantID, principal runtimecontent.PrincipalID, now time.Time) (agentruntime.SessionID, agentruntime.TurnID, runtimestate.ToolExecutionRecord, []byte) {
	t.Helper()
	approved := createApprovedToolGrant(t, ctx, content, compiler, store, tenant, principal, now)
	consume, err := compiler.CompileConsumeCapabilityGrant(runtimestate.ConsumeCapabilityGrantCommand{Scope: approved.workerScope, IdempotencyKey: "consume", SessionID: approved.sessionID, TurnID: approved.turnID, ToolCallID: approved.toolCallID, GrantID: approved.grantID, PolicyRevisionDigest: approved.digest})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, consume); err != nil {
		t.Fatal(err)
	}
	begin, err := compiler.CompileBeginToolExecution(runtimestate.BeginToolExecutionCommand{Scope: approved.workerScope, IdempotencyKey: "begin", SessionID: approved.sessionID, TurnID: approved.turnID, ToolCallID: approved.toolCallID, GrantID: approved.grantID, OperationID: "op_tool_000000000001"})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := store.Apply(ctx, begin)
	if err != nil {
		t.Fatal(err)
	}
	for _, execution := range plan.State().ToolExecutions {
		if execution.OperationID == "op_tool_000000000001" {
			return approved.sessionID, approved.turnID, execution, approved.descriptor
		}
	}
	t.Fatal("begin tool execution did not retain an execution record")
	return "", "", runtimestate.ToolExecutionRecord{}, nil
}

type approvedToolGrant struct {
	sessionID   agentruntime.SessionID
	turnID      agentruntime.TurnID
	toolCallID  string
	grantID     string
	digest      string
	descriptor  []byte
	workerScope runtimestate.MutationScope
}

func createApprovedToolGrant(t *testing.T, ctx context.Context, content *runtimecontent.Store, compiler *runtimestate.Compiler, store *runtimestate.MemoryRuntimeStateStore, tenant runtimecontent.TenantID, principal runtimecontent.PrincipalID, now time.Time) approvedToolGrant {
	t.Helper()
	body, err := content.StageAgentSpecificationBody(ctx, tenant, runtimecontent.AgentSpecificationBody{Name: "tool-worker", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "register", Specification: body})
	if err != nil {
		t.Fatal(err)
	}
	registration, err := store.Apply(ctx, registered)
	if err != nil {
		t.Fatal(err)
	}
	created, err := compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}, IdempotencyKey: "session", RevisionID: registration.Result().Revision.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	sessionPlan, err := store.Apply(ctx, created)
	if err != nil {
		t.Fatal(err)
	}
	input, err := content.StageInputEnvelope(ctx, tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "run approved tool"}})
	if err != nil {
		t.Fatal(err)
	}
	admit, err := compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}, IdempotencyKey: "input", SessionID: sessionPlan.Result().Session.SessionID, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := store.Apply(ctx, admit)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := []byte("approved immutable tool action")
	staged, err := content.StageToolActionDescriptor(ctx, tenant, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	workerScope := runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}
	intent, err := compiler.CompileRecordToolIntent(runtimestate.RecordToolIntentCommand{Scope: workerScope, IdempotencyKey: "tool-intent", SessionID: sessionPlan.Result().Session.SessionID, TurnID: accepted.Result().Turn.TurnID, ToolCallID: "tcall_1234567890ABCDEF", ToolName: "sandbox", ActionDigest: digest, PolicyRevisionDigest: digest, Descriptor: staged})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, intent); err != nil {
		t.Fatal(err)
	}
	request, err := compiler.CompileRequestApproval(runtimestate.RequestApprovalCommand{Scope: workerScope, IdempotencyKey: "approval", SessionID: sessionPlan.Result().Session.SessionID, TurnID: accepted.Result().Turn.TurnID, ToolCallID: "tcall_1234567890ABCDEF", ApprovalID: "appr_1234567890ABCDEF", ActionDigest: digest, PolicyRevisionDigest: digest, CapabilityDigest: digest, MaximumUses: 1, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, request); err != nil {
		t.Fatal(err)
	}
	decision, err := compiler.CompileDecideApproval(runtimestate.DecideApprovalCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}, IdempotencyKey: "decision", ApprovalID: "appr_1234567890ABCDEF", Decision: "approved"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, decision); err != nil {
		t.Fatal(err)
	}
	state, err := store.LoadRuntimeState(ctx, workerScope)
	if err != nil || len(state.Grants) != 1 {
		t.Fatalf("approved capability grant = %#v, %v", state.Grants, err)
	}
	return approvedToolGrant{sessionID: sessionPlan.Result().Session.SessionID, turnID: accepted.Result().Turn.TurnID, toolCallID: "tcall_1234567890ABCDEF", grantID: state.Grants[0].GrantID, digest: digest, descriptor: descriptor, workerScope: workerScope}
}

func toolOutbox(t *testing.T, ctx context.Context, store *runtimestate.MemoryRuntimeStateStore, tenant runtimecontent.TenantID) runtimestate.OutboxRecord {
	t.Helper()
	page, err := store.ReadOutbox(ctx, runtimestate.OutboxQuery{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher}, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range page.Records {
		if record.ToolCallID != "" && record.EventKind == "" {
			return record
		}
	}
	t.Fatalf("tool outbox = %#v, want tool intent", page.Records)
	return runtimestate.OutboxRecord{}
}

type recordingAdapter struct {
	response             runtimetool.Response
	executes, reconciles int
	last                 runtimetool.Request
}

func (adapter *recordingAdapter) Execute(_ context.Context, request runtimetool.Request) (runtimetool.Response, error) {
	adapter.executes++
	adapter.last = request
	return adapter.response, nil
}
func (adapter *recordingAdapter) Reconcile(_ context.Context, request runtimetool.Request) (runtimetool.Response, error) {
	adapter.reconciles++
	adapter.last = request
	return adapter.response, nil
}

type toolObjects struct{ values map[string][]byte }

func (objects *toolObjects) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	if _, ok := objects.values[key]; ok {
		return false, nil
	}
	objects.values[key] = append([]byte(nil), value...)
	return true, nil
}
func (objects *toolObjects) Get(_ context.Context, key string, _ int) ([]byte, error) {
	return append([]byte(nil), objects.values[key]...), nil
}

type toolIDs struct{ next uint64 }

func (ids *toolIDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	ids.next++
	return fmt.Sprintf("%s_%016d", kind, ids.next), nil
}

type temporalPublisher struct {
	starts   []runtimeorchestration.SessionStart
	commands []runtimeorchestration.Command
}

func (publisher *temporalPublisher) StartSession(_ context.Context, start runtimeorchestration.SessionStart) error {
	publisher.starts = append(publisher.starts, start)
	return nil
}
func (publisher *temporalPublisher) SignalSession(_ context.Context, _ runtimeorchestration.SessionStart, command runtimeorchestration.Command) error {
	publisher.commands = append(publisher.commands, command)
	return nil
}

type sandboxClient struct {
	operation            sandbox.Operation
	submits, waits, gets int
}

func (client *sandboxClient) Submit(_ context.Context, request sandbox.OperationRequest) (sandbox.OperationRef, error) {
	client.submits++
	return sandbox.OperationRef{ID: request.ID}, nil
}
func (client *sandboxClient) GetOperation(context.Context, sandbox.OperationID) (sandbox.Operation, error) {
	client.gets++
	return client.operation, nil
}
func (client *sandboxClient) WaitOperation(context.Context, sandbox.OperationID) (sandbox.Operation, error) {
	client.waits++
	return client.operation, nil
}
func (client *sandboxClient) WatchOperation(context.Context, sandbox.OperationID, sandbox.OperationCursor) (sandbox.OperationStream, error) {
	return nil, errors.New("not used")
}
func (client *sandboxClient) GetSandbox(context.Context, sandbox.SandboxID) (sandbox.SandboxInfo, error) {
	return sandbox.SandboxInfo{}, errors.New("not used")
}
func (client *sandboxClient) GetProcess(context.Context, sandbox.ProcessID) (sandbox.ProcessInfo, error) {
	return sandbox.ProcessInfo{}, errors.New("not used")
}
func (client *sandboxClient) ReplayOutput(context.Context, sandbox.ProcessID, sandbox.OutputCursor) (sandbox.OutputStream, error) {
	return nil, errors.New("not used")
}
func (client *sandboxClient) GetVolume(context.Context, sandbox.VolumeID) (sandbox.VolumeInfo, error) {
	return sandbox.VolumeInfo{}, errors.New("not used")
}
func (client *sandboxClient) ListVolumes(context.Context, sandbox.Page) (sandbox.VolumePage, error) {
	return sandbox.VolumePage{}, errors.New("not used")
}
func (client *sandboxClient) GetSnapshot(context.Context, sandbox.SnapshotID) (sandbox.SnapshotInfo, error) {
	return sandbox.SnapshotInfo{}, errors.New("not used")
}
func (client *sandboxClient) ListSnapshots(context.Context, sandbox.Page) (sandbox.SnapshotPage, error) {
	return sandbox.SnapshotPage{}, errors.New("not used")
}
func (client *sandboxClient) Close(context.Context) error { return nil }
