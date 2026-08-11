package runtimetool_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/mcptool"
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
		cancel      bool
		wantExecute int
		wantRecon   int
		wantState   runtimestate.ToolExecutionState
	}{
		{name: "new descriptor executes once", wantExecute: 1, wantState: runtimestate.ToolExecutionSucceeded},
		{name: "lost claim reconciles without reexecution", recovering: true, wantRecon: 1, wantState: runtimestate.ToolExecutionSucceeded},
		{name: "corrupt descriptor is refused before execution", corrupt: true, wantState: runtimestate.ToolExecutionFailed},
		{name: "missing descriptor is refused before execution", missing: true, wantState: runtimestate.ToolExecutionFailed},
		{name: "cancelled execution intent is finalized without dispatch", cancel: true, wantState: runtimestate.ToolExecutionFailed},
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
			if test.cancel {
				cancel, err := compiler.CompileCancelTurn(runtimestate.CancelTurnCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}, IdempotencyKey: "cancel-intended-tool", SessionID: session, TurnID: turn})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = store.Apply(ctx, cancel); err != nil {
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
			if !test.corrupt && !test.missing && !test.cancel && (!bytes.Equal(adapter.last.Descriptor, descriptor) || adapter.last.SessionID != session || adapter.last.TurnID != turn || adapter.last.OperationID != execution.OperationID) {
				t.Fatalf("adapter request = %#v, want authorized descriptor and exact operation provenance", adapter.last)
			}
			state, err := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityRuntimeWorker})
			if err != nil {
				t.Fatal(err)
			}
			if len(state.ToolExecutions) != 1 || state.ToolExecutions[0].State != test.wantState {
				t.Fatalf("tool execution state = %#v, want %s", state.ToolExecutions, test.wantState)
			}
			if !test.cancel {
				wantTurn := agentruntime.TurnSucceeded
				if test.wantState != runtimestate.ToolExecutionSucceeded {
					wantTurn = agentruntime.TurnFailed
				}
				if len(state.Turns) != 1 || state.Turns[0].State != wantTurn {
					t.Fatalf("terminal tool outcome left Turn = %#v, want %s", state.Turns, wantTurn)
				}
			}
			if test.corrupt && (state.ToolExecutions[0].Failure == nil || state.ToolExecutions[0].Failure.Message != "verified tool action descriptor is invalid") {
				t.Fatalf("corrupt descriptor outcome = %#v", state.ToolExecutions[0])
			}
			if test.cancel && (state.ToolExecutions[0].Failure == nil || state.ToolExecutions[0].Failure.Message != "tool execution is no longer authorized" || state.Grants[0].RevokedAt == nil) {
				t.Fatalf("cancelled tool outcome = %#v grants=%#v", state.ToolExecutions[0], state.Grants)
			}
			if !test.corrupt && !test.missing && !test.cancel && (len(state.Artifacts) != 1 || state.ToolExecutions[0].Result == nil || state.Artifacts[0].Reference != *state.ToolExecutions[0].Result) {
				t.Fatalf("tool output must be owner-readable artifact = artifacts=%#v execution=%#v", state.Artifacts, state.ToolExecutions[0])
			}
			if !test.corrupt && !test.missing && !test.cancel && !hasAuditKind(state.Audit, "capability_grant.exhausted") {
				t.Fatalf("terminal max-use grant lacks exhausted audit: %#v", state.Audit)
			}
			foundFinalizationEvent := false
			for _, event := range state.Events {
				if event.Kind == agentruntime.EventSandboxOperationFinalized && event.OperationID == execution.OperationID {
					foundFinalizationEvent = true
					break
				}
			}
			if !foundFinalizationEvent {
				t.Fatalf("tool terminal events = %#v, want durable sandbox finalization", state.Events)
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

func TestWorkerRedactsCredentialShapedOutputBeforeArtifactPersistence(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	objects := &toolObjects{values: map[string][]byte{}}
	content, _ := runtimecontent.New("runtime-content", objects)
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("principal-a")
	compiler, _ := runtimestate.NewCompiler(content)
	source, _ := clock.NewFake(now)
	planner, _ := runtimestate.NewRuntimeStatePlanner(source, &toolIDs{})
	store, _ := runtimestate.NewMemoryRuntimeStateStore(planner)
	createToolExecution(t, ctx, content, compiler, store, tenant, principal, now)
	worker, err := runtimetool.NewWorker(runtimetool.Config{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: &recordingAdapter{response: runtimetool.Response{Output: []byte("token=real-secret password:another")}}, Claimer: "tool-worker"})
	if err != nil || worker.ScanOnce(ctx) != nil {
		t.Fatalf("finalize redacted output: %v", err)
	}
	for _, value := range objects.values {
		if bytes.Contains(value, []byte("real-secret")) || bytes.Contains(value, []byte("another")) {
			t.Fatalf("credential leaked to object: %q", value)
		}
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
	for _, test := range []struct {
		name                   string
		recoverLostClaim       bool
		wantSubmits, wantWaits int
		wantGets               int
	}{
		{name: "fresh intent submits once", wantSubmits: 1, wantWaits: 1},
		{name: "lost claim observes existing operation", recoverLostClaim: true, wantGets: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
			descriptor, err := sandbox.EncodeControlOperationRequest(sandbox.OperationRequest{ID: "op_tool_000000000001", Kind: sandbox.OperationCloseSandbox, CloseSandbox: &sandbox.CloseSandboxRequest{SandboxID: "sbx_tool_000000000001"}})
			if err != nil {
				t.Fatal(err)
			}
			client := &sandboxClient{operation: sandbox.Operation{Ref: sandbox.OperationRef{ID: "op_tool_000000000001"}, State: sandbox.OperationSucceeded, Result: &sandbox.OperationResult{Kind: sandbox.ResultControl, Control: &sandbox.ControlResult{Action: sandbox.ControlClosed}}}}
			adapter, err := runtimetool.NewSandboxAdapter(client)
			if err != nil {
				t.Fatal(err)
			}
			objects := &toolObjects{values: map[string][]byte{}}
			content, _ := runtimecontent.New("runtime-content", objects)
			tenant, _ := runtimecontent.ParseTenantID("tenant-a")
			principal, _ := runtimecontent.ParsePrincipalID("principal-a")
			compiler, _ := runtimestate.NewCompiler(content)
			source, _ := clock.NewFake(now)
			planner, _ := runtimestate.NewRuntimeStatePlanner(source, &toolIDs{})
			store, _ := runtimestate.NewMemoryRuntimeStateStore(planner)
			_, _, execution, _ := createToolExecutionWithDescriptor(t, ctx, content, compiler, store, tenant, principal, now, descriptor)
			if test.recoverLostClaim {
				expireToolOutboxClaim(t, ctx, compiler, store, source, tenant, now, "lost-sandbox-claim")
			}
			worker, err := runtimetool.NewWorker(runtimetool.Config{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: adapter, Claimer: "tool-worker"})
			if err != nil || worker.ScanOnce(ctx) != nil || client.submits != test.wantSubmits || client.waits != test.wantWaits || client.gets != test.wantGets {
				t.Fatalf("brokered sandbox calls submit=%d wait=%d get=%d err=%v", client.submits, client.waits, client.gets, err)
			}
			if test.recoverLostClaim && (client.gotID != sandbox.OperationID(execution.OperationID) || client.submits != 0) {
				t.Fatalf("lost sandbox claim got operation=%q submits=%d, want %q and no resubmit", client.gotID, client.submits, execution.OperationID)
			}
			for _, invalid := range []runtimetool.Request{
				{OperationID: "op_tool_000000000001", Descriptor: []byte("not sandbox.control/v1")},
				{OperationID: "op_other_000000000001", Descriptor: descriptor},
			} {
				response, err := adapter.Execute(context.Background(), invalid)
				if err != nil || response.Failure == nil || response.Failure.Code != agentruntime.FailureInvalidInput || client.submits != test.wantSubmits {
					t.Fatalf("invalid descriptor execution = %#v, calls=%d, err=%v", response, client.submits, err)
				}
			}
		})
	}
}

func TestMCPAdapterExecutesOnlyThroughWorkerAndReconcilesWithoutResubmit(t *testing.T) {
	schema := []byte(`{"type":"object","properties":{"operation_id":{"type":"string"}},"required":["operation_id"],"additionalProperties":false}`)
	var decodedSchema any
	if err := json.Unmarshal(schema, &decodedSchema); err != nil {
		t.Fatal(err)
	}
	canonicalSchema, err := json.Marshal(decodedSchema)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonicalSchema)
	schemaDigest := "sha256:" + hex.EncodeToString(digest[:])
	var effectCalls, statusCalls int
	var statusOperationID string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var message struct {
			ID, Method string
			Params     json.RawMessage `json:"params"`
		}
		if json.NewDecoder(request.Body).Decode(&message) != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		switch message.Method {
		case "initialize":
			response.Header().Set("MCP-Session-Id", "session-worker")
			json.NewEncoder(response).Encode(map[string]any{"jsonrpc": "2.0", "id": message.ID, "result": map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{"tools": map[string]any{}}}})
		case "notifications/initialized":
			response.WriteHeader(http.StatusAccepted)
		case "tools/list":
			json.NewEncoder(response).Encode(map[string]any{"jsonrpc": "2.0", "id": message.ID, "result": map[string]any{"tools": []any{map[string]any{"name": "effect", "inputSchema": json.RawMessage(schema)}, map[string]any{"name": "status", "inputSchema": json.RawMessage(schema)}}}})
		case "tools/call":
			var call struct {
				Name      string `json:"name"`
				Arguments struct {
					OperationID string `json:"operation_id"`
				} `json:"arguments"`
			}
			if err := json.Unmarshal(message.Params, &call); err != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			switch call.Name {
			case "effect":
				effectCalls++
				json.NewEncoder(response).Encode(map[string]any{"jsonrpc": "2.0", "id": message.ID, "result": map[string]any{"content": []any{map[string]string{"type": "text", "text": "completed"}}}})
			case "status":
				statusCalls++
				statusOperationID = call.Arguments.OperationID
				json.NewEncoder(response).Encode(map[string]any{"jsonrpc": "2.0", "id": message.ID, "result": map[string]any{"content": []any{map[string]string{"type": "text", "text": "reconciled"}}, "structuredContent": map[string]string{"operation_id": call.Arguments.OperationID, "state": "succeeded"}}})
			default:
				response.WriteHeader(http.StatusBadRequest)
			}
		default:
			response.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	for _, test := range []struct {
		name                       string
		recoverLostClaim           bool
		wantEffect, wantStatusCall int
	}{
		{name: "fresh intent calls configured effect", wantEffect: 1},
		{name: "lost claim calls configured status", recoverLostClaim: true, wantStatusCall: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			effectCalls, statusCalls, statusOperationID = 0, 0, ""
			adapter, err := runtimetool.NewMCPAdapter(mcptool.Config{Servers: []mcptool.ServerConfig{{ID: "configured", Endpoint: server.URL + "/mcp", Credentials: adapterCredentials{}, Tools: []mcptool.ToolConfig{{Name: "effect", InputSchemaDigest: schemaDigest, OperationIDArgument: "operation_id"}, {Name: "status", InputSchemaDigest: schemaDigest, OperationIDArgument: "operation_id"}}, ReconcileTool: "status", ReconcileOperationArgument: "operation_id"}}, RequestTimeout: time.Second, CancelTimeout: time.Second, AllowInsecureLoopbackTests: true})
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
			objects := &toolObjects{values: map[string][]byte{}}
			content, _ := runtimecontent.New("runtime-content", objects)
			tenant, _ := runtimecontent.ParseTenantID("tenant-a")
			principal, _ := runtimecontent.ParsePrincipalID("principal-a")
			compiler, _ := runtimestate.NewCompiler(content)
			source, _ := clock.NewFake(now)
			planner, _ := runtimestate.NewRuntimeStatePlanner(source, &toolIDs{})
			store, _ := runtimestate.NewMemoryRuntimeStateStore(planner)
			descriptor := []byte(`{"version":"mcp.tool/v1","server_id":"configured","tool_name":"effect","arguments":{}}`)
			_, _, execution, _ := createToolExecutionWithDescriptor(t, ctx, content, compiler, store, tenant, principal, now, descriptor)
			if test.recoverLostClaim {
				expireToolOutboxClaim(t, ctx, compiler, store, source, tenant, now, "lost-mcp-claim")
			}
			worker, err := runtimetool.NewWorker(runtimetool.Config{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: adapter, Claimer: "tool-worker"})
			if err != nil || worker.ScanOnce(ctx) != nil || effectCalls != test.wantEffect || statusCalls != test.wantStatusCall {
				t.Fatalf("brokered MCP calls effect=%d status=%d err=%v", effectCalls, statusCalls, err)
			}
			if test.recoverLostClaim && (statusOperationID != string(execution.OperationID) || effectCalls != 0) {
				t.Fatalf("lost MCP claim status operation=%q effect calls=%d, want %q and no effect resubmit", statusOperationID, effectCalls, execution.OperationID)
			}
		})
	}
}

func TestBuiltinAdapterReconcilesLostWorkerClaimWithoutResubmitting(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	objects := &toolObjects{values: map[string][]byte{}}
	content, _ := runtimecontent.New("runtime-content", objects)
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("principal-a")
	compiler, _ := runtimestate.NewCompiler(content)
	source, _ := clock.NewFake(now)
	planner, _ := runtimestate.NewRuntimeStatePlanner(source, &toolIDs{})
	store, _ := runtimestate.NewMemoryRuntimeStateStore(planner)
	_, _, _, _ = createToolExecution(t, ctx, content, compiler, store, tenant, principal, now)
	record := toolOutbox(t, ctx, store, tenant)
	claim, err := compiler.CompileClaimOutbox(runtimestate.ClaimOutboxCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher}, IdempotencyKey: "lost-builtin-claim", OutboxID: record.OutboxID, ExpectedVersion: record.Version, Claimer: "lost", ClaimUntil: now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Apply(ctx, claim); err != nil {
		t.Fatal(err)
	}
	if err = source.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	inner := &builtinContractAdapter{contract: runtimetool.ExternalEffectContract{IdempotencyKey: "operation_id", Reconciles: true}}
	adapter, err := runtimetool.NewBuiltinAdapter(inner)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := runtimetool.NewWorker(runtimetool.Config{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: adapter, Claimer: "tool-worker"})
	if err != nil || worker.ScanOnce(ctx) != nil {
		t.Fatalf("recover builtin claim: %v", err)
	}
	if inner.executions != 0 || inner.reconciliations != 1 || inner.last.OperationID == "" {
		t.Fatalf("builtin calls execute=%d reconcile=%d request=%#v", inner.executions, inner.reconciliations, inner.last)
	}
}

func createToolExecution(t *testing.T, ctx context.Context, content *runtimecontent.Store, compiler *runtimestate.Compiler, store *runtimestate.MemoryRuntimeStateStore, tenant runtimecontent.TenantID, principal runtimecontent.PrincipalID, now time.Time) (agentruntime.SessionID, agentruntime.TurnID, runtimestate.ToolExecutionRecord, []byte) {
	return createToolExecutionWithDescriptor(t, ctx, content, compiler, store, tenant, principal, now, []byte("approved immutable tool action"))
}

func createToolExecutionWithDescriptor(t *testing.T, ctx context.Context, content *runtimecontent.Store, compiler *runtimestate.Compiler, store *runtimestate.MemoryRuntimeStateStore, tenant runtimecontent.TenantID, principal runtimecontent.PrincipalID, now time.Time, descriptor []byte) (agentruntime.SessionID, agentruntime.TurnID, runtimestate.ToolExecutionRecord, []byte) {
	t.Helper()
	approved := createApprovedToolGrantWithDescriptor(t, ctx, content, compiler, store, tenant, principal, now, descriptor)
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

func expireToolOutboxClaim(t *testing.T, ctx context.Context, compiler *runtimestate.Compiler, store *runtimestate.MemoryRuntimeStateStore, source *clock.Fake, tenant runtimecontent.TenantID, now time.Time, idempotencyKey string) {
	t.Helper()
	record := toolOutbox(t, ctx, store, tenant)
	claim, err := compiler.CompileClaimOutbox(runtimestate.ClaimOutboxCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher}, IdempotencyKey: idempotencyKey, OutboxID: record.OutboxID, ExpectedVersion: record.Version, Claimer: "lost-tool-worker", ClaimUntil: now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Apply(ctx, claim); err != nil {
		t.Fatal(err)
	}
	if err = source.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
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
	return createApprovedToolGrantWithDescriptor(t, ctx, content, compiler, store, tenant, principal, now, []byte("approved immutable tool action"))
}

func createApprovedToolGrantWithDescriptor(t *testing.T, ctx context.Context, content *runtimecontent.Store, compiler *runtimestate.Compiler, store *runtimestate.MemoryRuntimeStateStore, tenant runtimecontent.TenantID, principal runtimecontent.PrincipalID, now time.Time, descriptor []byte) approvedToolGrant {
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
	request, err := compiler.CompileRequestApproval(runtimestate.RequestApprovalCommand{Scope: workerScope, IdempotencyKey: "approval", SessionID: sessionPlan.Result().Session.SessionID, TurnID: accepted.Result().Turn.TurnID, ToolCallID: "tcall_1234567890ABCDEF", ApprovalID: "appr_1234567890ABCDEF", ActionDigest: digest, PolicyRevisionDigest: digest, CapabilityDigest: digest, ActionVerb: "write", ActionTarget: "workspace-service", MaximumUses: 1, ExpiresAt: now.Add(time.Hour)})
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

func (adapter *recordingAdapter) ExternalEffectContract() runtimetool.ExternalEffectContract {
	return runtimetool.ExternalEffectContract{IdempotencyKey: "operation_id", Reconciles: true}
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
	operation                    sandbox.Operation
	submits, waits, gets         int
	submittedID, waitedID, gotID sandbox.OperationID
}

func (client *sandboxClient) Submit(_ context.Context, request sandbox.OperationRequest) (sandbox.OperationRef, error) {
	client.submits++
	client.submittedID = request.ID
	return sandbox.OperationRef{ID: request.ID}, nil
}
func (client *sandboxClient) GetOperation(_ context.Context, operationID sandbox.OperationID) (sandbox.Operation, error) {
	client.gets++
	client.gotID = operationID
	return client.operation, nil
}
func (client *sandboxClient) WaitOperation(_ context.Context, operationID sandbox.OperationID) (sandbox.Operation, error) {
	client.waits++
	client.waitedID = operationID
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
