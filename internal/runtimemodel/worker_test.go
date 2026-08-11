package runtimemodel_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimemodel"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestWorkerFinalizesNewAndRecoveredModelIntentsWithoutBlindReinvoke(t *testing.T) {
	for _, test := range []struct {
		name       string
		recovering bool
		wantInvoke int
		wantRecon  int
		adapterErr error
		wantState  runtimestate.InvocationState
		wantTurn   agentruntime.TurnState
	}{
		{name: "new intent invokes once", wantInvoke: 1, wantState: runtimestate.InvocationSucceeded, wantTurn: agentruntime.TurnSucceeded},
		{name: "expired claim reconciles without invoke", recovering: true, wantRecon: 1, wantState: runtimestate.InvocationSucceeded, wantTurn: agentruntime.TurnSucceeded},
		{name: "unknown provider failure finalizes uncertainty", wantInvoke: 1, adapterErr: errors.New("provider credential and transport details"), wantState: runtimestate.InvocationUncertain, wantTurn: agentruntime.TurnFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
			content, err := runtimecontent.New("runtime-content", &modelObjects{values: map[string][]byte{}})
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
			planner, err := runtimestate.NewRuntimeStatePlanner(source, &modelIDs{})
			if err != nil {
				t.Fatal(err)
			}
			store, err := runtimestate.NewMemoryRuntimeStateStore(planner)
			if err != nil {
				t.Fatal(err)
			}
			session, turn, invocation := createModelIntent(t, ctx, content, compiler, store, tenant, principal)
			if test.recovering {
				record := invocationOutbox(t, ctx, store, tenant)
				claim, err := compiler.CompileClaimOutbox(runtimestate.ClaimOutboxCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher}, IdempotencyKey: "prior-model-claim", OutboxID: record.OutboxID, ExpectedVersion: record.Version, Claimer: "lost-model-worker", ClaimUntil: now.Add(time.Minute)})
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
			adapter := &recordingAdapter{response: runtimemodel.Response{Output: []byte("normalized model result")}, err: test.adapterErr}
			worker, err := runtimemodel.NewWorker(runtimemodel.WorkerConfig{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: adapter, Claimer: "model-worker"})
			if err != nil {
				t.Fatal(err)
			}
			if err := worker.ScanOnce(ctx); err != nil {
				t.Fatalf("scan model intent: %v", err)
			}
			if adapter.invocations != test.wantInvoke || adapter.reconciliations != test.wantRecon || adapter.last.OperationID != invocation.OperationID {
				t.Fatalf("adapter calls = invoke=%d reconcile=%d request=%#v", adapter.invocations, adapter.reconciliations, adapter.last)
			}
			state, err := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityRuntimeWorker})
			if err != nil {
				t.Fatal(err)
			}
			if len(state.Invocations) != 1 || state.Invocations[0].State != test.wantState || (test.wantState == runtimestate.InvocationSucceeded && state.Invocations[0].Result == nil) || (test.wantState == runtimestate.InvocationUncertain && (state.Invocations[0].Failure == nil || state.Invocations[0].Failure.Message != "model invocation outcome is uncertain")) || len(state.Turns) != 1 || state.Turns[0].TurnID != turn || state.Turns[0].State != test.wantTurn || state.Sessions[0].SessionID != session {
				t.Fatalf("final durable model state = %#v", state)
			}
			if test.wantState == runtimestate.InvocationUncertain && (len(state.Events) < 2 || state.Events[len(state.Events)-2].Kind != agentruntime.EventProducerGap || state.Events[len(state.Events)-1].Kind != agentruntime.EventTurnFailed) {
				t.Fatalf("uncertain producer events = %#v, want ordered explicit gap then finalization", state.Events)
			}
			if record := invocationOutbox(t, ctx, store, tenant); record.State != runtimestate.OutboxPublished {
				t.Fatalf("invocation outbox = %#v, want acknowledged after finalization", record)
			}
			if err := worker.ScanOnce(ctx); err != nil {
				t.Fatalf("rescan model intent: %v", err)
			}
			if adapter.invocations != test.wantInvoke || adapter.reconciliations != test.wantRecon {
				t.Fatalf("published intent reexecuted: invoke=%d reconcile=%d", adapter.invocations, adapter.reconciliations)
			}
		})
	}
}

func createModelIntent(t *testing.T, ctx context.Context, content *runtimecontent.Store, compiler *runtimestate.Compiler, store *runtimestate.MemoryRuntimeStateStore, tenant runtimecontent.TenantID, principal runtimecontent.PrincipalID) (agentruntime.SessionID, agentruntime.TurnID, runtimestate.InvocationRecord) {
	t.Helper()
	body, err := content.StageAgentSpecificationBody(ctx, tenant, runtimecontent.AgentSpecificationBody{Name: "model-worker", ModelProfile: "balanced", Instructions: "safe"})
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
	input, err := content.StageInputEnvelope(ctx, tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "hello"}})
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
	begin, err := compiler.CompileBeginInvocationAttempt(runtimestate.BeginInvocationAttemptCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "model-intent", SessionID: sessionPlan.Result().Session.SessionID, TurnID: accepted.Result().Turn.TurnID, OperationID: "model-operation-1", ExpectedSessionVersion: accepted.Result().Session.Version, ExpectedTurnVersion: accepted.Result().Turn.Version})
	if err != nil {
		t.Fatal(err)
	}
	intent, err := store.Apply(ctx, begin)
	if err != nil {
		t.Fatal(err)
	}
	return sessionPlan.Result().Session.SessionID, accepted.Result().Turn.TurnID, intent.Result().Invocation
}

func invocationOutbox(t *testing.T, ctx context.Context, store *runtimestate.MemoryRuntimeStateStore, tenant runtimecontent.TenantID) runtimestate.OutboxRecord {
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
	t.Fatalf("invocation outbox = %#v, want one invocation intent", page.Records)
	return runtimestate.OutboxRecord{}
}

type recordingAdapter struct {
	response        runtimemodel.Response
	invocations     int
	reconciliations int
	last            runtimemodel.Request
	err             error
}

func (adapter *recordingAdapter) Invoke(_ context.Context, request runtimemodel.Request) (runtimemodel.Response, error) {
	adapter.invocations++
	adapter.last = request
	return adapter.response, adapter.err
}

func (adapter *recordingAdapter) Reconcile(_ context.Context, request runtimemodel.Request) (runtimemodel.Response, error) {
	adapter.reconciliations++
	adapter.last = request
	return adapter.response, adapter.err
}

type modelObjects struct{ values map[string][]byte }

func (objects *modelObjects) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	if _, exists := objects.values[key]; exists {
		return false, nil
	}
	objects.values[key] = append([]byte(nil), value...)
	return true, nil
}

func (objects *modelObjects) Get(_ context.Context, key string, _ int) ([]byte, error) {
	return append([]byte(nil), objects.values[key]...), nil
}

type modelIDs struct{ next uint64 }

func (ids *modelIDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	ids.next++
	return fmt.Sprintf("%s_%016d", kind, ids.next), nil
}
