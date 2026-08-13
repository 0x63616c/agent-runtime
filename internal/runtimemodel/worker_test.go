package runtimemodel_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/providers/codexsubscription"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimemodel"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	"github.com/0x63616c/agent-runtime/internal/runtimetool"
	"github.com/0x63616c/agent-runtime/internal/subscriptioncanary"
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
			inputTokens := uint64(17)
			adapter := &recordingAdapter{response: runtimemodel.Response{Output: []byte("normalized model result"), Usage: &runtimestate.ModelUsage{InputTokens: &inputTokens}}, err: test.adapterErr}
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
			if adapter.last.ModelProfile != "balanced" {
				t.Fatalf("adapter request model profile = %q, want revision-pinned balanced", adapter.last.ModelProfile)
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
			if test.wantState == runtimestate.InvocationSucceeded && (state.Invocations[0].Usage == nil || state.Invocations[0].Usage.InputTokens == nil || *state.Invocations[0].Usage.InputTokens != inputTokens || state.Invocations[0].Usage.OutputTokens != nil) {
				t.Fatalf("model usage = %#v, want provider-neutral reported input and unknown output", state.Invocations[0].Usage)
			}
			if test.wantState == runtimestate.InvocationSucceeded && (len(state.Artifacts) != 1 || state.Invocations[0].Result == nil || state.Artifacts[0].Reference != *state.Invocations[0].Result || state.Artifacts[0].SessionID != session || state.Artifacts[0].TurnID != turn) {
				t.Fatalf("finalized model output = artifacts=%#v invocation=%#v, want one owner-bound immutable artifact", state.Artifacts, state.Invocations[0])
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

func TestWorkerCancellationLeavesClaimedInvocationForExactRecovery(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	content, err := runtimecontent.New("runtime-content", &modelObjects{values: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("principal-a")
	compiler, _ := runtimestate.NewCompiler(content)
	source, _ := clock.NewFake(now)
	planner, _ := runtimestate.NewRuntimeStatePlanner(source, &modelIDs{})
	store, _ := runtimestate.NewMemoryRuntimeStateStore(planner)
	_, _, invocation := createModelIntent(t, context.Background(), content, compiler, store, tenant, principal)

	ctx, cancel := context.WithCancel(context.Background())
	adapter := &cancellingAdapter{cancel: cancel}
	worker, err := runtimemodel.NewWorker(runtimemodel.WorkerConfig{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: adapter, Claimer: "model-worker"})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.ScanOnce(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("scan cancelled model intent = %v, want context cancellation", err)
	}
	if adapter.invocations != 1 || adapter.reconciliations != 0 {
		t.Fatalf("adapter calls = invoke=%d reconcile=%d", adapter.invocations, adapter.reconciliations)
	}
	state, err := store.LoadRuntimeState(context.Background(), runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityRuntimeWorker})
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Invocations) != 1 || state.Invocations[0].OperationID != invocation.OperationID || state.Invocations[0].State != runtimestate.InvocationIntent || state.Invocations[0].Failure != nil {
		t.Fatalf("cancelled invocation was finalized = %#v", state.Invocations)
	}
	if record := invocationOutbox(t, context.Background(), store, tenant); record.State != runtimestate.OutboxClaimed || record.ClaimUntil == nil {
		t.Fatalf("cancelled invocation outbox = %#v, want retained claimed record", record)
	}
}

func TestSubscriptionCanarySemanticE2ECancelsThenReconcilesWithoutOpaqueValues(t *testing.T) {
	const capability = "opaque-capability-value-must-never-persist"
	const credential = "opaque-credential-value-must-never-persist"
	values := map[string]string{
		"AR_SUBSCRIPTION_CANARY_CAPABILITY_ENV": "SUBSCRIPTION_CANARY_CAPABILITY",
		"AR_SUBSCRIPTION_CANARY_CREDENTIAL_ENV": "SUBSCRIPTION_CANARY_CREDENTIAL",
		"SUBSCRIPTION_CANARY_CAPABILITY":        capability,
		"SUBSCRIPTION_CANARY_CREDENTIAL":        credential,
		"AR_SUBSCRIPTION_CANARY_MODEL_PROFILE":  "balanced",
		"AR_SUBSCRIPTION_CANARY_REVISION":       "abcdef0123456789abcdef0123456789abcdef01",
		"AR_SUBSCRIPTION_CANARY_TIMEOUT":        "30s",
		"AR_SUBSCRIPTION_CANARY_CANCEL_MODE":    "explicit-cancel",
		"AR_SUBSCRIPTION_CANARY_RECOVERY_MODE":  "reconcile-on-restart",
	}
	config, err := subscriptioncanary.Load(func(name string) (string, bool) { value, found := values[name]; return value, found })
	if err != nil {
		t.Fatalf("load subscription canary preflight: %v", err)
	}
	assertNoOpaqueCanaryValues(t, []byte(fmt.Sprintf("%#v", config)), capability, credential)

	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	lifecycle := codexsubscription.NewLifecycle()
	reference := codexsubscription.CredentialContextRef("canary-context")
	if _, err := lifecycle.Register(reference, now); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.BeginLogin(reference, now); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.CompleteLogin(reference, codexsubscription.LifecycleReady, now); err != nil {
		t.Fatal(err)
	}
	status, err := lifecycle.Status(reference)
	if err != nil {
		t.Fatal(err)
	}
	assertNoOpaqueCanaryValues(t, []byte(fmt.Sprintf("%#v", status)), capability, credential)

	ctx := context.Background()
	objects := &modelObjects{values: map[string][]byte{}}
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
	planner, err := runtimestate.NewRuntimeStatePlanner(source, &modelIDs{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := runtimestate.NewMemoryRuntimeStateStore(planner)
	if err != nil {
		t.Fatal(err)
	}
	_, _, invocation := createModelIntent(t, ctx, content, compiler, store, tenant, principal)

	var logs bytes.Buffer
	cancelContext, cancel := context.WithCancel(ctx)
	provider := &canarySemanticAdapter{lifecycle: lifecycle, reference: reference, cancel: cancel, logger: slog.New(slog.NewJSONHandler(&logs, nil))}
	profile, err := runtimemodel.NewProfileAdapter(runtimemodel.ProfileAdapterConfig{Profiles: []runtimemodel.ProviderProfile{{Profile: config.ModelProfile, Provider: "subscription-fixture", Adapter: provider}}})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := runtimemodel.NewWorker(runtimemodel.WorkerConfig{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: profile, Claimer: "model-worker"})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.ScanOnce(cancelContext); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled canary invoke = %v, want context cancellation", err)
	}
	if provider.invocations != 1 || provider.reconciliations != 0 {
		t.Fatalf("cancelled canary calls = invoke=%d reconcile=%d", provider.invocations, provider.reconciliations)
	}
	if err := source.Advance(2*time.Minute + time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	restarted, err := runtimemodel.NewWorker(runtimemodel.WorkerConfig{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: profile, Claimer: "restarted-model-worker"})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.ScanOnce(ctx); err != nil {
		t.Fatalf("reconcile restarted canary: %v", err)
	}
	if provider.invocations != 1 || provider.reconciliations != 1 || provider.last.OperationID != invocation.OperationID {
		t.Fatalf("restarted canary calls = invoke=%d reconcile=%d operation=%q", provider.invocations, provider.reconciliations, provider.last.OperationID)
	}

	state, err := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityRuntimeWorker})
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Invocations) != 1 || state.Invocations[0].State != runtimestate.InvocationSucceeded {
		t.Fatalf("restarted canary invocation state = %#v", state.Invocations)
	}
	assertNoOpaqueCanaryValues(t, []byte(fmt.Sprintf("%#v", state)), capability, credential)
	assertNoOpaqueCanaryValues(t, logs.Bytes(), capability, credential)
	for key, value := range objects.values {
		assertNoOpaqueCanaryValues(t, []byte(key), capability, credential)
		assertNoOpaqueCanaryValues(t, value, capability, credential)
	}
}

func assertNoOpaqueCanaryValues(t *testing.T, value []byte, opaqueValues ...string) {
	t.Helper()
	for _, opaque := range opaqueValues {
		if bytes.Contains(value, []byte(opaque)) {
			t.Fatal("opaque canary value reached a diagnostic or persisted boundary")
		}
	}
}

func TestWorkerRoutesNormalizedModelToolThroughBrokerAndPausesTurn(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	content, _ := runtimecontent.New("runtime-content", &modelObjects{values: map[string][]byte{}})
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("principal-a")
	compiler, _ := runtimestate.NewCompiler(content)
	source, _ := clock.NewFake(now)
	planner, _ := runtimestate.NewRuntimeStatePlanner(source, &modelIDs{})
	store, _ := runtimestate.NewMemoryRuntimeStateStore(planner)
	session, turn, _ := createModelIntent(t, ctx, content, compiler, store, tenant, principal)
	policy, err := compiler.CompileRegisterPolicyRevision(runtimestate.RegisterPolicyRevisionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "tool-policy", Name: "workspace-write", Rules: []agentruntime.PolicyRule{{ToolName: "write", Decision: agentruntime.PolicyRequiresApproval}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Apply(ctx, policy); err != nil {
		t.Fatal(err)
	}
	broker, err := runtimetool.NewBroker(runtimetool.BrokerConfig{Store: store, Compiler: compiler, Planner: planner, Clock: source})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &recordingAdapter{response: runtimemodel.Response{Tool: &runtimemodel.ToolRequest{ToolCallID: "tcall_1234567890ABCDEF", ApprovalID: "appr_1234567890ABCDEF", PolicyName: "workspace-write", PolicyRevision: 1, ToolName: "write", ActionDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CapabilityDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Action: agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"}, MaximumUses: 1, ExpiresAt: now.Add(time.Hour), Descriptor: []byte("safe descriptor")}}}
	worker, err := runtimemodel.NewWorker(runtimemodel.WorkerConfig{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: adapter, Broker: broker, Claimer: "model-worker"})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.ScanOnce(ctx); err != nil {
		t.Fatal(err)
	}
	state, err := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker})
	if err != nil || len(state.ToolIntents) != 1 || len(state.Approvals) != 1 || state.Approvals[0].State != "pending" || len(state.Invocations) != 1 || state.Invocations[0].State != runtimestate.InvocationIntent || len(state.Turns) != 1 || state.Turns[0].SessionID != session || state.Turns[0].TurnID != turn || state.Turns[0].State != agentruntime.TurnWaitingForApproval {
		t.Fatalf("brokered model tool state = %#v, %v", state, err)
	}
}

func TestWorkerRefusesToolArgumentsOutsideDeclaredSchemaBeforeBrokerAdmission(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	content, _ := runtimecontent.New("runtime-content", &modelObjects{values: map[string][]byte{}})
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("principal-a")
	compiler, _ := runtimestate.NewCompiler(content)
	source, _ := clock.NewFake(now)
	planner, _ := runtimestate.NewRuntimeStatePlanner(source, &modelIDs{})
	store, _ := runtimestate.NewMemoryRuntimeStateStore(planner)
	session, _, _ := createModelIntentWithTools(t, ctx, content, compiler, store, tenant, principal, []agentruntime.ToolDefinition{{Name: "write", Description: "write", InputSchemaVersion: "agent-runtime.tool-input/v1", InputSchema: []byte(`{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}`)}})
	policy, _ := compiler.CompileRegisterPolicyRevision(runtimestate.RegisterPolicyRevisionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "tool-policy", Name: "workspace-write", Rules: []agentruntime.PolicyRule{{ToolName: "write", Decision: agentruntime.PolicyRequiresApproval}}})
	if _, err := store.Apply(ctx, policy); err != nil {
		t.Fatal(err)
	}
	broker, _ := runtimetool.NewBroker(runtimetool.BrokerConfig{Store: store, Compiler: compiler, Planner: planner, Clock: source})
	adapter := &recordingAdapter{response: runtimemodel.Response{Tool: &runtimemodel.ToolRequest{ToolCallID: "tcall_1234567890ABCDEF", ApprovalID: "appr_1234567890ABCDEF", PolicyName: "workspace-write", PolicyRevision: 1, ToolName: "write", ActionDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CapabilityDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Action: agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"}, MaximumUses: 1, ExpiresAt: now.Add(time.Hour), Descriptor: []byte(`{"safe":true}`), Arguments: []byte(`{"unexpected":true}`)}}}
	worker, err := runtimemodel.NewWorker(runtimemodel.WorkerConfig{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: adapter, Broker: broker, Claimer: "model-worker"})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.ScanOnce(ctx); err == nil {
		t.Fatal("model tool with invalid arguments was admitted")
	}
	state, err := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker})
	if err != nil || len(state.Approvals) != 0 || len(state.ToolIntents) != 0 || state.Sessions[0].SessionID != session {
		t.Fatalf("invalid arguments reached broker state = %#v, %v", state, err)
	}
}

func createModelIntent(t *testing.T, ctx context.Context, content *runtimecontent.Store, compiler *runtimestate.Compiler, store *runtimestate.MemoryRuntimeStateStore, tenant runtimecontent.TenantID, principal runtimecontent.PrincipalID) (agentruntime.SessionID, agentruntime.TurnID, runtimestate.InvocationRecord) {
	t.Helper()
	return createModelIntentWithTools(t, ctx, content, compiler, store, tenant, principal, []agentruntime.ToolDefinition{{Name: "write", Description: "write a bounded workspace value"}})
}

func createModelIntentWithTools(t *testing.T, ctx context.Context, content *runtimecontent.Store, compiler *runtimestate.Compiler, store *runtimestate.MemoryRuntimeStateStore, tenant runtimecontent.TenantID, principal runtimecontent.PrincipalID, tools []agentruntime.ToolDefinition) (agentruntime.SessionID, agentruntime.TurnID, runtimestate.InvocationRecord) {
	t.Helper()
	body, err := content.StageAgentSpecificationBody(ctx, tenant, runtimecontent.AgentSpecificationBody{Name: "model-worker", ModelProfile: "balanced", Instructions: "safe", Tools: tools})
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

type cancellingAdapter struct {
	cancel          context.CancelFunc
	invocations     int
	reconciliations int
}

type canarySemanticAdapter struct {
	lifecycle       *codexsubscription.Lifecycle
	reference       codexsubscription.CredentialContextRef
	cancel          context.CancelFunc
	logger          *slog.Logger
	invocations     int
	reconciliations int
	last            runtimemodel.Request
}

func (adapter *canarySemanticAdapter) Invoke(_ context.Context, request runtimemodel.Request) (runtimemodel.Response, error) {
	if _, err := adapter.lifecycle.Status(adapter.reference); err != nil {
		return runtimemodel.Response{}, err
	}
	adapter.invocations++
	adapter.last = request
	adapter.logger.Info("subscription fixture invoke cancelled", "operation_id", request.OperationID)
	adapter.cancel()
	return runtimemodel.Response{}, context.Canceled
}

func (adapter *canarySemanticAdapter) Reconcile(_ context.Context, request runtimemodel.Request) (runtimemodel.Response, error) {
	if status, err := adapter.lifecycle.Status(adapter.reference); err != nil || status.State != codexsubscription.LifecycleReady {
		return runtimemodel.Response{}, errors.New("reconcile subscription fixture: redacted lifecycle is not ready")
	}
	adapter.reconciliations++
	adapter.last = request
	adapter.logger.Info("subscription fixture reconciled", "operation_id", request.OperationID)
	return runtimemodel.Response{Output: []byte("reconciled model output")}, nil
}

func (adapter *cancellingAdapter) Invoke(_ context.Context, _ runtimemodel.Request) (runtimemodel.Response, error) {
	adapter.invocations++
	adapter.cancel()
	return runtimemodel.Response{}, context.Canceled
}

func (adapter *cancellingAdapter) Reconcile(_ context.Context, _ runtimemodel.Request) (runtimemodel.Response, error) {
	adapter.reconciliations++
	return runtimemodel.Response{}, context.Canceled
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
