package runtimeorchestration_test

import (
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
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestPublisherDerivesTemporalRoutesOnlyFromClaimedDurableOutbox(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	content, err := runtimecontent.New("runtime-content", &publisherObjects{values: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("principal-a")
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	timeSource, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(timeSource, &publisherIDs{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := runtimestate.NewMemoryRuntimeStateStore(planner)
	if err != nil {
		t.Fatal(err)
	}
	body, err := content.StageAgentSpecificationBody(ctx, tenant, runtimecontent.AgentSpecificationBody{Name: "publisher", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	registration, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "register", Specification: body})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := store.Apply(ctx, registration)
	if err != nil {
		t.Fatal(err)
	}
	created, err := compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}, IdempotencyKey: "create-session", RevisionID: registered.Result().Revision.RevisionID})
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
	accepted, err := compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}, IdempotencyKey: "input", SessionID: sessionPlan.Result().Session.SessionID, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	acceptedPlan, err := store.Apply(ctx, accepted)
	if err != nil {
		t.Fatal(err)
	}
	state := acceptedPlan.State()
	digest := "sha256:" + strings.Repeat("a", 64)
	descriptor, err := content.StageToolActionDescriptor(ctx, tenant, []byte("write action"))
	if err != nil {
		t.Fatal(err)
	}
	intent, err := compiler.CompileRecordToolIntent(runtimestate.RecordToolIntentCommand{
		Scope:                runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker},
		IdempotencyKey:       "tool-intent",
		SessionID:            sessionPlan.Result().Session.SessionID,
		TurnID:               state.Turns[0].TurnID,
		ToolCallID:           "tcall_1234567890ABCDEF",
		ToolName:             "write",
		ActionDigest:         digest,
		PolicyRevisionDigest: digest,
		Descriptor:           descriptor,
	})
	if err != nil {
		t.Fatal(err)
	}
	intentPlan, err := store.Apply(ctx, intent)
	if err != nil {
		t.Fatal(err)
	}
	state = intentPlan.State()
	approval, err := compiler.CompileRequestApproval(runtimestate.RequestApprovalCommand{
		Scope:                runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker},
		IdempotencyKey:       "request-approval",
		SessionID:            sessionPlan.Result().Session.SessionID,
		TurnID:               state.Turns[0].TurnID,
		ToolCallID:           "tcall_1234567890ABCDEF",
		ApprovalID:           "appr_1234567890ABCDEF",
		ActionDigest:         digest,
		PolicyRevisionDigest: digest,
		CapabilityDigest:     digest,
		ActionVerb:           "write",
		ActionTarget:         "workspace-service",
		MaximumUses:          1,
		ExpiresAt:            now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Apply(ctx, approval)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := compiler.CompileDecideApproval(runtimestate.DecideApprovalCommand{
		Scope:          runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner},
		IdempotencyKey: "approve-tool-intent",
		ApprovalID:     "appr_1234567890ABCDEF",
		Decision:       "approved",
	})
	if err != nil {
		t.Fatal(err)
	}
	decisionPlan, err := store.Apply(ctx, decision)
	if err != nil {
		t.Fatal(err)
	}
	if effects := decisionPlan.Effects(); len(effects.Events) != 1 || effects.Events[0].Kind != agentruntime.EventApprovalResolved || len(effects.Outbox) != 4 || len(effects.Audit) != 4 {
		t.Fatalf("approval decision effects = %#v, want one semantic route plus durable audit lifecycle routes", effects)
	}
	state = decisionPlan.State()
	begin, err := compiler.CompileBeginInvocationAttempt(runtimestate.BeginInvocationAttemptCommand{
		Scope:                  runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker},
		IdempotencyKey:         "begin-model-operation",
		SessionID:              sessionPlan.Result().Session.SessionID,
		TurnID:                 state.Turns[0].TurnID,
		OperationID:            "model-operation-1",
		ExpectedSessionVersion: state.Sessions[0].Version,
		ExpectedTurnVersion:    state.Turns[0].Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	beginPlan, err := store.Apply(ctx, begin)
	if err != nil {
		t.Fatal(err)
	}
	state = beginPlan.State()
	invocation := beginPlan.Result().Invocation
	producerLoss := &agentruntime.Failure{Code: agentruntime.FailureUnavailable, Message: "producer lost before a model operation outcome was recorded"}
	uncertain, err := compiler.CompileRecordInvocationOutcome(runtimestate.RecordInvocationOutcomeCommand{
		Scope:                  runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker},
		IdempotencyKey:         "model-operation-producer-loss",
		SessionID:              sessionPlan.Result().Session.SessionID,
		TurnID:                 state.Turns[0].TurnID,
		OperationID:            invocation.OperationID,
		Ordinal:                invocation.Ordinal,
		Fence:                  invocation.Fence,
		Outcome:                runtimestate.InvocationUncertain,
		Failure:                producerLoss,
		ExpectedSessionVersion: state.Sessions[0].Version,
		ExpectedTurnVersion:    state.Turns[0].Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	uncertainPlan, err := store.Apply(ctx, uncertain)
	if err != nil {
		t.Fatal(err)
	}
	state = uncertainPlan.State()
	settle, err := compiler.CompileSettleTurn(runtimestate.SettleTurnCommand{
		Scope:                  runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker},
		IdempotencyKey:         "finalize-producer-loss",
		SessionID:              sessionPlan.Result().Session.SessionID,
		TurnID:                 state.Turns[0].TurnID,
		ExpectedSessionVersion: state.Sessions[0].Version,
		ExpectedTurnVersion:    state.Turns[0].Version,
		Outcome: runtimestate.TerminalOutcome{
			OperationID: invocation.OperationID,
			Ordinal:     invocation.Ordinal,
			Fence:       invocation.Fence,
			State:       agentruntime.TurnFailed,
			Failure:     producerLoss,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	settledPlan, err := store.Apply(ctx, settle)
	if err != nil {
		t.Fatal(err)
	}
	if final := settledPlan.State(); len(final.Invocations) != 1 || final.Invocations[0].State != runtimestate.InvocationUncertain || settledPlan.Result().Turn.State != agentruntime.TurnFailed || len(settledPlan.Effects().Events) != 2 || settledPlan.Effects().Events[0].Kind != agentruntime.EventProducerGap || settledPlan.Effects().Events[1].Kind != agentruntime.EventTurnFailed {
		t.Fatalf("producer-loss finalization = %#v / %#v, want retained uncertain invocation and terminal failed route", settledPlan.Result(), settledPlan.Effects())
	}
	temporal := &recordingPublisher{}
	publisher, err := runtimeorchestration.NewPublisher(runtimeorchestration.PublisherConfig{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: timeSource, Publisher: temporal, Claimer: "orchestration-codec"})
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.ScanOnce(ctx); err != nil {
		t.Fatalf("scan durable outbox: %v", err)
	}
	if len(temporal.starts) != 1 || temporal.starts[0].SessionID != sessionPlan.Result().Session.SessionID.String() {
		t.Fatalf("starts = %#v, want durable Session start", temporal.starts)
	}
	if got, want := len(temporal.commands), 3; got != want || temporal.commands[0].Kind != runtimeorchestration.CommandInputAccepted || temporal.commands[1].Kind != runtimeorchestration.CommandApprovalResolved || temporal.commands[2].Kind != runtimeorchestration.CommandTurnFailed {
		t.Fatalf("commands = %#v, want durable input, approval, and producer-loss finalization routes", temporal.commands)
	}
	if temporal.commands[1].Sequence >= temporal.commands[2].Sequence {
		t.Fatalf("terminal command ordering = %#v, want approval before finalization", temporal.commands)
	}
	afterPublish, err := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher})
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range afterPublish.Outbox {
		if record.InvocationID != "" && record.EventKind == "" && record.State != runtimestate.OutboxPending {
			t.Fatalf("Temporal publisher acknowledged model intent %#v; model worker must own it", record)
		}
	}
	dispatcher, err := runtimeorchestration.NewDurableStateDispatcher(store)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range temporal.commands {
		if err := dispatcher.Dispatch(ctx, command); err != nil {
			t.Fatalf("recheck published durable route %s: %v", command.Kind, err)
		}
	}
	if err := dispatcher.Dispatch(ctx, runtimeorchestration.Command{Tenant: "tenant-a", OutboxID: "forged", SessionID: sessionPlan.Result().Session.SessionID.String(), Kind: runtimeorchestration.CommandInputAccepted, Sequence: 999}); err == nil {
		t.Fatal("forged Temporal command was accepted without a durable outbox route")
	}
	if err := publisher.ScanOnce(ctx); err != nil {
		t.Fatalf("rescan published durable outbox: %v", err)
	}
	if len(temporal.starts) != 1 || len(temporal.commands) != 3 {
		t.Fatalf("rescan redelivered published routes: starts=%#v commands=%#v", temporal.starts, temporal.commands)
	}
}

func TestDurableInputDispatchBeginsOneInvocationAcrossRepeatedRoutes(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 11, 13, 0, 0, 0, time.UTC)
	content, err := runtimecontent.New("runtime-content", &publisherObjects{values: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("principal-a")
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	timeSource, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(timeSource, &publisherIDs{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := runtimestate.NewMemoryRuntimeStateStore(planner)
	if err != nil {
		t.Fatal(err)
	}
	body, err := content.StageAgentSpecificationBody(ctx, tenant, runtimecontent.AgentSpecificationBody{Name: "scheduler", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	registration, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "register", Specification: body})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := store.Apply(ctx, registration)
	if err != nil {
		t.Fatal(err)
	}
	created, err := compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}, IdempotencyKey: "create-session", RevisionID: registered.Result().Revision.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.Apply(ctx, created)
	if err != nil {
		t.Fatal(err)
	}
	input, err := content.StageInputEnvelope(ctx, tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "schedule exactly once"}})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}, IdempotencyKey: "input", SessionID: session.Result().Session.SessionID, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, accepted); err != nil {
		t.Fatal(err)
	}
	temporal := &recordingPublisher{}
	publisher, err := runtimeorchestration.NewPublisher(runtimeorchestration.PublisherConfig{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: timeSource, Publisher: temporal, Claimer: "orchestration-codec"})
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.ScanOnce(ctx); err != nil {
		t.Fatalf("publish public input route: %v", err)
	}
	var inputRoute runtimeorchestration.Command
	for _, command := range temporal.commands {
		if command.Kind == runtimeorchestration.CommandInputAccepted {
			inputRoute = command
			break
		}
	}
	if inputRoute.OutboxID == "" {
		t.Fatalf("published commands = %#v, want input route", temporal.commands)
	}
	competing, err := compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}, IdempotencyKey: "competing-publisher-session", RevisionID: registered.Result().Revision.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	competingPlan, err := store.Apply(ctx, competing)
	if err != nil {
		t.Fatal(err)
	}
	var competingRoute runtimestate.OutboxRecord
	for _, route := range competingPlan.Effects().Outbox {
		if route.Aggregate != "audit_fact" {
			competingRoute = route
			break
		}
	}
	if competingRoute.OutboxID == "" {
		t.Fatalf("competing session routes = %#v, want a publisher-audited route", competingPlan.Effects().Outbox)
	}
	dispatcher, err := runtimeorchestration.NewDurableStateDispatcherWithInvocationScheduler(&competingPublisherMutationStore{MemoryRuntimeStateStore: store, compiler: compiler, competing: competingRoute}, compiler, planner, nil)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := dispatcher.Dispatch(ctx, inputRoute); err != nil {
			t.Fatalf("dispatch durable input route attempt %d: %v", attempt+1, err)
		}
	}
	state, err := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker})
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Invocations) != 1 {
		t.Fatalf("invocations = %#v, want exactly one durable begin attempt", state.Invocations)
	}
	invocation := state.Invocations[0]
	if invocation.SessionID != session.Result().Session.SessionID || invocation.TurnID == "" || invocation.OperationID != runtimestate.OperationID("orchestration-invocation-"+inputRoute.OutboxID) {
		t.Fatalf("invocation = %#v, want deterministic input-owned operation", invocation)
	}
	if !hasAuditOperation(state.Audit, "outbox.claimed", "competing-publisher-claim") || !hasReceiptOperation(state.Receipts, "competing-publisher-claim") {
		t.Fatalf("competing publisher mutation = audit %#v receipts %#v, want its committed receipt and audit", state.Audit, state.Receipts)
	}
}

func TestPublisherReclaimsAnUnacknowledgedRouteAfterProcessLoss(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	content, err := runtimecontent.New("runtime-content", &publisherObjects{values: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("principal-a")
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	timeSource, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(timeSource, &publisherIDs{})
	if err != nil {
		t.Fatal(err)
	}
	memory, err := runtimestate.NewMemoryRuntimeStateStore(planner)
	if err != nil {
		t.Fatal(err)
	}
	store := &failFirstAcknowledgementStore{MemoryRuntimeStateStore: memory}
	body, err := content.StageAgentSpecificationBody(ctx, tenant, runtimecontent.AgentSpecificationBody{Name: "reclaim", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "register", Specification: body})
	if err != nil {
		t.Fatal(err)
	}
	registeredPlan, err := store.Apply(ctx, registered)
	if err != nil {
		t.Fatal(err)
	}
	created, err := compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}, IdempotencyKey: "create-session", RevisionID: registeredPlan.Result().Revision.RevisionID})
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
	accepted, err := compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}, IdempotencyKey: "input", SessionID: sessionPlan.Result().Session.SessionID, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, accepted); err != nil {
		t.Fatal(err)
	}
	temporal := &recordingPublisher{}
	publisher, err := runtimeorchestration.NewPublisher(runtimeorchestration.PublisherConfig{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: timeSource, Publisher: temporal, Claimer: "orchestration-codec"})
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.ScanOnce(ctx); err == nil {
		t.Fatal("publish result = nil, want simulated acknowledgement-loss error")
	}
	if len(temporal.commands) != 1 {
		t.Fatalf("commands after lost acknowledgement = %#v, want one delivered route", temporal.commands)
	}
	claimedState, err := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAuditOperation(claimedState.Audit, "outbox.claimed", "temporal-claim-"+temporal.commands[0].OutboxID+"-") || hasAuditOperation(claimedState.Audit, "outbox.published", "temporal-ack-"+temporal.commands[0].OutboxID+"-") {
		t.Fatalf("audit after lost acknowledgement = %#v, want claimed fact without published fact", claimedState.Audit)
	}
	if err := timeSource.Advance(2*time.Minute + time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	if err := publisher.ScanOnce(ctx); err != nil {
		t.Fatalf("reclaim expired durable outbox route: %v", err)
	}
	if len(temporal.commands) != 2 || temporal.commands[0] != temporal.commands[1] {
		t.Fatalf("commands after reclaim = %#v, want exactly one duplicate durable route", temporal.commands)
	}
	publishedState, err := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAuditOperation(publishedState.Audit, "outbox.published", "temporal-ack-"+temporal.commands[0].OutboxID+"-") {
		t.Fatalf("audit after recovered acknowledgement = %#v, want published fact", publishedState.Audit)
	}
	page, err := store.ReadOutbox(ctx, runtimestate.OutboxQuery{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher}, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range page.Records {
		if string(record.OutboxID) == temporal.commands[0].OutboxID {
			if record.State != runtimestate.OutboxPublished {
				t.Fatalf("reclaimed input route = %#v, want published", record)
			}
			return
		}
	}
	t.Fatalf("outbox after reclaim = %#v, want the delivered input route", page.Records)
}

func hasAuditOperation(facts []runtimestate.AuditFactRecord, kind, operationPrefix string) bool {
	for _, fact := range facts {
		if fact.Kind == kind && strings.HasPrefix(string(fact.OperationID), operationPrefix) {
			return true
		}
	}
	return false
}

// failFirstAcknowledgementStore simulates the narrow crash window after a
// Temporal route succeeds but before its durable acknowledgement commits.
// The durable lease must be reclaimable; the workflow is responsible for
// treating the repeated route as a deterministic no-op.
type failFirstAcknowledgementStore struct {
	*runtimestate.MemoryRuntimeStateStore
	failed bool
}

// competingPublisherMutationStore injects one actual publisher claim between
// the dispatcher's read and CAS. Claiming appends the normal publisher receipt
// and audit fact, so the dispatcher must rehydrate/replan its exact operation.
type competingPublisherMutationStore struct {
	*runtimestate.MemoryRuntimeStateStore
	compiler  *runtimestate.Compiler
	competing runtimestate.OutboxRecord
	mutated   bool
}

func (store *competingPublisherMutationStore) ApplyCompiledMutation(ctx context.Context, planner *runtimestate.RuntimeStatePlanner, mutation runtimestate.CompiledMutation) (runtimestate.TransitionPlan, error) {
	if mutation.ReceiptBinding().Command == runtimestate.CommandBeginInvocation && !store.mutated {
		store.mutated = true
		state, err := store.MemoryRuntimeStateStore.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: store.competing.Tenant, Authority: runtimestate.AuthorityOutboxPublisher})
		if err != nil {
			return runtimestate.TransitionPlan{}, err
		}
		current, found := outboxByID(state, store.competing.OutboxID)
		if !found {
			return runtimestate.TransitionPlan{}, runtimestate.ErrNotFoundOrDenied
		}
		claim, err := store.compiler.CompileClaimOutbox(runtimestate.ClaimOutboxCommand{Scope: runtimestate.MutationScope{Tenant: current.Tenant, Authority: runtimestate.AuthorityOutboxPublisher}, IdempotencyKey: "competing-publisher-claim", OutboxID: current.OutboxID, ExpectedVersion: current.Version, Claimer: "competing-publisher", ClaimUntil: current.CommittedAt.Add(time.Minute)})
		if err != nil {
			return runtimestate.TransitionPlan{}, err
		}
		if _, err := store.MemoryRuntimeStateStore.Apply(ctx, claim); err != nil {
			return runtimestate.TransitionPlan{}, fmt.Errorf("claim competing publisher route %#v: %w", current, err)
		}
	}
	plan, err := store.MemoryRuntimeStateStore.ApplyCompiledMutation(ctx, planner, mutation)
	if err != nil {
		state, loadErr := store.MemoryRuntimeStateStore.LoadRuntimeState(ctx, mutation.ReceiptBinding().Scope)
		return runtimestate.TransitionPlan{}, fmt.Errorf("atomic begin after competing claim (sessions=%#v turns=%#v invocations=%#v load=%v): %w", state.Sessions, state.Turns, state.Invocations, loadErr, err)
	}
	return plan, nil
}

func hasReceiptOperation(receipts []runtimestate.MutationReceipt, operationPrefix string) bool {
	for _, receipt := range receipts {
		if strings.HasPrefix(string(receipt.OperationID), operationPrefix) {
			return true
		}
	}
	return false
}

func outboxByID(state runtimestate.RuntimeState, outboxID runtimestate.OutboxID) (runtimestate.OutboxRecord, bool) {
	for _, record := range state.Outbox {
		if record.OutboxID == outboxID {
			return record, true
		}
	}
	return runtimestate.OutboxRecord{}, false
}

func (store *failFirstAcknowledgementStore) PersistTransitionPlan(ctx context.Context, plan runtimestate.TransitionPlan) error {
	if plan.Kind() == runtimestate.CommandAcknowledgeOutbox && plan.Result().Outbox.EventKind == agentruntime.EventInputAccepted && !store.failed {
		store.failed = true
		return errors.New("simulated process loss before outbox acknowledgement")
	}
	return store.MemoryRuntimeStateStore.PersistTransitionPlan(ctx, plan)
}

type recordingPublisher struct {
	starts   []runtimeorchestration.SessionStart
	commands []runtimeorchestration.Command
}

func (publisher *recordingPublisher) StartSession(_ context.Context, start runtimeorchestration.SessionStart) error {
	publisher.starts = append(publisher.starts, start)
	return nil
}

func (publisher *recordingPublisher) SignalSession(_ context.Context, _ runtimeorchestration.SessionStart, command runtimeorchestration.Command) error {
	publisher.commands = append(publisher.commands, command)
	return nil
}

type publisherObjects struct{ values map[string][]byte }

func (objects *publisherObjects) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	if _, exists := objects.values[key]; exists {
		return false, nil
	}
	objects.values[key] = append([]byte(nil), value...)
	return true, nil
}

func (objects *publisherObjects) Get(_ context.Context, key string, _ int) ([]byte, error) {
	return append([]byte(nil), objects.values[key]...), nil
}

type publisherIDs struct{ next uint64 }

func (ids *publisherIDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	ids.next++
	return fmt.Sprintf("%s_%016d", kind, ids.next), nil
}
