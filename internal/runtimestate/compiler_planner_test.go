package runtimestate_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func testRuntimeContent(t *testing.T) (*runtimecontent.Store, *memoryObjects, runtimecontent.TenantID, runtimecontent.PrincipalID) {
	t.Helper()
	tenant, err := runtimecontent.ParseTenantID("tenant-a")
	if err != nil {
		t.Fatalf("parse tenant: %v", err)
	}
	principal, err := runtimecontent.ParsePrincipalID("principal-a")
	if err != nil {
		t.Fatalf("parse principal: %v", err)
	}
	objects := &memoryObjects{values: map[string][]byte{}}
	store, err := runtimecontent.New("runtime-content", objects)
	if err != nil {
		t.Fatalf("new content: %v", err)
	}
	return store, objects, tenant, principal
}

type memoryObjects struct{ values map[string][]byte }

func (objects *memoryObjects) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	if _, ok := objects.values[key]; ok {
		return false, nil
	}
	objects.values[key] = append([]byte(nil), value...)
	return true, nil
}
func (objects *memoryObjects) Get(_ context.Context, key string, _ int) ([]byte, error) {
	return append([]byte(nil), objects.values[key]...), nil
}
func validAgentID(t *testing.T) agentruntime.AgentID {
	t.Helper()
	value, err := agentruntime.ParseAgentID("agent_1234567890ABCDEF")
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func validRevisionID(t *testing.T) agentruntime.AgentRevisionID {
	t.Helper()
	value, err := agentruntime.ParseAgentRevisionID("arev_1234567890ABCDEF")
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func validSessionID(t *testing.T) agentruntime.SessionID {
	t.Helper()
	value, err := agentruntime.ParseSessionID("sess_1234567890ABCDEF")
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func validReference() runtimecontent.Reference {
	return runtimecontent.Reference{Digest: "sha256:1234567890abcdef", MediaType: runtimecontent.AgentSpecificationBodyMediaTypeV1, SizeBytes: 1}
}
func ownerScope(tenant runtimecontent.TenantID, principal runtimecontent.PrincipalID) runtimestate.MutationScope {
	return runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}
}
func workerScope(tenant runtimecontent.TenantID, principal runtimecontent.PrincipalID) runtimestate.MutationScope {
	return runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}
}

func TestCompilerCreatesTheOnlyReceiptBoundMutationAndPlannerCreatesRevision(t *testing.T) {
	content, _, tenant, _ := testRuntimeContent(t)
	handoff, err := content.StageAgentSpecificationBody(context.Background(), tenant, runtimecontent.AgentSpecificationBody{Name: "planner", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatalf("stage specification: %v", err)
	}
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	compiled, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{
		Scope:          runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator},
		IdempotencyKey: "create-agent", Specification: handoff,
	})
	if err != nil {
		t.Fatalf("compile RegisterAgentRevision: %v", err)
	}
	if got := compiled.ReceiptBinding(); got.Command != runtimestate.CommandRegisterAgentRevision || got.RequestDigest == "" || got.IdempotencyKey != "create-agent" {
		t.Fatalf("receipt binding = %#v, want compiler-owned canonical receipt", got)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(fixedPlannerClock{now: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)}, &uniquePlannerIDs{})
	if err != nil {
		t.Fatalf("new planner: %v", err)
	}
	plan, err := planner.Plan(context.Background(), runtimestate.RuntimeState{}, compiled)
	if err != nil {
		t.Fatalf("plan RegisterAgentRevision: %v", err)
	}
	result := plan.Result()
	if result.Revision.Revision != 1 || result.Revision.Name != "planner" || result.Receipt.RequestDigest != compiled.ReceiptBinding().RequestDigest {
		t.Fatalf("plan result = %#v, want compiled revision metadata and receipt", result)
	}
	if len(plan.State().Revisions) != 1 || len(plan.Effects().Audit) != 1 || len(plan.Effects().Outbox) != 1 {
		t.Fatalf("plan failed to atomically derive revision/effects: %#v", plan)
	}
	if len(plan.BaseState().Revisions) != 0 {
		t.Fatalf("plan base = %#v, want exact pre-transition snapshot", plan.BaseState())
	}
	principal, err := runtimecontent.ParsePrincipalID("principal-a")
	if err != nil {
		t.Fatalf("parse principal: %v", err)
	}
	create, err := compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: ownerScope(tenant, principal), IdempotencyKey: "create-session", RevisionID: result.Revision.RevisionID})
	if err != nil {
		t.Fatalf("compile create Session: %v", err)
	}
	sessionPlan, err := planner.Plan(context.Background(), plan.State(), create)
	if err != nil {
		t.Fatalf("plan create Session: %v", err)
	}
	if got := sessionPlan.Result(); got.Session.State != agentruntime.SessionOpen || len(sessionPlan.Effects().Events) != 1 || sessionPlan.Effects().Events[0].Kind != agentruntime.EventSessionCreated {
		t.Fatalf("Session plan = %#v / %#v, want pinned open Session and creation event", got, sessionPlan.Effects())
	}
	revisionHandoff, err := content.StageAgentSpecificationBody(context.Background(), tenant, runtimecontent.AgentSpecificationBody{Name: "planner", ModelProfile: "balanced", Instructions: "safer"})
	if err != nil {
		t.Fatalf("stage revision specification: %v", err)
	}
	revise, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "revise-agent", AgentID: result.Revision.AgentID, ExpectedRevision: result.Revision.Revision, Specification: revisionHandoff})
	if err != nil {
		t.Fatalf("compile revision: %v", err)
	}
	revisionPlan, err := planner.Plan(context.Background(), sessionPlan.State(), revise)
	if err != nil {
		t.Fatalf("plan revision: %v", err)
	}
	if got := revisionPlan.Result(); got.Revision.Revision != 2 || got.Revision.AgentID != result.Revision.AgentID || revisionPlan.State().Sessions[0].RevisionID != result.Revision.RevisionID {
		t.Fatalf("revision plan = %#v / %#v, want immutable revision and unchanged Session pin", got, revisionPlan.State().Sessions[0])
	}
}

func TestPlannerPromotesQueuedTurnAfterOneWinningSettlement(t *testing.T) {
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
	state := runtimestate.RuntimeState{Revisions: []runtimestate.AgentRevisionRecord{{Tenant: tenant, AgentID: validAgentID(t), RevisionID: validRevisionID(t), Revision: 1, Name: "planner", ModelProfile: "balanced", Specification: validReference(), CreatedAt: now, RetainUntil: now.Add(time.Hour)}}, Sessions: []runtimestate.SessionRecord{{Tenant: tenant, Principal: principal, SessionID: validSessionID(t), AgentID: validAgentID(t), RevisionID: validRevisionID(t), State: agentruntime.SessionOpen, Version: 3, CreatedAt: now, UpdatedAt: now, RetainUntil: now.Add(time.Hour)}}}
	for _, text := range []string{"first", "second"} {
		handoff, err := content.StageInputEnvelope(context.Background(), tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: text}})
		if err != nil {
			t.Fatalf("stage input: %v", err)
		}
		mutation, err := compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: ownerScope(tenant, principal), IdempotencyKey: "input-" + text, SessionID: state.Sessions[0].SessionID, Input: handoff})
		if err != nil {
			t.Fatalf("compile input: %v", err)
		}
		plan, err := planner.Plan(context.Background(), state, mutation)
		if err != nil {
			t.Fatalf("plan input: %v", err)
		}
		state = plan.State()
	}
	active, queued := state.Turns[0], state.Turns[1]
	if active.State != agentruntime.TurnRunning || queued.State != agentruntime.TurnQueued {
		t.Fatalf("turn states = %s/%s, want running/queued", active.State, queued.State)
	}
	begin, err := compiler.CompileBeginInvocationAttempt(runtimestate.BeginInvocationAttemptCommand{Scope: workerScope(tenant, principal), IdempotencyKey: "begin", SessionID: active.SessionID, TurnID: active.TurnID, OperationID: "operation-1", ExpectedSessionVersion: state.Sessions[0].Version, ExpectedTurnVersion: active.Version})
	if err != nil {
		t.Fatalf("compile begin: %v", err)
	}
	beginPlan, err := planner.Plan(context.Background(), state, begin)
	if err != nil {
		t.Fatalf("plan begin: %v", err)
	}
	state = beginPlan.State()
	invocation := beginPlan.Result().Invocation
	resultReference := runtimecontent.Reference{Digest: "sha256:result", MediaType: "application/test", SizeBytes: 1}
	outcome, err := compiler.CompileRecordInvocationOutcome(runtimestate.RecordInvocationOutcomeCommand{Scope: workerScope(tenant, principal), IdempotencyKey: "outcome", SessionID: active.SessionID, TurnID: active.TurnID, OperationID: invocation.OperationID, Ordinal: invocation.Ordinal, Fence: invocation.Fence, Outcome: runtimestate.InvocationSucceeded, Result: &resultReference, ExpectedSessionVersion: state.Sessions[0].Version, ExpectedTurnVersion: state.Turns[0].Version})
	if err != nil {
		t.Fatalf("compile outcome: %v", err)
	}
	outcomePlan, err := planner.Plan(context.Background(), state, outcome)
	if err != nil {
		t.Fatalf("plan outcome: %v", err)
	}
	state = outcomePlan.State()
	settle, err := compiler.CompileSettleTurn(runtimestate.SettleTurnCommand{Scope: workerScope(tenant, principal), IdempotencyKey: "settle", SessionID: active.SessionID, TurnID: active.TurnID, ExpectedSessionVersion: state.Sessions[0].Version, ExpectedTurnVersion: state.Turns[0].Version, Outcome: runtimestate.TerminalOutcome{OperationID: invocation.OperationID, Ordinal: invocation.Ordinal, Fence: invocation.Fence, State: agentruntime.TurnSucceeded}})
	if err != nil {
		t.Fatalf("compile settle: %v", err)
	}
	plan, err := planner.Plan(context.Background(), state, settle)
	if err != nil {
		t.Fatalf("plan settle: %v", err)
	}
	if got := plan.Result(); got.Turn.State != agentruntime.TurnSucceeded || got.Promoted == nil || got.Promoted.TurnID != queued.TurnID || got.Promoted.State != agentruntime.TurnRunning {
		t.Fatalf("settlement result = %#v, want winning terminal and queued promotion", got)
	}
	if len(plan.Effects().Events) < 2 || plan.Effects().Events[len(plan.Effects().Events)-1].Kind != agentruntime.EventTurnStarted {
		t.Fatalf("settlement effects = %#v, want terminal then promoted event", plan.Effects())
	}
	replay, err := planner.Plan(context.Background(), plan.State(), settle)
	if err != nil || replay.Result().Receipt.RequestDigest != plan.Result().Receipt.RequestDigest {
		t.Fatalf("exact settlement replay = %#v, %v; want original safe result", replay.Result(), err)
	}
}

func TestPlannerCancelsQueuedWorkClosesAfterDrainAndFencesOutboxLeases(t *testing.T) {
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
	sessionID := validSessionID(t)
	state := runtimestate.RuntimeState{Sessions: []runtimestate.SessionRecord{{Tenant: tenant, Principal: principal, SessionID: sessionID, State: agentruntime.SessionOpen, Version: 1, CreatedAt: now, UpdatedAt: now, RetainUntil: now.Add(time.Hour)}}}
	for _, text := range []string{"active", "queued"} {
		handoff, err := content.StageInputEnvelope(context.Background(), tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: text}})
		if err != nil {
			t.Fatalf("stage %s: %v", text, err)
		}
		command, err := compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: ownerScope(tenant, principal), IdempotencyKey: "admit-" + text, SessionID: sessionID, Input: handoff})
		if err != nil {
			t.Fatalf("compile %s: %v", text, err)
		}
		plan, err := planner.Plan(context.Background(), state, command)
		if err != nil {
			t.Fatalf("plan %s: %v", text, err)
		}
		state = plan.State()
	}
	queued := state.Turns[1]
	cancel, err := compiler.CompileCancelTurn(runtimestate.CancelTurnCommand{Scope: ownerScope(tenant, principal), IdempotencyKey: "cancel-queued", SessionID: sessionID, TurnID: queued.TurnID})
	if err != nil {
		t.Fatalf("compile cancel queued: %v", err)
	}
	cancelPlan, err := planner.Plan(context.Background(), state, cancel)
	if err != nil {
		t.Fatalf("plan cancel queued: %v", err)
	}
	if got := cancelPlan.Result(); got.Promoted != nil || got.Turn.State != agentruntime.TurnCancelled || cancelPlan.State().Turns[0].State != agentruntime.TurnRunning {
		t.Fatalf("queued cancellation = %#v / %#v, want no second running turn", got, cancelPlan.State().Turns)
	}
	state = cancelPlan.State()
	close, err := compiler.CompileCloseSession(runtimestate.CloseSessionCommand{Scope: ownerScope(tenant, principal), IdempotencyKey: "close", SessionID: sessionID})
	if err != nil {
		t.Fatalf("compile close: %v", err)
	}
	closePlan, err := planner.Plan(context.Background(), state, close)
	if err != nil {
		t.Fatalf("plan close: %v", err)
	}
	if closePlan.Result().Session.State != agentruntime.SessionClosing {
		t.Fatalf("close state = %s, want closing while active turn drains", closePlan.Result().Session.State)
	}
	state = closePlan.State()
	cancelActive, err := compiler.CompileCancelTurn(runtimestate.CancelTurnCommand{Scope: ownerScope(tenant, principal), IdempotencyKey: "cancel-active", SessionID: sessionID, TurnID: state.Turns[0].TurnID})
	if err != nil {
		t.Fatalf("compile active cancel: %v", err)
	}
	drainPlan, err := planner.Plan(context.Background(), state, cancelActive)
	if err != nil {
		t.Fatalf("plan active cancel: %v", err)
	}
	if drainPlan.Result().Session.State != agentruntime.SessionCompleted {
		t.Fatalf("drained close = %s, want completed", drainPlan.Result().Session.State)
	}
	state = drainPlan.State()
	if len(state.Outbox) == 0 {
		t.Fatal("lifecycle plans omitted durable outbox work")
	}
	work := state.Outbox[0]
	claimUntil := now.Add(time.Minute)
	claim, err := compiler.CompileClaimOutbox(runtimestate.ClaimOutboxCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher}, IdempotencyKey: "claim", OutboxID: work.OutboxID, ExpectedVersion: work.Version, Claimer: "publisher-a", ClaimUntil: claimUntil})
	if err != nil {
		t.Fatalf("compile claim: %v", err)
	}
	claimPlan, err := planner.Plan(context.Background(), state, claim)
	if err != nil {
		t.Fatalf("plan claim: %v", err)
	}
	claimed := claimPlan.Result().Outbox
	if claimed.State != runtimestate.OutboxClaimed || claimed.Version != work.Version+1 {
		t.Fatalf("claimed Outbox = %#v", claimed)
	}
	ack, err := compiler.CompileAcknowledgeOutbox(runtimestate.AcknowledgeOutboxCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher}, IdempotencyKey: "ack", OutboxID: claimed.OutboxID, ExpectedVersion: claimed.Version, Claimer: "publisher-a", PublishedAt: now})
	if err != nil {
		t.Fatalf("compile acknowledgement: %v", err)
	}
	ackPlan, err := planner.Plan(context.Background(), claimPlan.State(), ack)
	if err != nil {
		t.Fatalf("plan acknowledgement: %v", err)
	}
	if ackPlan.Result().Outbox.State != runtimestate.OutboxPublished {
		t.Fatalf("acknowledged Outbox = %#v", ackPlan.Result().Outbox)
	}
}

func TestPlannerRegistersWorkerArtifactWithAuthorizationAuditOutboxAndReplay(t *testing.T) {
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
	sessionID, turnID := validSessionID(t), agentruntime.TurnID("turn_1234567890ABCDEF")
	state := runtimestate.RuntimeState{Sessions: []runtimestate.SessionRecord{{Tenant: tenant, Principal: principal, SessionID: sessionID, State: agentruntime.SessionOpen, Version: 1, CreatedAt: now, UpdatedAt: now, RetainUntil: now.Add(time.Hour)}}, Turns: []runtimestate.TurnRecord{{Tenant: tenant, Principal: principal, SessionID: sessionID, TurnID: turnID, State: agentruntime.TurnRunning, Version: 1, RetentionUntil: now.Add(time.Hour)}}}
	handoff, err := content.StageArtifact(context.Background(), tenant, "text/plain", []byte("safe artifact"))
	if err != nil {
		t.Fatalf("stage artifact: %v", err)
	}
	command, err := compiler.CompileRegisterArtifact(runtimestate.RegisterArtifactCommand{Scope: workerScope(tenant, principal), IdempotencyKey: "artifact-1", SessionID: sessionID, TurnID: turnID, Artifact: handoff})
	if err != nil {
		t.Fatalf("compile artifact: %v", err)
	}
	plan, err := planner.Plan(context.Background(), state, command)
	if err != nil {
		t.Fatalf("plan artifact: %v", err)
	}
	result := plan.Result()
	if result.Artifact.ArtifactID == "" || result.Artifact.Reference.Digest == "" || len(plan.Effects().Audit) != 1 || len(plan.Effects().Outbox) != 1 {
		t.Fatalf("artifact plan = %#v / %#v, want metadata plus audit/outbox", result, plan.Effects())
	}
	replay, err := planner.Plan(context.Background(), plan.State(), command)
	if err != nil || replay.Result().Artifact != result.Artifact {
		t.Fatalf("artifact exact replay = %#v, %v; want original metadata", replay.Result(), err)
	}
	other, err := content.StageArtifact(context.Background(), tenant, "text/plain", []byte("different artifact"))
	if err != nil {
		t.Fatalf("stage conflicting artifact: %v", err)
	}
	conflict, err := compiler.CompileRegisterArtifact(runtimestate.RegisterArtifactCommand{Scope: workerScope(tenant, principal), IdempotencyKey: "artifact-1", SessionID: sessionID, TurnID: turnID, Artifact: other})
	if err != nil {
		t.Fatalf("compile conflicting artifact: %v", err)
	}
	if _, err := planner.Plan(context.Background(), plan.State(), conflict); !errors.Is(err, runtimestate.ErrConflict) {
		t.Fatalf("conflicting artifact receipt error = %v, want ErrConflict", err)
	}
}

func TestCompilerRejectsForgedScopeAndCompilesOnlyStateScopedContentReaders(t *testing.T) {
	content, _, tenant, principal := testRuntimeContent(t)
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	if _, err := compiler.CompileCloseSession(runtimestate.CloseSessionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "wrong-authority", SessionID: validSessionID(t)}); err == nil {
		t.Fatal("worker scope compiled Session-owner close")
	}
	bodyReader, err := compiler.CompileAuthorizeAgentSpecificationBodyRead(runtimestate.AgentSpecificationBodyReadCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, AgentID: validAgentID(t), RevisionID: validRevisionID(t)})
	if err != nil {
		t.Fatalf("compile body reader: %v", err)
	}
	if agent, revision := bodyReader.AgentRevision(); agent != validAgentID(t) || revision != validRevisionID(t) {
		t.Fatalf("body reader target = %s/%s", agent, revision)
	}
	inputID, err := agentruntime.ParseInputID("inpt_1234567890ABCDEF")
	if err != nil {
		t.Fatal(err)
	}
	inputReader, err := compiler.CompileAuthorizeInputEnvelopeRead(runtimestate.InputEnvelopeReadCommand{Scope: ownerScope(tenant, principal), SessionID: validSessionID(t), InputID: inputID})
	if err != nil {
		t.Fatalf("compile Input reader: %v", err)
	}
	if session, input := inputReader.Input(); session != validSessionID(t) || input != inputID {
		t.Fatalf("Input reader target = %s/%s", session, input)
	}
}

type fixedPlannerClock struct{ now time.Time }

func (clock fixedPlannerClock) Now() time.Time { return clock.now }

type fixedPlannerIDs struct{ next int }

func (ids *fixedPlannerIDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	ids.next++
	return string(kind) + "_1234567890ABCDEF", nil
}

type uniquePlannerIDs struct{ next int }

func (ids *uniquePlannerIDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	ids.next++
	return string(kind) + "_" + fmt.Sprintf("%016d", ids.next), nil
}
