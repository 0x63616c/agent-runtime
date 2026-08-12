package runtimestate_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
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
	if len(plan.State().Revisions) != 1 || len(plan.Effects().Audit) != 4 || len(plan.Effects().Outbox) != 5 || plan.Effects().Outbox[0].AuditFactID != plan.Effects().Audit[0].AuditFactID || !hasLifecyclePhases(plan.Effects(), "register_agent_revision", "attempted", "authorized", "committed") {
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

func TestPlannerSessionCancellationTransitionTableAndReplay(t *testing.T) {
	now := time.Date(2026, 8, 12, 2, 0, 0, 0, time.UTC)
	content, _, tenant, principal := testRuntimeContent(t)
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(fixedPlannerClock{now: now}, &uniquePlannerIDs{})
	if err != nil {
		t.Fatalf("new planner: %v", err)
	}
	owner := ownerScope(tenant, principal)
	sessionID := validSessionID(t)

	for _, candidate := range []struct {
		name    string
		initial agentruntime.SessionState
		want    agentruntime.SessionState
		pending bool
		err     error
	}{
		{name: "open becomes cancelled", initial: agentruntime.SessionOpen, want: agentruntime.SessionCancelled},
		{name: "closing becomes cancelled", initial: agentruntime.SessionClosing, want: agentruntime.SessionCancelled},
		{name: "open with admitted work is refused", initial: agentruntime.SessionOpen, pending: true, err: runtimestate.ErrConflict},
		{name: "completed is terminal", initial: agentruntime.SessionCompleted, err: runtimestate.ErrConflict},
		{name: "cancelled is terminal", initial: agentruntime.SessionCancelled, err: runtimestate.ErrConflict},
		{name: "failed is terminal", initial: agentruntime.SessionFailed, err: runtimestate.ErrConflict},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			command, err := compiler.CompileCancelSession(runtimestate.CancelSessionCommand{Scope: owner, IdempotencyKey: "cancel-" + strings.ReplaceAll(candidate.name, " ", "-"), SessionID: sessionID})
			if err != nil {
				t.Fatalf("compile cancel Session: %v", err)
			}
			state := runtimestate.RuntimeState{Sessions: []runtimestate.SessionRecord{{Tenant: tenant, Principal: principal, SessionID: sessionID, State: candidate.initial, Version: 1, CreatedAt: now, UpdatedAt: now, RetainUntil: now.Add(time.Hour)}}}
			if candidate.pending {
				state.Turns = []runtimestate.TurnRecord{{Tenant: tenant, Principal: principal, SessionID: sessionID, TurnID: agentruntime.TurnID("turn_1234567890ABCDEF"), State: agentruntime.TurnRunning}}
			}
			plan, err := planner.Plan(context.Background(), state, command)
			if !errors.Is(err, candidate.err) {
				t.Fatalf("cancel from %q error = %v, want %v", candidate.initial, err, candidate.err)
			}
			if candidate.err != nil {
				return
			}
			if plan.Result().Session.State != candidate.want || len(plan.Effects().Events) != 1 || plan.Effects().Events[0].Kind != agentruntime.EventSessionCancelled || !hasLifecyclePhases(plan.Effects(), "cancel_session", "attempted", "authorized", "committed", "terminal") {
				t.Fatalf("cancel from %q plan = %#v / %#v", candidate.initial, plan.Result(), plan.Effects())
			}
			replay, err := planner.Plan(context.Background(), plan.State(), command)
			if err != nil || replay.Result().Session != plan.Result().Session || !reflect.DeepEqual(replay.State(), plan.State()) {
				t.Fatalf("cancel replay = %#v / %#v / %v, want original Session and unchanged state", replay.Result(), replay.State(), err)
			}
		})
	}
}

func TestPlannerSessionCloseTransitionTableAndReplay(t *testing.T) {
	now := time.Date(2026, 8, 12, 1, 55, 0, 0, time.UTC)
	content, _, tenant, principal := testRuntimeContent(t)
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(fixedPlannerClock{now: now}, &uniquePlannerIDs{})
	if err != nil {
		t.Fatalf("new planner: %v", err)
	}
	owner := ownerScope(tenant, principal)
	sessionID := validSessionID(t)

	for _, candidate := range []struct {
		name    string
		initial agentruntime.SessionState
		pending bool
		want    agentruntime.SessionState
		events  []agentruntime.EventKind
		err     error
	}{
		{name: "drained open completes", initial: agentruntime.SessionOpen, want: agentruntime.SessionCompleted, events: []agentruntime.EventKind{agentruntime.EventSessionClosing, agentruntime.EventSessionCompleted}},
		{name: "open with admitted work closes", initial: agentruntime.SessionOpen, pending: true, want: agentruntime.SessionClosing, events: []agentruntime.EventKind{agentruntime.EventSessionClosing}},
		{name: "closing rejects second close", initial: agentruntime.SessionClosing, err: runtimestate.ErrConflict},
		{name: "completed is terminal", initial: agentruntime.SessionCompleted, err: runtimestate.ErrConflict},
		{name: "cancelled is terminal", initial: agentruntime.SessionCancelled, err: runtimestate.ErrConflict},
		{name: "failed is terminal", initial: agentruntime.SessionFailed, err: runtimestate.ErrConflict},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			command, err := compiler.CompileCloseSession(runtimestate.CloseSessionCommand{Scope: owner, IdempotencyKey: "close-" + strings.ReplaceAll(candidate.name, " ", "-"), SessionID: sessionID})
			if err != nil {
				t.Fatalf("compile close Session: %v", err)
			}
			state := runtimestate.RuntimeState{Sessions: []runtimestate.SessionRecord{{Tenant: tenant, Principal: principal, SessionID: sessionID, State: candidate.initial, Version: 1, CreatedAt: now, UpdatedAt: now, RetainUntil: now.Add(time.Hour)}}}
			if candidate.pending {
				state.Turns = []runtimestate.TurnRecord{{Tenant: tenant, Principal: principal, SessionID: sessionID, TurnID: agentruntime.TurnID("turn_1234567890ABCDEF"), State: agentruntime.TurnRunning}}
			}
			plan, err := planner.Plan(context.Background(), state, command)
			if !errors.Is(err, candidate.err) {
				t.Fatalf("close from %q error = %v, want %v", candidate.initial, err, candidate.err)
			}
			if candidate.err != nil {
				return
			}
			if plan.Result().Session.State != candidate.want || len(plan.Effects().Events) != len(candidate.events) || !hasLifecyclePhases(plan.Effects(), "close_session", "attempted", "authorized", "committed", "terminal") {
				t.Fatalf("close from %q plan = %#v / %#v", candidate.initial, plan.Result(), plan.Effects())
			}
			for index, kind := range candidate.events {
				if plan.Effects().Events[index].Kind != kind {
					t.Fatalf("close event %d = %q, want %q", index, plan.Effects().Events[index].Kind, kind)
				}
			}
			replay, err := planner.Plan(context.Background(), plan.State(), command)
			if err != nil || replay.Result().Session != plan.Result().Session || !reflect.DeepEqual(replay.State(), plan.State()) {
				t.Fatalf("close replay = %#v / %#v / %v, want original Session and unchanged state", replay.Result(), replay.State(), err)
			}
		})
	}
}

func TestPlannerSessionFailureTransitionTableAndReplay(t *testing.T) {
	now := time.Date(2026, 8, 12, 2, 5, 0, 0, time.UTC)
	content, _, tenant, principal := testRuntimeContent(t)
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(fixedPlannerClock{now: now}, &uniquePlannerIDs{})
	if err != nil {
		t.Fatalf("new planner: %v", err)
	}
	worker := workerScope(tenant, principal)
	sessionID := validSessionID(t)

	for _, candidate := range []struct {
		name    string
		initial agentruntime.SessionState
		want    agentruntime.SessionState
		pending bool
		err     error
	}{
		{name: "open becomes failed", initial: agentruntime.SessionOpen, want: agentruntime.SessionFailed},
		{name: "closing becomes failed", initial: agentruntime.SessionClosing, want: agentruntime.SessionFailed},
		{name: "open with admitted work is refused", initial: agentruntime.SessionOpen, pending: true, err: runtimestate.ErrConflict},
		{name: "completed is terminal", initial: agentruntime.SessionCompleted, err: runtimestate.ErrConflict},
		{name: "cancelled is terminal", initial: agentruntime.SessionCancelled, err: runtimestate.ErrConflict},
		{name: "failed is terminal", initial: agentruntime.SessionFailed, err: runtimestate.ErrConflict},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			command, err := compiler.CompileFailSession(runtimestate.FailSessionCommand{Scope: worker, IdempotencyKey: "fail-" + strings.ReplaceAll(candidate.name, " ", "-"), SessionID: sessionID})
			if err != nil {
				t.Fatalf("compile fail Session: %v", err)
			}
			state := runtimestate.RuntimeState{Sessions: []runtimestate.SessionRecord{{Tenant: tenant, Principal: principal, SessionID: sessionID, State: candidate.initial, Version: 1, CreatedAt: now, UpdatedAt: now, RetainUntil: now.Add(time.Hour)}}}
			if candidate.pending {
				state.Turns = []runtimestate.TurnRecord{{Tenant: tenant, Principal: principal, SessionID: sessionID, TurnID: agentruntime.TurnID("turn_1234567890ABCDEF"), State: agentruntime.TurnRunning}}
			}
			plan, err := planner.Plan(context.Background(), state, command)
			if !errors.Is(err, candidate.err) {
				t.Fatalf("fail from %q error = %v, want %v", candidate.initial, err, candidate.err)
			}
			if candidate.err != nil {
				return
			}
			if plan.Result().Session.State != candidate.want || len(plan.Effects().Events) != 1 || plan.Effects().Events[0].Kind != agentruntime.EventSessionFailed || !hasLifecyclePhases(plan.Effects(), "fail_session", "attempted", "authorized", "committed", "terminal") {
				t.Fatalf("fail from %q plan = %#v / %#v", candidate.initial, plan.Result(), plan.Effects())
			}
			replay, err := planner.Plan(context.Background(), plan.State(), command)
			if err != nil || replay.Result().Session != plan.Result().Session || !reflect.DeepEqual(replay.State(), plan.State()) {
				t.Fatalf("failure replay = %#v / %#v / %v, want original Session and unchanged state", replay.Result(), replay.State(), err)
			}
		})
	}
}

func TestCompilerReservesSessionTerminalAuthorities(t *testing.T) {
	content, _, tenant, principal := testRuntimeContent(t)
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	sessionID := validSessionID(t)
	if _, err := compiler.CompileCancelSession(runtimestate.CancelSessionCommand{Scope: workerScope(tenant, principal), IdempotencyKey: "wrong-worker-cancel", SessionID: sessionID}); err == nil {
		t.Fatal("worker compiled caller-owned Session cancellation")
	}
	if _, err := compiler.CompileFailSession(runtimestate.FailSessionCommand{Scope: ownerScope(tenant, principal), IdempotencyKey: "wrong-owner-fail", SessionID: sessionID}); err == nil {
		t.Fatal("caller compiled worker-owned Session failure")
	}
}

func TestPlannerAppendsAuditFactsAndDeduplicatesExactOperationReplay(t *testing.T) {
	content, _, tenant, principal := testRuntimeContent(t)
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(fixedPlannerClock{now: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)}, &uniquePlannerIDs{})
	if err != nil {
		t.Fatalf("new planner: %v", err)
	}
	body, err := content.StageAgentSpecificationBody(context.Background(), tenant, runtimecontent.AgentSpecificationBody{Name: "audit", ModelProfile: "balanced", Instructions: "retain audit facts"})
	if err != nil {
		t.Fatalf("stage Agent specification: %v", err)
	}
	register, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "audit-register", Specification: body})
	if err != nil {
		t.Fatalf("compile registration: %v", err)
	}
	registered, err := planner.Plan(context.Background(), runtimestate.RuntimeState{}, register)
	if err != nil {
		t.Fatalf("plan registration: %v", err)
	}
	before := append([]runtimestate.AuditFactRecord(nil), registered.State().Audit...)
	if len(before) == 0 {
		t.Fatal("registration emitted no audit facts")
	}

	create, err := compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: ownerScope(tenant, principal), IdempotencyKey: "audit-session", RevisionID: registered.Result().Revision.RevisionID})
	if err != nil {
		t.Fatalf("compile Session: %v", err)
	}
	created, err := planner.Plan(context.Background(), registered.State(), create)
	if err != nil {
		t.Fatalf("plan Session: %v", err)
	}
	if len(created.State().Audit) <= len(before) {
		t.Fatalf("audit count after new operation = %d, want append after %d", len(created.State().Audit), len(before))
	}
	for index, fact := range before {
		if created.State().Audit[index] != fact {
			t.Fatalf("prior audit fact %d changed from %#v to %#v", index, fact, created.State().Audit[index])
		}
	}

	replayed, err := planner.Plan(context.Background(), created.State(), create)
	if err != nil {
		t.Fatalf("replay exact Session operation: %v", err)
	}
	if len(replayed.State().Audit) != len(created.State().Audit) {
		t.Fatalf("replayed audit count = %d, want deduplicated %d", len(replayed.State().Audit), len(created.State().Audit))
	}
	for index, fact := range created.State().Audit {
		if replayed.State().Audit[index] != fact {
			t.Fatalf("replayed audit fact %d changed from %#v to %#v", index, fact, replayed.State().Audit[index])
		}
	}
}

func TestPlannerAssignsIndependentRetentionHorizonsByDataClass(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	content, _, tenant, principal := testRuntimeContent(t)
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	retention := classRetention{fallback: time.Hour, durations: map[runtimestate.DataClass]time.Duration{
		runtimestate.DataClassAgentRevision: 2 * time.Hour,
		runtimestate.DataClassSession:       3 * time.Hour,
		runtimestate.DataClassInput:         4 * time.Hour,
		runtimestate.DataClassTurn:          5 * time.Hour,
		runtimestate.DataClassEvent:         6 * time.Hour,
		runtimestate.DataClassAudit:         7 * time.Hour,
		runtimestate.DataClassOutbox:        8 * time.Hour,
		runtimestate.DataClassReceipt:       9 * time.Hour,
	}}
	planner, err := runtimestate.NewRuntimeStatePlanner(fixedPlannerClock{now: now}, &uniquePlannerIDs{}, runtimestate.WithRetentionPolicy(retention))
	if err != nil {
		t.Fatal(err)
	}
	body, err := content.StageAgentSpecificationBody(context.Background(), tenant, runtimecontent.AgentSpecificationBody{Name: "retention", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	register, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "register", Specification: body})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := planner.Plan(context.Background(), runtimestate.RuntimeState{}, register)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := registered.Result().Revision.RetainUntil, now.Add(2*time.Hour); !got.Equal(want) {
		t.Fatalf("Agent retention = %s, want %s", got, want)
	}
	if got, want := registered.Effects().Audit[0].RetentionUntil, now.Add(7*time.Hour); !got.Equal(want) {
		t.Fatalf("Agent audit retention = %s, want %s", got, want)
	}
	if got, want := registered.Effects().Outbox[0].RetentionUntil, now.Add(8*time.Hour); !got.Equal(want) {
		t.Fatalf("Agent outbox retention = %s, want %s", got, want)
	}
	if got, want := registered.Result().Receipt.RetentionUntil, now.Add(9*time.Hour); !got.Equal(want) {
		t.Fatalf("Agent receipt retention = %s, want %s", got, want)
	}
	create, err := compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: ownerScope(tenant, principal), IdempotencyKey: "session", RevisionID: registered.Result().Revision.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	created, err := planner.Plan(context.Background(), registered.State(), create)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := created.Result().Session.RetainUntil, now.Add(3*time.Hour); !got.Equal(want) {
		t.Fatalf("Session retention = %s, want %s", got, want)
	}
	if got, want := created.Effects().Events[0].RetentionUntil, now.Add(6*time.Hour); !got.Equal(want) {
		t.Fatalf("Session event retention = %s, want %s", got, want)
	}
	input, err := content.StageInputEnvelope(context.Background(), tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "retention"}})
	if err != nil {
		t.Fatal(err)
	}
	admit, err := compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: ownerScope(tenant, principal), IdempotencyKey: "input", SessionID: created.Result().Session.SessionID, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := planner.Plan(context.Background(), created.State(), admit)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := accepted.Result().Input.RetentionUntil, now.Add(4*time.Hour); !got.Equal(want) {
		t.Fatalf("Input retention = %s, want %s", got, want)
	}
	if got, want := accepted.Result().Turn.RetentionUntil, now.Add(5*time.Hour); !got.Equal(want) {
		t.Fatalf("Turn retention = %s, want %s", got, want)
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

func TestPlannerRetriesModelInvocationWithinOneRunningTurn(t *testing.T) {
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
	state := runtimestate.RuntimeState{
		Sessions: []runtimestate.SessionRecord{{Tenant: tenant, Principal: principal, SessionID: sessionID, State: agentruntime.SessionOpen, Version: 1, CreatedAt: now, UpdatedAt: now, RetainUntil: now.Add(time.Hour)}},
		Turns:    []runtimestate.TurnRecord{{Tenant: tenant, Principal: principal, SessionID: sessionID, TurnID: turnID, State: agentruntime.TurnRunning, Version: 1, RetentionUntil: now.Add(time.Hour)}},
	}
	beginFirst, err := compiler.CompileBeginInvocationAttempt(runtimestate.BeginInvocationAttemptCommand{Scope: workerScope(tenant, principal), IdempotencyKey: "retry-first", SessionID: sessionID, TurnID: turnID, OperationID: "model-operation-1", ExpectedSessionVersion: state.Sessions[0].Version, ExpectedTurnVersion: state.Turns[0].Version})
	if err != nil {
		t.Fatalf("compile first invocation: %v", err)
	}
	firstPlan, err := planner.Plan(context.Background(), state, beginFirst)
	if err != nil {
		t.Fatalf("plan first invocation: %v", err)
	}
	state = firstPlan.State()
	first := firstPlan.Result().Invocation
	failure := &agentruntime.Failure{Code: agentruntime.FailureUnavailable, Message: "model temporarily unavailable", Retryable: true}
	recordFirst, err := compiler.CompileRecordInvocationOutcome(runtimestate.RecordInvocationOutcomeCommand{Scope: workerScope(tenant, principal), IdempotencyKey: "retry-first-outcome", SessionID: sessionID, TurnID: turnID, OperationID: first.OperationID, Ordinal: first.Ordinal, Fence: first.Fence, Outcome: runtimestate.InvocationFailed, Failure: failure, ExpectedSessionVersion: state.Sessions[0].Version, ExpectedTurnVersion: state.Turns[0].Version})
	if err != nil {
		t.Fatalf("compile retryable outcome: %v", err)
	}
	failedPlan, err := planner.Plan(context.Background(), state, recordFirst)
	if err != nil {
		t.Fatalf("plan retryable outcome: %v", err)
	}
	state = failedPlan.State()
	if state.Turns[0].State != agentruntime.TurnRunning || len(state.Invocations) != 1 || state.Invocations[0].State != runtimestate.InvocationFailed {
		t.Fatalf("retryable first attempt state = %#v / %#v, want one failed attempt and a running Turn", state.Invocations, state.Turns)
	}
	beginSecond, err := compiler.CompileBeginInvocationAttempt(runtimestate.BeginInvocationAttemptCommand{Scope: workerScope(tenant, principal), IdempotencyKey: "retry-second", SessionID: sessionID, TurnID: turnID, OperationID: "model-operation-2", ExpectedSessionVersion: state.Sessions[0].Version, ExpectedTurnVersion: state.Turns[0].Version, ExpectedFence: first.Fence})
	if err != nil {
		t.Fatalf("compile retry invocation: %v", err)
	}
	secondPlan, err := planner.Plan(context.Background(), state, beginSecond)
	if err != nil {
		t.Fatalf("plan retry invocation: %v", err)
	}
	second := secondPlan.Result().Invocation
	if len(secondPlan.State().Turns) != 1 || secondPlan.State().Turns[0].State != agentruntime.TurnRunning || len(secondPlan.State().Invocations) != 2 || second.TurnID != turnID || second.Ordinal != first.Ordinal+1 || second.Fence != first.Fence+1 || second.State != runtimestate.InvocationIntent {
		t.Fatalf("retry invocation = %#v state=%#v, want second fenced attempt on the same running Turn", second, secondPlan.State())
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

func TestPlannerDoesNotRecursivelyAuditAuditFactRouteLifecycle(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	content, _, tenant, _ := testRuntimeContent(t)
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(fixedPlannerClock{now: now}, &uniquePlannerIDs{})
	if err != nil {
		t.Fatalf("new planner: %v", err)
	}
	handoff, err := content.StageAgentSpecificationBody(context.Background(), tenant, runtimecontent.AgentSpecificationBody{Name: "audit-route", ModelProfile: "balanced", Instructions: "avoid recursive audit routes"})
	if err != nil {
		t.Fatalf("stage registration body: %v", err)
	}
	registration, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{
		Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "audit-route-registration",
		Specification: handoff,
	})
	if err != nil {
		t.Fatalf("compile registration: %v", err)
	}
	initial, err := planner.Plan(context.Background(), runtimestate.RuntimeState{}, registration)
	if err != nil {
		t.Fatalf("plan registration: %v", err)
	}
	var route runtimestate.OutboxRecord
	for _, candidate := range initial.State().Outbox {
		if candidate.Aggregate == "audit_fact" {
			route = candidate
			break
		}
	}
	if route.OutboxID == "" || route.AuditFactID == "" {
		t.Fatalf("registration did not create an audit route: %#v", initial.State().Outbox)
	}
	claim, err := compiler.CompileClaimOutbox(runtimestate.ClaimOutboxCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher}, IdempotencyKey: "claim-audit-route", OutboxID: route.OutboxID, ExpectedVersion: route.Version, Claimer: "audit-publisher", ClaimUntil: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("compile audit route claim: %v", err)
	}
	claimed, err := planner.Plan(context.Background(), initial.State(), claim)
	if err != nil {
		t.Fatalf("plan audit route claim: %v", err)
	}
	if len(claimed.Effects().Audit) != 0 || len(claimed.Effects().Outbox) != 0 || len(claimed.State().Audit) != len(initial.State().Audit) || len(claimed.State().Outbox) != len(initial.State().Outbox) {
		t.Fatalf("audit route claim recursively created lifecycle records: %#v", claimed.Effects())
	}
	ack, err := compiler.CompileAcknowledgeOutbox(runtimestate.AcknowledgeOutboxCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher}, IdempotencyKey: "ack-audit-route", OutboxID: route.OutboxID, ExpectedVersion: claimed.Result().Outbox.Version, Claimer: "audit-publisher", PublishedAt: now})
	if err != nil {
		t.Fatalf("compile audit route acknowledgement: %v", err)
	}
	acknowledged, err := planner.Plan(context.Background(), claimed.State(), ack)
	if err != nil {
		t.Fatalf("plan audit route acknowledgement: %v", err)
	}
	if len(acknowledged.Effects().Audit) != 0 || len(acknowledged.Effects().Outbox) != 0 || len(acknowledged.State().Audit) != len(claimed.State().Audit) || len(acknowledged.State().Outbox) != len(claimed.State().Outbox) {
		t.Fatalf("audit route acknowledgement recursively created lifecycle records: %#v", acknowledged.Effects())
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
	if result.Artifact.ArtifactID == "" || result.Artifact.Reference.Digest == "" || len(plan.Effects().Audit) != 4 || len(plan.Effects().Outbox) != 5 || plan.Effects().Outbox[0].AuditFactID != plan.Effects().Audit[0].AuditFactID || !hasLifecyclePhases(plan.Effects(), "register_artifact", "attempted", "authorized", "committed") {
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

func TestPlannerAppendsConversationOnlyAtExpectedVersionAndReplaysIdempotently(t *testing.T) {
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
	entry, err := content.StageConversationEntry(context.Background(), tenant, []byte("model semantic context"))
	if err != nil {
		t.Fatalf("stage conversation: %v", err)
	}
	command, err := compiler.CompileAppendConversation(runtimestate.AppendConversationCommand{Scope: workerScope(tenant, principal), IdempotencyKey: "conversation-1", SessionID: sessionID, ExpectedVersion: 0, Entry: entry})
	if err != nil {
		t.Fatalf("compile conversation: %v", err)
	}
	plan, err := planner.Plan(context.Background(), state, command)
	if err != nil {
		t.Fatalf("plan conversation: %v", err)
	}
	if result := plan.Result(); result.Conversation.Version != 1 || len(plan.Effects().Audit) != 4 || len(plan.Effects().Outbox) != 5 || plan.Effects().Outbox[0].AuditFactID != plan.Effects().Audit[0].AuditFactID || !hasLifecyclePhases(plan.Effects(), "append_conversation", "attempted", "authorized", "committed") {
		t.Fatalf("conversation plan = %#v / %#v", result, plan.Effects())
	}
	if replay, err := planner.Plan(context.Background(), plan.State(), command); err != nil || replay.Result().Conversation != plan.Result().Conversation {
		t.Fatalf("conversation replay = %#v, %v", replay.Result(), err)
	}
	other, err := content.StageConversationEntry(context.Background(), tenant, []byte("racing writer"))
	if err != nil {
		t.Fatalf("stage racing entry: %v", err)
	}
	conflict, err := compiler.CompileAppendConversation(runtimestate.AppendConversationCommand{Scope: workerScope(tenant, principal), IdempotencyKey: "conversation-2", SessionID: sessionID, ExpectedVersion: 0, Entry: other})
	if err != nil {
		t.Fatalf("compile stale conversation: %v", err)
	}
	if _, err := planner.Plan(context.Background(), plan.State(), conflict); !errors.Is(err, runtimestate.ErrConflict) {
		t.Fatalf("stale append error = %v, want conflict", err)
	}
}

func TestPlannerPersistsToolIntentBeforeApprovalDecision(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	content, _, tenant, principal := testRuntimeContent(t)
	compiler, _ := runtimestate.NewCompiler(content)
	planner, _ := runtimestate.NewRuntimeStatePlanner(fixedPlannerClock{now: now}, &uniquePlannerIDs{})
	session := validSessionID(t)
	turn := agentruntime.TurnID("turn_1234567890ABCDEF")
	state := runtimestate.RuntimeState{Sessions: []runtimestate.SessionRecord{{Tenant: tenant, Principal: principal, SessionID: session, State: agentruntime.SessionOpen, CreatedAt: now, UpdatedAt: now}}, Turns: []runtimestate.TurnRecord{{Tenant: tenant, Principal: principal, SessionID: session, TurnID: turn, State: agentruntime.TurnRunning}}}
	digest := "sha256:" + strings.Repeat("a", 64)
	descriptor, err := content.StageToolActionDescriptor(context.Background(), tenant, []byte("canonical tool action"))
	if err != nil {
		t.Fatal(err)
	}
	intent, err := compiler.CompileRecordToolIntent(runtimestate.RecordToolIntentCommand{Scope: workerScope(tenant, principal), IdempotencyKey: "intent", SessionID: session, TurnID: turn, ToolCallID: "tcall_1234567890ABCDEF", ToolName: "write", ActionDigest: digest, PolicyRevisionDigest: digest, Descriptor: descriptor})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.Plan(context.Background(), state, intent)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := compiler.CompileRequestApproval(runtimestate.RequestApprovalCommand{Scope: workerScope(tenant, principal), IdempotencyKey: "approval", SessionID: session, TurnID: turn, ToolCallID: "tcall_1234567890ABCDEF", ApprovalID: "appr_1234567890ABCDEF", ActionDigest: digest, PolicyRevisionDigest: digest, CapabilityDigest: digest, MaximumUses: 1, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	plan, err = planner.Plan(context.Background(), plan.State(), approval)
	if err != nil || len(plan.State().Approvals) != 1 {
		t.Fatalf("approval=%v state=%#v", err, plan.State().Approvals)
	}
	decision, err := compiler.CompileDecideApproval(runtimestate.DecideApprovalCommand{Scope: ownerScope(tenant, principal), IdempotencyKey: "decision", ApprovalID: "appr_1234567890ABCDEF", Decision: "approved"})
	if err != nil {
		t.Fatal(err)
	}
	plan, err = planner.Plan(context.Background(), plan.State(), decision)
	if err != nil || plan.State().Approvals[0].State != "approved" || len(plan.Effects().Audit) != 4 || len(plan.Effects().Events) != 1 || plan.Effects().Events[0].Kind != agentruntime.EventApprovalResolved || len(plan.Effects().Outbox) != 4 || !hasLifecyclePhases(plan.Effects(), "decide_approval", "attempted", "authorized", "committed") {
		t.Fatalf("decision=%v %#v", err, plan.State().Approvals)
	}
	if len(plan.State().Grants) != 1 {
		t.Fatalf("approved decision grants = %#v; want one bounded capability grant", plan.State().Grants)
	}
	grant := plan.State().Grants[0]
	if grant.ToolCallID != "tcall_1234567890ABCDEF" || grant.CapabilityDigest != digest || grant.MaximumUses != 1 || grant.Uses != 0 || !grant.ExpiresAt.Equal(now.Add(time.Hour)) || grant.PolicyRevisionDigest != digest {
		t.Fatalf("capability grant = %#v; want proposal-bounded unused grant", grant)
	}
}

func TestPlannerConsumesApprovedCapabilityOnlyWithinItsPolicyAndExpiry(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	content, _, tenant, principal := testRuntimeContent(t)
	compiler, _ := runtimestate.NewCompiler(content)
	planner, _ := runtimestate.NewRuntimeStatePlanner(fixedPlannerClock{now: now}, &uniquePlannerIDs{})
	session := validSessionID(t)
	turn := agentruntime.TurnID("turn_1234567890ABCDEF")
	digest := "sha256:" + strings.Repeat("a", 64)
	state := runtimestate.RuntimeState{
		Sessions:    []runtimestate.SessionRecord{{Tenant: tenant, Principal: principal, SessionID: session, State: agentruntime.SessionOpen, CreatedAt: now, UpdatedAt: now}},
		Turns:       []runtimestate.TurnRecord{{Tenant: tenant, Principal: principal, SessionID: session, TurnID: turn, State: agentruntime.TurnRunning}},
		ToolIntents: []runtimestate.ToolIntentRecord{{Tenant: tenant, Principal: principal, SessionID: session, TurnID: turn, ToolCallID: "tcall_1234567890ABCDEF", ActionDigest: digest, PolicyRevisionDigest: digest, CreatedAt: now}},
		Grants:      []runtimestate.CapabilityGrantRecord{{Tenant: tenant, Principal: principal, GrantID: "grant_1234567890ABCDE", ToolCallID: "tcall_1234567890ABCDEF", CapabilityDigest: digest, MaximumUses: 1, ExpiresAt: now.Add(time.Hour), PolicyRevisionDigest: digest, CreatedAt: now}},
	}
	consume, err := compiler.CompileConsumeCapabilityGrant(runtimestate.ConsumeCapabilityGrantCommand{Scope: workerScope(tenant, principal), IdempotencyKey: "use-grant", SessionID: session, TurnID: turn, ToolCallID: "tcall_1234567890ABCDEF", GrantID: "grant_1234567890ABCDE", PolicyRevisionDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.Plan(context.Background(), state, consume)
	if err != nil || plan.State().Grants[0].Uses != 1 || len(plan.Effects().Audit) != 4 || !hasLifecyclePhases(plan.Effects(), "consume_capability_grant", "attempted", "authorized", "committed") {
		t.Fatalf("consume approved capability = %#v, %v", plan.State().Grants, err)
	}
	begin, err := compiler.CompileBeginToolExecution(runtimestate.BeginToolExecutionCommand{Scope: workerScope(tenant, principal), IdempotencyKey: "begin-tool", SessionID: session, TurnID: turn, ToolCallID: "tcall_1234567890ABCDEF", GrantID: "grant_1234567890ABCDE", OperationID: "tool-operation-1"})
	if err != nil {
		t.Fatal(err)
	}
	toolPlan, err := planner.Plan(context.Background(), plan.State(), begin)
	if err != nil || len(toolPlan.State().ToolExecutions) != 1 || toolPlan.State().ToolExecutions[0].State != runtimestate.ToolExecutionIntent || len(toolPlan.Effects().Outbox) != 5 || toolPlan.Effects().Outbox[0].AuditFactID != toolPlan.Effects().Audit[0].AuditFactID || toolPlan.Effects().Outbox[4].ToolCallID != "tcall_1234567890ABCDEF" || !hasLifecyclePhases(toolPlan.Effects(), "begin_tool_execution", "attempted", "authorized", "committed") {
		t.Fatalf("tool execution intent = %#v / %#v, %v", toolPlan.State().ToolExecutions, toolPlan.Effects(), err)
	}
	if _, err := planner.Plan(context.Background(), plan.State(), consume); err != nil {
		t.Fatalf("replay consume capability: %v", err)
	}
	second, err := compiler.CompileConsumeCapabilityGrant(runtimestate.ConsumeCapabilityGrantCommand{Scope: workerScope(tenant, principal), IdempotencyKey: "use-grant-again", SessionID: session, TurnID: turn, ToolCallID: "tcall_1234567890ABCDEF", GrantID: "grant_1234567890ABCDE", PolicyRevisionDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := planner.Plan(context.Background(), plan.State(), second); !errors.Is(err, runtimestate.ErrConflict) {
		t.Fatalf("exhausted capability error = %v, want conflict", err)
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

func hasLifecyclePhases(effects runtimestate.EffectSet, command string, phases ...string) bool {
	seen := map[string]bool{}
	for _, fact := range effects.Audit {
		seen[fact.Kind] = true
	}
	for _, phase := range phases {
		if !seen[command+"."+phase] {
			return false
		}
	}
	for _, route := range effects.Outbox {
		if route.Aggregate != "audit_fact" || route.AuditFactID == "" {
			continue
		}
		for _, fact := range effects.Audit {
			if fact.AuditFactID == route.AuditFactID {
				seen["route:"+fact.Kind] = true
			}
		}
	}
	for _, phase := range phases {
		if !seen["route:"+command+"."+phase] {
			return false
		}
	}
	return true
}

type fixedPlannerClock struct{ now time.Time }

func (clock fixedPlannerClock) Now() time.Time { return clock.now }

type classRetention struct {
	fallback  time.Duration
	durations map[runtimestate.DataClass]time.Duration
}

func (policy classRetention) RetainUntil(now time.Time) time.Time { return now.Add(policy.fallback) }

func (policy classRetention) RetainClassUntil(class runtimestate.DataClass, now time.Time) time.Time {
	if duration, ok := policy.durations[class]; ok {
		return now.Add(duration)
	}
	return policy.RetainUntil(now)
}

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
