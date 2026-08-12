package runtimeorchestration_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimeorchestration"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"
)

func TestSessionWorkflowDoesNotStartAWaitingApprovalTurn(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 11, 21, 0, 0, 0, time.UTC)
	content, err := runtimecontent.New("workflow-pending-approval", &publisherObjects{values: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("alice")
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
	ownerScope := runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}
	workerScope := runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}
	revisionBody, err := content.StageAgentSpecificationBody(ctx, tenant, runtimecontent.AgentSpecificationBody{Name: "waiting", ModelProfile: "balanced", Instructions: "wait for approval"})
	if err != nil {
		t.Fatal(err)
	}
	registration, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "waiting-register", Specification: revisionBody})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := store.Apply(ctx, registration)
	if err != nil {
		t.Fatal(err)
	}
	create, err := compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: ownerScope, IdempotencyKey: "waiting-session", RevisionID: registered.Result().Revision.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.Apply(ctx, create)
	if err != nil {
		t.Fatal(err)
	}
	input, err := content.StageInputEnvelope(ctx, tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "hold this tool call"}})
	if err != nil {
		t.Fatal(err)
	}
	admit, err := compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: ownerScope, IdempotencyKey: "waiting-input", SessionID: session.Result().Session.SessionID, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := store.Apply(ctx, admit)
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	descriptor, err := content.StageToolActionDescriptor(ctx, tenant, []byte("private pending descriptor"))
	if err != nil {
		t.Fatal(err)
	}
	intent, err := compiler.CompileRecordToolIntent(runtimestate.RecordToolIntentCommand{Scope: workerScope, IdempotencyKey: "waiting-intent", SessionID: session.Result().Session.SessionID, TurnID: accepted.Result().Turn.TurnID, ToolCallID: "tcall_1234567890ABCDEF", ToolName: "write", ActionDigest: digest, PolicyRevisionDigest: digest, Descriptor: descriptor})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, intent); err != nil {
		t.Fatal(err)
	}
	pending, err := compiler.CompileRequestApproval(runtimestate.RequestApprovalCommand{Scope: workerScope, IdempotencyKey: "waiting-approval", SessionID: session.Result().Session.SessionID, TurnID: accepted.Result().Turn.TurnID, ToolCallID: "tcall_1234567890ABCDEF", ApprovalID: "appr_1234567890ABCDEF", ActionDigest: digest, PolicyRevisionDigest: digest, CapabilityDigest: digest, ActionVerb: "write", ActionTarget: "workspace-service", MaximumUses: 1, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, pending); err != nil {
		t.Fatal(err)
	}
	state, err := store.LoadRuntimeState(ctx, workerScope)
	if err != nil || len(state.Turns) != 1 || state.Turns[0].State != agentruntime.TurnWaitingForApproval || len(state.Approvals) != 1 || state.Approvals[0].State != "pending" {
		t.Fatalf("durable pending approval state = %#v, %v", state, err)
	}
	var inputRoute runtimestate.OutboxRecord
	for _, record := range state.Outbox {
		if record.EventKind == agentruntime.EventInputAccepted && record.SessionID == session.Result().Session.SessionID && record.TurnID == accepted.Result().Turn.TurnID {
			inputRoute = record
			break
		}
	}
	if inputRoute.OutboxID == "" {
		t.Fatalf("input admission did not retain a workflow route: %#v", state.Outbox)
	}
	claim, err := compiler.CompileClaimOutbox(runtimestate.ClaimOutboxCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher}, IdempotencyKey: "waiting-input-claim", OutboxID: inputRoute.OutboxID, ExpectedVersion: inputRoute.Version, Claimer: "workflow-pending-test", ClaimUntil: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.Apply(ctx, claim)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := runtimeorchestration.NewDurableStateDispatcherWithInvocationScheduler(store, compiler, planner, nil)
	if err != nil {
		t.Fatal(err)
	}
	activities, err := runtimeorchestration.NewActivities(dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	var suite testsuite.WorkflowTestSuite
	environment := suite.NewTestWorkflowEnvironment()
	environment.RegisterActivityWithOptions(activities.DispatchStateCommand, activity.RegisterOptions{Name: runtimeorchestration.DispatchStateCommandActivity})
	command := runtimeorchestration.Command{Tenant: string(tenant), OutboxID: string(claimed.Result().Outbox.OutboxID), SessionID: string(session.Result().Session.SessionID), Kind: runtimeorchestration.CommandInputAccepted, Sequence: claimed.Result().Outbox.EventSequence}
	environment.RegisterDelayedCallback(func() {
		environment.SignalWorkflow(runtimeorchestration.SessionCommandSignal, command)
	}, 0)
	environment.ExecuteWorkflow(runtimeorchestration.SessionWorkflow, runtimeorchestration.WorkflowInput{SessionID: string(session.Result().Session.SessionID), ContinueAfter: 1})
	if err := environment.GetWorkflowError(); err == nil {
		t.Fatal("workflow error = nil, want Continue-As-New after the pending input route")
	} else {
		var execution *temporal.WorkflowExecutionError
		if !errors.As(err, &execution) || !workflow.IsContinueAsNewError(errors.Unwrap(execution)) {
			t.Fatalf("workflow error = %v, want Continue-As-New after the pending input route", err)
		}
	}
	state, err = store.LoadRuntimeState(ctx, workerScope)
	if err != nil || len(state.Invocations) != 0 || state.Turns[0].State != agentruntime.TurnWaitingForApproval {
		t.Fatalf("workflow dispatched a pending approval turn: state=%#v err=%v", state, err)
	}
}

func TestSessionWorkflowDispatchesOrderedStateCommandsAndContinuesAsNew(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	environment := suite.NewTestWorkflowEnvironment()
	var dispatched []runtimeorchestration.Command
	environment.RegisterActivityWithOptions(func(_ context.Context, command runtimeorchestration.Command) error {
		dispatched = append(dispatched, command)
		return nil
	}, activity.RegisterOptions{Name: runtimeorchestration.DispatchStateCommandActivity})
	environment.RegisterDelayedCallback(func() {
		environment.SignalWorkflow(runtimeorchestration.SessionCommandSignal, runtimeorchestration.Command{Tenant: "tenant-a", OutboxID: "outbox-1", SessionID: "sess_1234567890ABCDEF", Kind: runtimeorchestration.CommandInputAccepted, Sequence: 1})
	}, 0)
	environment.RegisterDelayedCallback(func() {
		environment.SignalWorkflow(runtimeorchestration.SessionCommandSignal, runtimeorchestration.Command{Tenant: "tenant-a", OutboxID: "outbox-1", SessionID: "sess_1234567890ABCDEF", Kind: runtimeorchestration.CommandInputAccepted, Sequence: 1})
	}, 0)
	environment.RegisterDelayedCallback(func() {
		environment.SignalWorkflow(runtimeorchestration.SessionCommandSignal, runtimeorchestration.Command{Tenant: "tenant-a", OutboxID: "outbox-2", SessionID: "sess_1234567890ABCDEF", Kind: runtimeorchestration.CommandTurnCancelled, Sequence: 2})
	}, 0)
	environment.ExecuteWorkflow(runtimeorchestration.SessionWorkflow, runtimeorchestration.WorkflowInput{SessionID: "sess_1234567890ABCDEF", ContinueAfter: 2})
	if !environment.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}
	if err := environment.GetWorkflowError(); err == nil {
		t.Fatal("workflow error = nil, want Continue-As-New")
	} else {
		var execution *temporal.WorkflowExecutionError
		if !errors.As(err, &execution) || !workflow.IsContinueAsNewError(errors.Unwrap(execution)) {
			t.Fatalf("workflow error = %v, want Continue-As-New", err)
		}
	}
	if len(dispatched) != 2 || dispatched[0].Sequence != 1 || dispatched[1].Sequence != 2 {
		t.Fatalf("dispatched = %#v, want ordered commands", dispatched)
	}
}

func TestSessionWorkflowRejectsACommandForAnotherSession(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	environment := suite.NewTestWorkflowEnvironment()
	environment.RegisterDelayedCallback(func() {
		environment.SignalWorkflow(runtimeorchestration.SessionCommandSignal, runtimeorchestration.Command{Tenant: "tenant-a", OutboxID: "outbox-1", SessionID: "sess_ABCDEFGHIJ123456", Kind: runtimeorchestration.CommandInputAccepted, Sequence: 1})
	}, 0)
	environment.ExecuteWorkflow(runtimeorchestration.SessionWorkflow, runtimeorchestration.WorkflowInput{SessionID: "sess_1234567890ABCDEF", ContinueAfter: 2})
	if err := environment.GetWorkflowError(); err == nil {
		t.Fatal("workflow error = nil, want command binding failure")
	}
}

func TestSessionWorkflowRejectsOversizedPrivatePayloads(t *testing.T) {
	t.Run("continuation state", func(t *testing.T) {
		var suite testsuite.WorkflowTestSuite
		environment := suite.NewTestWorkflowEnvironment()
		environment.ExecuteWorkflow(runtimeorchestration.SessionWorkflow, runtimeorchestration.WorkflowInput{SessionID: strings.Repeat("s", 257), ContinueAfter: 1})
		if err := environment.GetWorkflowError(); err == nil || !strings.Contains(err.Error(), "invalid runtime Session workflow input") {
			t.Fatalf("workflow error = %v, want bounded continuation-state refusal", err)
		}
	})

	t.Run("durable command", func(t *testing.T) {
		var suite testsuite.WorkflowTestSuite
		environment := suite.NewTestWorkflowEnvironment()
		environment.RegisterDelayedCallback(func() {
			environment.SignalWorkflow(runtimeorchestration.SessionCommandSignal, runtimeorchestration.Command{Tenant: "tenant-a", OutboxID: strings.Repeat("o", 257), SessionID: "sess_1234567890ABCDEF", Kind: runtimeorchestration.CommandInputAccepted, Sequence: 1})
		}, 0)
		environment.ExecuteWorkflow(runtimeorchestration.SessionWorkflow, runtimeorchestration.WorkflowInput{SessionID: "sess_1234567890ABCDEF", ContinueAfter: 1})
		if err := environment.GetWorkflowError(); err == nil || !strings.Contains(err.Error(), "invalid runtime Session workflow command") {
			t.Fatalf("workflow error = %v, want bounded command refusal", err)
		}
	})
}

func TestSessionWorkflowFinalizesAfterDurableSessionCompletedRoute(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	environment := suite.NewTestWorkflowEnvironment()
	var dispatched []runtimeorchestration.Command
	environment.RegisterActivityWithOptions(func(_ context.Context, command runtimeorchestration.Command) error {
		dispatched = append(dispatched, command)
		return nil
	}, activity.RegisterOptions{Name: runtimeorchestration.DispatchStateCommandActivity})
	environment.RegisterDelayedCallback(func() {
		environment.SignalWorkflow(runtimeorchestration.SessionCommandSignal, runtimeorchestration.Command{Tenant: "tenant-a", OutboxID: "outbox-1", SessionID: "sess_1234567890ABCDEF", Kind: runtimeorchestration.CommandInputAccepted, Sequence: 1})
	}, 0)
	environment.RegisterDelayedCallback(func() {
		environment.SignalWorkflow(runtimeorchestration.SessionCommandSignal, runtimeorchestration.Command{Tenant: "tenant-a", OutboxID: "outbox-2", SessionID: "sess_1234567890ABCDEF", Kind: runtimeorchestration.CommandSessionCompleted, Sequence: 2})
	}, 0)
	environment.ExecuteWorkflow(runtimeorchestration.SessionWorkflow, runtimeorchestration.WorkflowInput{SessionID: "sess_1234567890ABCDEF", ContinueAfter: 100})
	if err := environment.GetWorkflowError(); err != nil {
		t.Fatalf("workflow error = %v, want terminal completion", err)
	}
	if len(dispatched) != 2 || dispatched[1].Kind != runtimeorchestration.CommandSessionCompleted {
		t.Fatalf("dispatched = %#v, want durable completion route", dispatched)
	}
}

func TestSessionWorkflowKeepsApprovalSandboxAndEventFinalizationOrdered(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	environment := suite.NewTestWorkflowEnvironment()
	var dispatched []runtimeorchestration.Command
	environment.RegisterActivityWithOptions(func(_ context.Context, command runtimeorchestration.Command) error {
		dispatched = append(dispatched, command)
		return nil
	}, activity.RegisterOptions{Name: runtimeorchestration.DispatchStateCommandActivity})
	commands := []runtimeorchestration.Command{
		{Tenant: "tenant-a", OutboxID: "outbox-input", SessionID: "sess_1234567890ABCDEF", Kind: runtimeorchestration.CommandInputAccepted, Sequence: 1},
		{Tenant: "tenant-a", OutboxID: "outbox-approval", SessionID: "sess_1234567890ABCDEF", Kind: runtimeorchestration.CommandApprovalResolved, Sequence: 2},
		{Tenant: "tenant-a", OutboxID: "outbox-sandbox", SessionID: "sess_1234567890ABCDEF", Kind: runtimeorchestration.CommandSandboxOperationFinalized, Sequence: 3},
		{Tenant: "tenant-a", OutboxID: "outbox-complete", SessionID: "sess_1234567890ABCDEF", Kind: runtimeorchestration.CommandSessionCompleted, Sequence: 4},
	}
	for _, command := range commands {
		command := command
		environment.RegisterDelayedCallback(func() {
			environment.SignalWorkflow(runtimeorchestration.SessionCommandSignal, command)
		}, 0)
	}
	environment.ExecuteWorkflow(runtimeorchestration.SessionWorkflow, runtimeorchestration.WorkflowInput{SessionID: "sess_1234567890ABCDEF", ContinueAfter: 100})
	if err := environment.GetWorkflowError(); err != nil {
		t.Fatalf("workflow error = %v, want terminal completion", err)
	}
	if len(dispatched) != len(commands) {
		t.Fatalf("dispatched = %#v, want every durable lifecycle route", dispatched)
	}
	for index, command := range commands {
		if dispatched[index] != command {
			t.Fatalf("dispatched[%d] = %#v, want %#v", index, dispatched[index], command)
		}
	}
}

// TestSessionWorkflowExercisesEveryOwnedTerminalEffectRoute is the TMP-010
// test-environment matrix. It makes the private workflow own only ordered,
// already-durable route observation: approval, model terminal/gap finalization,
// sandbox finalization, explicit cancellation, and close/drain each flow to
// the same durable completion boundary without a workflow-local side effect.
func TestSessionWorkflowExercisesEveryOwnedTerminalEffectRoute(t *testing.T) {
	for _, scenario := range []struct {
		name  string
		kinds []runtimeorchestration.CommandKind
	}{
		{name: "approved sandbox finalization", kinds: []runtimeorchestration.CommandKind{runtimeorchestration.CommandInputAccepted, runtimeorchestration.CommandApprovalResolved, runtimeorchestration.CommandSandboxOperationFinalized, runtimeorchestration.CommandSessionCompleted}},
		{name: "normalized model success", kinds: []runtimeorchestration.CommandKind{runtimeorchestration.CommandInputAccepted, runtimeorchestration.CommandTurnSucceeded, runtimeorchestration.CommandSessionCompleted}},
		{name: "model producer gap terminal failure", kinds: []runtimeorchestration.CommandKind{runtimeorchestration.CommandInputAccepted, runtimeorchestration.CommandTurnFailed, runtimeorchestration.CommandSessionCompleted}},
		{name: "explicit cancellation", kinds: []runtimeorchestration.CommandKind{runtimeorchestration.CommandInputAccepted, runtimeorchestration.CommandTurnCancelled, runtimeorchestration.CommandSessionCompleted}},
		{name: "closing drain", kinds: []runtimeorchestration.CommandKind{runtimeorchestration.CommandInputAccepted, runtimeorchestration.CommandSessionClosing, runtimeorchestration.CommandSessionCompleted}},
		{name: "terminal session cancellation", kinds: []runtimeorchestration.CommandKind{runtimeorchestration.CommandSessionCancelled}},
		{name: "terminal session failure", kinds: []runtimeorchestration.CommandKind{runtimeorchestration.CommandSessionFailed}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var suite testsuite.WorkflowTestSuite
			environment := suite.NewTestWorkflowEnvironment()
			var dispatched []runtimeorchestration.Command
			environment.RegisterActivityWithOptions(func(_ context.Context, command runtimeorchestration.Command) error {
				dispatched = append(dispatched, command)
				return nil
			}, activity.RegisterOptions{Name: runtimeorchestration.DispatchStateCommandActivity})
			sessionID := "sess_1234567890ABCDEF"
			for index, kind := range scenario.kinds {
				command := runtimeorchestration.Command{Tenant: "tenant-a", OutboxID: "outbox-" + string(kind), SessionID: sessionID, Kind: kind, Sequence: uint64(index + 1)}
				environment.RegisterDelayedCallback(func() {
					environment.SignalWorkflow(runtimeorchestration.SessionCommandSignal, command)
				}, 0)
			}
			environment.ExecuteWorkflow(runtimeorchestration.SessionWorkflow, runtimeorchestration.WorkflowInput{SessionID: sessionID, ContinueAfter: 100})
			if err := environment.GetWorkflowError(); err != nil {
				t.Fatalf("workflow error = %v", err)
			}
			if len(dispatched) != len(scenario.kinds) {
				t.Fatalf("dispatched = %#v, want %d ordered durable routes", dispatched, len(scenario.kinds))
			}
			for index, command := range dispatched {
				if command.Kind != scenario.kinds[index] || command.Sequence != uint64(index+1) {
					t.Fatalf("dispatched[%d] = %#v, want kind=%s sequence=%d", index, command, scenario.kinds[index], index+1)
				}
			}
		})
	}
}

func TestDispatchStateCommandClassifiesRetrySafetyWithoutRepeatingUnknownEffects(t *testing.T) {
	command := runtimeorchestration.Command{Tenant: "tenant-a", OutboxID: "outbox-1", SessionID: "sess_1234567890ABCDEF", Kind: runtimeorchestration.CommandInputAccepted, Sequence: 1}
	for _, scenario := range []struct {
		name          string
		dispatchError error
		nonRetryable  string
		cancelled     bool
	}{
		{name: "cancellation", dispatchError: context.Canceled, cancelled: true},
		{name: "deterministic durable route", dispatchError: runtimestate.ErrIntegrity, nonRetryable: "runtime.deterministic_outbox_route"},
		{name: "uncertain external effect", dispatchError: runtimeorchestration.ErrUncertainExternalEffect, nonRetryable: "runtime.uncertain_external_effect"},
		{name: "incompatible persisted policy", dispatchError: runtimeorchestration.ErrIncompatiblePersistedPolicy, nonRetryable: "runtime.incompatible_persisted_policy"},
		{name: "backend unavailable", dispatchError: runtimestate.ErrUnavailable},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			activities, err := runtimeorchestration.NewActivities(dispatchErrorDispatcher{err: scenario.dispatchError})
			if err != nil {
				t.Fatal(err)
			}
			err = activities.DispatchStateCommand(context.Background(), command)
			var application *temporal.ApplicationError
			if scenario.cancelled {
				if !temporal.IsCanceledError(err) {
					t.Fatalf("DispatchStateCommand() error = %v, want Temporal cancellation", err)
				}
				return
			}
			if scenario.nonRetryable == "" {
				if err != scenario.dispatchError {
					t.Fatalf("DispatchStateCommand() error = %v, want retryable %v", err, scenario.dispatchError)
				}
				return
			}
			if !errors.As(err, &application) || application.Type() != scenario.nonRetryable {
				t.Fatalf("DispatchStateCommand() error = %v, want non-retryable %q", err, scenario.nonRetryable)
			}
		})
	}
}

// TestSessionWorkflowRetriesOnlyRetryableDurableDispatch proves the workflow's
// actual Temporal retry policy, not merely its activity error classifier. A
// temporary state outage retries the same already-durable command; a second
// successful observation then permits the terminal session route. The
// dispatcher performs no external effect, so retry is limited to durable-route
// observation and cannot re-run a model, tool, or sandbox action.
func TestSessionWorkflowRetriesOnlyRetryableDurableDispatch(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	environment := suite.NewTestWorkflowEnvironment()
	dispatcher := &scriptedDispatcher{failures: map[runtimeorchestration.CommandKind][]error{
		runtimeorchestration.CommandInputAccepted: {runtimestate.ErrUnavailable, nil},
	}}
	activities, err := runtimeorchestration.NewActivities(dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	environment.RegisterActivityWithOptions(activities.DispatchStateCommand, activity.RegisterOptions{Name: runtimeorchestration.DispatchStateCommandActivity})
	sessionID := "sess_1234567890ABCDEF"
	environment.RegisterDelayedCallback(func() {
		environment.SignalWorkflow(runtimeorchestration.SessionCommandSignal, runtimeorchestration.Command{Tenant: "tenant-a", OutboxID: "outbox-input", SessionID: sessionID, Kind: runtimeorchestration.CommandInputAccepted, Sequence: 1})
	}, 0)
	environment.RegisterDelayedCallback(func() {
		environment.SignalWorkflow(runtimeorchestration.SessionCommandSignal, runtimeorchestration.Command{Tenant: "tenant-a", OutboxID: "outbox-complete", SessionID: sessionID, Kind: runtimeorchestration.CommandSessionCompleted, Sequence: 2})
	}, 5*time.Second)
	environment.ExecuteWorkflow(runtimeorchestration.SessionWorkflow, runtimeorchestration.WorkflowInput{SessionID: sessionID, ContinueAfter: 100})
	if err := environment.GetWorkflowError(); err != nil {
		t.Fatalf("workflow error = %v", err)
	}
	if got := dispatcher.count(runtimeorchestration.CommandInputAccepted); got != 2 {
		t.Fatalf("retryable durable input dispatches = %d, want 2", got)
	}
	if got := dispatcher.count(runtimeorchestration.CommandSessionCompleted); got != 1 {
		t.Fatalf("terminal session dispatches = %d, want 1", got)
	}
}

// TestSessionWorkflowDoesNotRetryCancelledDurableDispatch proves a cancelled
// activity is propagated to Temporal as cancellation rather than replaced.
// Explicit public cancellation is already a persisted route; retrying this
// private observation would not restore a cancelled model/tool/sandbox effect.
func TestSessionWorkflowDoesNotRetryCancelledDurableDispatch(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	environment := suite.NewTestWorkflowEnvironment()
	dispatcher := &scriptedDispatcher{failures: map[runtimeorchestration.CommandKind][]error{
		runtimeorchestration.CommandTurnCancelled: {context.Canceled},
	}}
	activities, err := runtimeorchestration.NewActivities(dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	environment.RegisterActivityWithOptions(activities.DispatchStateCommand, activity.RegisterOptions{Name: runtimeorchestration.DispatchStateCommandActivity})
	sessionID := "sess_1234567890ABCDEF"
	environment.RegisterDelayedCallback(func() {
		environment.SignalWorkflow(runtimeorchestration.SessionCommandSignal, runtimeorchestration.Command{Tenant: "tenant-a", OutboxID: "outbox-cancel", SessionID: sessionID, Kind: runtimeorchestration.CommandTurnCancelled, Sequence: 1})
	}, 0)
	environment.ExecuteWorkflow(runtimeorchestration.SessionWorkflow, runtimeorchestration.WorkflowInput{SessionID: sessionID, ContinueAfter: 100})
	if err := environment.GetWorkflowError(); err == nil {
		t.Fatal("workflow error = nil, want propagated cancellation")
	}
	if got := dispatcher.count(runtimeorchestration.CommandTurnCancelled); got != 1 {
		t.Fatalf("cancelled durable dispatches = %d, want no retry", got)
	}
}

type scriptedDispatcher struct {
	failures map[runtimeorchestration.CommandKind][]error
	commands []runtimeorchestration.Command
}

func (dispatcher *scriptedDispatcher) Dispatch(_ context.Context, command runtimeorchestration.Command) error {
	dispatcher.commands = append(dispatcher.commands, command)
	if failures := dispatcher.failures[command.Kind]; len(failures) > 0 {
		err := failures[0]
		dispatcher.failures[command.Kind] = failures[1:]
		return err
	}
	return nil
}

func (dispatcher *scriptedDispatcher) count(kind runtimeorchestration.CommandKind) int {
	count := 0
	for _, command := range dispatcher.commands {
		if command.Kind == kind {
			count++
		}
	}
	return count
}

type dispatchErrorDispatcher struct{ err error }

func (dispatcher dispatchErrorDispatcher) Dispatch(context.Context, runtimeorchestration.Command) error {
	return dispatcher.err
}
