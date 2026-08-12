package runtimeorchestration_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimeorchestration"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"
)

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
