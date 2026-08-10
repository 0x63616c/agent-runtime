package runtimeorchestration_test

import (
	"context"
	"errors"
	"testing"

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

func TestDispatchStateCommandClassifiesRetrySafetyWithoutRepeatingUnknownEffects(t *testing.T) {
	command := runtimeorchestration.Command{Tenant: "tenant-a", OutboxID: "outbox-1", SessionID: "sess_1234567890ABCDEF", Kind: runtimeorchestration.CommandInputAccepted, Sequence: 1}
	for _, scenario := range []struct {
		name          string
		dispatchError error
		nonRetryable  string
	}{
		{name: "cancellation", dispatchError: context.Canceled},
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

type dispatchErrorDispatcher struct{ err error }

func (dispatcher dispatchErrorDispatcher) Dispatch(context.Context, runtimeorchestration.Command) error {
	return dispatcher.err
}
