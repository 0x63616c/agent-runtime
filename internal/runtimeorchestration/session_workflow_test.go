package runtimeorchestration_test

import (
	"context"
	"errors"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/runtimeorchestration"
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
