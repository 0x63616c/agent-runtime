// Package runtimeorchestration contains the private, replay-safe Temporal adapter for durable Session work.
package runtimeorchestration

import (
	"context"
	"errors"
	"time"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/workflow"
)

const (
	// SessionCommandSignal is the private signal name for one already-durable state command.
	SessionCommandSignal = "runtime.session.command.v1"
	// DispatchStateCommandActivity is the registered activity name that reaches the state-backed dispatcher.
	DispatchStateCommandActivity = "runtime.dispatch-state-command.v1"
	workflowVersionChange        = "runtime.session-workflow.command-dispatch.v1"
)

// CommandKind is the closed private workflow command vocabulary.
type CommandKind string

const (
	// CommandInputAccepted represents an already persisted input-admission outbox route.
	CommandInputAccepted CommandKind = "input_accepted"
	// CommandTurnCancelled represents an already persisted cancellation route.
	CommandTurnCancelled CommandKind = "turn_cancelled"
)

// Command carries only public runtime IDs and ordered durable metadata; never content or backend handles.
type Command struct {
	SessionID string
	Kind      CommandKind
	Sequence  uint64
}

// WorkflowInput is the compact replay-safe continuation state for one Session workflow chain.
type WorkflowInput struct {
	SessionID     string
	NextSequence  uint64
	ContinueAfter uint32
}

// StateDispatcher is the private activity port to the state-backed runtime authority.
type StateDispatcher interface {
	Dispatch(context.Context, Command) error
}

// Activities carries the injected state-backed dispatch authority outside workflow replay.
type Activities struct{ dispatcher StateDispatcher }

// NewActivities constructs one activity set from the required state-backed dispatcher.
func NewActivities(dispatcher StateDispatcher) (*Activities, error) {
	if dispatcher == nil {
		return nil, errors.New("create runtime orchestration activities: state dispatcher is required")
	}
	return &Activities{dispatcher: dispatcher}, nil
}

// DispatchStateCommand delivers one already-durable command to the state-backed dispatcher.
func (activities *Activities) DispatchStateCommand(ctx context.Context, command Command) error {
	if activities == nil || activities.dispatcher == nil {
		return errors.New("dispatch runtime state command: state dispatcher is required")
	}
	if err := validateCommand(command); err != nil {
		return err
	}
	if err := activities.dispatcher.Dispatch(ctx, command); err != nil {
		return err
	}
	return nil
}

// Register binds the complete private workflow/activity set to a runtime-owned worker.
func Register(registrar workflowRegistry, activities *Activities) error {
	if registrar == nil || activities == nil {
		return errors.New("register runtime orchestration: registrar and activities are required")
	}
	registrar.RegisterWorkflow(SessionWorkflow)
	registrar.RegisterActivityWithOptions(activities.DispatchStateCommand, activity.RegisterOptions{Name: DispatchStateCommandActivity})
	return nil
}

type workflowRegistry interface {
	RegisterWorkflow(any)
	RegisterActivityWithOptions(any, activity.RegisterOptions)
}

// SessionWorkflow serially dispatches already-durable command routes and rolls over with compact state.
func SessionWorkflow(ctx workflow.Context, input WorkflowInput) error {
	if input.SessionID == "" || input.ContinueAfter == 0 {
		return errors.New("invalid runtime Session workflow input")
	}
	if workflow.GetVersion(ctx, workflowVersionChange, workflow.DefaultVersion, 1) != 1 {
		return errors.New("unsupported runtime Session workflow version")
	}
	commands := workflow.GetSignalChannel(ctx, SessionCommandSignal)
	for {
		var command Command
		commands.Receive(ctx, &command)
		if command.SessionID != input.SessionID || command.Sequence != input.NextSequence+1 {
			return errors.New("invalid runtime Session workflow command")
		}
		if err := workflow.ExecuteActivity(workflow.WithActivityOptions(ctx, workflow.ActivityOptions{StartToCloseTimeout: time.Minute}), DispatchStateCommandActivity, command).Get(ctx, nil); err != nil {
			return err
		}
		input.NextSequence = command.Sequence
		if input.NextSequence >= uint64(input.ContinueAfter) {
			return workflow.NewContinueAsNewError(ctx, SessionWorkflow, input)
		}
	}
}

func validateCommand(command Command) error {
	if command.SessionID == "" || command.Sequence == 0 || (command.Kind != CommandInputAccepted && command.Kind != CommandTurnCancelled) {
		return errors.New("invalid runtime state command")
	}
	return nil
}
