// Package runtimeorchestration contains the private, replay-safe Temporal adapter for durable Session work.
package runtimeorchestration

import (
	"context"
	"errors"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

const (
	// SessionCommandSignal is the private signal name for one already-durable state command.
	SessionCommandSignal = "runtime.session.command.v1"
	// DispatchStateCommandActivity is the registered activity name that reaches the state-backed dispatcher.
	DispatchStateCommandActivity   = "runtime.dispatch-state-command.v1"
	workflowVersionChange          = "runtime.session-workflow.command-dispatch.v1"
	deterministicRouteErrorType    = "runtime.deterministic_outbox_route"
	uncertainEffectErrorType       = "runtime.uncertain_external_effect"
	incompatiblePolicyErrorType    = "runtime.incompatible_persisted_policy"
	maximumWorkflowIdentifierBytes = 256
	maximumWorkflowCommandBytes    = 1024
	maximumWorkflowContinueAfter   = 10000
)

var (
	// ErrUncertainExternalEffect stops automatic retry when a future activity
	// cannot prove whether an irreversible effect happened. It must reconcile
	// from durable operation state instead of blindly executing again.
	ErrUncertainExternalEffect = errors.New("runtime external effect is uncertain")
	// ErrIncompatiblePersistedPolicy stops retry when durable policy state can
	// no longer be interpreted by the active worker version.
	ErrIncompatiblePersistedPolicy = errors.New("runtime persisted policy is incompatible")
)

// CommandKind is the closed private workflow command vocabulary.
type CommandKind string

const (
	// CommandInputAccepted represents an already persisted input-admission outbox route.
	CommandInputAccepted CommandKind = "input_accepted"
	// CommandTurnCancelled represents an already persisted cancellation route.
	CommandTurnCancelled CommandKind = "turn_cancelled"
	// CommandTurnSucceeded represents an already persisted terminal operation route.
	CommandTurnSucceeded CommandKind = "turn_succeeded"
	// CommandTurnFailed represents an already persisted failed terminal operation route.
	CommandTurnFailed CommandKind = "turn_failed"
	// CommandApprovalResolved represents an already persisted terminal approval route.
	CommandApprovalResolved CommandKind = "approval_resolved"
	// CommandSandboxOperationFinalized represents an already persisted sandbox finalization route.
	CommandSandboxOperationFinalized CommandKind = "sandbox_operation_finalized"
	// CommandSessionClosing reports that durable state stopped accepting Inputs
	// while work already admitted is allowed to drain.
	CommandSessionClosing CommandKind = "session_closing"
	// CommandSessionCompleted finalizes a drained Session workflow chain.
	CommandSessionCompleted CommandKind = "session_completed"
	// CommandSessionCancelled finalizes an explicitly cancelled Session workflow chain.
	CommandSessionCancelled CommandKind = "session_cancelled"
	// CommandSessionFailed finalizes a runtime-failed Session workflow chain.
	CommandSessionFailed CommandKind = "session_failed"
)

// Command carries only public runtime IDs and ordered durable metadata; never content or backend handles.
type Command struct {
	Tenant    string
	OutboxID  string
	SessionID string
	Kind      CommandKind
	Sequence  uint64
}

// WorkflowInput is the compact replay-safe continuation state for one Session workflow chain.
type WorkflowInput struct {
	SessionID     string
	NextSequence  uint64
	Dispatched    uint32
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

// DurableStateDispatcher rechecks the state-owned outbox route before an
// activity may act on a Temporal signal. A Temporal credential by itself
// therefore cannot manufacture runtime work: the command must name a durable
// outbox record with the matching tenant, Session, and event route.
type DurableStateDispatcher struct {
	store    runtimestate.RuntimeStateStore
	compiler *runtimestate.Compiler
	planner  *runtimestate.RuntimeStatePlanner
}

// NewDurableStateDispatcher creates the state-only activity authority. It has
// no runtime-content reader and no public API credential.
func NewDurableStateDispatcher(store runtimestate.RuntimeStateStore) (*DurableStateDispatcher, error) {
	if store == nil {
		return nil, errors.New("create durable state dispatcher: state store is required")
	}
	return &DurableStateDispatcher{store: store}, nil
}

// NewDurableStateDispatcherWithInvocationScheduler composes the private
// public-input-to-model-intent scheduler. It retains the exact durable outbox
// route check and has no public API or content-read authority.
func NewDurableStateDispatcherWithInvocationScheduler(store runtimestate.RuntimeStateStore, compiler *runtimestate.Compiler, planner *runtimestate.RuntimeStatePlanner) (*DurableStateDispatcher, error) {
	if store == nil || compiler == nil || planner == nil {
		return nil, errors.New("create durable state dispatcher: state, compiler, and planner are required")
	}
	return &DurableStateDispatcher{store: store, compiler: compiler, planner: planner}, nil
}

// Dispatch confirms the publisher-selected outbox route remains durable.
func (dispatcher *DurableStateDispatcher) Dispatch(ctx context.Context, command Command) error {
	if dispatcher == nil || dispatcher.store == nil || validateCommand(command) != nil {
		return errors.New("dispatch durable runtime state command: invalid dispatcher or command")
	}
	tenant, err := runtimecontent.ParseTenantID(command.Tenant)
	if err != nil {
		return errors.New("dispatch durable runtime state command: invalid tenant")
	}
	after := runtimestate.OutboxID("")
	for {
		page, err := dispatcher.store.ReadOutbox(ctx, runtimestate.OutboxQuery{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher}, After: after, Limit: 256})
		if err != nil {
			return err
		}
		for _, record := range page.Records {
			if string(record.OutboxID) != command.OutboxID {
				continue
			}
			if string(record.SessionID) != command.SessionID || !matchesCommand(record.EventKind, command.Kind) || (record.State != runtimestate.OutboxClaimed && record.State != runtimestate.OutboxPublished) {
				return errors.New("dispatch durable runtime state command: outbox route is not dispatchable")
			}
			if command.Kind == CommandInputAccepted && dispatcher.compiler != nil && dispatcher.planner != nil {
				return dispatcher.beginInvocation(ctx, record)
			}
			return nil
		}
		if page.Next == "" || page.Next == after {
			break
		}
		after = page.Next
	}
	return errors.New("dispatch durable runtime state command: outbox route is absent")
}

func (dispatcher *DurableStateDispatcher) beginInvocation(ctx context.Context, record runtimestate.OutboxRecord) error {
	scope := runtimestate.MutationScope{Tenant: record.Tenant, Principal: record.Principal, Authority: runtimestate.AuthorityRuntimeWorker}
	state, err := dispatcher.store.LoadRuntimeState(ctx, scope)
	if err != nil {
		return err
	}
	var session *runtimestate.SessionRecord
	for index := range state.Sessions {
		candidate := &state.Sessions[index]
		if candidate.Tenant == record.Tenant && candidate.Principal == record.Principal && candidate.SessionID == record.SessionID {
			session = candidate
			break
		}
	}
	var turn *runtimestate.TurnRecord
	for index := range state.Turns {
		candidate := &state.Turns[index]
		if candidate.Tenant == record.Tenant && candidate.Principal == record.Principal && candidate.SessionID == record.SessionID && candidate.TurnID == record.TurnID {
			turn = candidate
			break
		}
	}
	if session == nil || turn == nil {
		return runtimestate.ErrNotFoundOrDenied
	}
	if turn.State != agentruntime.TurnRunning {
		return nil
	}
	for _, invocation := range state.Invocations {
		if invocation.Tenant == record.Tenant && invocation.Principal == record.Principal && invocation.SessionID == record.SessionID && invocation.TurnID == record.TurnID {
			return nil
		}
	}
	mutation, err := dispatcher.compiler.CompileBeginInvocationAttempt(runtimestate.BeginInvocationAttemptCommand{
		Scope:                  scope,
		IdempotencyKey:         "orchestration-invocation-" + string(record.OutboxID),
		SessionID:              record.SessionID,
		TurnID:                 record.TurnID,
		OperationID:            runtimestate.OperationID("orchestration-invocation-" + string(record.OutboxID)),
		ExpectedSessionVersion: session.Version,
		ExpectedTurnVersion:    turn.Version,
	})
	if err != nil {
		return err
	}
	plan, err := dispatcher.planner.Plan(ctx, state, mutation)
	if err != nil {
		return err
	}
	return dispatcher.store.PersistTransitionPlan(ctx, plan)
}

// DispatchStateCommand delivers one already-durable command to the state-backed dispatcher.
func (activities *Activities) DispatchStateCommand(ctx context.Context, command Command) error {
	if activities == nil || activities.dispatcher == nil {
		return temporal.NewNonRetryableApplicationError("state dispatcher is required", deterministicRouteErrorType, nil)
	}
	if err := validateCommand(command); err != nil {
		return temporal.NewNonRetryableApplicationError("invalid durable state command", deterministicRouteErrorType, err)
	}
	if err := activities.dispatcher.Dispatch(ctx, command); err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			// A Go context error by itself is encoded by Temporal as an ordinary
			// activity failure and would be retried. Preserve the intended
			// cancellation semantics with Temporal's typed cancellation result.
			return temporal.NewCanceledError("durable state dispatch cancelled")
		case errors.Is(err, runtimestate.ErrNotFoundOrDenied), errors.Is(err, runtimestate.ErrIntegrity):
			return temporal.NewNonRetryableApplicationError("durable outbox route rejected", deterministicRouteErrorType, err)
		case errors.Is(err, ErrUncertainExternalEffect):
			return temporal.NewNonRetryableApplicationError("external effect outcome is uncertain", uncertainEffectErrorType, err)
		case errors.Is(err, ErrIncompatiblePersistedPolicy):
			return temporal.NewNonRetryableApplicationError("persisted policy is incompatible", incompatiblePolicyErrorType, err)
		default:
			// State unavailability remains retryable. Typed cancellation above
			// stops the activity without scheduling a replacement attempt.
			return err
		}
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
	if validateWorkflowInput(input) != nil {
		return errors.New("invalid runtime Session workflow input")
	}
	if workflow.GetVersion(ctx, workflowVersionChange, workflow.DefaultVersion, 1) != 1 {
		return errors.New("unsupported runtime Session workflow version")
	}
	commands := workflow.GetSignalChannel(ctx, SessionCommandSignal)
	for {
		var command Command
		commands.Receive(ctx, &command)
		if command.SessionID != input.SessionID || validateCommand(command) != nil {
			return errors.New("invalid runtime Session workflow command")
		}
		// Publishing is at-least-once: a reclaimed lease can re-signal an already
		// recorded route. The duplicate is a deterministic no-op, not a second
		// external effect. Outbox event sequence can have intentional gaps where
		// product events do not need a worker command.
		if command.Sequence <= input.NextSequence {
			continue
		}
		activityContext := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
			StartToCloseTimeout: time.Minute,
			RetryPolicy: &temporal.RetryPolicy{
				InitialInterval:        time.Second,
				BackoffCoefficient:     2,
				MaximumInterval:        30 * time.Second,
				MaximumAttempts:        5,
				NonRetryableErrorTypes: []string{deterministicRouteErrorType, uncertainEffectErrorType, incompatiblePolicyErrorType},
			},
		})
		if err := workflow.ExecuteActivity(activityContext, DispatchStateCommandActivity, command).Get(ctx, nil); err != nil {
			return err
		}
		input.NextSequence = command.Sequence
		input.Dispatched++
		if command.Kind == CommandSessionCompleted || command.Kind == CommandSessionCancelled || command.Kind == CommandSessionFailed {
			return nil
		}
		if input.Dispatched >= input.ContinueAfter {
			input.Dispatched = 0
			return workflow.NewContinueAsNewError(ctx, SessionWorkflow, input)
		}
	}
}

func validateCommand(command Command) error {
	if command.Tenant == "" || command.OutboxID == "" || command.SessionID == "" || command.Sequence == 0 || !knownCommandKind(command.Kind) {
		return errors.New("invalid runtime state command")
	}
	if len(command.Tenant) > maximumWorkflowIdentifierBytes || len(command.OutboxID) > maximumWorkflowIdentifierBytes || len(command.SessionID) > maximumWorkflowIdentifierBytes || len(command.Tenant)+len(command.OutboxID)+len(command.SessionID)+len(command.Kind)+8 > maximumWorkflowCommandBytes {
		return errors.New("invalid runtime state command")
	}
	return nil
}

func validateWorkflowInput(input WorkflowInput) error {
	if input.SessionID == "" || len(input.SessionID) > maximumWorkflowIdentifierBytes || input.ContinueAfter == 0 || input.ContinueAfter > maximumWorkflowContinueAfter {
		return errors.New("invalid runtime Session workflow input")
	}
	return nil
}

func matchesCommand(event agentruntime.EventKind, command CommandKind) bool {
	return event == agentruntime.EventInputAccepted && command == CommandInputAccepted ||
		event == agentruntime.EventTurnCancelled && command == CommandTurnCancelled ||
		event == agentruntime.EventTurnSucceeded && command == CommandTurnSucceeded ||
		event == agentruntime.EventTurnFailed && command == CommandTurnFailed ||
		event == agentruntime.EventApprovalResolved && command == CommandApprovalResolved ||
		event == agentruntime.EventSandboxOperationFinalized && command == CommandSandboxOperationFinalized ||
		event == agentruntime.EventSessionClosing && command == CommandSessionClosing ||
		event == agentruntime.EventSessionCompleted && command == CommandSessionCompleted ||
		event == agentruntime.EventSessionCancelled && command == CommandSessionCancelled ||
		event == agentruntime.EventSessionFailed && command == CommandSessionFailed
}

func knownCommandKind(kind CommandKind) bool {
	return kind == CommandInputAccepted || kind == CommandTurnCancelled || kind == CommandTurnSucceeded || kind == CommandTurnFailed || kind == CommandApprovalResolved || kind == CommandSandboxOperationFinalized || kind == CommandSessionClosing || kind == CommandSessionCompleted || kind == CommandSessionCancelled || kind == CommandSessionFailed
}
