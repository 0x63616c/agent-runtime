package runtimetool

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/0x63616c/agent-runtime/sandbox"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

// SandboxAdapter executes only canonical sandbox.control/v1 requests supplied
// by the worker's verified descriptor reader. It never constructs an action
// from runtime metadata, and recovered claims query the same durable sandbox
// operation instead of submitting again.
type SandboxAdapter struct{ client sandbox.Client }

// NewSandboxAdapter constructs the concrete external-effect adapter.
func NewSandboxAdapter(client sandbox.Client) (*SandboxAdapter, error) {
	if client == nil {
		return nil, errors.New("create sandbox tool adapter: sandbox client is required")
	}
	return &SandboxAdapter{client: client}, nil
}

// ExternalEffectContract declares sandbox-control's operation-ID recovery path.
func (adapter *SandboxAdapter) ExternalEffectContract() ExternalEffectContract {
	return ExternalEffectContract{IdempotencyKey: "operation_id", Reconciles: true}
}

func (adapter *SandboxAdapter) Execute(ctx context.Context, request Request) (Response, error) {
	if !dispatchAuthorized(request) {
		return refusedDirectDispatch(), nil
	}
	action, response := decodeSandboxAction(request)
	if response.Failure != nil {
		return response, nil
	}
	if _, err := adapter.client.Submit(ctx, action); err != nil {
		return Response{}, err
	}
	operation, err := adapter.client.WaitOperation(ctx, action.ID)
	if err != nil {
		return Response{}, err
	}
	return sandboxResponse(operation)
}

func (adapter *SandboxAdapter) Reconcile(ctx context.Context, request Request) (Response, error) {
	if !dispatchAuthorized(request) {
		return refusedDirectDispatch(), nil
	}
	action, response := decodeSandboxAction(request)
	if response.Failure != nil {
		return response, nil
	}
	operation, err := adapter.client.GetOperation(ctx, action.ID)
	if err != nil {
		return Response{}, err
	}
	return sandboxResponse(operation)
}

func decodeSandboxAction(request Request) (sandbox.OperationRequest, Response) {
	action, err := sandbox.DecodeControlOperationRequest(request.Descriptor)
	if err != nil || action.ID == "" || string(action.ID) != string(request.OperationID) {
		return sandbox.OperationRequest{}, Response{Failure: &agentruntime.Failure{Code: agentruntime.FailureInvalidInput, Message: "verified tool action descriptor is invalid"}}
	}
	return action, Response{}
}

func sandboxResponse(operation sandbox.Operation) (Response, error) {
	switch operation.State {
	case sandbox.OperationSucceeded:
		output, err := json.Marshal(struct {
			OperationID sandbox.OperationID      `json:"operation_id"`
			State       sandbox.OperationState   `json:"state"`
			Result      *sandbox.OperationResult `json:"result,omitempty"`
		}{OperationID: operation.Ref.ID, State: operation.State, Result: operation.Result})
		if err != nil {
			return Response{}, err
		}
		return Response{Output: output, MediaType: "application/json"}, nil
	case sandbox.OperationFailed, sandbox.OperationCancelled:
		return Response{Failure: &agentruntime.Failure{Code: agentruntime.FailureInternal, Message: "sandbox operation failed"}}, nil
	case sandbox.OperationUncertain, sandbox.OperationCleanupPending, sandbox.OperationExpired, sandbox.OperationTombstoned:
		return Response{Failure: &agentruntime.Failure{Code: agentruntime.FailureUnavailable, Message: "sandbox operation outcome is uncertain"}, Uncertain: true}, nil
	default:
		return Response{Failure: &agentruntime.Failure{Code: agentruntime.FailureUnavailable, Message: "sandbox operation outcome is uncertain"}, Uncertain: true}, nil
	}
}
