package runtimetool

import (
	"context"
	"errors"

	"github.com/0x63616c/agent-runtime/internal/mcptool"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

// BuiltinAdapter labels an in-process tool implementation while preserving the
// broker-only Worker entry point and external-effect recovery contract.
type BuiltinAdapter struct{ adapter ContractAdapter }

// NewBuiltinAdapter constructs a broker-only builtin adapter seam.
func NewBuiltinAdapter(adapter ContractAdapter) (*BuiltinAdapter, error) {
	if adapter == nil || adapter.ExternalEffectContract() != (ExternalEffectContract{IdempotencyKey: "operation_id", Reconciles: true}) {
		return nil, errors.New("create builtin tool adapter: recovery contract is required")
	}
	return &BuiltinAdapter{adapter: adapter}, nil
}

// Execute delegates only after Worker authorization.
func (adapter *BuiltinAdapter) Execute(ctx context.Context, request Request) (Response, error) {
	if !dispatchAuthorized(request) {
		return refusedDirectDispatch(), nil
	}
	return adapter.adapter.Execute(ctx, request)
}

// Reconcile observes the exact existing operation without submission.
func (adapter *BuiltinAdapter) Reconcile(ctx context.Context, request Request) (Response, error) {
	if !dispatchAuthorized(request) {
		return refusedDirectDispatch(), nil
	}
	return adapter.adapter.Reconcile(ctx, request)
}

// ExternalEffectContract preserves the wrapped adapter declaration.
func (adapter *BuiltinAdapter) ExternalEffectContract() ExternalEffectContract {
	return adapter.adapter.ExternalEffectContract()
}

// MCPAdapter labels the concrete Streamable HTTP MCP transport behind the same
// broker-only seam. It receives only the Worker-authorized immutable
// descriptor and runtime-owned operation ID.
type MCPAdapter struct{ client *mcptool.Client }

// NewMCPAdapter constructs a broker-only MCP adapter seam.
func NewMCPAdapter(config mcptool.Config) (*MCPAdapter, error) {
	client, err := mcptool.NewClient(config)
	if err != nil {
		return nil, err
	}
	return &MCPAdapter{client: client}, nil
}
func (adapter *MCPAdapter) Execute(ctx context.Context, request Request) (Response, error) {
	return adapter.invoke(ctx, request, false)
}
func (adapter *MCPAdapter) Reconcile(ctx context.Context, request Request) (Response, error) {
	return adapter.invoke(ctx, request, true)
}
func (adapter *MCPAdapter) ExternalEffectContract() ExternalEffectContract {
	return ExternalEffectContract{IdempotencyKey: "operation_id", Reconciles: true}
}

func (adapter *MCPAdapter) invoke(ctx context.Context, request Request, reconcile bool) (Response, error) {
	if adapter == nil || adapter.client == nil {
		return Response{}, errors.New("use MCP tool: client is unavailable")
	}
	if !dispatchAuthorized(request) {
		return refusedDirectDispatch(), nil
	}
	descriptor, err := mcptool.DecodeDescriptor(request.Descriptor)
	if err != nil {
		return Response{Failure: &agentruntime.Failure{Code: agentruntime.FailureInvalidInput, Message: "MCP tool descriptor is invalid"}}, nil
	}
	var output []byte
	var terminal bool
	if reconcile {
		output, terminal, err = adapter.client.Reconcile(ctx, descriptor, string(request.OperationID))
	} else {
		output, terminal, err = adapter.client.Execute(ctx, descriptor, string(request.OperationID))
	}
	if err == nil {
		return Response{Output: output, MediaType: "text/plain; charset=utf-8"}, nil
	}
	if errors.Is(err, mcptool.ErrInvalidDescriptor) || errors.Is(err, mcptool.ErrUnauthorizedServerTool) {
		return Response{Failure: &agentruntime.Failure{Code: agentruntime.FailureInvalidInput, Message: "MCP tool is not authorized"}}, nil
	}
	if terminal {
		return Response{Failure: &agentruntime.Failure{Code: agentruntime.FailureUnavailable, Message: "MCP tool reported a terminal failure"}}, nil
	}
	if errors.Is(err, mcptool.ErrUncertain) {
		return Response{Uncertain: true, Failure: &agentruntime.Failure{Code: agentruntime.FailureUnavailable, Message: "MCP tool outcome is uncertain"}}, nil
	}
	return Response{}, err
}
