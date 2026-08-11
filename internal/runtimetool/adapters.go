package runtimetool

import (
	"context"
	"errors"
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

// MCPAdapter labels an MCP transport adapter behind the same broker-only seam.
type MCPAdapter struct{ adapter ContractAdapter }

// NewMCPAdapter constructs a broker-only MCP adapter seam.
func NewMCPAdapter(adapter ContractAdapter) (*MCPAdapter, error) {
	if adapter == nil || adapter.ExternalEffectContract() != (ExternalEffectContract{IdempotencyKey: "operation_id", Reconciles: true}) {
		return nil, errors.New("create MCP tool adapter: recovery contract is required")
	}
	return &MCPAdapter{adapter: adapter}, nil
}
func (adapter *MCPAdapter) Execute(ctx context.Context, request Request) (Response, error) {
	if !dispatchAuthorized(request) {
		return refusedDirectDispatch(), nil
	}
	return adapter.adapter.Execute(ctx, request)
}
func (adapter *MCPAdapter) Reconcile(ctx context.Context, request Request) (Response, error) {
	if !dispatchAuthorized(request) {
		return refusedDirectDispatch(), nil
	}
	return adapter.adapter.Reconcile(ctx, request)
}
func (adapter *MCPAdapter) ExternalEffectContract() ExternalEffectContract {
	return adapter.adapter.ExternalEffectContract()
}
