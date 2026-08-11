package runtimetool_test

import (
	"context"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/runtimetool"
)

func TestBuiltinAdapterRefusesAnUnsafeExternalEffectContract(t *testing.T) {
	unsafe := &builtinContractAdapter{contract: runtimetool.ExternalEffectContract{IdempotencyKey: "caller-key", Reconciles: false}}
	if adapter, err := runtimetool.NewBuiltinAdapter(unsafe); err == nil || adapter != nil {
		t.Fatalf("unsafe builtin adapter = %#v, %v; want recovery-contract refusal", adapter, err)
	}

	safe := &builtinContractAdapter{contract: runtimetool.ExternalEffectContract{IdempotencyKey: "operation_id", Reconciles: true}}
	adapter, err := runtimetool.NewBuiltinAdapter(safe)
	if err != nil {
		t.Fatalf("create safe builtin adapter: %v", err)
	}
	request := runtimetool.Request{OperationID: "op_tool_000000000001"}
	for _, invoke := range []func(context.Context, runtimetool.Request) (runtimetool.Response, error){adapter.Execute, adapter.Reconcile} {
		response, invokeErr := invoke(context.Background(), request)
		if invokeErr != nil || response.Failure == nil || safe.executions != 0 || safe.reconciliations != 0 {
			t.Fatalf("direct builtin adapter dispatch = %#v, calls=%d/%d err=%v", response, safe.executions, safe.reconciliations, invokeErr)
		}
	}
}

type builtinContractAdapter struct {
	contract        runtimetool.ExternalEffectContract
	executions      int
	reconciliations int
	last            runtimetool.Request
}

func (adapter *builtinContractAdapter) Execute(_ context.Context, request runtimetool.Request) (runtimetool.Response, error) {
	adapter.executions++
	adapter.last = request
	return runtimetool.Response{Output: []byte("bounded builtin result")}, nil
}

func (adapter *builtinContractAdapter) Reconcile(_ context.Context, request runtimetool.Request) (runtimetool.Response, error) {
	adapter.reconciliations++
	adapter.last = request
	return runtimetool.Response{Output: []byte("bounded builtin status")}, nil
}

func (adapter *builtinContractAdapter) ExternalEffectContract() runtimetool.ExternalEffectContract {
	return adapter.contract
}
