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
	if _, err = adapter.Execute(context.Background(), request); err != nil || safe.executions != 1 || safe.last.OperationID != request.OperationID {
		t.Fatalf("builtin execution = calls=%d request=%#v err=%v", safe.executions, safe.last, err)
	}
	if _, err = adapter.Reconcile(context.Background(), request); err != nil || safe.reconciliations != 1 || safe.last.OperationID != request.OperationID {
		t.Fatalf("builtin recovery = calls=%d request=%#v err=%v", safe.reconciliations, safe.last, err)
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
