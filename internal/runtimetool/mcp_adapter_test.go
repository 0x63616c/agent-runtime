package runtimetool_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/mcptool"
	"github.com/0x63616c/agent-runtime/internal/runtimetool"
)

// This proves the concrete MCP adapter accepts only the immutable descriptor
// shape Worker receives after state authorization. A model cannot turn a raw
// URL into an adapter call, and the adapter still satisfies Worker’s recovery
// contract rather than creating a second execution path.
func TestMCPAdapterRefusesRawEndpointDescriptorBeforeNetworkDispatch(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer server.Close()
	schemaDigest := "sha256:" + strings.Repeat("a", 64)
	adapter, err := runtimetool.NewMCPAdapter(mcptool.Config{Servers: []mcptool.ServerConfig{{
		ID: "configured", Endpoint: server.URL + "/mcp", Credentials: adapterCredentials{},
		Tools:         []mcptool.ToolConfig{{Name: "effect", InputSchemaDigest: schemaDigest, OperationIDArgument: "operation_id"}, {Name: "status", InputSchemaDigest: schemaDigest, OperationIDArgument: "operation_id"}},
		ReconcileTool: "status", ReconcileOperationArgument: "operation_id",
	}}, RequestTimeout: time.Second, CancelTimeout: time.Second, AllowInsecureLoopbackTests: true})
	if err != nil {
		t.Fatal(err)
	}
	var _ runtimetool.ContractAdapter = adapter
	response, err := adapter.Execute(context.Background(), runtimetool.Request{OperationID: "op_test_000000000001", Descriptor: []byte(`{"version":"mcp.tool/v1","server_id":"https://attacker.invalid/mcp","tool_name":"effect","arguments":{}}`)})
	if err != nil || response.Failure == nil || requests != 0 {
		t.Fatalf("raw endpoint descriptor response=%#v err=%v requests=%d", response, err, requests)
	}
	if got := adapter.ExternalEffectContract(); got != (runtimetool.ExternalEffectContract{IdempotencyKey: "operation_id", Reconciles: true}) {
		t.Fatalf("MCP external-effect contract = %#v", got)
	}
}

type adapterCredentials struct{}

func (adapterCredentials) Authorization(context.Context) (string, error) {
	return "Bearer adapter-test", nil
}
