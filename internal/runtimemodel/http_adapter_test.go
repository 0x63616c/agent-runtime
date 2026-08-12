package runtimemodel_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimemodel"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
)

func TestHTTPAdapterNormalizesBoundedStreamAndReconcilesWithoutPOST(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Header.Get("Authorization") != "Bearer model-token" || request.Header.Get("Accept") != "application/x-ndjson" || request.URL.Path != "/provider/v1/invocations/op_model_0001" {
			t.Fatalf("normalized request = method=%s path=%s headers=%#v", request.Method, request.URL.Path, request.Header)
		}
		if requests == 1 {
			if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("invoke request = method=%s content-type=%q", request.Method, request.Header.Get("Content-Type"))
			}
			body, err := io.ReadAll(request.Body)
			if err != nil || string(body) != `{"tenant":"tenant-a","session_id":"sess_0000000000000001","turn_id":"turn_0000000000000001","operation_id":"op_model_0001"}` {
				t.Fatalf("invoke body = %q, %v", body, err)
			}
		} else if request.Method != http.MethodGet {
			t.Fatalf("reconcile method = %s, want GET", request.Method)
		}
		writer.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		_, _ = fmt.Fprint(writer, "{\"type\":\"delta\",\"delta\":\"normal \"}\n{\"type\":\"delta\",\"delta\":\"stream\"}\n{\"type\":\"completed\",\"input_tokens\":3,\"output_tokens\":2}\n")
	}))
	defer server.Close()
	adapter, err := runtimemodel.NewHTTPAdapter(runtimemodel.HTTPAdapterConfig{Endpoint: server.URL + "/provider", Token: "model-token", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	response, err := adapter.Invoke(context.Background(), runtimemodel.Request{Tenant: tenant, SessionID: "sess_0000000000000001", TurnID: "turn_0000000000000001", OperationID: runtimestate.OperationID("op_model_0001")})
	if err != nil || string(response.Output) != "normal stream" || response.Usage == nil || response.Usage.InputTokens == nil || *response.Usage.InputTokens != 3 || response.Usage.OutputTokens == nil || *response.Usage.OutputTokens != 2 {
		t.Fatalf("normalized invoke = %#v, %v", response, err)
	}
	reconciled, err := adapter.Reconcile(context.Background(), runtimemodel.Request{Tenant: tenant, SessionID: "sess_0000000000000001", TurnID: "turn_0000000000000001", OperationID: runtimestate.OperationID("op_model_0001")})
	if err != nil || string(reconciled.Output) != "normal stream" || requests != 2 {
		t.Fatalf("normalized reconciliation = %#v, %v requests=%d", reconciled, err, requests)
	}
}

func TestHTTPAdapterRejectsUnboundedAndNonterminalStreams(t *testing.T) {
	for _, stream := range []string{
		"{\"type\":\"delta\",\"delta\":\"missing terminal\"}\n",
		"{\"type\":\"completed\"}\n",
		"{\"type\":\"delta\",\"delta\":\"x\"}\n{\"type\":\"completed\"}\n{\"type\":\"delta\",\"delta\":\"late\"}\n",
		"{\"type\":\"delta\",\"delta\":\"" + strings.Repeat("x", 2<<20) + "\"}\n{\"type\":\"completed\"}\n",
	} {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/x-ndjson")
			_, _ = fmt.Fprint(writer, stream)
		}))
		adapter, err := runtimemodel.NewHTTPAdapter(runtimemodel.HTTPAdapterConfig{Endpoint: server.URL, Token: "model-token", HTTPClient: server.Client()})
		if err != nil {
			t.Fatal(err)
		}
		_, err = adapter.Invoke(context.Background(), runtimemodel.Request{Tenant: "tenant-a", SessionID: "sess_0000000000000001", TurnID: "turn_0000000000000001", OperationID: "op_model_0001"})
		server.Close()
		if err == nil {
			t.Fatalf("stream %q was accepted", stream[:min(len(stream), 80)])
		}
	}
}
