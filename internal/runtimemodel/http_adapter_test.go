package runtimemodel_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimemodel"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
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

func TestHTTPAdapterRejectsNonHTTPSNonLoopbackEndpoints(t *testing.T) {
	for _, endpoint := range []string{
		"http://model.example.com",
		"http://192.0.2.1",
		"ftp://model.example.com",
	} {
		adapter, err := runtimemodel.NewHTTPAdapter(runtimemodel.HTTPAdapterConfig{Endpoint: endpoint, Token: "model-token"})
		if err == nil || adapter != nil {
			t.Fatalf("NewHTTPAdapter(%q) accepted a non-HTTPS non-loopback endpoint", endpoint)
		}
	}
	for _, endpoint := range []string{"http://127.0.0.1:8080", "http://[::1]:8080", "http://localhost:8080", "https://model.example.com"} {
		adapter, err := runtimemodel.NewHTTPAdapter(runtimemodel.HTTPAdapterConfig{Endpoint: endpoint, Token: "model-token"})
		if err != nil || adapter == nil {
			t.Fatalf("NewHTTPAdapter(%q) = %#v, %v", endpoint, adapter, err)
		}
	}
}

func TestHTTPAdapterRejectsRedirectBeforeSendingCredentialToTarget(t *testing.T) {
	targetRequests := 0
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		targetRequests++
		if request.Header.Get("Authorization") != "" {
			t.Fatal("redirect target received a model credential")
		}
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusFound)
	}))
	defer redirector.Close()
	adapter, err := runtimemodel.NewHTTPAdapter(runtimemodel.HTTPAdapterConfig{Endpoint: redirector.URL, Token: "model-token"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.Invoke(context.Background(), runtimemodel.Request{Tenant: "tenant-a", SessionID: "sess_0000000000000001", TurnID: "turn_0000000000000001", OperationID: "op_model_0001"})
	if err == nil || !strings.Contains(err.Error(), "redirects are forbidden") || targetRequests != 0 {
		t.Fatalf("redirect invocation error = %v, target requests = %d", err, targetRequests)
	}
}

func TestHTTPAdapterParsesOnlyCanonicalSafeToolOutcomes(t *testing.T) {
	valid := `{"type":"tool","tool":{"tool_call_id":"tcall_1234567890ABCDEF","approval_id":"appr_1234567890ABCDEF","policy_name":"workspace-write","policy_revision":1,"tool_name":"workspace.write","action":{"verb":"write","target":"workspace-service"},"maximum_uses":1,"expires_at":"2026-08-11T13:00:00Z","descriptor":{"path":"notes.txt","kind":"workspace.write"},"arguments":{"path":"notes.txt"}}}` + "\n"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/x-ndjson")
		if _, err := fmt.Fprint(writer, valid); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()
	adapter, err := runtimemodel.NewHTTPAdapter(runtimemodel.HTTPAdapterConfig{Endpoint: server.URL, Token: "model-token", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	request := runtimemodel.Request{Tenant: "tenant-a", SessionID: "sess_0000000000000001", TurnID: "turn_0000000000000001", OperationID: "op_model_0001", Tools: []agentruntime.ToolDefinition{{Name: "workspace.write", Description: "write a workspace value", InputSchemaVersion: "agent-runtime.tool-input/v1", InputSchema: []byte(`{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}`)}}}
	response, err := adapter.Invoke(context.Background(), request)
	if err != nil || response.Tool == nil || response.Tool.ToolName != "workspace.write" || response.Tool.Action.Verb != "write" || response.Tool.Action.Target != "workspace-service" || response.Tool.ExpiresAt != time.Date(2026, 8, 11, 13, 0, 0, 0, time.UTC) || string(response.Tool.Descriptor) != `{"kind":"workspace.write","path":"notes.txt"}` || !strings.HasPrefix(response.Tool.ActionDigest, "sha256:") || !strings.HasPrefix(response.Tool.CapabilityDigest, "sha256:") {
		t.Fatalf("canonical tool response = %#v, %v", response, err)
	}
	for _, stream := range []string{
		strings.Replace(valid, `"maximum_uses":1`, `"maximum_uses":0`, 1),
		strings.Replace(valid, `"descriptor":{"path":"notes.txt","kind":"workspace.write"}`, `"descriptor":{"token":"must-not-cross"}`, 1),
		strings.Replace(valid, `"action":{"verb":"write","target":"workspace-service"}`, `"action":{"verb":"write","target":"workspace-service","extra":true}`, 1),
		strings.Replace(valid, `"tool_name":"workspace.write"`, `"tool_name":"workspace.write","raw_arguments":"never"`, 1),
		strings.Replace(valid, `"arguments":{"path":"notes.txt"}`, `"arguments":{"path":17}`, 1),
		strings.Replace(valid, `"arguments":{"path":"notes.txt"}`, `"arguments":{"path":"notes.txt","extra":true}`, 1),
		strings.Replace(valid, `"tool_name":"workspace.write"`, `"tool_name":"workspace.delete"`, 1),
	} {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/x-ndjson")
			if _, err := fmt.Fprint(writer, stream); err != nil {
				t.Fatal(err)
			}
		}))
		adapter, err := runtimemodel.NewHTTPAdapter(runtimemodel.HTTPAdapterConfig{Endpoint: server.URL, Token: "model-token", HTTPClient: server.Client()})
		if err != nil {
			t.Fatal(err)
		}
		_, err = adapter.Invoke(context.Background(), request)
		server.Close()
		if err == nil {
			t.Fatalf("unsafe tool stream was accepted: %s", stream)
		}
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
