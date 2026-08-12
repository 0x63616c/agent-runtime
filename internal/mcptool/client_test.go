package mcptool

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestClientNegotiatesSessionValidatesPinnedSchemaAndCallsToolAcrossReconnect(t *testing.T) {
	schema := []byte(`{"type":"object","properties":{"query":{"type":"string"},"operation_id":{"type":"string"}},"required":["query","operation_id"],"additionalProperties":false}`)
	var lock sync.Mutex
	var methods []string
	var callArguments map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var message struct {
			ID     string          `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&message); err != nil {
			t.Errorf("decode request: %v", err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		lock.Lock()
		methods = append(methods, message.Method)
		lock.Unlock()
		if request.Header.Get("Authorization") != "Bearer test-credential" || request.Header.Get("Origin") != serverURLOrigin(request) {
			t.Errorf("credential/origin headers = %q / %q", request.Header.Get("Authorization"), request.Header.Get("Origin"))
		}
		if message.Method != "initialize" && (request.Header.Get("MCP-Session-Id") != "session-a" || request.Header.Get("MCP-Protocol-Version") != protocolVersion) {
			t.Errorf("negotiated headers = session %q version %q", request.Header.Get("MCP-Session-Id"), request.Header.Get("MCP-Protocol-Version"))
		}
		switch message.Method {
		case "initialize":
			response.Header().Set("MCP-Session-Id", "session-a")
			response.Header().Set("Connection", "close") // subsequent POST must reconnect with the negotiated session.
			writeRPC(response, message.ID, map[string]any{"protocolVersion": protocolVersion, "capabilities": map[string]any{"tools": map[string]any{}}})
		case "notifications/initialized":
			response.WriteHeader(http.StatusAccepted)
		case "tools/list":
			writeRPC(response, message.ID, map[string]any{"tools": []any{map[string]any{"name": "search", "inputSchema": json.RawMessage(schema)}, map[string]any{"name": "status", "inputSchema": json.RawMessage(statusSchema())}}})
		case "tools/call":
			var params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			if err := json.Unmarshal(message.Params, &params); err != nil {
				t.Fatal(err)
			}
			callArguments = params.Arguments
			writeRPC(response, message.ID, map[string]any{"content": []any{map[string]string{"type": "text", "text": "result"}}, "structuredContent": map[string]string{"operation_id": "op_test_000000000001", "state": "succeeded"}})
		default:
			response.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	client := newTestClient(t, server.URL, schemaDigest(schema), schemaDigest(statusSchema()), 1<<20)
	descriptor, err := DecodeDescriptor([]byte(`{"version":"mcp.tool/v1","server_id":"test","tool_name":"search","arguments":{"query":"durable tools"}}`))
	if err != nil {
		t.Fatal(err)
	}
	output, terminal, err := client.Execute(context.Background(), descriptor, "op_test_000000000001")
	if err != nil || terminal || !strings.Contains(string(output), "result") {
		t.Fatalf("execute = %s terminal=%v err=%v", output, terminal, err)
	}
	if callArguments["operation_id"] != "op_test_000000000001" || callArguments["query"] != "durable tools" {
		t.Fatalf("tools/call arguments = %#v", callArguments)
	}
	lock.Lock()
	defer lock.Unlock()
	if got, want := strings.Join(methods, ","), "initialize,notifications/initialized,tools/list,tools/call"; got != want {
		t.Fatalf("MCP lifecycle = %s, want %s", got, want)
	}
}

func TestClientAcceptsSSEJSONRPCResponse(t *testing.T) {
	schema := []byte(`{"type":"object","properties":{"operation_id":{"type":"string"}},"required":["operation_id"],"additionalProperties":false}`)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		message := decodeMessage(t, request)
		switch message.Method {
		case "initialize":
			response.Header().Set("MCP-Session-Id", "session-sse")
			writeRPC(response, message.ID, map[string]any{"protocolVersion": protocolVersion, "capabilities": map[string]any{"tools": map[string]any{}}})
		case "notifications/initialized":
			response.WriteHeader(http.StatusAccepted)
		case "tools/list":
			writeRPC(response, message.ID, map[string]any{"tools": []any{map[string]any{"name": "search", "inputSchema": json.RawMessage(schema)}, map[string]any{"name": "status", "inputSchema": json.RawMessage(statusSchema())}}})
		case "tools/call":
			response.Header().Set("Content-Type", "text/event-stream")
			_, _ = response.Write([]byte("id: 1\ndata: {}\n\n"))
			payload, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": message.ID, "result": map[string]any{"content": []any{map[string]string{"type": "text", "text": "sse"}}}})
			_, _ = response.Write([]byte("id: 2\ndata: " + string(payload) + "\n\n"))
		}
	}))
	defer server.Close()
	client := newTestClient(t, server.URL, schemaDigest(schema), schemaDigest(statusSchema()), 1<<20)
	descriptor, _ := DecodeDescriptor([]byte(`{"version":"mcp.tool/v1","server_id":"test","tool_name":"search","arguments":{}}`))
	output, terminal, err := client.Execute(context.Background(), descriptor, "op_test_000000000001")
	if err != nil || terminal || !strings.Contains(string(output), "sse") {
		t.Fatalf("SSE execute = %s terminal=%v err=%v", output, terminal, err)
	}
}

func TestClientCancelsStreamingCallAndNeverResubmits(t *testing.T) {
	schema := []byte(`{"type":"object","properties":{"operation_id":{"type":"string"}},"required":["operation_id"],"additionalProperties":false}`)
	started := make(chan struct{})
	cancelled := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		message := decodeMessage(t, request)
		switch message.Method {
		case "initialize":
			response.Header().Set("MCP-Session-Id", "session-cancel")
			writeRPC(response, message.ID, map[string]any{"protocolVersion": protocolVersion, "capabilities": map[string]any{"tools": map[string]any{}}})
		case "notifications/initialized":
			response.WriteHeader(http.StatusAccepted)
		case "tools/list":
			writeRPC(response, message.ID, map[string]any{"tools": []any{map[string]any{"name": "search", "inputSchema": json.RawMessage(schema)}, map[string]any{"name": "status", "inputSchema": json.RawMessage(statusSchema())}}})
		case "tools/call":
			close(started)
			<-request.Context().Done()
		case "notifications/cancelled":
			var parameters struct {
				RequestID string `json:"requestId"`
			}
			_ = json.Unmarshal(message.Params, &parameters)
			cancelled <- parameters.RequestID
			response.WriteHeader(http.StatusAccepted)
		}
	}))
	defer server.Close()
	client := newTestClient(t, server.URL, schemaDigest(schema), schemaDigest(statusSchema()), 1<<20)
	descriptor, _ := DecodeDescriptor([]byte(`{"version":"mcp.tool/v1","server_id":"test","tool_name":"search","arguments":{}}`))
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	deadline, finishDeadline := context.WithTimeout(context.Background(), time.Second)
	defer finishDeadline()
	result := make(chan error, 1)
	go func() {
		_, _, err := client.Execute(ctx, descriptor, "op_test_000000000001")
		result <- err
	}()
	select {
	case <-started:
		stop()
	case <-deadline.Done():
		t.Fatal("tools/call did not begin")
	}
	if err := <-result; !errors.Is(err, ErrUncertain) {
		t.Fatalf("cancelled execute error = %v, want uncertain", err)
	}
	select {
	case requestID := <-cancelled:
		if requestID != "op_test_000000000001" {
			t.Fatalf("cancelled request ID = %q", requestID)
		}
	case <-deadline.Done():
		t.Fatal("MCP cancellation notification was not sent")
	}
}

func TestClientReconcilesThroughPinnedStatusToolWithoutResubmittingEffect(t *testing.T) {
	effectSchema := []byte(`{"type":"object","properties":{"operation_id":{"type":"string"}},"required":["operation_id"],"additionalProperties":false}`)
	var calledEffect bool
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		message := decodeMessage(t, request)
		switch message.Method {
		case "initialize":
			response.Header().Set("MCP-Session-Id", "session-reconcile")
			writeRPC(response, message.ID, map[string]any{"protocolVersion": protocolVersion, "capabilities": map[string]any{"tools": map[string]any{}}})
		case "notifications/initialized":
			response.WriteHeader(http.StatusAccepted)
		case "tools/list":
			writeRPC(response, message.ID, map[string]any{"tools": []any{map[string]any{"name": "effect", "inputSchema": json.RawMessage(effectSchema)}, map[string]any{"name": "status", "inputSchema": json.RawMessage(statusSchema())}}})
		case "tools/call":
			var params struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(message.Params, &params)
			if params.Name == "effect" {
				calledEffect = true
			}
			writeRPC(response, message.ID, map[string]any{"content": []any{map[string]string{"type": "text", "text": "reconciled"}}, "structuredContent": map[string]string{"operation_id": "op_test_000000000001", "state": "succeeded"}})
		}
	}))
	defer server.Close()
	client := newTestClientWithTool(t, server.URL, "effect", effectSchema, "status", statusSchema(), 1<<20)
	descriptor, _ := DecodeDescriptor([]byte(`{"version":"mcp.tool/v1","server_id":"test","tool_name":"effect","arguments":{}}`))
	output, terminal, err := client.Reconcile(context.Background(), descriptor, "op_test_000000000001")
	if err != nil || terminal || !strings.Contains(string(output), "reconciled") || calledEffect {
		t.Fatalf("reconcile = %s terminal=%v err=%v effectCalled=%v", output, terminal, err, calledEffect)
	}
}

func TestClientRefusesUnsafeConfigurationCredentialsSchemaAndBounds(t *testing.T) {
	if _, err := NewClient(Config{Servers: []ServerConfig{{ID: "test", Endpoint: "http://example.invalid/mcp", Credentials: staticCredentials("Bearer x"), Tools: []ToolConfig{{Name: "tool", InputSchemaDigest: "sha256:" + strings.Repeat("a", 64), OperationIDArgument: "operation_id"}}, ReconcileTool: "tool", ReconcileOperationArgument: "operation_id"}}, RequestTimeout: time.Second, CancelTimeout: time.Second}); err == nil {
		t.Fatal("insecure non-loopback endpoint was accepted")
	}
	calls := 0
	schema := []byte(`{"type":"object","properties":{"operation_id":{"type":"string"}},"required":["operation_id"]}`)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls++
		message := decodeMessage(t, request)
		if message.Method == "initialize" {
			response.Header().Set("MCP-Session-Id", "session-refusal")
			writeRPC(response, message.ID, map[string]any{"protocolVersion": protocolVersion, "capabilities": map[string]any{"tools": map[string]any{}}})
			return
		}
		if message.Method == "notifications/initialized" {
			response.WriteHeader(http.StatusAccepted)
			return
		}
		if message.Method == "tools/list" {
			writeRPC(response, message.ID, map[string]any{"tools": []any{map[string]any{"name": "search", "inputSchema": json.RawMessage(schema)}, map[string]any{"name": "status", "inputSchema": json.RawMessage(statusSchema())}}})
		}
	}))
	defer server.Close()
	client := newTestClient(t, server.URL, "sha256:"+strings.Repeat("b", 64), schemaDigest(statusSchema()), 1<<20)
	descriptor, _ := DecodeDescriptor([]byte(`{"version":"mcp.tool/v1","server_id":"test","tool_name":"search","arguments":{}}`))
	if _, _, err := client.Execute(context.Background(), descriptor, "op_test_000000000001"); err == nil {
		t.Fatal("schema mismatch was accepted")
	}
	if calls != 3 { // initialize, initialized, tools/list; no external tools/call.
		t.Fatalf("schema mismatch calls = %d", calls)
	}
	credentialClient := newTestClientWithCredentials(t, server.URL, schemaDigest(schema), schemaDigest(statusSchema()), 1<<20, failingCredentials{})
	if _, _, err := credentialClient.Execute(context.Background(), descriptor, "op_test_000000000001"); err == nil || strings.Contains(err.Error(), "do-not-leak") {
		t.Fatalf("credential failure = %v", err)
	}
}

func TestClientRefusesRedirectWithoutForwardingCredential(t *testing.T) {
	redirectTargetCalls := 0
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		redirectTargetCalls++
		if request.Header.Get("Authorization") != "" {
			t.Errorf("redirect target received credential")
		}
		response.WriteHeader(http.StatusInternalServerError)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL+"/mcp", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	schema := []byte(`{"type":"object","properties":{"operation_id":{"type":"string"}},"required":["operation_id"]}`)
	client := newTestClient(t, redirector.URL, schemaDigest(schema), schemaDigest(statusSchema()), 1<<20)
	descriptor, _ := DecodeDescriptor([]byte(`{"version":"mcp.tool/v1","server_id":"test","tool_name":"search","arguments":{}}`))
	if _, _, err := client.Execute(context.Background(), descriptor, "op_test_000000000001"); err == nil {
		t.Fatal("redirect response was accepted")
	}
	if redirectTargetCalls != 0 {
		t.Fatalf("redirect target calls = %d, want 0", redirectTargetCalls)
	}
}

func TestClientRefusesBoundedToolResultBeforeReturningIt(t *testing.T) {
	schema := []byte(`{"type":"object","properties":{"operation_id":{"type":"string"}},"required":["operation_id"],"additionalProperties":false}`)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		message := decodeMessage(t, request)
		switch message.Method {
		case "initialize":
			response.Header().Set("MCP-Session-Id", "session-limit")
			writeRPC(response, message.ID, map[string]any{"protocolVersion": protocolVersion, "capabilities": map[string]any{"tools": map[string]any{}}})
		case "notifications/initialized":
			response.WriteHeader(http.StatusAccepted)
		case "tools/list":
			writeRPC(response, message.ID, map[string]any{"tools": []any{map[string]any{"name": "search", "inputSchema": json.RawMessage(schema)}, map[string]any{"name": "status", "inputSchema": json.RawMessage(statusSchema())}}})
		case "tools/call":
			writeRPC(response, message.ID, map[string]any{"content": []any{map[string]string{"type": "text", "text": strings.Repeat("x", 8192)}}})
		}
	}))
	defer server.Close()
	client := newTestClient(t, server.URL, schemaDigest(schema), schemaDigest(statusSchema()), 1024)
	descriptor, _ := DecodeDescriptor([]byte(`{"version":"mcp.tool/v1","server_id":"test","tool_name":"search","arguments":{}}`))
	if _, _, err := client.Execute(context.Background(), descriptor, "op_test_000000000001"); err == nil {
		t.Fatal("oversized MCP tool response was returned")
	}
}

var errResponseBodyClose = errors.New("response body close failure")

func TestSessionPostReturnsResponseCloseFailure(t *testing.T) {
	endpoint, err := url.Parse("https://mcp.example.test/mcp")
	if err != nil {
		t.Fatal(err)
	}
	session := session{
		client: &Client{roundTripper: roundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusAccepted, Body: closeFailureBody{Reader: strings.NewReader("")}, Header: make(http.Header)}, nil
		})},
		server: server{endpoint: endpoint, origin: "https://mcp.example.test", credentials: staticCredentials("Bearer test-credential")},
	}
	if _, err := session.post(context.Background(), rpcRequest{JSONRPC: "2.0", Method: "notifications/initialized"}, true); err == nil || !errors.Is(err, errResponseBodyClose) {
		t.Fatalf("close failure = %v", err)
	}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (roundTripper roundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTripper(request)
}

type closeFailureBody struct{ io.Reader }

func (closeFailureBody) Close() error { return errResponseBodyClose }

type message struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

func decodeMessage(t *testing.T, request *http.Request) message {
	t.Helper()
	var decoded message
	if err := json.NewDecoder(request.Body).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func writeRPC(response http.ResponseWriter, id string, result any) {
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func statusSchema() []byte {
	return []byte(`{"type":"object","properties":{"operation_id":{"type":"string"}},"required":["operation_id"],"additionalProperties":false}`)
}

func newTestClient(t *testing.T, endpoint, toolDigest, statusDigest string, maximum int64) *Client {
	t.Helper()
	return newTestClientWithCredentials(t, endpoint, toolDigest, statusDigest, maximum, staticCredentials("Bearer test-credential"))
}
func newTestClientWithTool(t *testing.T, endpoint, tool string, toolSchema []byte, status string, statusSchemaRaw []byte, maximum int64) *Client {
	t.Helper()
	return newTestClientWithCredentialsAndTool(t, endpoint, tool, schemaDigest(toolSchema), status, schemaDigest(statusSchemaRaw), maximum, staticCredentials("Bearer test-credential"))
}
func newTestClientWithCredentials(t *testing.T, endpoint, toolDigest, statusDigest string, maximum int64, credentials CredentialSource) *Client {
	t.Helper()
	return newTestClientWithCredentialsAndTool(t, endpoint, "search", toolDigest, "status", statusDigest, maximum, credentials)
}
func newTestClientWithCredentialsAndTool(t *testing.T, endpoint, tool, toolDigest, status, statusDigest string, maximum int64, credentials CredentialSource) *Client {
	t.Helper()
	client, err := NewClient(Config{Servers: []ServerConfig{{ID: "test", Endpoint: endpoint + "/mcp", Credentials: credentials, Tools: []ToolConfig{{Name: tool, InputSchemaDigest: toolDigest, OperationIDArgument: "operation_id"}, {Name: status, InputSchemaDigest: statusDigest, OperationIDArgument: "operation_id"}}, ReconcileTool: status, ReconcileOperationArgument: "operation_id"}}, RequestTimeout: time.Second, CancelTimeout: time.Second, MaximumResultBytes: maximum, AllowInsecureLoopbackTests: true})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

type staticCredentials string

func (value staticCredentials) Authorization(context.Context) (string, error) {
	return string(value), nil
}

type failingCredentials struct{}

func (failingCredentials) Authorization(context.Context) (string, error) {
	return "", errors.New("do-not-leak")
}

func serverURLOrigin(request *http.Request) string { return "http://" + request.Host }
