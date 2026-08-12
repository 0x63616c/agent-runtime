// Package mcptool implements the private, bounded Streamable HTTP MCP client
// used by the runtime tool adapter.
package mcptool

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	protocolVersion           = "2025-11-25"
	maximumDescriptorBytes    = 256 << 10
	defaultMaximumResultBytes = 1 << 20
	maximumToolPages          = 8
	maximumListedTools        = 256
)

// ErrUncertain reports that the caller cannot safely know whether an MCP
// operation completed. Callers must reconcile, never resubmit.
var ErrUncertain = errors.New("MCP tool operation outcome is uncertain")

// ErrInvalidDescriptor reports that a broker-authorized descriptor is not a
// canonical MCP action. It is safe for the adapter to surface as invalid input.
var ErrInvalidDescriptor = errors.New("invalid MCP tool descriptor")

// ErrUnauthorizedServerTool reports an endpoint reference or Tool name that
// is absent from operator configuration. It must never trigger a network call.
var ErrUnauthorizedServerTool = errors.New("MCP server or tool is not authorized")

// CredentialSource obtains an authorization value only while one outbound MCP
// request is being constructed. Its value is never retained by Client.
type CredentialSource interface {
	Authorization(context.Context) (string, error)
}

// ServerConfig declares one operator-configured MCP endpoint. The model never
// supplies this endpoint or its credential source.
type ServerConfig struct {
	ID                         string
	Endpoint                   string
	Credentials                CredentialSource
	Tools                      []ToolConfig
	ReconcileTool              string
	ReconcileOperationArgument string
}

// ToolConfig pins one server tool and its input schema. The operation ID is
// injected only into the declared argument, never chosen by a model request.
type ToolConfig struct {
	Name                string
	InputSchemaDigest   string
	OperationIDArgument string
}

// Config constructs a bounded Streamable HTTP client. HTTP is only available
// for explicit loopback test fixtures; production endpoints must use HTTPS.
type Config struct {
	Servers                    []ServerConfig
	RoundTripper               http.RoundTripper
	RequestTimeout             time.Duration
	CancelTimeout              time.Duration
	MaximumResultBytes         int64
	AllowInsecureLoopbackTests bool
}

// Descriptor is the private canonical MCP action persisted only after broker
// admission. It contains no endpoint URL, session, credential, or capability.
type Descriptor struct {
	Version   string          `json:"version"`
	ServerID  string          `json:"server_id"`
	ToolName  string          `json:"tool_name"`
	Arguments json.RawMessage `json:"arguments"`
}

// DecodeDescriptor parses one exact mcp.tool/v1 immutable descriptor.
func DecodeDescriptor(raw []byte) (Descriptor, error) {
	if len(raw) == 0 || len(raw) > maximumDescriptorBytes {
		return Descriptor{}, errors.New("decode MCP tool descriptor: invalid size")
	}
	var descriptor Descriptor
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&descriptor); err != nil || decoder.More() {
		return Descriptor{}, errors.New("decode MCP tool descriptor: invalid canonical value")
	}
	if descriptor.Version != "mcp.tool/v1" || !validName(descriptor.ServerID) || !validName(descriptor.ToolName) || len(descriptor.Arguments) == 0 || len(descriptor.Arguments) > maximumDescriptorBytes || !validJSONObject(descriptor.Arguments) {
		return Descriptor{}, errors.New("decode MCP tool descriptor: invalid canonical value")
	}
	return descriptor, nil
}

// Client is a private stateless MCP requester. A fresh protocol session per
// operation makes connection loss observational rather than authorization
// state, while every request still carries the negotiated session headers.
type Client struct {
	servers        map[string]server
	roundTripper   http.RoundTripper
	requestTimeout time.Duration
	cancelTimeout  time.Duration
	maximumResult  int64
}

type server struct {
	id                         string
	endpoint                   *url.URL
	origin                     string
	credentials                CredentialSource
	tools                      map[string]ToolConfig
	reconcileTool              string
	reconcileOperationArgument string
}

// NewClient constructs a fail-closed Streamable HTTP MCP client.
func NewClient(config Config) (*Client, error) {
	if len(config.Servers) == 0 || config.RequestTimeout <= 0 || config.CancelTimeout <= 0 {
		return nil, errors.New("create MCP client: servers and positive request limits are required")
	}
	maximum := config.MaximumResultBytes
	if maximum == 0 {
		maximum = defaultMaximumResultBytes
	}
	if maximum <= 0 || maximum > 8<<20 {
		return nil, errors.New("create MCP client: result limit is invalid")
	}
	servers := make(map[string]server, len(config.Servers))
	for _, supplied := range config.Servers {
		resolved, err := validateServer(supplied, config.AllowInsecureLoopbackTests)
		if err != nil || servers[resolved.id].id != "" {
			return nil, errors.New("create MCP client: invalid or duplicate server configuration")
		}
		servers[resolved.id] = resolved
	}
	roundTripper := config.RoundTripper
	if roundTripper == nil {
		roundTripper = http.DefaultTransport
	}
	return &Client{servers: servers, roundTripper: roundTripper, requestTimeout: config.RequestTimeout, cancelTimeout: config.CancelTimeout, maximumResult: maximum}, nil
}

func validateServer(config ServerConfig, allowInsecureLoopback bool) (server, error) {
	if !validName(config.ID) || config.Credentials == nil || len(config.Tools) == 0 || !validName(config.ReconcileTool) || !validName(config.ReconcileOperationArgument) {
		return server{}, errors.New("invalid MCP server configuration")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.User != nil || endpoint.Fragment != "" || endpoint.RawQuery != "" || endpoint.Host == "" || endpoint.Path == "" {
		return server{}, errors.New("invalid MCP endpoint")
	}
	if endpoint.Scheme != "https" && (!allowInsecureLoopback || endpoint.Scheme != "http" || !loopbackHost(endpoint.Hostname())) {
		return server{}, errors.New("MCP endpoint requires HTTPS")
	}
	tools := make(map[string]ToolConfig, len(config.Tools))
	for _, tool := range config.Tools {
		if !validName(tool.Name) || !validDigest(tool.InputSchemaDigest) || !validName(tool.OperationIDArgument) || tools[tool.Name].Name != "" {
			return server{}, errors.New("invalid MCP tool configuration")
		}
		tools[tool.Name] = tool
	}
	if tools[config.ReconcileTool].Name == "" {
		return server{}, errors.New("MCP reconcile tool must be pinned")
	}
	return server{id: config.ID, endpoint: endpoint, origin: endpoint.Scheme + "://" + endpoint.Host, credentials: config.Credentials, tools: tools, reconcileTool: config.ReconcileTool, reconcileOperationArgument: config.ReconcileOperationArgument}, nil
}

// Execute invokes the broker-authorized configured tool exactly once. A
// transport failure after submission is uncertain and must be reconciled.
func (client *Client) Execute(ctx context.Context, descriptor Descriptor, operationID string) ([]byte, bool, error) {
	configured, err := client.resolve(descriptor)
	if err != nil {
		return nil, false, err
	}
	arguments, err := appendOperationID(descriptor.Arguments, configured.tools[descriptor.ToolName].OperationIDArgument, operationID)
	if err != nil {
		return nil, false, fmt.Errorf("prepare MCP tool call: %w", ErrInvalidDescriptor)
	}
	session, err := client.initialize(ctx, configured)
	if err != nil {
		return nil, false, err
	}
	if err := client.validateTool(ctx, session, descriptor.ToolName, arguments); err != nil {
		return nil, false, err
	}
	result, err := client.call(ctx, session, operationID, descriptor.ToolName, arguments)
	if err != nil {
		return nil, false, err
	}
	if result.IsError {
		return nil, true, errors.New("MCP tool reported a terminal error")
	}
	return result.safeOutput(), false, nil
}

// Reconcile observes a server-declared operation-status tool. It never calls
// the original external-effect tool again.
func (client *Client) Reconcile(ctx context.Context, descriptor Descriptor, operationID string) ([]byte, bool, error) {
	configured, err := client.resolve(descriptor)
	if err != nil {
		return nil, false, err
	}
	session, err := client.initialize(ctx, configured)
	if err != nil {
		return nil, false, err
	}
	arguments, err := json.Marshal(map[string]string{configured.reconcileOperationArgument: operationID})
	if err != nil {
		return nil, false, err
	}
	if err := client.validateTool(ctx, session, configured.reconcileTool, arguments); err != nil {
		return nil, false, err
	}
	result, err := client.call(ctx, session, "reconcile-"+operationID, configured.reconcileTool, arguments)
	if err != nil {
		return nil, false, err
	}
	if result.IsError {
		return nil, false, ErrUncertain
	}
	state, exactOperation, ok := result.status()
	if !ok || exactOperation != operationID {
		return nil, false, ErrUncertain
	}
	switch state {
	case "succeeded":
		return result.safeOutput(), false, nil
	case "failed", "cancelled":
		return nil, true, errors.New("MCP tool reported a terminal error")
	default:
		return nil, false, ErrUncertain
	}
}

func (client *Client) resolve(descriptor Descriptor) (server, error) {
	if descriptor.Version != "mcp.tool/v1" {
		return server{}, fmt.Errorf("use MCP tool: %w", ErrInvalidDescriptor)
	}
	configured, found := client.servers[descriptor.ServerID]
	if !found || configured.tools[descriptor.ToolName].Name == "" {
		return server{}, fmt.Errorf("use MCP tool: %w", ErrUnauthorizedServerTool)
	}
	return configured, nil
}

type session struct {
	client  *Client
	server  server
	id      string
	version string
}

func (client *Client) initialize(ctx context.Context, configured server) (session, error) {
	s := session{client: client, server: configured, version: protocolVersion}
	result, err := s.request(ctx, "initialize", "initialize", map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]string{"name": "agent-runtime", "version": "m7"},
	})
	if err != nil {
		return session{}, err
	}
	var initialized struct {
		ProtocolVersion string `json:"protocolVersion"`
		Capabilities    struct {
			Tools json.RawMessage `json:"tools"`
		} `json:"capabilities"`
	}
	if json.Unmarshal(result, &initialized) != nil || initialized.ProtocolVersion != protocolVersion || len(initialized.Capabilities.Tools) == 0 || string(initialized.Capabilities.Tools) == "null" {
		return session{}, errors.New("initialize MCP session: server did not negotiate tools")
	}
	if err := s.notification(ctx, "notifications/initialized", map[string]any{}); err != nil {
		return session{}, err
	}
	return s, nil
}

func (client *Client) validateTool(ctx context.Context, s session, name string, arguments []byte) error {
	configured, found := s.server.tools[name]
	if !found {
		return errors.New("validate MCP tool: tool is not operator configured")
	}
	var cursor string
	for page := 0; page < maximumToolPages; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		result, err := s.request(ctx, fmt.Sprintf("tools-list-%d", page), "tools/list", params)
		if err != nil {
			return err
		}
		var listed struct {
			Tools []struct {
				Name        string          `json:"name"`
				InputSchema json.RawMessage `json:"inputSchema"`
			} `json:"tools"`
			NextCursor string `json:"nextCursor"`
		}
		if json.Unmarshal(result, &listed) != nil || len(listed.Tools) > maximumListedTools {
			return errors.New("validate MCP tool: invalid tools list")
		}
		for _, listedTool := range listed.Tools {
			if listedTool.Name != name {
				continue
			}
			if schemaDigest(listedTool.InputSchema) != configured.InputSchemaDigest {
				return errors.New("validate MCP tool: server schema does not match pinned configuration")
			}
			return validateArguments(listedTool.InputSchema, arguments)
		}
		if listed.NextCursor == "" {
			break
		}
		cursor = listed.NextCursor
	}
	return errors.New("validate MCP tool: configured tool was not advertised")
}

func (client *Client) call(ctx context.Context, s session, requestID, name string, arguments []byte) (callResult, error) {
	var decoded any
	if json.Unmarshal(arguments, &decoded) != nil {
		return callResult{}, errors.New("call MCP tool: invalid canonical arguments")
	}
	result, err := s.request(ctx, requestID, "tools/call", map[string]any{"name": name, "arguments": decoded})
	if err != nil {
		return callResult{}, err
	}
	var response callResult
	if json.Unmarshal(result, &response) != nil || !response.valid() {
		return callResult{}, errors.New("call MCP tool: invalid bounded result")
	}
	if len(response.safeOutput()) > int(client.maximumResult) {
		return callResult{}, errors.New("call MCP tool: result exceeds configured limit")
	}
	return response, nil
}

func (s *session) request(ctx context.Context, id, method string, params any) (json.RawMessage, error) {
	requestContext, cancel := context.WithTimeout(ctx, s.client.requestTimeout)
	defer cancel()
	response, err := s.post(requestContext, rpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params}, false)
	if err != nil {
		if requestContext.Err() != nil && method != "initialize" {
			s.cancel(id)
			return nil, ErrUncertain
		}
		return nil, err
	}
	return response, nil
}

func (s *session) notification(ctx context.Context, method string, params any) error {
	requestContext, cancel := context.WithTimeout(ctx, s.client.requestTimeout)
	defer cancel()
	_, err := s.post(requestContext, rpcRequest{JSONRPC: "2.0", Method: method, Params: params}, true)
	return err
}

func (s *session) cancel(requestID string) {
	ctx, cancel := context.WithTimeout(context.Background(), s.client.cancelTimeout)
	defer cancel()
	// Cancellation is a best-effort MCP notification. It intentionally does not
	// carry a caller context or credential error to a public event/log path.
	_, _ = s.post(ctx, rpcRequest{JSONRPC: "2.0", Method: "notifications/cancelled", Params: map[string]string{"requestId": requestID, "reason": "runtime request deadline exceeded"}}, true)
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

func (s *session) post(ctx context.Context, value rpcRequest, notification bool) (result json.RawMessage, err error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("send MCP request: encode request")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.server.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("send MCP request: create request")
	}
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", s.server.origin)
	if s.id != "" {
		request.Header.Set("MCP-Session-Id", s.id)
	}
	if value.Method != "initialize" {
		request.Header.Set("MCP-Protocol-Version", s.version)
	}
	credential, err := s.server.credentials.Authorization(ctx)
	if err != nil || !validAuthorization(credential) {
		return nil, errors.New("send MCP request: credential unavailable")
	}
	request.Header.Set("Authorization", credential)
	httpClient := &http.Client{Transport: s.client.roundTripper, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, errors.New("send MCP request: transport unavailable")
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil && err == nil {
			result = nil
			err = fmt.Errorf("send MCP request: close response: %w", closeErr)
		}
	}()
	if notification {
		if response.StatusCode != http.StatusAccepted {
			return nil, errors.New("send MCP notification: server did not accept notification")
		}
		return nil, nil
	}
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("send MCP request: unexpected response status")
	}
	contentType, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if parseErr != nil || (contentType != "application/json" && contentType != "text/event-stream") {
		return nil, errors.New("send MCP request: unsupported response transport")
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, s.client.maximumResult+1))
	if err != nil || int64(len(encoded)) > s.client.maximumResult {
		return nil, errors.New("send MCP request: response exceeds configured limit")
	}
	if contentType == "text/event-stream" {
		encoded, err = responseFromSSE(encoded, value.ID)
		if err != nil {
			return nil, err
		}
	}
	result, err = decodeRPCResponse(encoded, value.ID)
	if err != nil {
		return nil, err
	}
	if value.Method == "initialize" {
		sessionID := response.Header.Get("MCP-Session-Id")
		if sessionID != "" && !validSessionID(sessionID) {
			return nil, errors.New("initialize MCP session: invalid session identifier")
		}
		s.id = sessionID
	}
	return result, nil
}

func decodeRPCResponse(encoded []byte, requestID string) (json.RawMessage, error) {
	var decoded struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(encoded, &decoded) != nil || decoded.JSONRPC != "2.0" || decoded.Error != nil || len(decoded.Result) == 0 || string(decoded.ID) != fmt.Sprintf("%q", requestID) {
		return nil, errors.New("send MCP request: invalid JSON-RPC response")
	}
	return decoded.Result, nil
}

// responseFromSSE extracts the response matching the request ID while safely
// ignoring related progress/notification frames. Stream closure without the
// response is never retried as a call; the caller reports an uncertain effect.
func responseFromSSE(encoded []byte, requestID string) ([]byte, error) {
	lines := bytes.Split(encoded, []byte("\n"))
	var data [][]byte
	for _, rawLine := range lines {
		line := bytes.TrimSuffix(rawLine, []byte("\r"))
		if len(line) == 0 {
			if response, found := responseEvent(data, requestID); found {
				return response, nil
			}
			data = nil
			continue
		}
		if bytes.HasPrefix(line, []byte("data:")) {
			value := bytes.TrimPrefix(line, []byte("data:"))
			data = append(data, bytes.TrimPrefix(value, []byte(" ")))
		}
	}
	if response, found := responseEvent(data, requestID); found {
		return response, nil
	}
	return nil, errors.New("send MCP request: SSE stream ended without response")
}

func responseEvent(data [][]byte, requestID string) ([]byte, bool) {
	if len(data) == 0 {
		return nil, false
	}
	encoded := bytes.Join(data, []byte("\n"))
	var decoded struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(encoded, &decoded) != nil || string(decoded.ID) != fmt.Sprintf("%q", requestID) {
		return nil, false
	}
	return encoded, true
}

type callResult struct {
	Content           json.RawMessage `json:"content"`
	StructuredContent json.RawMessage `json:"structuredContent,omitempty"`
	IsError           bool            `json:"isError,omitempty"`
}

func (result callResult) valid() bool {
	return len(result.Content) > 0 && json.Valid(result.Content) && (len(result.StructuredContent) == 0 || json.Valid(result.StructuredContent))
}
func (result callResult) safeOutput() []byte {
	output, _ := json.Marshal(struct {
		Content           json.RawMessage `json:"content"`
		StructuredContent json.RawMessage `json:"structured_content,omitempty"`
	}{Content: result.Content, StructuredContent: result.StructuredContent})
	return output
}
func (result callResult) status() (string, string, bool) {
	var status struct {
		OperationID string `json:"operation_id"`
		State       string `json:"state"`
	}
	if len(result.StructuredContent) == 0 || json.Unmarshal(result.StructuredContent, &status) != nil || !validName(status.OperationID) {
		return "", "", false
	}
	return status.State, status.OperationID, true
}

func appendOperationID(arguments []byte, name, operationID string) ([]byte, error) {
	if !validName(name) || !validName(operationID) {
		return nil, errors.New("prepare MCP tool call: invalid operation identity")
	}
	var decoded map[string]json.RawMessage
	if json.Unmarshal(arguments, &decoded) != nil || decoded == nil {
		return nil, errors.New("prepare MCP tool call: invalid canonical arguments")
	}
	if existing, found := decoded[name]; found && string(existing) != fmt.Sprintf("%q", operationID) {
		return nil, errors.New("prepare MCP tool call: descriptor cannot override operation identity")
	}
	encoded, _ := json.Marshal(operationID)
	decoded[name] = encoded
	return json.Marshal(decoded)
}

func schemaDigest(schema []byte) string {
	var decoded any
	if json.Unmarshal(schema, &decoded) != nil {
		return ""
	}
	encoded, err := json.Marshal(decoded)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validJSONObject(raw []byte) bool {
	var decoded map[string]json.RawMessage
	return json.Unmarshal(raw, &decoded) == nil && decoded != nil
}
func validName(value string) bool {
	return value != "" && len(value) <= 128 && !strings.ContainsAny(value, "\x00\r\n \t")
}
func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}
func validAuthorization(value string) bool {
	return value != "" && len(value) <= 4096 && !strings.ContainsAny(value, "\x00\r\n")
}
func validSessionID(value string) bool {
	return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\x00\r\n \t")
}
func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
