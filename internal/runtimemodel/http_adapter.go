package runtimemodel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

const (
	maxStreamLineBytes  = 64 << 10
	maxStreamOutput     = 2 << 20
	maxToolDescriptor   = 48 << 10
	modelRequestTimeout = 30 * time.Second
)

// HTTPAdapterConfig configures the concrete, provider-neutral normalized-stream
// protocol. Endpoint and token are process-owned; the adapter never retains
// raw prompts, provider-specific request fields, or credentials in runtime
// state. A deployed endpoint must implement this protocol before it is a
// production provider integration.
type HTTPAdapterConfig struct {
	Endpoint   string
	Token      string
	HTTPClient *http.Client
}

// HTTPAdapter talks to one operator-configured normalized-stream endpoint.
// It deliberately implements a small runtime protocol rather than a
// provider-specific API. Invoke POSTs an operation identity to /v1/invocations
// and Reconcile GETs that exact identity, so recovery never issues a second
// provider effect.
type HTTPAdapter struct {
	endpoint *url.URL
	token    string
	client   *http.Client
}

// NewHTTPAdapter validates an operator-configured normalized-stream adapter.
func NewHTTPAdapter(config HTTPAdapterConfig) (*HTTPAdapter, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint == nil || endpoint.Scheme == "" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("create normalized model HTTP adapter: endpoint must be an absolute origin")
	}
	if endpoint.Scheme != "https" && (endpoint.Scheme != "http" || !loopbackHost(endpoint.Hostname())) {
		return nil, errors.New("create normalized model HTTP adapter: endpoint must use HTTPS unless it is a literal loopback development address")
	}
	if config.Token == "" {
		return nil, errors.New("create normalized model HTTP adapter: model credential is required")
	}
	return &HTTPAdapter{endpoint: endpoint, token: config.Token, client: boundedNoRedirectClient(config.HTTPClient)}, nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func boundedNoRedirectClient(provided *http.Client) *http.Client {
	if provided == nil {
		provided = &http.Client{}
	}
	client := *provided
	client.Timeout = modelRequestTimeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("normalized model redirects are forbidden")
	}
	return &client
}

// Invoke executes one new normalized provider operation exactly once.
func (adapter *HTTPAdapter) Invoke(ctx context.Context, request Request) (Response, error) {
	body, err := json.Marshal(normalizedRequest{Tenant: string(request.Tenant), SessionID: request.SessionID.String(), TurnID: request.TurnID.String(), OperationID: string(request.OperationID)})
	if err != nil {
		return Response{}, fmt.Errorf("encode normalized model invocation: %w", err)
	}
	return adapter.exchange(ctx, http.MethodPost, adapter.operationURL(request.OperationID), bytes.NewReader(body))
}

// Reconcile reads the terminal state of the exact operation. It never POSTs.
func (adapter *HTTPAdapter) Reconcile(ctx context.Context, request Request) (Response, error) {
	return adapter.exchange(ctx, http.MethodGet, adapter.operationURL(request.OperationID), nil)
}

func (adapter *HTTPAdapter) operationURL(operationID runtimestate.OperationID) string {
	endpoint := *adapter.endpoint
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/v1/invocations/" + url.PathEscape(string(operationID))
	return endpoint.String()
}

func (adapter *HTTPAdapter) exchange(ctx context.Context, method, endpoint string, body io.Reader) (result Response, err error) {
	if adapter == nil || adapter.endpoint == nil || adapter.client == nil {
		return Response{}, errors.New("invoke normalized model stream: adapter is not configured")
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return Response{}, fmt.Errorf("create normalized model request: %w", err)
	}
	request.Header.Set("Accept", "application/x-ndjson")
	request.Header.Set("Authorization", "Bearer "+adapter.token)
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := adapter.client.Do(request)
	if err != nil {
		return Response{}, fmt.Errorf("send normalized model request: %w", err)
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close normalized model response: %w", closeErr)
		}
	}()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return Response{}, fmt.Errorf("normalized model response status %d", response.StatusCode)
	}
	if mediaType := response.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(mediaType), "application/x-ndjson") {
		return Response{}, errors.New("normalized model response must be application/x-ndjson")
	}
	return decodeNormalizedStream(response.Body)
}

type normalizedRequest struct {
	Tenant      string `json:"tenant"`
	SessionID   string `json:"session_id"`
	TurnID      string `json:"turn_id"`
	OperationID string `json:"operation_id"`
}

type normalizedEvent struct {
	Type         string                `json:"type"`
	Delta        string                `json:"delta,omitempty"`
	Failure      *agentruntime.Failure `json:"failure,omitempty"`
	InputTokens  *uint64               `json:"input_tokens,omitempty"`
	OutputTokens *uint64               `json:"output_tokens,omitempty"`
	Tool         json.RawMessage       `json:"tool,omitempty"`
}

// normalizedTool is the sole provider-wire Tool representation. Its descriptor
// remains a private, bounded action commitment; public Approvals retain only
// their fixed action summary and bounded capability projection.
type normalizedTool struct {
	ToolCallID     string           `json:"tool_call_id"`
	ApprovalID     string           `json:"approval_id"`
	PolicyName     string           `json:"policy_name"`
	PolicyRevision uint64           `json:"policy_revision"`
	ToolName       string           `json:"tool_name"`
	Action         normalizedAction `json:"action"`
	MaximumUses    uint32           `json:"maximum_uses"`
	ExpiresAt      time.Time        `json:"expires_at"`
	Descriptor     json.RawMessage  `json:"descriptor"`
	Arguments      json.RawMessage  `json:"arguments,omitempty"`
}

type normalizedAction struct {
	Verb   string `json:"verb"`
	Target string `json:"target"`
}

func decodeNormalizedStream(body io.Reader) (Response, error) {
	if body == nil {
		return Response{}, errors.New("decode normalized model stream: response body is required")
	}
	reader := bufio.NewScanner(body)
	reader.Buffer(make([]byte, 4096), maxStreamLineBytes)
	var output bytes.Buffer
	var terminal *normalizedEvent
	for reader.Scan() {
		if terminal != nil {
			return Response{}, errors.New("decode normalized model stream: event after terminal outcome")
		}
		var event normalizedEvent
		if err := decodeStrictJSON(reader.Bytes(), &event); err != nil {
			return Response{}, errors.New("decode normalized model stream: invalid event")
		}
		switch event.Type {
		case "delta":
			if event.Delta == "" || event.Failure != nil || event.InputTokens != nil || event.OutputTokens != nil || output.Len()+len(event.Delta) > maxStreamOutput {
				return Response{}, errors.New("decode normalized model stream: invalid or oversized delta")
			}
			output.WriteString(event.Delta)
		case "completed", "failed", "tool":
			terminal = &event
		default:
			return Response{}, errors.New("decode normalized model stream: unknown event type")
		}
	}
	if err := reader.Err(); err != nil {
		return Response{}, fmt.Errorf("decode normalized model stream: %w", err)
	}
	if terminal == nil {
		return Response{}, errors.New("decode normalized model stream: terminal outcome is required")
	}
	usage := &runtimestate.ModelUsage{InputTokens: terminal.InputTokens, OutputTokens: terminal.OutputTokens}
	if usage.InputTokens == nil && usage.OutputTokens == nil {
		usage = nil
	}
	switch terminal.Type {
	case "completed":
		if terminal.Failure != nil || len(terminal.Tool) != 0 || output.Len() == 0 {
			return Response{}, errors.New("decode normalized model stream: completed outcome is invalid")
		}
		return Response{Output: output.Bytes(), Usage: usage}, nil
	case "failed":
		if terminal.Failure == nil || len(terminal.Tool) != 0 || output.Len() != 0 || !safeFailure(terminal.Failure) {
			return Response{}, errors.New("decode normalized model stream: failed outcome is invalid")
		}
		return Response{Failure: terminal.Failure.Clone(), Usage: usage}, nil
	case "tool":
		if terminal.Failure != nil || output.Len() != 0 || terminal.InputTokens != nil || terminal.OutputTokens != nil {
			return Response{}, errors.New("decode normalized model stream: tool outcome is invalid")
		}
		tool, err := parseNormalizedTool(terminal.Tool)
		if err != nil {
			return Response{}, err
		}
		return Response{Tool: &tool}, nil
	default:
		return Response{}, errors.New("decode normalized model stream: terminal outcome is invalid")
	}
}

func decodeStrictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("unexpected trailing JSON value")
	}
	return nil
}

func parseNormalizedTool(raw json.RawMessage) (ToolRequest, error) {
	if len(raw) == 0 || len(raw) > maxToolDescriptor {
		return ToolRequest{}, errors.New("decode normalized model stream: tool is missing or oversized")
	}
	var tool normalizedTool
	if err := decodeStrictJSON(raw, &tool); err != nil {
		return ToolRequest{}, errors.New("decode normalized model stream: invalid tool schema")
	}
	if _, err := agentruntime.ParseApprovalID(tool.ApprovalID); err != nil || !validToolIdentity(tool.ToolCallID) || !validToolIdentity(tool.PolicyName) || tool.PolicyRevision == 0 || !validToolIdentity(tool.ToolName) || !validAction(tool.Action) || tool.MaximumUses == 0 || tool.MaximumUses > 32 || tool.ExpiresAt.IsZero() || tool.ExpiresAt.Location() != time.UTC {
		return ToolRequest{}, errors.New("decode normalized model stream: invalid tool fields")
	}
	descriptor, err := canonicalToolDescriptor(tool.Descriptor)
	if err != nil {
		return ToolRequest{}, err
	}
	arguments, err := canonicalToolArguments(tool.Arguments)
	if err != nil {
		return ToolRequest{}, err
	}
	actionDigest := digestToolBytes(descriptor)
	capability, err := json.Marshal(struct {
		PolicyName     string           `json:"policy_name"`
		PolicyRevision uint64           `json:"policy_revision"`
		ToolName       string           `json:"tool_name"`
		Action         normalizedAction `json:"action"`
		MaximumUses    uint32           `json:"maximum_uses"`
		ExpiresAt      time.Time        `json:"expires_at"`
	}{tool.PolicyName, tool.PolicyRevision, tool.ToolName, tool.Action, tool.MaximumUses, tool.ExpiresAt})
	if err != nil {
		return ToolRequest{}, errors.New("decode normalized model stream: canonicalize tool capability")
	}
	return ToolRequest{ToolCallID: tool.ToolCallID, ApprovalID: tool.ApprovalID, PolicyName: tool.PolicyName, PolicyRevision: tool.PolicyRevision, ToolName: tool.ToolName, ActionDigest: actionDigest, CapabilityDigest: digestToolBytes(capability), Action: agentruntime.ApprovalAction{Verb: tool.Action.Verb, Target: tool.Action.Target}, MaximumUses: tool.MaximumUses, ExpiresAt: tool.ExpiresAt, Descriptor: descriptor, Arguments: arguments}, nil
}

func canonicalToolArguments(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return []byte(`{}`), nil
	}
	if len(raw) > maxToolDescriptor {
		return nil, errors.New("decode normalized model stream: tool arguments are oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil || decoder.More() || value == nil {
		return nil, errors.New("decode normalized model stream: tool arguments must be an object")
	}
	canonical, err := json.Marshal(value)
	if err != nil || len(canonical) > maxToolDescriptor {
		return nil, errors.New("decode normalized model stream: canonical tool arguments are invalid")
	}
	return canonical, nil
}

func canonicalToolDescriptor(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 || len(raw) > maxToolDescriptor {
		return nil, errors.New("decode normalized model stream: tool descriptor is missing or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil || decoder.More() {
		return nil, errors.New("decode normalized model stream: tool descriptor must be one JSON value")
	}
	if _, ok := value.(map[string]any); !ok || containsCredentialField(value) {
		return nil, errors.New("decode normalized model stream: tool descriptor is not safe")
	}
	canonical, err := json.Marshal(value)
	if err != nil || len(canonical) == 0 || len(canonical) > maxToolDescriptor {
		return nil, errors.New("decode normalized model stream: canonical tool descriptor is invalid")
	}
	return canonical, nil
}

func containsCredentialField(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			switch strings.ToLower(key) {
			case "authorization", "cookie", "credential", "credentials", "password", "secret", "token":
				return true
			}
			if containsCredentialField(nested) {
				return true
			}
		}
	case []any:
		for _, nested := range typed {
			if containsCredentialField(nested) {
				return true
			}
		}
	}
	return false
}

func validToolIdentity(value string) bool {
	return len(value) > 0 && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func validAction(action normalizedAction) bool {
	return (action.Verb == "execute" || action.Verb == "restart" || action.Verb == "write" || action.Verb == "delete") && (action.Target == "workspace-service" || action.Target == "sandbox-process" || action.Target == "artifact" || action.Target == "network-request")
}

func digestToolBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return fmt.Sprintf("sha256:%x", sum)
}

func safeFailure(failure *agentruntime.Failure) bool {
	return failure != nil && failure.Code != "" && len(failure.Message) <= 1024 && len(failure.Details) <= 16
}
