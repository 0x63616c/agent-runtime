package runtimemodel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

const (
	maxStreamLineBytes = 64 << 10
	maxStreamOutput    = 2 << 20
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
	if config.Token == "" {
		return nil, errors.New("create normalized model HTTP adapter: model credential is required")
	}
	client := config.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPAdapter{endpoint: endpoint, token: config.Token, client: client}, nil
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

func (adapter *HTTPAdapter) exchange(ctx context.Context, method, endpoint string, body io.Reader) (Response, error) {
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
	defer response.Body.Close()
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
		if err := json.Unmarshal(reader.Bytes(), &event); err != nil {
			return Response{}, errors.New("decode normalized model stream: invalid event")
		}
		switch event.Type {
		case "delta":
			if event.Delta == "" || event.Failure != nil || event.InputTokens != nil || event.OutputTokens != nil || output.Len()+len(event.Delta) > maxStreamOutput {
				return Response{}, errors.New("decode normalized model stream: invalid or oversized delta")
			}
			output.WriteString(event.Delta)
		case "completed", "failed":
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
		if terminal.Failure != nil || output.Len() == 0 {
			return Response{}, errors.New("decode normalized model stream: completed outcome is invalid")
		}
		return Response{Output: output.Bytes(), Usage: usage}, nil
	case "failed":
		if terminal.Failure == nil || output.Len() != 0 || !safeFailure(terminal.Failure) {
			return Response{}, errors.New("decode normalized model stream: failed outcome is invalid")
		}
		return Response{Failure: terminal.Failure.Clone(), Usage: usage}, nil
	default:
		return Response{}, errors.New("decode normalized model stream: terminal outcome is invalid")
	}
}

func safeFailure(failure *agentruntime.Failure) bool {
	return failure != nil && failure.Code != "" && len(failure.Message) <= 1024 && len(failure.Details) <= 16
}
