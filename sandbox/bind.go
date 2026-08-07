package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"time"
)

const controlV1 = "sandbox.control/v1"
const bindResponseKind = "bind-response"

type bindResponse struct {
	Version   string    `json:"version"`
	Kind      string    `json:"kind"`
	Assertion string    `json:"assertion"`
	ExpiresAt time.Time `json:"expires_at"`
}
type bindTransport interface {
	Bind(context.Context, string) (bindResponse, error)
}
type bindTransportFunc func(context.Context, string) (bindResponse, error)

func (f bindTransportFunc) Bind(ctx context.Context, authorization string) (bindResponse, error) {
	return f(ctx, authorization)
}

type boundClient struct {
	*coreClient
	assertion string
	expiresAt time.Time
}

func newClientWithBindTransportAt(ctx context.Context, config ClientConfig, transport bindTransport, now time.Time) (*boundClient, error) {
	if err := validateClientConfig(config); err != nil {
		return nil, err
	}
	if err := contextFailure(ctx); err != nil {
		return nil, err
	}
	if transport == nil {
		return nil, newFailure(FailureUnavailable, "sandbox bind transport is required", RetryAfterReconcile)
	}
	sink := &credentialSink{}
	defer sink.ClearAuthorization()
	if err := config.Credentials.Apply(ctx, sink); err != nil {
		if contextErr := contextFailure(ctx); contextErr != nil {
			return nil, contextErr
		}
		return nil, newFailure(FailureUnavailable, "sandbox credentials are unavailable", RetryAfterReconcile)
	}
	authorization, err := sink.consumeAuthorization()
	if err != nil {
		return nil, err
	}
	response, err := transport.Bind(ctx, authorization)
	if err != nil {
		if contextErr := contextFailure(ctx); contextErr != nil {
			return nil, contextErr
		}
		return nil, newFailure(FailureUnavailable, "sandbox bind failed", RetryAfterReconcile)
	}
	if response.Version != controlV1 || response.Kind != bindResponseKind || response.Assertion == "" || response.ExpiresAt.IsZero() || !response.ExpiresAt.After(now.UTC()) {
		return nil, newFailure(FailureNotFoundOrDenied, "sandbox bind response is invalid", RetryNever)
	}
	core := newCoreClient("bound-principal", now.UTC())
	return &boundClient{coreClient: core, assertion: response.Assertion, expiresAt: response.ExpiresAt.UTC()}, nil
}

type credentialSink struct {
	mu            sync.Mutex
	authorization string
	setCalls      uint8
	invalid       bool
	revoked       bool
}

func (sink *credentialSink) SetAuthorization(scheme, value string) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.revoked {
		return newFailure(FailureUnavailable, "credential sink is revoked", RetryNever)
	}
	sink.setCalls++
	if sink.setCalls != 1 || !validAuthorizationPart(scheme) || !validAuthorizationValue(value) {
		sink.invalid = true
		return newFailure(FailureUnavailable, "credential source returned invalid authorization", RetryNever)
	}
	sink.authorization = scheme + " " + value
	return nil
}
func (sink *credentialSink) ClearAuthorization() {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.authorization = ""
	sink.revoked = true
}

func (sink *credentialSink) consumeAuthorization() (string, error) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.revoked || sink.invalid || sink.setCalls != 1 || sink.authorization == "" {
		sink.authorization = ""
		sink.revoked = true
		return "", newFailure(FailureUnavailable, "credential source returned invalid authorization", RetryNever)
	}
	authorization := sink.authorization
	sink.authorization = ""
	sink.revoked = true
	return authorization, nil
}

func validAuthorizationPart(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}\t", character) {
			return false
		}
	}
	return true
}

func validAuthorizationValue(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character == '\r' || character == '\n' || character == 0 || character == 0x7f {
			return false
		}
	}
	return true
}
func decodeBindResponse(data []byte) (bindResponse, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	token, err := decoder.Token()
	if err != nil {
		return bindResponse{}, newFailure(FailureInvalidArgument, "bind response is not a canonical JSON object", RetryNever)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return bindResponse{}, newFailure(FailureInvalidArgument, "bind response must be a JSON object", RetryNever)
	}
	seen := make(map[string]struct{}, 4)
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return bindResponse{}, newFailure(FailureInvalidArgument, "bind response key is invalid", RetryNever)
		}
		name, ok := key.(string)
		if !ok {
			return bindResponse{}, newFailure(FailureInvalidArgument, "bind response key is invalid", RetryNever)
		}
		if _, duplicate := seen[name]; duplicate {
			return bindResponse{}, newFailure(FailureInvalidArgument, "bind response contains a duplicate key", RetryNever)
		}
		seen[name] = struct{}{}
		var discard json.RawMessage
		if err := decoder.Decode(&discard); err != nil {
			return bindResponse{}, newFailure(FailureInvalidArgument, "bind response value is invalid", RetryNever)
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return bindResponse{}, newFailure(FailureInvalidArgument, "bind response object is incomplete", RetryNever)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return bindResponse{}, newFailure(FailureInvalidArgument, "bind response has trailing data", RetryNever)
	}
	if len(seen) != 4 {
		return bindResponse{}, newFailure(FailureInvalidArgument, "bind response contains unknown fields", RetryNever)
	}
	var response bindResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return bindResponse{}, newFailure(FailureInvalidArgument, "bind response is invalid", RetryNever)
	}
	if response.Version != controlV1 || response.Kind != bindResponseKind || response.Assertion == "" || response.ExpiresAt.IsZero() || response.ExpiresAt.Location() != time.UTC {
		return bindResponse{}, newFailure(FailureInvalidArgument, "bind response violates sandbox.control/v1", RetryNever)
	}
	return response, nil
}
