package agentruntime_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestHTTPClientSendsBoundedAuthenticatedOpenAPIRequest(t *testing.T) {
	t.Parallel()
	credential, err := agentruntime.NewStaticBearerCredential("test-token-000000")
	if err != nil {
		t.Fatalf("NewStaticBearerCredential: %v", err)
	}
	var observed *http.Request
	transport := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		observed = request.Clone(context.Background())
		body := `{"id":"agent_1234567890ABCDEF","revision_id":"arev_1234567890ABCDEF","revision":1,"name":"assistant","model_profile":"balanced","instructions":"safe","created_at":"2026-08-07T12:00:00Z"}`
		return response(http.StatusCreated, request.Header.Get("X-Request-ID"), body), nil
	})
	client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: "https://runtime.example", HTTPClient: &http.Client{Transport: transport}, Credentials: credential, RequestIDs: fixedRequestIDs{}})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	created, err := client.CreateAgent(context.Background(), agentruntime.CreateAgentRequest{IdempotencyKey: "create-one", Name: "assistant", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if created.Revision != 1 {
		t.Fatalf("revision = %d", created.Revision)
	}
	if observed.Method != http.MethodPost || observed.URL.Path != "/v1/admin/agents" {
		t.Fatalf("request = %s %s", observed.Method, observed.URL.Path)
	}
	if observed.Header.Get("Authorization") != "Bearer test-token-000000" {
		t.Fatal("authorization was not applied to the request")
	}
	if observed.Header.Get("Idempotency-Key") != "create-one" {
		t.Fatal("idempotency key was not sent")
	}
	if got := credential.String(); got != "StaticBearerCredential{Token:[REDACTED]}" {
		t.Fatalf("credential String = %q", got)
	}
	if got := fmt.Sprintf("%#v", credential); strings.Contains(got, "test-token") || got != "StaticBearerCredential{Token:[REDACTED]}" {
		t.Fatalf("credential detailed format = %q", got)
	}
}

func TestHTTPClientRejectsUnsafeOrigins(t *testing.T) {
	t.Parallel()
	credential, _ := agentruntime.NewStaticBearerCredential("test-token-000000")
	for _, origin := range []string{"http://runtime.example", "https://user:pass@runtime.example", "https://runtime.example/path", "https://:443", "https://runtime.example?"} {
		if _, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: origin, HTTPClient: http.DefaultClient, Credentials: credential, RequestIDs: fixedRequestIDs{}}); err == nil {
			t.Fatalf("NewClient(%q) error = nil", origin)
		}
	}
}

func TestHTTPClientRejectsUnknownAndOversizedResponses(t *testing.T) {
	t.Parallel()
	credential, _ := agentruntime.NewStaticBearerCredential("test-token-000000")
	for name, body := range map[string]string{
		"unknown":   `{"events":[],"unknown":true}`,
		"oversized": `{"events":[]}` + strings.Repeat(" ", 2048),
	} {
		t.Run(name, func(t *testing.T) {
			client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: "https://runtime.example", HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				return response(http.StatusOK, request.Header.Get("X-Request-ID"), body), nil
			})}, Credentials: credential, RequestIDs: fixedRequestIDs{}, MaxResponseBytes: 1024})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			sessionID, _ := agentruntime.ParseSessionID("sess_1234567890ABCDEF")
			if _, err := client.Events(context.Background(), sessionID, "", 10); err == nil {
				t.Fatal("Events error = nil")
			}
		})
	}
}

func TestHTTPClientRequiresMatchingRequestIDOnSafeFailure(t *testing.T) {
	t.Parallel()
	credential, _ := agentruntime.NewStaticBearerCredential("test-token-000000")
	client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: "https://runtime.example", HTTPClient: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusNotFound, "req_9999999999999999", `{"request_id":"req_9999999999999999","error":{"code":"not_found","message":"resource not found","retryable":false}}`), nil
	})}, Credentials: credential, RequestIDs: fixedRequestIDs{}})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	sessionID, _ := agentruntime.ParseSessionID("sess_1234567890ABCDEF")
	if _, err := client.InspectSession(context.Background(), sessionID); err == nil || !strings.Contains(err.Error(), "request ID mismatch") {
		t.Fatalf("InspectSession error = %v", err)
	}
}

func TestHTTPClientRejectsFailureOutsideStableBounds(t *testing.T) {
	t.Parallel()
	credential, _ := agentruntime.NewStaticBearerCredential("test-token-000000")
	for name, failure := range map[string]string{
		"unknown code":      `{"code":"backend_error","message":"no","retryable":false}`,
		"oversized message": `{"code":"internal","message":"` + strings.Repeat("x", 1025) + `","retryable":false}`,
		"unsafe detail key": `{"code":"internal","message":"no","retryable":false,"details":{"unsafe key":"value"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			body := `{"request_id":"req_1234567890ABCDEF","error":` + failure + `}`
			client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: "https://runtime.example", HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				return response(http.StatusInternalServerError, request.Header.Get("X-Request-ID"), body), nil
			})}, Credentials: credential, RequestIDs: fixedRequestIDs{}})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			sessionID, _ := agentruntime.ParseSessionID("sess_1234567890ABCDEF")
			if _, err := client.InspectSession(context.Background(), sessionID); err == nil || !strings.Contains(err.Error(), "invalid safe failure envelope") {
				t.Fatalf("InspectSession error = %v", err)
			}
		})
	}
}

func TestHTTPClientNeverFollowsRedirectsWithBearerCredential(t *testing.T) {
	t.Parallel()
	received := make(chan string, 1)
	destination := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) { received <- request.Header.Get("Authorization") }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	credential, _ := agentruntime.NewStaticBearerCredential("test-token-000000")
	client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: redirect.URL, HTTPClient: http.DefaultClient, Credentials: credential, RequestIDs: fixedRequestIDs{}})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	sessionID, _ := agentruntime.ParseSessionID("sess_1234567890ABCDEF")
	if _, err := client.InspectSession(context.Background(), sessionID); err == nil {
		t.Fatal("InspectSession redirect error = nil")
	}
	select {
	case authorization := <-received:
		t.Fatalf("redirect destination received authorization %q", authorization)
	default:
	}
}

func TestHTTPClientRejectsMissingResponseAndUnexpectedContentType(t *testing.T) {
	t.Parallel()
	credential, _ := agentruntime.NewStaticBearerCredential("test-token-000000")
	for name, transport := range map[string]http.RoundTripper{
		"missing response": roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, nil }),
		"unexpected content type": roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			response := response(http.StatusOK, request.Header.Get("X-Request-ID"), `{"events":[]}`)
			response.Header.Set("Content-Type", "text/html")
			return response, nil
		}),
	} {
		t.Run(name, func(t *testing.T) {
			client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: "https://runtime.example", HTTPClient: &http.Client{Transport: transport}, Credentials: credential, RequestIDs: fixedRequestIDs{}})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			sessionID, _ := agentruntime.ParseSessionID("sess_1234567890ABCDEF")
			if _, err := client.Events(context.Background(), sessionID, "", 10); err == nil {
				t.Fatal("Events error = nil")
			}
		})
	}
}

func TestHTTPClientHonorsCancellationBeforeTransport(t *testing.T) {
	t.Parallel()
	credential, _ := agentruntime.NewStaticBearerCredential("test-token-000000")
	called := false
	client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: "https://runtime.example", HTTPClient: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) { called = true; return nil, context.Canceled })}, Credentials: credential, RequestIDs: fixedRequestIDs{}})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sessionID, _ := agentruntime.ParseSessionID("sess_1234567890ABCDEF")
	if _, err := client.InspectSession(ctx, sessionID); err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("InspectSession error = %v", err)
	}
	if called {
		t.Fatal("transport was called after cancellation")
	}
}

type fixedRequestIDs struct{}

func (fixedRequestIDs) NextRequestID() (agentruntime.RequestID, error) {
	return agentruntime.ParseRequestID("req_1234567890ABCDEF")
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (transport roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func response(status int, requestID, body string) *http.Response {
	header := make(http.Header)
	header.Set("X-Request-ID", requestID)
	header.Set("Content-Type", "application/json")
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}
}
