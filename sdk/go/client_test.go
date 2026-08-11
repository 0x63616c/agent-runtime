package agentruntime_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

func TestHTTPClientOpensArtifactWithoutBufferingAndVerifiesTheTrailer(t *testing.T) {
	credential, _ := agentruntime.NewStaticBearerCredential("test-token-000000")
	body := []byte("streamed artifact bytes")
	sum := sha256.Sum256(body)
	reader := &countingReadCloser{Reader: strings.NewReader(string(body))}
	var observed *http.Request
	client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: "https://runtime.example", HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		observed = request.Clone(context.Background())
		header := make(http.Header)
		header.Set("X-Request-ID", request.Header.Get("X-Request-ID"))
		header.Set("Content-Type", "text/plain")
		header.Set("X-Agent-Runtime-Artifact-Size", fmt.Sprintf("%d", len(body)))
		header.Set("X-Agent-Runtime-Artifact-SHA256", hex.EncodeToString(sum[:]))
		return &http.Response{StatusCode: http.StatusOK, Header: header, Trailer: http.Header{"Digest": []string{"sha-256=" + hex.EncodeToString(sum[:])}}, Body: reader}, nil
	})}, Credentials: credential, RequestIDs: fixedRequestIDs{}})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	stream, err := client.OpenArtifact(context.Background(), "art_0000000000000001")
	if err != nil {
		t.Fatalf("open Artifact: %v", err)
	}
	if reader.reads != 0 {
		t.Fatalf("open Artifact buffered %d reads before returning", reader.reads)
	}
	got, err := io.ReadAll(stream.Body)
	if err != nil || string(got) != string(body) {
		t.Fatalf("read Artifact stream = %q, %v", got, err)
	}
	if err := stream.Body.Close(); err != nil {
		t.Fatalf("close completed Artifact stream: %v", err)
	}
	if !reader.closed || stream.Artifact.SHA256 != hex.EncodeToString(sum[:]) || stream.Artifact.SizeBytes != int64(len(body)) {
		t.Fatalf("stream = %#v closed=%v, want verified immutable metadata and closed body", stream.Artifact, reader.closed)
	}
	if observed.Method != http.MethodGet || observed.URL.Path != "/v1/artifacts/art_0000000000000001" || observed.Header.Get("Accept") != "application/octet-stream" || observed.Header.Get("Authorization") != "Bearer test-token-000000" {
		t.Fatalf("open Artifact request = %#v", observed)
	}
}

func TestHTTPClientReadArtifactRequiresMatchingContentLength(t *testing.T) {
	t.Parallel()
	credential, _ := agentruntime.NewStaticBearerCredential("test-token-000000")
	body := "four"
	digest := sha256.Sum256([]byte(body))
	client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: "https://runtime.example", HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set("X-Request-ID", request.Header.Get("X-Request-ID"))
		header.Set("Content-Type", "text/plain")
		header.Set("Content-Length", "5")
		header.Set("Digest", "sha-256="+hex.EncodeToString(digest[:]))
		return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}, Credentials: credential, RequestIDs: fixedRequestIDs{}})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.ReadArtifact(context.Background(), "art_0000000000000001"); err == nil || !strings.Contains(err.Error(), "invalid content length") {
		t.Fatalf("ReadArtifact error = %v, want bounded content-length refusal", err)
	}
}

func TestHTTPClientRejectsArtifactStreamDigestMismatchAndSupportsCancellationClose(t *testing.T) {
	credential, _ := agentruntime.NewStaticBearerCredential("test-token-000000")
	body := []byte("streamed artifact bytes")
	sum := sha256.Sum256(body)
	for name, trailer := range map[string]string{"mismatch": "sha-256=" + strings.Repeat("0", 64), "missing": ""} {
		t.Run(name, func(t *testing.T) {
			reader := &countingReadCloser{Reader: strings.NewReader(string(body))}
			client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: "https://runtime.example", HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				header := make(http.Header)
				header.Set("X-Request-ID", request.Header.Get("X-Request-ID"))
				header.Set("Content-Type", "text/plain")
				header.Set("X-Agent-Runtime-Artifact-Size", fmt.Sprintf("%d", len(body)))
				header.Set("X-Agent-Runtime-Artifact-SHA256", hex.EncodeToString(sum[:]))
				trailers := make(http.Header)
				if trailer != "" {
					trailers.Set("Digest", trailer)
				}
				return &http.Response{StatusCode: http.StatusOK, Header: header, Trailer: trailers, Body: reader}, nil
			})}, Credentials: credential, RequestIDs: fixedRequestIDs{}})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			stream, err := client.OpenArtifact(context.Background(), "art_0000000000000001")
			if err != nil {
				t.Fatalf("open Artifact: %v", err)
			}
			if _, err := io.ReadAll(stream.Body); err == nil {
				t.Fatal("read mismatched Artifact stream error = nil")
			}
			if err := stream.Body.Close(); err != nil {
				t.Fatalf("close mismatched Artifact stream: %v", err)
			}
			if !reader.closed {
				t.Fatal("stream reader was not closed after read completion")
			}
		})
	}
	reader := &countingReadCloser{Reader: strings.NewReader(string(body))}
	client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: "https://runtime.example", HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set("X-Request-ID", request.Header.Get("X-Request-ID"))
		header.Set("Content-Type", "text/plain")
		header.Set("X-Agent-Runtime-Artifact-Size", fmt.Sprintf("%d", len(body)))
		header.Set("X-Agent-Runtime-Artifact-SHA256", hex.EncodeToString(sum[:]))
		return &http.Response{StatusCode: http.StatusOK, Header: header, Trailer: http.Header{"Digest": []string{"sha-256=" + hex.EncodeToString(sum[:])}}, Body: reader}, nil
	})}, Credentials: credential, RequestIDs: fixedRequestIDs{}})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	stream, err := client.OpenArtifact(context.Background(), "art_0000000000000001")
	if err != nil {
		t.Fatalf("open Artifact: %v", err)
	}
	if err := stream.Body.Close(); err != nil || !reader.closed {
		t.Fatalf("close early stream = %v closed=%v", err, reader.closed)
	}
}

func TestHTTPClientPreservesSafeArtifactStreamFailures(t *testing.T) {
	credential, _ := agentruntime.NewStaticBearerCredential("test-token-000000")
	client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: "https://runtime.example", HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		body := `{"request_id":"` + request.Header.Get("X-Request-ID") + `","error":{"code":"not_found","message":"resource not found","retryable":false}}`
		return response(http.StatusNotFound, request.Header.Get("X-Request-ID"), body), nil
	})}, Credentials: credential, RequestIDs: fixedRequestIDs{}})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.OpenArtifact(context.Background(), "art_0000000000000001")
	var runtimeError *agentruntime.Error
	if !errors.As(err, &runtimeError) || runtimeError.Failure.Code != agentruntime.FailureNotFound {
		t.Fatalf("open Artifact failure = %v, want safe not-found", err)
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

type countingReadCloser struct {
	io.Reader
	reads  int
	closed bool
}

func (reader *countingReadCloser) Read(value []byte) (int, error) {
	reader.reads++
	return reader.Reader.Read(value)
}

func (reader *countingReadCloser) Close() error {
	reader.closed = true
	return nil
}
