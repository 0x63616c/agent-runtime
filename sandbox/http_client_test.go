package sandbox

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewClientBindsThroughPinnedHTTPSWithoutAmbientTrust(t *testing.T) {
	bindCalls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		bindCalls++
		if request.URL.Path != bindRouteV1 || request.Method != http.MethodPost {
			t.Fatalf("bind request = %s %s", request.Method, request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer test-credential" {
			t.Fatalf("authorization = %q", got)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := string(body), `{"version":"sandbox.control/v1","kind":"bind-request"}`; got != want {
			t.Fatalf("bind body = %q, want %q", got, want)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"version":"sandbox.control/v1","kind":"bind-response","assertion":"opaque-binding","expires_at":"2030-01-01T00:00:00Z"}`))
	}))
	t.Cleanup(server.Close)

	certificate := server.Certificate()
	roots := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	source, err := NewStaticTrustBundleSource(map[TrustBundleRef]TrustBundle{
		"trust/test": {Version: "test/v1", PEMRoots: roots},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(context.Background(), ClientConfig{
		Endpoint: Endpoint{URL: server.URL},
		TLS:      TLSConfig{ServerName: certificate.DNSNames[0], TrustBundleRef: "trust/test"},
		Credentials: credentialSourceFunc(func(_ context.Context, sink CredentialSink) error {
			return sink.SetAuthorization("Bearer", "test-credential")
		}),
		TrustBundles:   source,
		RequestTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if bindCalls != 1 {
		t.Fatalf("bind calls = %d, want one", bindCalls)
	}
	if err := client.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPClientSubmitsAndReconnectsOperationWithFreshBoundCredential(t *testing.T) {
	acceptedAt := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	request := OperationRequest{ID: "op_http", Kind: OperationCloseSandbox, CloseSandbox: &CloseSandboxRequest{SandboxID: "sbx_http"}}
	operation := Operation{Ref: OperationRef{ID: request.ID, AcceptedAt: acceptedAt}, Kind: request.Kind, State: OperationAccepted, Target: OperationTarget{Kind: TargetSandbox, SandboxID: "sbx_http"}, CanonicalDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", EffectiveSpecDigest: "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", CapabilityDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111", RetentionExpiresAt: acceptedAt.Add(time.Hour), LatestCursor: "operation:1"}
	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, httpRequest *http.Request) {
		call := calls.Add(1)
		if got := httpRequest.Header.Get("Authorization"); got != "Bearer credential-"+string(rune('0'+call)) {
			t.Errorf("call %d authorization = %q", call, got)
		}
		switch call {
		case 1:
			if httpRequest.URL.Path != bindRouteV1 {
				t.Errorf("bind path = %q", httpRequest.URL.Path)
			}
			writeTestJSON(t, writer, bindResponse{Version: controlV1, Kind: bindResponseKind, Assertion: "opaque-binding", ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)})
		case 2:
			if httpRequest.Method != http.MethodPost || httpRequest.URL.Path != operationsRouteV1 || httpRequest.Header.Get(bindingHeaderV1) != "opaque-binding" {
				t.Errorf("submit request = %s %s binding=%q", httpRequest.Method, httpRequest.URL.Path, httpRequest.Header.Get(bindingHeaderV1))
			}
			body, err := io.ReadAll(httpRequest.Body)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decodeOperationRequestV1(body)
			if err != nil || decoded.ID != request.ID || decoded.Kind != request.Kind {
				t.Errorf("decode submit = %#v, %v", decoded, err)
			}
			writeTestJSON(t, writer, operationResponseEnvelope{Version: controlV1, Kind: operationResponseKind, Operation: operation})
		case 3:
			if httpRequest.Method != http.MethodGet || httpRequest.URL.Path != operationsRouteV1+"/op_http" || httpRequest.Header.Get(bindingHeaderV1) != "opaque-binding" {
				t.Errorf("get request = %s %s binding=%q", httpRequest.Method, httpRequest.URL.Path, httpRequest.Header.Get(bindingHeaderV1))
			}
			writeTestJSON(t, writer, operationResponseEnvelope{Version: controlV1, Kind: operationResponseKind, Operation: operation})
		default:
			t.Errorf("unexpected request %d", call)
		}
	}))
	t.Cleanup(server.Close)

	client := newTestHTTPClient(t, server, func(_ context.Context, sink CredentialSink) error {
		call := calls.Load() + 1
		return sink.SetAuthorization("Bearer", "credential-"+string(rune('0'+call)))
	})
	ref, err := client.Submit(context.Background(), request)
	if err != nil || ref != operation.Ref {
		t.Fatalf("Submit() = %#v, %v; want %#v", ref, err, operation.Ref)
	}
	got, err := client.GetOperation(context.Background(), request.ID)
	if err != nil || got.Ref != operation.Ref || got.CanonicalDigest != operation.CanonicalDigest {
		t.Fatalf("GetOperation() = %#v, %v", got, err)
	}
	if calls.Load() != 3 {
		t.Fatalf("HTTP calls = %d, want bind plus two operation attempts", calls.Load())
	}
}

func TestHTTPClientReplaysAuthenticatedBoundedOutputAfterCursor(t *testing.T) {
	events := []OutputEvent{{Kind: OutputEventChunk, Cursor: "output:assignment:stdout:2", Stream: OutputStdout, Chunk: &OutputChunk{Bytes: []byte("[REDACTED]"), Redacted: true}}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == bindRouteV1 {
			writeTestJSON(t, writer, bindResponse{Version: controlV1, Kind: bindResponseKind, Assertion: "opaque-binding", ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)})
			return
		}
		if request.Method != http.MethodGet || request.URL.Path != processesRouteV1+"prc_output/output" || request.URL.Query().Get("after") != "output:assignment:stdout:1" || request.Header.Get(bindingHeaderV1) != "opaque-binding" {
			t.Errorf("output replay request = %s %s binding=%q", request.Method, request.URL.String(), request.Header.Get(bindingHeaderV1))
		}
		writeTestJSON(t, writer, outputEventsResponseEnvelope{Version: controlV1, Kind: outputEventsResponseKind, Events: events})
	}))
	t.Cleanup(server.Close)
	client := newTestHTTPClient(t, server, func(_ context.Context, sink CredentialSink) error {
		return sink.SetAuthorization("Bearer", "credential")
	})
	stream, err := client.ReplayOutput(context.Background(), "prc_output", "output:assignment:stdout:1")
	if err != nil {
		t.Fatalf("ReplayOutput() error = %v", err)
	}
	defer stream.Close()
	event, err := stream.Next(context.Background())
	if err != nil || event.Cursor != events[0].Cursor || string(event.Chunk.Bytes) != "[REDACTED]" || !event.Chunk.Redacted {
		t.Fatalf("ReplayOutput() event = %#v, %v", event, err)
	}
}

func TestHTTPClientMapsSafeFailureAndCancellationWithoutTransportCause(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == bindRouteV1 {
			writeTestJSON(t, writer, bindResponse{Version: controlV1, Kind: bindResponseKind, Assertion: "opaque-binding", ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)})
			return
		}
		writer.WriteHeader(http.StatusConflict)
		writeTestJSON(t, writer, failureResponseEnvelope{Version: controlV1, Kind: failureResponseKind, Failure: Failure{Code: FailureOperationConflict, Message: "operation ID has different immutable input", Retry: RetryNever}})
	}))
	t.Cleanup(server.Close)
	client := newTestHTTPClient(t, server, func(_ context.Context, sink CredentialSink) error {
		return sink.SetAuthorization("Bearer", "credential")
	})
	_, err := client.Submit(context.Background(), OperationRequest{ID: "op_conflict", Kind: OperationCloseSandbox, CloseSandbox: &CloseSandboxRequest{SandboxID: "sbx_conflict"}})
	failure, ok := AsFailure(err)
	if !ok || failure.Code != FailureOperationConflict || errors.Unwrap(err) != nil || failure.Message != "operation ID has different immutable input" {
		t.Fatalf("Submit() failure = %#v, unwrap=%v, error=%v", failure, errors.Unwrap(err), err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = client.GetOperation(cancelled, "op_conflict")
	failure, ok = AsFailure(err)
	if !ok || failure.Code != FailureCancelled || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled GetOperation() failure = %#v, %v", failure, err)
	}
}

func TestApplyAuthorizationDoesNotCallCredentialSourceAfterCancellation(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	_, err := applyAuthorization(cancelled, credentialSourceFunc(func(_ context.Context, sink CredentialSink) error {
		called = true
		return sink.SetAuthorization("Bearer", "late")
	}))
	failure, ok := AsFailure(err)
	if !ok || failure.Code != FailureCancelled || !errors.Is(err, context.Canceled) {
		t.Fatalf("applyAuthorization() failure = %#v, %v; want cancellation", failure, err)
	}
	if called {
		t.Fatal("applyAuthorization() called credential source after cancellation")
	}
}

func TestHTTPClientCloseFencesANonCooperativeCredentialSourceBeforeItCanReachTheServer(t *testing.T) {
	enteredCredentials := make(chan struct{})
	credentialMutation := make(chan error, 1)
	requests := make(chan string, 2)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == bindRouteV1 {
			writeTestJSON(t, writer, bindResponse{Version: controlV1, Kind: bindResponseKind, Assertion: "opaque-binding", ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)})
			return
		}
		requests <- request.URL.Path
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	var credentialCalls atomic.Int64
	client := newTestHTTPClient(t, server, func(ctx context.Context, sink CredentialSink) error {
		if credentialCalls.Add(1) == 1 {
			return sink.SetAuthorization("Bearer", "bind")
		}
		close(enteredCredentials)
		<-ctx.Done()
		credentialMutation <- sink.SetAuthorization("Bearer", "late")
		return nil
	})
	result := make(chan error, 1)
	go func() { _, err := client.GetOperation(context.Background(), "op_close"); result <- err }()
	<-enteredCredentials
	if err := client.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-result; err == nil {
		t.Fatal("GetOperation() = nil, want cancelled failure")
	} else if failure, ok := AsFailure(err); !ok || failure.Code != FailureCancelled {
		t.Fatalf("GetOperation() = %v, want cancelled failure", err)
	}
	if err := <-credentialMutation; err == nil {
		t.Fatal("SetAuthorization() after Close cancellation = nil, want client-owned refusal")
	}
	select {
	case path := <-requests:
		t.Fatalf("post-close request reached server: %s", path)
	default:
	}
}

func TestHTTPClientRejectsNonCanonicalOrOversizedOperationResponse(t *testing.T) {
	acceptedAt := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	valid := Operation{Ref: OperationRef{ID: "op_response", AcceptedAt: acceptedAt}, Kind: OperationCloseSandbox, State: OperationAccepted, Target: OperationTarget{Kind: TargetSandbox, SandboxID: "sbx_response"}, CanonicalDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", EffectiveSpecDigest: "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", CapabilityDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111", RetentionExpiresAt: acceptedAt.Add(time.Hour), LatestCursor: "operation:1"}
	unknownState := valid
	unknownState.State = "server-invented-state"
	ambiguousTarget := valid
	ambiguousTarget.Target.ProcessID = "prc_smuggled"
	invalidCursor := valid
	invalidCursor.LatestCursor = "operation:0"
	responses := [][]byte{
		[]byte(`{"version":"sandbox.control/v1","kind":"operation-response","operation":{},"operation":{}}`),
		make([]byte, maxControlV1Bytes+1),
		mustMarshalTest(t, operationResponseEnvelope{Version: controlV1, Kind: operationResponseKind, Operation: unknownState}),
		mustMarshalTest(t, operationResponseEnvelope{Version: controlV1, Kind: operationResponseKind, Operation: ambiguousTarget}),
		mustMarshalTest(t, operationResponseEnvelope{Version: controlV1, Kind: operationResponseKind, Operation: invalidCursor}),
	}
	for index, response := range responses {
		t.Run(string(rune('a'+index)), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path == bindRouteV1 {
					writeTestJSON(t, writer, bindResponse{Version: controlV1, Kind: bindResponseKind, Assertion: "opaque-binding", ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)})
					return
				}
				_, _ = writer.Write(response)
			}))
			t.Cleanup(server.Close)
			client := newTestHTTPClient(t, server, func(_ context.Context, sink CredentialSink) error {
				return sink.SetAuthorization("Bearer", "credential")
			})
			_, err := client.GetOperation(context.Background(), "op_response")
			failure, ok := AsFailure(err)
			if !ok || failure.Code != FailureUnavailable {
				t.Fatalf("GetOperation() failure = %#v, %v", failure, err)
			}
		})
	}
}

func TestHTTPClientRejectsHostileFailureDetails(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == bindRouteV1 {
			writeTestJSON(t, writer, bindResponse{Version: controlV1, Kind: bindResponseKind, Assertion: "opaque-binding", ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)})
			return
		}
		writer.WriteHeader(http.StatusConflict)
		_, _ = writer.Write(mustMarshalTest(t, failureResponseEnvelope{Version: controlV1, Kind: failureResponseKind, Failure: Failure{Code: FailureOperationConflict, Message: "unsafe", Retry: RetryNever, Details: []FailureDetail{{Key: "server-private-field", Value: "leak"}}}}))
	}))
	t.Cleanup(server.Close)
	client := newTestHTTPClient(t, server, func(_ context.Context, sink CredentialSink) error {
		return sink.SetAuthorization("Bearer", "credential")
	})
	_, err := client.GetOperation(context.Background(), "op_response")
	failure, ok := AsFailure(err)
	if !ok || failure.Code != FailureUnavailable || failure.Message != "sandbox control failure response is invalid" {
		t.Fatalf("GetOperation() failure = %#v, %v", failure, err)
	}
}

func mustMarshalTest(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func newTestHTTPClient(t *testing.T, server *httptest.Server, credentials credentialSourceFunc) Client {
	t.Helper()
	certificate := server.Certificate()
	roots := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	source, err := NewStaticTrustBundleSource(map[TrustBundleRef]TrustBundle{"trust/test": {Version: "test/v1", PEMRoots: roots}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(context.Background(), ClientConfig{Endpoint: Endpoint{URL: server.URL}, TLS: TLSConfig{ServerName: certificate.DNSNames[0], TrustBundleRef: "trust/test"}, Credentials: credentials, TrustBundles: source, RequestTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close(context.Background()) })
	return client
}

func writeTestJSON(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	writer.Header().Set("Content-Type", "application/json")
	_, _ = writer.Write(encoded)
}

func TestStaticTrustBundleSourceFreezesAndDefensivelyReturnsPEM(t *testing.T) {
	pemRoots := []byte("original")
	source, err := NewStaticTrustBundleSource(map[TrustBundleRef]TrustBundle{
		"trust/test": {Version: "test/v1", PEMRoots: pemRoots},
	})
	if err != nil {
		t.Fatal(err)
	}
	pemRoots[0] = 'X'
	first, err := source.ResolveTrustBundle(context.Background(), "trust/test")
	if err != nil {
		t.Fatal(err)
	}
	first.PEMRoots[0] = 'Y'
	second, err := source.ResolveTrustBundle(context.Background(), "trust/test")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(second.PEMRoots), "original"; got != want {
		t.Fatalf("resolved PEM = %q, want frozen %q", got, want)
	}
}

func TestNewClientRejectsTrustBundleWithoutCertificate(t *testing.T) {
	source, err := NewStaticTrustBundleSource(map[TrustBundleRef]TrustBundle{
		"trust/invalid": {Version: "test/v1", PEMRoots: []byte("not a certificate")},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewClient(context.Background(), ClientConfig{
		Endpoint:       Endpoint{URL: "https://sandbox.example.test"},
		TLS:            TLSConfig{ServerName: "sandbox.example.test", TrustBundleRef: "trust/invalid"},
		Credentials:    credentialSourceFunc(func(_ context.Context, sink CredentialSink) error { return sink.SetAuthorization("Bearer", "test") }),
		TrustBundles:   source,
		RequestTimeout: time.Second,
	})
	failure, ok := AsFailure(err)
	if !ok || failure.Code != FailureInvalidArgument {
		t.Fatalf("trust failure = %#v, %v", failure, err)
	}
}
