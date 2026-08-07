package temporalpayload

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestUIHandlerOnlyPermitsConfiguredTemporalUIRequests(t *testing.T) {
	t.Parallel()

	codec := newTestCodec(t, NewMemoryBlobStore())
	handler, err := NewUIHandler(codec, UIHandlerOptions{
		AllowedNamespaces: []string{"runtime-test"},
		AllowedOrigins:    []string{"https://temporal.example"},
		Authorizer:        UIRequestAuthorizerFunc(testUIRequestAuthorizer),
	})
	if err != nil {
		t.Fatalf("NewUIHandler() error = %v", err)
	}

	body, err := protojson.Marshal(&commonpb.Payloads{Payloads: []*commonpb.Payload{testPayload([]byte("hello"))}})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	denied := httptest.NewRequest(http.MethodPost, "/decode", bytes.NewReader(body))
	denied.Header.Set("X-Namespace", "another-namespace")
	denied.Header.Set("Authorization", "Bearer allowed")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, denied)
	if response.Code != http.StatusForbidden {
		t.Fatalf("unconfigured namespace response = %d, want %d", response.Code, http.StatusForbidden)
	}

	preflight := httptest.NewRequest(http.MethodOptions, "/decode", nil)
	preflight.Header.Set("Origin", "https://temporal.example")
	preflightResponse := httptest.NewRecorder()
	handler.ServeHTTP(preflightResponse, preflight)
	if preflightResponse.Code != http.StatusNoContent {
		t.Fatalf("preflight response = %d, want %d", preflightResponse.Code, http.StatusNoContent)
	}
	if got := preflightResponse.Header().Get("Access-Control-Allow-Origin"); got != "https://temporal.example" {
		t.Fatalf("allow origin = %q, want configured origin", got)
	}
}

func TestUIHandlerRequiresAuthenticationAndNamespaceAuthorization(t *testing.T) {
	t.Parallel()

	codec := newTestCodec(t, NewMemoryBlobStore())
	if _, err := NewUIHandler(codec, UIHandlerOptions{AllowedNamespaces: []string{"runtime-test"}}); err == nil {
		t.Fatal("NewUIHandler() error = nil, want required authorizer error")
	}
	handler, err := NewUIHandler(codec, UIHandlerOptions{
		AllowedNamespaces: []string{"runtime-test"},
		AllowedOrigins:    []string{"https://temporal.example"},
		Authorizer:        UIRequestAuthorizerFunc(testUIRequestAuthorizer),
	})
	if err != nil {
		t.Fatalf("NewUIHandler() error = %v", err)
	}

	for _, test := range []struct {
		name       string
		identity   string
		namespace  string
		origin     string
		wantStatus int
	}{
		{name: "missing identity", namespace: "runtime-test", wantStatus: http.StatusUnauthorized},
		{name: "denied identity", identity: "Bearer denied", namespace: "runtime-test", wantStatus: http.StatusForbidden},
		{name: "spoofed namespace", identity: "Bearer allowed", namespace: "another-namespace", wantStatus: http.StatusForbidden},
		{name: "untrusted origin", identity: "Bearer allowed", namespace: "runtime-test", origin: "https://untrusted.example", wantStatus: http.StatusForbidden},
		{name: "allowed identity", identity: "Bearer allowed", namespace: "runtime-test", origin: "https://temporal.example", wantStatus: http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/not-a-payload-endpoint", nil)
			request.Header.Set("X-Namespace", test.namespace)
			request.Header.Set("Authorization", test.identity)
			request.Header.Set("Origin", test.origin)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("response = %d, want %d", response.Code, test.wantStatus)
			}
		})
	}
}

func TestTwoConsumersExchangeEveryRepresentationAndTheUIInspectsIt(t *testing.T) {
	t.Parallel()

	store := NewMemoryBlobStore()
	runtimeConsumer := newTestCodec(t, store)
	secondConsumer := newTestCodec(t, store)
	handler, err := NewUIHandler(secondConsumer, UIHandlerOptions{AllowedNamespaces: []string{"runtime-test"}, Authorizer: UIRequestAuthorizerFunc(testUIRequestAuthorizer)})
	if err != nil {
		t.Fatalf("NewUIHandler() error = %v", err)
	}

	for _, value := range []payloadValue{
		{Bytes: []byte("inline")},
		{Bytes: bytes.Repeat([]byte("compressible "), 4096)},
		{Bytes: incompressibleBytes(64 * 1024)},
	} {
		payload, err := runtimeConsumer.DataConverter().ToPayload(value)
		if err != nil {
			t.Fatalf("ToPayload(%d bytes) error = %v", len(value.Bytes), err)
		}
		var received payloadValue
		if err := secondConsumer.DataConverter().FromPayload(payload, &received); err != nil {
			t.Fatalf("second consumer FromPayload(%d bytes) error = %v", len(value.Bytes), err)
		}
		if !bytes.Equal(received.Bytes, value.Bytes) {
			t.Fatalf("second consumer value = %#v, want %#v", received, value)
		}

		response := callPayloadEndpoint(t, handler, "/decode", payload)
		if response.Code != http.StatusOK {
			t.Fatalf("UI decode status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
		}
		decoded := &commonpb.Payloads{}
		if err := protojson.Unmarshal(response.Body.Bytes(), decoded); err != nil {
			t.Fatalf("decode UI response: %v", err)
		}
		original, err := converter.GetDefaultDataConverter().ToPayload(value)
		if err != nil {
			t.Fatalf("default ToPayload() error = %v", err)
		}
		if !proto.Equal(decoded.Payloads[0], original) {
			t.Fatalf("UI decoded payload = %v, want %v", decoded.Payloads[0], original)
		}
	}
}

func callPayloadEndpoint(t *testing.T, handler http.Handler, path string, payload *commonpb.Payload) *httptest.ResponseRecorder {
	t.Helper()
	body, err := protojson.Marshal(&commonpb.Payloads{Payloads: []*commonpb.Payload{payload}})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	request.Header.Set("X-Namespace", "runtime-test")
	request.Header.Set("Authorization", "Bearer allowed")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func testUIRequestAuthorizer(request *http.Request, namespace string) (AuthorizationDecision, error) {
	if request.Header.Get("Authorization") == "Bearer denied" {
		return AuthorizationDecision{Authenticated: true}, nil
	}
	if request.Header.Get("Authorization") != "Bearer allowed" {
		return AuthorizationDecision{}, nil
	}
	return AuthorizationDecision{Authenticated: true, Allowed: namespace == "runtime-test"}, nil
}
