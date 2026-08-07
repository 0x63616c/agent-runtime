//go:build integration

package temporalpayload_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0x63616c/agent-runtime/temporalpayload"
	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestRuntimeAndIndependentConsumerExchangePayloadsThroughTheUI(t *testing.T) {
	store := temporalpayload.NewMemoryBlobStore()
	runtimeCodec, err := temporalpayload.NewCodec(store, temporalpayload.WithBlobPrefix("runtime/payloads"))
	if err != nil {
		t.Fatalf("create runtime codec: %v", err)
	}
	secondCodec, err := temporalpayload.NewCodec(store, temporalpayload.WithBlobPrefix("runtime/payloads"))
	if err != nil {
		t.Fatalf("create second consumer codec: %v", err)
	}
	handler, err := temporalpayload.NewUIHandler(secondCodec,
		temporalpayload.WithTemporalUINamespaces("runtime-test"),
		temporalpayload.WithTemporalUIOrigins("https://ui.example"),
		temporalpayload.WithTemporalUIRequestAuthorizer(temporalpayload.UIRequestAuthorizerFunc(func(*http.Request, string) (temporalpayload.AuthorizationDecision, error) {
			return temporalpayload.AuthorizationDecision{Authenticated: true, Allowed: true}, nil
		})),
	)
	if err != nil {
		t.Fatalf("create UI handler: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	want := payloadExchangeValue{Bytes: exchangeIncompressibleBytes(64 * 1024)}
	payload, err := runtimeCodec.DataConverter().ToPayload(want)
	if err != nil {
		t.Fatalf("runtime encode: %v", err)
	}
	var received payloadExchangeValue
	if err := secondCodec.DataConverter().FromPayload(payload, &received); err != nil {
		t.Fatalf("independent consumer decode: %v", err)
	}
	if !bytes.Equal(received.Bytes, want.Bytes) {
		t.Fatal("independent consumer payload differs")
	}

	body, err := protojson.Marshal(&commonpb.Payloads{Payloads: []*commonpb.Payload{payload}})
	if err != nil {
		t.Fatalf("marshal UI decode request: %v", err)
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL+"/decode", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create UI decode request: %v", err)
	}
	request.Header.Set("Origin", "https://ui.example")
	request.Header.Set("X-Namespace", "runtime-test")
	request.Header.Set("Authorization", "Bearer checked-by-boundary")
	request.Header.Set("authorization-extras", "ui-identity-only")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("call UI decode endpoint: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("UI decode status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	decoded := &commonpb.Payloads{}
	if err := protojson.Unmarshal(mustReadAll(t, response), decoded); err != nil {
		t.Fatalf("decode UI response: %v", err)
	}
	original, err := converter.GetDefaultDataConverter().ToPayload(want)
	if err != nil {
		t.Fatalf("encode expected plain payload: %v", err)
	}
	if !proto.Equal(decoded.Payloads[0], original) {
		t.Fatal("UI response does not contain the plain decoded payload")
	}
}

type payloadExchangeValue struct {
	Bytes []byte `json:"bytes"`
}

func exchangeIncompressibleBytes(sizeBytes int) []byte {
	result := make([]byte, sizeBytes)
	state := uint64(1)
	for index := range result {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		result[index] = byte(state)
	}
	return result
}

func mustReadAll(t *testing.T, response *http.Response) []byte {
	t.Helper()
	value, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read UI response: %v", err)
	}
	return value
}
