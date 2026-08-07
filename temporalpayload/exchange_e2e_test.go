//go:build integration

package temporalpayload_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/temporalpayloadruntime"
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
	runtimeFactory, err := temporalpayloadruntime.NewFactory(runtimeCodec)
	if err != nil {
		t.Fatalf("create runtime factory: %v", err)
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

	for _, test := range []struct {
		name     string
		payload  *commonpb.Payload
		encoding string
	}{
		{name: "inline", payload: exchangePayload([]byte("inline")), encoding: "json/plain"},
		{name: "zstd", payload: exchangePayload(bytes.Repeat([]byte("x"), 1024)), encoding: temporalpayload.EncodingZstd},
		{name: "remote", payload: exchangePayload(exchangeIncompressibleBytes(64 * 1024)), encoding: temporalpayload.EncodingRemote},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload, err := runtimeFactory.DataConverter().ToPayload(converter.NewRawValue(test.payload))
			if err != nil {
				t.Fatalf("runtime factory encode: %v", err)
			}
			if got := string(payload.Metadata[converter.MetadataEncoding]); got != test.encoding {
				t.Fatalf("runtime factory encoding = %q, want %q", got, test.encoding)
			}
			var received converter.RawValue
			if err := secondCodec.DataConverter().FromPayload(payload, &received); err != nil {
				t.Fatalf("independent consumer decode: %v", err)
			}
			if !proto.Equal(received.Payload(), test.payload) {
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
			if !proto.Equal(decoded.Payloads[0], test.payload) {
				t.Fatal("UI response does not contain the plain decoded payload")
			}
		})
	}
}

func exchangePayload(data []byte) *commonpb.Payload {
	return &commonpb.Payload{Metadata: map[string][]byte{
		converter.MetadataEncoding: []byte("json/plain"),
	}, Data: bytes.Clone(data)}
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
