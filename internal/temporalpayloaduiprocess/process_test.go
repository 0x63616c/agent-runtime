package temporalpayloaduiprocess_test

import (
	"bytes"
	"context"
	stderrors "errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/temporalpayloaduiprocess"
	"github.com/0x63616c/agent-runtime/temporalpayload"
	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const validConfig = `{
  "version": 1,
  "blob_prefix": "runtime/payloads",
  "maximum_blob_bytes": 1048576,
  "io_timeout_milliseconds": 1000,
  "temporal_ui_namespaces": ["runtime-test"],
  "temporal_ui_origins": ["https://temporal.example"]
}`

func TestParseRequiresAnExplicitBoundedUIInspectionPolicy(t *testing.T) {
	t.Parallel()

	if _, err := temporalpayloaduiprocess.Parse(strings.NewReader(validConfig)); err != nil {
		t.Fatalf("Parse(valid): %v", err)
	}
	for _, test := range []struct {
		name    string
		content string
	}{
		{name: "unknown field", content: strings.Replace(validConfig, `"version": 1`, `"version": 1, "unknown": true`, 1)},
		{name: "unsafe prefix", content: strings.Replace(validConfig, `"runtime/payloads"`, `"../payloads"`, 1)},
		{name: "unbounded bytes", content: strings.Replace(validConfig, `1048576`, `0`, 1)},
		{name: "unbounded timeout", content: strings.Replace(validConfig, `1000`, `60001`, 1)},
		{name: "missing namespace", content: strings.Replace(validConfig, `["runtime-test"]`, `[]`, 1)},
		{name: "missing origin", content: strings.Replace(validConfig, `["https://temporal.example"]`, `[]`, 1)},
		{name: "wildcard origin", content: strings.Replace(validConfig, `"https://temporal.example"`, `"*"`, 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := temporalpayloaduiprocess.Parse(strings.NewReader(test.content)); err == nil {
				t.Fatal("Parse(invalid) error = nil")
			}
		})
	}
	if _, err := temporalpayloaduiprocess.Parse(strings.NewReader(validConfig + strings.Repeat(" ", 32<<10))); err == nil {
		t.Fatal("Parse(oversized) error = nil")
	}
}

func TestServeAuthorizesBeforeReadingAndInspectsEveryRepresentation(t *testing.T) {
	store := &recordingStore{store: temporalpayload.NewMemoryBlobStore()}
	producer, err := temporalpayload.NewCodec(store,
		temporalpayload.WithBlobPrefix("runtime/payloads"),
		temporalpayload.WithMaximumBlobBytes(1<<20),
		temporalpayload.WithIOTimeout(time.Second),
	)
	if err != nil {
		t.Fatalf("NewCodec(producer): %v", err)
	}
	config := parseConfig(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- temporalpayloaduiprocess.Serve(ctx, config, store, temporalpayload.UIRequestAuthorizerFunc(testAuthorizer), listener)
	}()
	baseURL := "http://" + listener.Addr().String()

	for _, test := range []struct {
		name         string
		value        []byte
		wantEncoding string
	}{
		{name: "inline", value: []byte("inline"), wantEncoding: "json/plain"},
		{name: "zstd", value: bytes.Repeat([]byte("x"), 1024), wantEncoding: temporalpayload.EncodingZstd},
		{name: "remote", value: incompressibleBytes(64 << 10), wantEncoding: temporalpayload.EncodingRemote},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := &commonpb.Payload{Metadata: map[string][]byte{converter.MetadataEncoding: []byte("json/plain")}, Data: bytes.Clone(test.value)}
			if test.name == "remote" {
				original.Metadata["source"] = []byte("test")
			}
			encoded, err := producer.Encode([]*commonpb.Payload{original})
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			payload := encoded[0]
			if got := string(payload.Metadata[converter.MetadataEncoding]); got != test.wantEncoding {
				t.Fatalf("encoding = %q, want %q", got, test.wantEncoding)
			}
			response := callEndpoint(t, baseURL, "/decode", payload, "Bearer allowed")
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(response.Body)
				t.Fatalf("decode status = %d, want 200: %s", response.StatusCode, body)
			}
			var decoded commonpb.Payloads
			if err := protojson.Unmarshal(mustRead(t, response.Body), &decoded); err != nil {
				t.Fatalf("unmarshal decoded response: %v", err)
			}
			if len(decoded.Payloads) != 1 || !proto.Equal(decoded.Payloads[0], original) {
				t.Fatalf("decoded payload = %v, want %v", decoded.Payloads, original)
			}
		})
	}

	remote, err := producer.DataConverter().ToPayload(payloadValue{Bytes: incompressibleBytes(64 << 10)})
	if err != nil {
		t.Fatalf("ToPayload(remote): %v", err)
	}
	before := store.getCalls()
	denied := callEndpoint(t, baseURL, "/decode", remote, "Bearer denied")
	defer denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("denied status = %d, want 403", denied.StatusCode)
	}
	if got := store.getCalls(); got != before {
		t.Fatalf("blob reads after denied request = %d, want %d", got-before, 0)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

func TestServeCancelsAndDoesNotExposeStoreDiagnostics(t *testing.T) {
	config := parseConfig(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	backing := temporalpayload.NewMemoryBlobStore()
	producer, err := temporalpayload.NewCodec(backing,
		temporalpayload.WithBlobPrefix("runtime/payloads"),
		temporalpayload.WithMaximumBlobBytes(1<<20),
		temporalpayload.WithIOTimeout(time.Second),
	)
	if err != nil {
		t.Fatalf("NewCodec(producer): %v", err)
	}
	remote, err := producer.DataConverter().ToPayload(payloadValue{Bytes: incompressibleBytes(64 << 10)})
	if err != nil {
		t.Fatalf("ToPayload(remote): %v", err)
	}
	if got := string(remote.Metadata[converter.MetadataEncoding]); got != temporalpayload.EncodingRemote {
		t.Fatalf("remote encoding = %q, want %q", got, temporalpayload.EncodingRemote)
	}
	store := &recordingStore{store: backing, err: stderrors.New("top-secret storage diagnostic")}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- temporalpayloaduiprocess.Serve(ctx, config, store, temporalpayload.UIRequestAuthorizerFunc(testAuthorizer), listener)
	}()

	response := callEndpoint(t, "http://"+listener.Addr().String(), "/decode", remote, "Bearer allowed")
	body := mustRead(t, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("decode status = %d, want 400", response.StatusCode)
	}
	if bytes.Contains(body, []byte("top-secret storage diagnostic")) || bytes.Contains(body, []byte("runtime/payloads")) {
		t.Fatalf("response leaked blob diagnostic: %s", body)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

func TestServeBoundsUIRequestBodiesByTheDeclaredBlobPolicy(t *testing.T) {
	config, err := temporalpayloaduiprocess.Parse(strings.NewReader(strings.Replace(validConfig, `1048576`, `128`, 1)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- temporalpayloaduiprocess.Serve(ctx, config, temporalpayload.NewMemoryBlobStore(), temporalpayload.UIRequestAuthorizerFunc(testAuthorizer), listener)
	}()

	response := callEndpoint(t, "http://"+listener.Addr().String(), "/decode", &commonpb.Payload{Metadata: map[string][]byte{converter.MetadataEncoding: []byte("json/plain")}, Data: bytes.Repeat([]byte("x"), 1024)}, "Bearer allowed")
	body := mustRead(t, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized status = %d, want 400", response.StatusCode)
	}
	if !bytes.Equal(body, []byte("Temporal UI payload transformation failed\n")) {
		t.Fatalf("oversized response = %q, want redacted failure", body)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

func parseConfig(t *testing.T) temporalpayloaduiprocess.Config {
	t.Helper()
	config, err := temporalpayloaduiprocess.Parse(strings.NewReader(validConfig))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return config
}

func callEndpoint(t *testing.T, baseURL, path string, payload *commonpb.Payload, authorization string) *http.Response {
	t.Helper()
	body, err := protojson.Marshal(&commonpb.Payloads{Payloads: []*commonpb.Payload{payload}})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, baseURL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	request.Header.Set("X-Namespace", "runtime-test")
	request.Header.Set("Origin", "https://temporal.example")
	request.Header.Set("Authorization", authorization)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	return response
}

func mustRead(t *testing.T, reader io.Reader) []byte {
	t.Helper()
	value, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return value
}

func testAuthorizer(request *http.Request, namespace string) (temporalpayload.AuthorizationDecision, error) {
	if request.Header.Get("Authorization") == "Bearer denied" {
		return temporalpayload.AuthorizationDecision{Authenticated: true}, nil
	}
	if request.Header.Get("Authorization") != "Bearer allowed" {
		return temporalpayload.AuthorizationDecision{}, nil
	}
	return temporalpayload.AuthorizationDecision{Authenticated: true, Allowed: namespace == "runtime-test"}, nil
}

type payloadValue struct {
	Bytes []byte `json:"bytes"`
}

type recordingStore struct {
	store *temporalpayload.MemoryBlobStore
	err   error
	mu    sync.Mutex
	gets  int
}

func (store *recordingStore) Put(ctx context.Context, key temporalpayload.BlobKey, value []byte) error {
	if store.err != nil {
		return store.err
	}
	return store.store.Put(ctx, key, value)
}

func (store *recordingStore) Get(ctx context.Context, key temporalpayload.BlobKey, maxBytes int) ([]byte, error) {
	store.mu.Lock()
	store.gets++
	store.mu.Unlock()
	if store.err != nil {
		return nil, store.err
	}
	return store.store.Get(ctx, key, maxBytes)
}

func (store *recordingStore) getCalls() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.gets
}

func incompressibleBytes(size int) []byte {
	result := make([]byte, size)
	state := uint64(1)
	for index := range result {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		result[index] = byte(state)
	}
	return result
}
