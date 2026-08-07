//go:build integration

package temporalpayloadruntime

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/temporalpayload"
	commonpb "go.temporal.io/api/common/v1"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestFactoryWorkerExchangesEveryPayloadRepresentationAgainstTemporal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	server, err := testsuite.StartDevServer(ctx, testsuite.DevServerOptions{})
	if err != nil {
		t.Fatalf("start Temporal development server: %v", err)
	}
	defer func() {
		if stopErr := server.Stop(); stopErr != nil {
			t.Errorf("stop Temporal development server: %v", stopErr)
		}
	}()

	store := temporalpayload.NewMemoryBlobStore()
	runtimeCodec, err := temporalpayload.NewCodec(store, temporalpayload.WithBlobPrefix("integration/payloads"))
	if err != nil {
		t.Fatalf("create runtime codec: %v", err)
	}
	factory, err := NewFactory(runtimeCodec)
	if err != nil {
		t.Fatalf("NewFactory() error = %v", err)
	}
	ownedClient, err := factory.NewClient(ctx, client.Options{HostPort: server.FrontendHostPort()})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer ownedClient.temporalClient.Close()

	runtimeWorker, err := factory.NewWorker(ownedClient, "payload-codec-integration", worker.Options{})
	if err != nil {
		t.Fatalf("NewWorker() error = %v", err)
	}
	runtimeWorker.RegisterWorkflow(payloadCodecIntegrationWorkflow)
	if err := runtimeWorker.Start(); err != nil {
		t.Fatalf("start runtime worker: %v", err)
	}
	defer runtimeWorker.Stop()

	independentCodec, err := temporalpayload.NewCodec(store, temporalpayload.WithBlobPrefix("integration/payloads"))
	if err != nil {
		t.Fatalf("create independent public codec: %v", err)
	}
	uiHandler, err := temporalpayload.NewUIHandler(independentCodec,
		temporalpayload.WithTemporalUINamespaces("default"),
		temporalpayload.WithTemporalUIOrigins("https://ui.example"),
		temporalpayload.WithTemporalUIRequestAuthorizer(temporalpayload.UIRequestAuthorizerFunc(func(*http.Request, string) (temporalpayload.AuthorizationDecision, error) {
			return temporalpayload.AuthorizationDecision{Authenticated: true, Allowed: true}, nil
		})),
	)
	if err != nil {
		t.Fatalf("create UI handler: %v", err)
	}
	uiServer := httptest.NewServer(uiHandler)
	defer uiServer.Close()

	for _, test := range []struct {
		name     string
		payload  *commonpb.Payload
		encoding string
	}{
		{name: "inline", payload: integrationPayload([]byte("inline")), encoding: "json/plain"},
		{name: "zstd", payload: integrationPayload(bytes.Repeat([]byte("x"), 1024)), encoding: temporalpayload.EncodingZstd},
		{name: "remote", payload: integrationPayload(integrationIncompressibleBytes(64 * 1024)), encoding: temporalpayload.EncodingRemote},
	} {
		t.Run(test.name, func(t *testing.T) {
			workflowID := "payload-codec-integration-" + test.name
			run, err := ownedClient.temporalClient.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
				ID:        workflowID,
				TaskQueue: "payload-codec-integration",
			}, payloadCodecIntegrationWorkflow, converter.NewRawValue(test.payload))
			if err != nil {
				t.Fatalf("execute workflow: %v", err)
			}
			var ownedResult converter.RawValue
			if err := run.Get(ctx, &ownedResult); err != nil {
				t.Fatalf("get workflow result through owned client: %v", err)
			}
			if !proto.Equal(ownedResult.Payload(), test.payload) {
				t.Fatal("owned client result differs after worker exchange")
			}

			encoded := completedResultPayload(t, ctx, ownedClient.temporalClient, workflowID, run.GetRunID())
			if got := string(encoded.Metadata[converter.MetadataEncoding]); got != test.encoding {
				t.Fatalf("stored history encoding = %q, want %q", got, test.encoding)
			}
			var independentResult converter.RawValue
			if err := independentCodec.DataConverter().FromPayload(encoded, &independentResult); err != nil {
				t.Fatalf("independent public consumer decode: %v", err)
			}
			if !proto.Equal(independentResult.Payload(), test.payload) {
				t.Fatal("independent public consumer payload differs")
			}
			assertUIInspection(t, ctx, uiServer.URL, encoded, test.payload)
		})
	}
}

func payloadCodecIntegrationWorkflow(_ workflow.Context, value converter.RawValue) (converter.RawValue, error) {
	return value, nil
}

func completedResultPayload(t *testing.T, ctx context.Context, temporalClient client.Client, workflowID, runID string) *commonpb.Payload {
	t.Helper()
	iterator := temporalClient.GetWorkflowHistory(ctx, workflowID, runID, false, enumspb.HISTORY_EVENT_FILTER_TYPE_CLOSE_EVENT)
	if !iterator.HasNext() {
		t.Fatal("completed workflow history has no close event")
	}
	event, err := iterator.Next()
	if err != nil {
		t.Fatalf("read completed workflow history: %v", err)
	}
	result := event.GetWorkflowExecutionCompletedEventAttributes().GetResult().GetPayloads()
	if len(result) != 1 {
		t.Fatalf("completed workflow result payload count = %d, want 1", len(result))
	}
	return result[0]
}

func assertUIInspection(t *testing.T, ctx context.Context, serverURL string, encoded, expected *commonpb.Payload) {
	t.Helper()
	body, err := protojson.Marshal(&commonpb.Payloads{Payloads: []*commonpb.Payload{encoded}})
	if err != nil {
		t.Fatalf("marshal UI decode request: %v", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/decode", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create UI decode request: %v", err)
	}
	request.Header.Set("Origin", "https://ui.example")
	request.Header.Set("X-Namespace", "default")
	request.Header.Set("Authorization", "Bearer checked-by-boundary")
	request.Header.Set("authorization-extras", "ui-identity-only")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("call UI decode endpoint: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Errorf("close failed UI response body: %v", closeErr)
		}
		t.Fatalf("UI decode status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	responseBody, err := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err != nil {
		t.Fatalf("read UI response: %v", err)
	}
	if closeErr != nil {
		t.Fatalf("close UI response body: %v", closeErr)
	}
	decoded := &commonpb.Payloads{}
	if err := protojson.Unmarshal(responseBody, decoded); err != nil {
		t.Fatalf("decode UI response: %v", err)
	}
	if len(decoded.Payloads) != 1 || !proto.Equal(decoded.Payloads[0], expected) {
		t.Fatal("UI response does not contain the plain decoded payload")
	}
}

func integrationPayload(data []byte) *commonpb.Payload {
	return &commonpb.Payload{Metadata: map[string][]byte{
		converter.MetadataEncoding: []byte("json/plain"),
	}, Data: bytes.Clone(data)}
}

func integrationIncompressibleBytes(sizeBytes int) []byte {
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
