//go:build integration

package temporalpayloadruntime

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/temporalpayload"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

func TestFactoryWorkerInheritsTheOwnedCodecAgainstTemporal(t *testing.T) {
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

	codec, err := temporalpayload.NewCodec(temporalpayload.NewMemoryBlobStore(), temporalpayload.WithBlobPrefix("integration/payloads"))
	if err != nil {
		t.Fatalf("NewCodec() error = %v", err)
	}
	factory, err := NewFactory(codec)
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

	want := payloadCodecIntegrationValue{Bytes: integrationIncompressibleBytes(64 * 1024)}
	run, err := ownedClient.temporalClient.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID:        "payload-codec-integration",
		TaskQueue: "payload-codec-integration",
	}, payloadCodecIntegrationWorkflow, want)
	if err != nil {
		t.Fatalf("execute workflow: %v", err)
	}
	var got payloadCodecIntegrationValue
	if err := run.Get(ctx, &got); err != nil {
		t.Fatalf("get workflow result: %v", err)
	}
	if !bytes.Equal(got.Bytes, want.Bytes) {
		t.Fatal("worker result differs after remote payload decode")
	}
}

type payloadCodecIntegrationValue struct {
	Bytes []byte `json:"bytes"`
}

func payloadCodecIntegrationWorkflow(_ workflow.Context, value payloadCodecIntegrationValue) (payloadCodecIntegrationValue, error) {
	return value, nil
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
