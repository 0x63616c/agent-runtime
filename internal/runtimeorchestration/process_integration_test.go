//go:build integration

package runtimeorchestration_test

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimeorchestration"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"
)

func TestCodecEnabledWorkerStartsAgainstDurableDependenciesAndRestarts(t *testing.T) {
	postgresDSN := requiredWorkerEnvironment(t, "AR_RUNTIME_API_POSTGRES_DSN")
	endpoint := requiredWorkerEnvironment(t, "AR_RUNTIME_API_MINIO_ENDPOINT")
	accessKey := requiredWorkerEnvironment(t, "AR_RUNTIME_API_MINIO_ACCESS_KEY")
	secretKey := requiredWorkerEnvironment(t, "AR_RUNTIME_API_MINIO_SECRET_KEY")
	bucket := requiredWorkerEnvironment(t, "AR_RUNTIME_API_MINIO_BUCKET") + "-temporal-payload"
	objects, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(accessKey, secretKey, ""), Secure: false})
	if err != nil {
		t.Fatal(err)
	}
	if err := objects.MakeBucket(context.Background(), bucket, minio.MakeBucketOptions{}); err != nil && minio.ToErrorResponse(err).Code != "BucketAlreadyOwnedByYou" {
		t.Fatalf("create dedicated temporal payload bucket: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	server, err := testsuite.StartDevServer(ctx, testsuite.DevServerOptions{ClientOptions: &client.Options{Namespace: "agent-runtime"}})
	if err != nil {
		t.Fatalf("start Temporal development server: %v", err)
	}
	defer func() { _ = server.Stop() }()
	config := runtimeorchestration.ProcessConfig{
		DatabaseDSN:         postgresDSN,
		TemporalEndpoint:    server.FrontendHostPort(),
		TemporalToken:       "integration-private-temporal-token",
		Namespace:           "agent-runtime",
		TaskQueue:           "agent-runtime-worker-restart-integration",
		PayloadBlobEndpoint: endpoint,
		PayloadBlobBucket:   bucket,
		PayloadBlobPrefix:   "temporal-payload",
		PayloadAccessKey:    accessKey,
		PayloadSecretKey:    secretKey,
	}
	startAndStopWorker(t, config)
	startAndStopWorker(t, config)
}

func startAndStopWorker(t *testing.T, config runtimeorchestration.ProcessConfig) {
	t.Helper()
	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	deadline, cancelDeadline := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelDeadline()
	firstWait := make(chan struct{})
	var waited sync.Once
	wait := func(ctx context.Context, _ time.Duration) error {
		waited.Do(func() { close(firstWait) })
		<-ctx.Done()
		return ctx.Err()
	}
	done := make(chan error, 1)
	go func() { done <- runtimeorchestration.RunWithWait(runCtx, config, wait) }()
	select {
	case <-firstWait:
		cancelRun()
	case err := <-done:
		t.Fatalf("start codec-enabled worker: %v", err)
	case <-deadline.Done():
		t.Fatalf("codec-enabled worker did not reach first outbox wait: %v", deadline.Err())
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stop codec-enabled worker: %v", err)
		}
	case <-deadline.Done():
		t.Fatalf("codec-enabled worker did not shut down: %v", deadline.Err())
	}
}

func requiredWorkerEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required for durable worker integration", name)
	}
	return value
}
