//go:build integration

package runtimeorchestration_test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimeapi"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimeorchestration"
	"github.com/0x63616c/agent-runtime/internal/runtimepostgres"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/jackc/pgx/v5/pgxpool"
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
	contentBucket := requiredWorkerEnvironment(t, "AR_RUNTIME_API_MINIO_BUCKET")
	bucket := contentBucket + "-temporal-payload"
	objects, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(accessKey, secretKey, ""), Secure: false})
	if err != nil {
		t.Fatal(err)
	}
	if err := objects.MakeBucket(context.Background(), contentBucket, minio.MakeBucketOptions{}); err != nil && minio.ToErrorResponse(err).Code != "BucketAlreadyOwnedByYou" {
		t.Fatalf("create isolated runtime-content bucket: %v", err)
	}
	if err := objects.MakeBucket(context.Background(), bucket, minio.MakeBucketOptions{}); err != nil && minio.ToErrorResponse(err).Code != "BucketAlreadyOwnedByYou" {
		t.Fatalf("create dedicated temporal payload bucket: %v", err)
	}
	seedDurableSessionAndCancellation(t, postgresDSN, endpoint, accessKey, secretKey, contentBucket)
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
	assertOutboxPublished(t, postgresDSN, "codec-worker")
	startAndStopWorker(t, config)
	assertOutboxPublished(t, postgresDSN, "codec-worker")
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

func seedDurableSessionAndCancellation(t *testing.T, dsn, endpoint, accessKey, secretKey, bucket string) {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open durable state pool: %v", err)
	}
	defer pool.Close()
	state, err := runtimepostgres.NewRuntimeStateStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	minioClient, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(accessKey, secretKey, ""), Secure: false})
	if err != nil {
		t.Fatal(err)
	}
	immutable, err := runtimecontent.NewMinIOImmutableClient(minioClient)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := runtimecontent.NewS3ImmutableObjects(immutable, bucket)
	if err != nil {
		t.Fatal(err)
	}
	content, err := runtimecontent.New("runtime-content", objects)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	stamp, err := clock.NewFake(time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(stamp, &workerIntegrationIDs{})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := runtimeapi.NewStateRuntime(runtimeapi.StateRuntimeConfig{Content: content, Compiler: compiler, Planner: planner, Store: state, ModelProfiles: []string{"balanced"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	admin := runtimeapi.Identity{Tenant: "codec-worker", Principal: "admin", Admin: true}
	owner := runtimeapi.Identity{Tenant: "codec-worker", Principal: "owner"}
	agent, err := runtime.CreateAgent(ctx, admin, agentruntime.CreateAgentRequest{IdempotencyKey: "codec-worker-agent", Name: "worker-proof", ModelProfile: "balanced", Instructions: "durable outbox only"})
	if err != nil {
		t.Fatalf("seed durable Agent: %v", err)
	}
	session, err := runtime.CreateSession(ctx, owner, agentruntime.CreateSessionRequest{IdempotencyKey: "codec-worker-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatalf("seed durable Session: %v", err)
	}
	accepted, err := runtime.SendInput(ctx, owner, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "codec-worker-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "outbox route"}}})
	if err != nil {
		t.Fatalf("seed durable Input: %v", err)
	}
	if _, err := runtime.CancelTurn(ctx, owner, agentruntime.CancelTurnRequest{SessionID: session.ID, TurnID: accepted.Turn.ID, IdempotencyKey: "codec-worker-cancel"}); err != nil {
		t.Fatalf("seed durable cancellation: %v", err)
	}
}

func assertOutboxPublished(t *testing.T, dsn, tenant string) {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	state, err := runtimepostgres.NewRuntimeStateStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := runtimecontent.ParseTenantID(tenant)
	if err != nil {
		t.Fatal(err)
	}
	page, err := state.ReadOutbox(context.Background(), runtimestate.OutboxQuery{Scope: runtimestate.MutationScope{Tenant: parsed, Authority: runtimestate.AuthorityOutboxPublisher}, Limit: 16})
	if err != nil {
		t.Fatalf("read published durable outbox: %v", err)
	}
	if len(page.Records) < 4 {
		t.Fatalf("durable outbox records = %#v, want session, input, cancellation and derived events", page.Records)
	}
	for _, record := range page.Records {
		if record.State != runtimestate.OutboxPublished {
			t.Fatalf("outbox %s = %s, want published", record.OutboxID, record.State)
		}
	}
}

type workerIntegrationIDs struct{ next uint64 }

func (source *workerIntegrationIDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	source.next++
	return fmt.Sprintf("%s_%016d", kind, source.next), nil
}
