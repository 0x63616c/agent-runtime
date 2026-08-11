//go:build integration

package runtimeorchestration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimeapi"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimepostgres"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	"github.com/0x63616c/agent-runtime/internal/temporalpayloadruntime"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/worker"
)

// TestPostgresOutboxReclaimsLiveTemporalRouteAfterAcknowledgementLoss proves
// the TMP-010 cross-authority recovery boundary. It deliberately loses only
// the PostgreSQL acknowledgement after Temporal accepted the exact durable
// input route, recreates the publisher client, then proves lease reclaim and
// durable acknowledgement without manufacturing a second state dispatch.
func TestPostgresOutboxReclaimsLiveTemporalRouteAfterAcknowledgementLoss(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	postgresDSN := requiredPublisherEnvironment(t, "AR_RUNTIME_API_POSTGRES_DSN")
	endpoint := requiredPublisherEnvironment(t, "AR_RUNTIME_API_MINIO_ENDPOINT")
	accessKey := requiredPublisherEnvironment(t, "AR_RUNTIME_API_MINIO_ACCESS_KEY")
	secretKey := requiredPublisherEnvironment(t, "AR_RUNTIME_API_MINIO_SECRET_KEY")
	contentBucket := requiredPublisherEnvironment(t, "AR_RUNTIME_API_MINIO_BUCKET")
	payloadBucket := contentBucket + "-temporal-payload-reclaim"

	objects, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(accessKey, secretKey, ""), Secure: false})
	if err != nil {
		t.Fatal(err)
	}
	for _, bucket := range []string{contentBucket, payloadBucket} {
		if err := objects.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil && minio.ToErrorResponse(err).Code != "BucketAlreadyOwnedByYou" {
			t.Fatalf("create integration bucket %q: %v", bucket, err)
		}
	}
	pool, err := pgxpool.New(ctx, postgresDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store, err := runtimepostgres.NewRuntimeStateStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	content := publisherIntegrationContent(t, endpoint, accessKey, secretKey, contentBucket)
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	timeSource, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(timeSource, &publisherIntegrationIDs{})
	if err != nil {
		t.Fatal(err)
	}
	tenant, session, _ := seedPublisherIntegrationSession(t, ctx, content, compiler, planner, store)

	server, err := testsuite.StartDevServer(ctx, testsuite.DevServerOptions{})
	if err != nil {
		t.Fatalf("start Temporal development server: %v", err)
	}
	defer func() { _ = server.Stop() }()
	factory, err := temporalpayloadruntime.NewS3Factory(temporalpayloadruntime.S3Config{Endpoint: endpoint, Bucket: payloadBucket, Prefix: "postgres-temporal-reclaim", AccessKey: accessKey, SecretKey: secretKey})
	if err != nil {
		t.Fatal(err)
	}
	taskQueue := "postgres-temporal-reclaim"
	workerClient, err := factory.NewClient(ctx, client.Options{HostPort: server.FrontendHostPort()})
	if err != nil {
		t.Fatal(err)
	}
	defer workerClient.Close()
	workerRuntime, err := factory.NewWorker(workerClient, taskQueue, worker.Options{})
	if err != nil {
		t.Fatal(err)
	}
	durableDispatcher, err := NewDurableStateDispatcher(store)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := &publisherIntegrationDispatcher{StateDispatcher: durableDispatcher}
	activities, err := NewActivities(dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	if err := Register(workerRuntime, activities); err != nil {
		t.Fatal(err)
	}
	if err := workerRuntime.Start(); err != nil {
		t.Fatal(err)
	}
	defer workerRuntime.Stop()

	publisherClient, err := factory.NewClient(ctx, client.Options{HostPort: server.FrontendHostPort()})
	if err != nil {
		t.Fatal(err)
	}
	failingStore := &failFirstPostgresAcknowledgementStore{RuntimeStateStore: store}
	tenants := publisherIntegrationTenants{tenant: tenant}
	publisher, err := NewPublisher(PublisherConfig{Store: failingStore, Tenants: tenants, Compiler: compiler, Planner: planner, Clock: timeSource, Publisher: temporalSessionPublisher{client: publisherClient, taskQueue: taskQueue}, Claimer: "postgres-temporal-publisher"})
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.ScanOnce(ctx); err == nil || !strings.Contains(err.Error(), "simulated publisher process loss") {
		t.Fatalf("publish outbox = %v, want acknowledgement-loss error after Temporal accepts the input route", err)
	}
	if !dispatcher.waitFor(ctx, CommandInputAccepted) {
		t.Fatal("live Temporal workflow did not dispatch the durable input route before acknowledgement loss")
	}
	dispatchedInput, found := dispatcher.first(CommandInputAccepted)
	if !found {
		t.Fatal("live Temporal workflow did not retain its dispatched input command")
	}
	claimed := loadPublisherIntegrationState(t, ctx, store, tenant)
	inputRoute := publisherIntegrationOutbox(t, claimed, dispatchedInput.OutboxID)
	if inputRoute.State != runtimestate.OutboxClaimed || !hasPublisherIntegrationAudit(claimed.Audit, "outbox.claimed", "temporal-claim-"+string(inputRoute.OutboxID)+"-") || hasPublisherIntegrationAudit(claimed.Audit, "outbox.published", "temporal-ack-"+string(inputRoute.OutboxID)+"-") {
		t.Fatalf("state after lost acknowledgement = %#v / %#v, want claimed durable input without acknowledgement", inputRoute, claimed.Audit)
	}
	publisherClient.Close()

	if err := timeSource.Advance(2*time.Minute + time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	restartedClient, err := factory.NewClient(ctx, client.Options{HostPort: server.FrontendHostPort()})
	if err != nil {
		t.Fatal(err)
	}
	defer restartedClient.Close()
	restartedPublisher, err := NewPublisher(PublisherConfig{Store: store, Tenants: tenants, Compiler: compiler, Planner: planner, Clock: timeSource, Publisher: temporalSessionPublisher{client: restartedClient, taskQueue: taskQueue}, Claimer: "postgres-temporal-publisher"})
	if err != nil {
		t.Fatal(err)
	}
	if err := restartedPublisher.ScanOnce(ctx); err != nil {
		t.Fatalf("reclaim PostgreSQL outbox after publisher restart: %v", err)
	}
	recovered := loadPublisherIntegrationState(t, ctx, store, tenant)
	inputRoute = publisherIntegrationOutbox(t, recovered, dispatchedInput.OutboxID)
	if inputRoute.State != runtimestate.OutboxPublished || !hasPublisherIntegrationAudit(recovered.Audit, "outbox.published", "temporal-ack-"+string(inputRoute.OutboxID)+"-") {
		t.Fatalf("state after publisher restart = %#v / %#v, want reclaimed published input route", inputRoute, recovered.Audit)
	}
	if got := dispatcher.count(CommandInputAccepted); got != 1 {
		t.Fatalf("live Temporal input dispatches = %d, want one; reclaimed duplicate must be a workflow no-op", got)
	}
	if session.ID == "" {
		t.Fatal("seeded Session identifier is empty")
	}
}

func publisherIntegrationContent(t *testing.T, endpoint, accessKey, secretKey, bucket string) *runtimecontent.Store {
	t.Helper()
	objects, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(accessKey, secretKey, ""), Secure: false})
	if err != nil {
		t.Fatal(err)
	}
	immutable, err := runtimecontent.NewMinIOImmutableClient(objects)
	if err != nil {
		t.Fatal(err)
	}
	s3, err := runtimecontent.NewS3ImmutableObjects(immutable, bucket)
	if err != nil {
		t.Fatal(err)
	}
	content, err := runtimecontent.New("postgres-temporal-reclaim", s3)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func seedPublisherIntegrationSession(t *testing.T, ctx context.Context, content *runtimecontent.Store, compiler *runtimestate.Compiler, planner *runtimestate.RuntimeStatePlanner, store runtimestate.RuntimeStateStore) (runtimecontent.TenantID, agentruntime.Session, agentruntime.SendInputResult) {
	t.Helper()
	runtime, err := runtimeapi.NewStateRuntime(runtimeapi.StateRuntimeConfig{Content: content, Compiler: compiler, Planner: planner, Store: store, ModelProfiles: []string{"balanced"}})
	if err != nil {
		t.Fatal(err)
	}
	admin := runtimeapi.Identity{Tenant: "postgres-temporal", Principal: "admin", Admin: true}
	owner := runtimeapi.Identity{Tenant: "postgres-temporal", Principal: "owner"}
	agent, err := runtime.CreateAgent(ctx, admin, agentruntime.CreateAgentRequest{IdempotencyKey: "postgres-temporal-agent", Name: "reclaim", ModelProfile: "balanced", Instructions: "durably reclaim"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := runtime.CreateSession(ctx, owner, agentruntime.CreateSessionRequest{IdempotencyKey: "postgres-temporal-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := runtime.SendInput(ctx, owner, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "postgres-temporal-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "recover one exact durable route"}}})
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := runtimecontent.ParseTenantID("postgres-temporal")
	if err != nil {
		t.Fatal(err)
	}
	return tenant, session, accepted
}

func loadPublisherIntegrationState(t *testing.T, ctx context.Context, store runtimestate.RuntimeStateStore, tenant runtimecontent.TenantID) runtimestate.RuntimeState {
	t.Helper()
	state, err := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func publisherIntegrationOutbox(t *testing.T, state runtimestate.RuntimeState, outboxID string) runtimestate.OutboxRecord {
	t.Helper()
	for _, record := range state.Outbox {
		if string(record.OutboxID) == outboxID {
			return record
		}
	}
	t.Fatalf("outbox route %s = absent from %#v", outboxID, state.Outbox)
	return runtimestate.OutboxRecord{}
}

func hasPublisherIntegrationAudit(facts []runtimestate.AuditFactRecord, kind, prefix string) bool {
	for _, fact := range facts {
		if fact.Kind == kind && len(prefix) <= len(string(fact.OperationID)) && string(fact.OperationID)[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func requiredPublisherEnvironment(t *testing.T, name string) string {
	t.Helper()
	if value := os.Getenv(name); value != "" {
		return value
	}
	t.Fatalf("%s is required for PostgreSQL/Temporal publisher integration", name)
	return ""
}

type failFirstPostgresAcknowledgementStore struct {
	runtimestate.RuntimeStateStore
	failed bool
}

func (store *failFirstPostgresAcknowledgementStore) PersistTransitionPlan(ctx context.Context, plan runtimestate.TransitionPlan) error {
	if !store.failed && plan.Kind() == runtimestate.CommandAcknowledgeOutbox && plan.Result().Outbox.EventKind == agentruntime.EventInputAccepted {
		store.failed = true
		return errors.New("simulated publisher process loss before PostgreSQL acknowledgement")
	}
	return store.RuntimeStateStore.PersistTransitionPlan(ctx, plan)
}

type publisherIntegrationDispatcher struct {
	StateDispatcher
	mu       sync.Mutex
	commands []Command
	notify   chan struct{}
}

func (dispatcher *publisherIntegrationDispatcher) Dispatch(ctx context.Context, command Command) error {
	if err := dispatcher.StateDispatcher.Dispatch(ctx, command); err != nil {
		return err
	}
	dispatcher.mu.Lock()
	dispatcher.commands = append(dispatcher.commands, command)
	notify := dispatcher.notify
	dispatcher.notify = make(chan struct{})
	if notify != nil {
		close(notify)
	}
	dispatcher.mu.Unlock()
	return nil
}

func (dispatcher *publisherIntegrationDispatcher) waitFor(ctx context.Context, kind CommandKind) bool {
	for {
		if dispatcher.count(kind) > 0 {
			return true
		}
		dispatcher.mu.Lock()
		notify := dispatcher.notify
		if notify == nil {
			notify = make(chan struct{})
			dispatcher.notify = notify
		}
		dispatcher.mu.Unlock()
		select {
		case <-notify:
		case <-ctx.Done():
			return false
		}
	}
}

func (dispatcher *publisherIntegrationDispatcher) count(kind CommandKind) int {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	count := 0
	for _, command := range dispatcher.commands {
		if command.Kind == kind {
			count++
		}
	}
	return count
}

func (dispatcher *publisherIntegrationDispatcher) first(kind CommandKind) (Command, bool) {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	for _, command := range dispatcher.commands {
		if command.Kind == kind {
			return command, true
		}
	}
	return Command{}, false
}

type publisherIntegrationIDs struct{ next uint64 }

func (ids *publisherIntegrationIDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	ids.next++
	return fmt.Sprintf("%s_%016d", kind, ids.next), nil
}

type publisherIntegrationTenants struct{ tenant runtimecontent.TenantID }

func (source publisherIntegrationTenants) ListOutboxTenants(context.Context) ([]runtimecontent.TenantID, error) {
	return []runtimecontent.TenantID{source.tenant}, nil
}
