//go:build integration

package runtimeorchestration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	timeSource, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	store, err := runtimepostgres.NewRuntimeStateStore(pool, timeSource)
	if err != nil {
		t.Fatal(err)
	}
	content := publisherIntegrationContent(t, endpoint, accessKey, secretKey, contentBucket)
	compiler, err := runtimestate.NewCompiler(content)
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

// TestPostgresOutboxRecoversAcrossActualPublisherProcessKills proves the
// DAT-012/DAT-013 boundary with a real child publisher process. It kills the
// process after durable claim and after Temporal accepts the route before the
// PostgreSQL acknowledgement, then rebuilds the publisher and proves the
// exact at-least-once/reconciled outcomes and audit facts.
func TestPostgresOutboxRecoversAcrossActualPublisherProcessKills(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	postgresDSN := requiredPublisherEnvironment(t, "AR_RUNTIME_API_POSTGRES_DSN")
	endpoint := requiredPublisherEnvironment(t, "AR_RUNTIME_API_MINIO_ENDPOINT")
	accessKey := requiredPublisherEnvironment(t, "AR_RUNTIME_API_MINIO_ACCESS_KEY")
	secretKey := requiredPublisherEnvironment(t, "AR_RUNTIME_API_MINIO_SECRET_KEY")
	contentBucket := requiredPublisherEnvironment(t, "AR_RUNTIME_API_MINIO_BUCKET")
	payloadBucket := contentBucket + "-temporal-payload-process-kill"

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
	storeClock, err := clock.NewFake(time.Date(2026, 8, 10, 16, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	store, err := runtimepostgres.NewRuntimeStateStore(pool, storeClock)
	if err != nil {
		t.Fatal(err)
	}
	server, err := testsuite.StartDevServer(ctx, testsuite.DevServerOptions{})
	if err != nil {
		t.Fatalf("start Temporal development server: %v", err)
	}
	defer func() { _ = server.Stop() }()
	factory, err := temporalpayloadruntime.NewS3Factory(temporalpayloadruntime.S3Config{Endpoint: endpoint, Bucket: payloadBucket, Prefix: "postgres-temporal-process-kill", AccessKey: accessKey, SecretKey: secretKey})
	if err != nil {
		t.Fatal(err)
	}
	taskQueue := "postgres-temporal-process-kill"
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

	for _, scenario := range []struct {
		name                 string
		mode                 string
		deliveredBeforeDeath bool
	}{
		{name: "after_claim_before_temporal_route", mode: "after_claim"},
		{name: "after_temporal_route_before_postgres_ack", mode: "after_route", deliveredBeforeDeath: true},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			now := time.Date(2026, 8, 10, 16, 0, 0, 0, time.UTC)
			timeSource, err := clock.NewFake(now)
			if err != nil {
				t.Fatal(err)
			}
			content := publisherIntegrationContent(t, endpoint, accessKey, secretKey, contentBucket)
			compiler, err := runtimestate.NewCompiler(content)
			if err != nil {
				t.Fatal(err)
			}
			planner, err := runtimestate.NewRuntimeStatePlanner(timeSource, &publisherIntegrationIDs{})
			if err != nil {
				t.Fatal(err)
			}
			tenantName := "process-kill-" + strings.ReplaceAll(scenario.mode, "_", "-")
			tenant, session, _ := seedPublisherIntegrationSessionForTenant(t, ctx, content, compiler, planner, store, tenantName)
			before := loadPublisherIntegrationState(t, ctx, store, tenant)
			inputRoute := publisherIntegrationInputRoute(t, before, session.ID)

			output, err := runKilledPublisherProcess(ctx, scenario.mode, tenant, postgresDSN, endpoint, accessKey, secretKey, contentBucket, payloadBucket, server.FrontendHostPort(), taskQueue)
			if err == nil {
				t.Fatal("publisher child exited successfully, want forced process death")
			}
			if _, ok := err.(*exec.ExitError); !ok || !strings.Contains(string(output), "publisher-process-kill:"+scenario.mode) {
				t.Fatalf("publisher child result = %v output=%q, want forced %s death", err, output, scenario.mode)
			}

			claimed := loadPublisherIntegrationState(t, ctx, store, tenant)
			inputRoute = publisherIntegrationOutbox(t, claimed, string(inputRoute.OutboxID))
			if inputRoute.State != runtimestate.OutboxClaimed || !hasPublisherIntegrationAudit(claimed.Audit, "outbox.claimed", "temporal-claim-"+string(inputRoute.OutboxID)+"-") || hasPublisherIntegrationAudit(claimed.Audit, "outbox.published", "temporal-ack-"+string(inputRoute.OutboxID)+"-") {
				t.Fatalf("state after %s process death = %#v / %#v, want claimed route without acknowledgement", scenario.mode, inputRoute, claimed.Audit)
			}
			if scenario.deliveredBeforeDeath {
				if !dispatcher.waitForSession(ctx, CommandInputAccepted, tenant, session.ID) {
					t.Fatal("Temporal did not receive the input route before forced death")
				}
			} else if got := dispatcher.countForSession(CommandInputAccepted, tenant, session.ID); got != 0 {
				t.Fatalf("Temporal input dispatches before claim-boundary recovery = %d, want 0", got)
			}

			if err := timeSource.Advance(2*time.Minute + time.Nanosecond); err != nil {
				t.Fatal(err)
			}
			restartedClient, err := factory.NewClient(ctx, client.Options{HostPort: server.FrontendHostPort()})
			if err != nil {
				t.Fatal(err)
			}
			defer restartedClient.Close()
			restartedPublisher, err := NewPublisher(PublisherConfig{Store: store, Tenants: publisherIntegrationTenants{tenant: tenant}, Compiler: compiler, Planner: planner, Clock: timeSource, Publisher: temporalSessionPublisher{client: restartedClient, taskQueue: taskQueue}, Claimer: "postgres-temporal-publisher"})
			if err != nil {
				t.Fatal(err)
			}
			if err := restartedPublisher.ScanOnce(ctx); err != nil {
				t.Fatalf("recover %s publisher route: %v", scenario.mode, err)
			}
			if !dispatcher.waitForSession(ctx, CommandInputAccepted, tenant, session.ID) {
				t.Fatal("recovered publisher did not deliver the durable input route")
			}
			recovered := loadPublisherIntegrationState(t, ctx, store, tenant)
			inputRoute = publisherIntegrationOutbox(t, recovered, string(inputRoute.OutboxID))
			if inputRoute.State != runtimestate.OutboxPublished || !hasPublisherIntegrationAudit(recovered.Audit, "outbox.published", "temporal-ack-"+string(inputRoute.OutboxID)+"-") {
				t.Fatalf("state after %s process recovery = %#v / %#v, want published route", scenario.mode, inputRoute, recovered.Audit)
			}
			if got := dispatcher.countForSession(CommandInputAccepted, tenant, session.ID); got != 1 {
				t.Fatalf("Temporal input dispatches after %s process recovery = %d, want exactly one", scenario.mode, got)
			}
		})
	}
}

// TestPostgresOutboxReclaimsAuditExportAfterSinkOutage proves the DAT-006/007
// boundary with PostgreSQL as the audit/outbox authority and a real HTTP sink.
// A rejected export stays durably claimed without acknowledgement; a rebuilt
// publisher reclaims its lease, exports the exact retained fact once, then
// records publication. This is explicitly at-least-once, never fail-closed.
func TestPostgresOutboxReclaimsAuditExportAfterSinkOutage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	postgresDSN := requiredPublisherEnvironment(t, "AR_RUNTIME_API_POSTGRES_DSN")
	endpoint := requiredPublisherEnvironment(t, "AR_RUNTIME_API_MINIO_ENDPOINT")
	accessKey := requiredPublisherEnvironment(t, "AR_RUNTIME_API_MINIO_ACCESS_KEY")
	secretKey := requiredPublisherEnvironment(t, "AR_RUNTIME_API_MINIO_SECRET_KEY")
	contentBucket := requiredPublisherEnvironment(t, "AR_RUNTIME_API_MINIO_BUCKET")
	objects, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(accessKey, secretKey, ""), Secure: false})
	if err != nil {
		t.Fatal(err)
	}
	if err := objects.MakeBucket(ctx, contentBucket, minio.MakeBucketOptions{}); err != nil && minio.ToErrorResponse(err).Code != "BucketAlreadyOwnedByYou" {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, postgresDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	now := time.Date(2026, 8, 11, 3, 0, 0, 0, time.UTC)
	timeSource, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	store, err := runtimepostgres.NewRuntimeStateStore(pool, timeSource)
	if err != nil {
		t.Fatal(err)
	}
	content := publisherIntegrationContent(t, endpoint, accessKey, secretKey, contentBucket)
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(timeSource, &publisherIntegrationIDs{}, runtimestate.WithRetentionPolicy(auditPublisherRetention{}))
	if err != nil {
		t.Fatal(err)
	}
	tenant, _, _ := seedPublisherIntegrationSessionForTenant(t, ctx, content, compiler, planner, store, "audit-export-outage")

	var attempts, accepted []runtimestate.AuditFactRecord
	outage := true
	sink := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		var fact runtimestate.AuditFactRecord
		if err := json.NewDecoder(request.Body).Decode(&fact); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		attempts = append(attempts, fact)
		if outage {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		accepted = append(accepted, fact)
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer sink.Close()
	exporter, err := NewHTTPAuditExporter(sink.URL, sink.Client())
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(PublisherConfig{Store: store, Tenants: publisherIntegrationTenants{tenant: tenant}, Compiler: compiler, Planner: planner, Clock: timeSource, Publisher: auditNoopSessionPublisher{}, AuditExporter: exporter, Claimer: "audit-export-publisher"})
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.ScanOnce(ctx); err == nil {
		t.Fatal("publish during audit-sink outage = nil, want durable retryable failure")
	}
	if len(attempts) != 1 || len(accepted) != 0 {
		t.Fatalf("audit sink during outage attempts=%#v accepted=%#v, want one rejected exact fact", attempts, accepted)
	}
	claimed := loadPublisherIntegrationState(t, ctx, store, tenant)
	claimedRoute := publisherIntegrationAuditExportRoute(t, claimed, attempts[0].AuditFactID)
	if claimedRoute.State != runtimestate.OutboxClaimed || claimedRoute.AuditFactID != attempts[0].AuditFactID {
		t.Fatalf("audit route after sink outage = %#v / %#v, want claimed exact audit route without publication", claimedRoute, claimed.Audit)
	}
	fact := publisherIntegrationAuditFact(t, claimed, claimedRoute.AuditFactID)
	if !fact.RetentionUntil.After(claimedRoute.RetentionUntil) {
		t.Fatalf("audit retention %s must independently exceed outbox retention %s", fact.RetentionUntil, claimedRoute.RetentionUntil)
	}

	outage = false
	if err := timeSource.Advance(2*time.Minute + time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewPublisher(PublisherConfig{Store: store, Tenants: publisherIntegrationTenants{tenant: tenant}, Compiler: compiler, Planner: planner, Clock: timeSource, Publisher: auditNoopSessionPublisher{}, AuditExporter: exporter, Claimer: "audit-export-publisher"})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.ScanOnce(ctx); err != nil {
		t.Fatalf("reclaim audit export after sink recovery: %v", err)
	}
	recovered := loadPublisherIntegrationState(t, ctx, store, tenant)
	recoveredRoute := publisherIntegrationOutbox(t, recovered, string(claimedRoute.OutboxID))
	if recoveredRoute.State != runtimestate.OutboxPublished || recoveredRoute.AuditFactID != fact.AuditFactID {
		t.Fatalf("audit route after sink recovery = %#v / %#v, want published", recoveredRoute, recovered.Audit)
	}
	if got := countPublisherIntegrationAuditFact(accepted, fact.AuditFactID); got != 1 {
		t.Fatalf("accepted audit exports for %s = %d, want exactly one after outage recovery; attempts=%#v", fact.AuditFactID, got, attempts)
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
	return seedPublisherIntegrationSessionForTenant(t, ctx, content, compiler, planner, store, "postgres-temporal")
}

func seedPublisherIntegrationSessionForTenant(t *testing.T, ctx context.Context, content *runtimecontent.Store, compiler *runtimestate.Compiler, planner *runtimestate.RuntimeStatePlanner, store runtimestate.RuntimeStateStore, tenantName string) (runtimecontent.TenantID, agentruntime.Session, agentruntime.SendInputResult) {
	t.Helper()
	runtime, err := runtimeapi.NewStateRuntime(runtimeapi.StateRuntimeConfig{Content: content, Compiler: compiler, Planner: planner, Store: store, ModelProfiles: []string{"balanced"}})
	if err != nil {
		t.Fatal(err)
	}
	admin := runtimeapi.Identity{Tenant: tenantName, Principal: "admin", Admin: true}
	owner := runtimeapi.Identity{Tenant: tenantName, Principal: "owner"}
	agent, err := runtime.CreateAgent(ctx, admin, agentruntime.CreateAgentRequest{IdempotencyKey: tenantName + "-agent", Name: "reclaim", ModelProfile: "balanced", Instructions: "durably reclaim"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := runtime.CreateSession(ctx, owner, agentruntime.CreateSessionRequest{IdempotencyKey: tenantName + "-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := runtime.SendInput(ctx, owner, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: tenantName + "-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "recover one exact durable route"}}})
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := runtimecontent.ParseTenantID(tenantName)
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

func publisherIntegrationInputRoute(t *testing.T, state runtimestate.RuntimeState, sessionID agentruntime.SessionID) runtimestate.OutboxRecord {
	t.Helper()
	for _, record := range state.Outbox {
		if record.SessionID == sessionID && record.EventKind == agentruntime.EventInputAccepted {
			return record
		}
	}
	t.Fatalf("input route for Session %s = absent from %#v", sessionID, state.Outbox)
	return runtimestate.OutboxRecord{}
}

func publisherIntegrationAuditExportRoute(t *testing.T, state runtimestate.RuntimeState, auditFactID runtimestate.AuditFactID) runtimestate.OutboxRecord {
	t.Helper()
	for _, record := range state.Outbox {
		if record.Aggregate == "audit_fact" && record.AuditFactID == auditFactID {
			return record
		}
	}
	t.Fatalf("audit export route for %s = absent from %#v", auditFactID, state.Outbox)
	return runtimestate.OutboxRecord{}
}

func publisherIntegrationAuditFact(t *testing.T, state runtimestate.RuntimeState, id runtimestate.AuditFactID) runtimestate.AuditFactRecord {
	t.Helper()
	for _, fact := range state.Audit {
		if fact.AuditFactID == id {
			return fact
		}
	}
	t.Fatalf("audit fact %s = absent from %#v", id, state.Audit)
	return runtimestate.AuditFactRecord{}
}

func countPublisherIntegrationAuditFact(facts []runtimestate.AuditFactRecord, id runtimestate.AuditFactID) int {
	count := 0
	for _, fact := range facts {
		if fact.AuditFactID == id {
			count++
		}
	}
	return count
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

const publisherProcessKillMarker = "publisher-process-kill:"

// TestPublisherProcessKillHelper is run only as a child test process by the
// process-kill integration matrix. It deliberately terminates without running
// defers at one named durable acknowledgement boundary.
func TestPublisherProcessKillHelper(t *testing.T) {
	if os.Getenv("AR_PUBLISHER_PROCESS_KILL_HELPER") != "1" {
		return
	}
	ctx := context.Background()
	mode := os.Getenv("AR_PUBLISHER_PROCESS_KILL_MODE")
	tenant, err := runtimecontent.ParseTenantID(os.Getenv("AR_PUBLISHER_PROCESS_KILL_TENANT"))
	if err != nil {
		t.Fatal(err)
	}
	postgresDSN := requiredPublisherEnvironment(t, "AR_RUNTIME_API_POSTGRES_DSN")
	endpoint := requiredPublisherEnvironment(t, "AR_RUNTIME_API_MINIO_ENDPOINT")
	accessKey := requiredPublisherEnvironment(t, "AR_RUNTIME_API_MINIO_ACCESS_KEY")
	secretKey := requiredPublisherEnvironment(t, "AR_RUNTIME_API_MINIO_SECRET_KEY")
	contentBucket := requiredPublisherEnvironment(t, "AR_RUNTIME_API_MINIO_BUCKET")
	payloadBucket := os.Getenv("AR_PUBLISHER_PROCESS_KILL_PAYLOAD_BUCKET")
	temporalEndpoint := os.Getenv("AR_PUBLISHER_PROCESS_KILL_TEMPORAL_ENDPOINT")
	taskQueue := os.Getenv("AR_PUBLISHER_PROCESS_KILL_TASK_QUEUE")
	if payloadBucket == "" || temporalEndpoint == "" || taskQueue == "" || (mode != "after_claim" && mode != "after_route") {
		t.Fatal("process-kill helper has incomplete bounded configuration")
	}
	pool, err := pgxpool.New(ctx, postgresDSN)
	if err != nil {
		t.Fatal(err)
	}
	content := publisherIntegrationContent(t, endpoint, accessKey, secretKey, contentBucket)
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	timeSource, err := clock.NewFake(time.Date(2026, 8, 10, 16, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(timeSource, &publisherIntegrationIDs{next: 10000})
	if err != nil {
		t.Fatal(err)
	}
	store, err := runtimepostgres.NewRuntimeStateStore(pool, timeSource)
	if err != nil {
		t.Fatal(err)
	}
	factory, err := temporalpayloadruntime.NewS3Factory(temporalpayloadruntime.S3Config{Endpoint: endpoint, Bucket: payloadBucket, Prefix: "postgres-temporal-process-kill", AccessKey: accessKey, SecretKey: secretKey})
	if err != nil {
		t.Fatal(err)
	}
	temporalClient, err := factory.NewClient(ctx, client.Options{HostPort: temporalEndpoint})
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(PublisherConfig{Store: &processKillingStore{RuntimeStateStore: store, mode: mode}, Tenants: publisherIntegrationTenants{tenant: tenant}, Compiler: compiler, Planner: planner, Clock: timeSource, Publisher: temporalSessionPublisher{client: temporalClient, taskQueue: taskQueue}, Claimer: "postgres-temporal-publisher"})
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.ScanOnce(ctx); err != nil {
		t.Fatalf("process-kill helper returned before forced death: %v", err)
	}
	t.Fatal("process-kill helper returned without reaching the requested death boundary")
}

func runKilledPublisherProcess(ctx context.Context, mode string, tenant runtimecontent.TenantID, postgresDSN, endpoint, accessKey, secretKey, contentBucket, payloadBucket, temporalEndpoint, taskQueue string) ([]byte, error) {
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPublisherProcessKillHelper$")
	command.Env = append(os.Environ(),
		"AR_PUBLISHER_PROCESS_KILL_HELPER=1",
		"AR_PUBLISHER_PROCESS_KILL_MODE="+mode,
		"AR_PUBLISHER_PROCESS_KILL_TENANT="+string(tenant),
		"AR_RUNTIME_API_POSTGRES_DSN="+postgresDSN,
		"AR_RUNTIME_API_MINIO_ENDPOINT="+endpoint,
		"AR_RUNTIME_API_MINIO_ACCESS_KEY="+accessKey,
		"AR_RUNTIME_API_MINIO_SECRET_KEY="+secretKey,
		"AR_RUNTIME_API_MINIO_BUCKET="+contentBucket,
		"AR_PUBLISHER_PROCESS_KILL_PAYLOAD_BUCKET="+payloadBucket,
		"AR_PUBLISHER_PROCESS_KILL_TEMPORAL_ENDPOINT="+temporalEndpoint,
		"AR_PUBLISHER_PROCESS_KILL_TASK_QUEUE="+taskQueue,
	)
	return command.CombinedOutput()
}

type processKillingStore struct {
	runtimestate.RuntimeStateStore
	mode string
}

func (store *processKillingStore) PersistTransitionPlan(ctx context.Context, plan runtimestate.TransitionPlan) error {
	if store.mode == "after_route" && plan.Kind() == runtimestate.CommandAcknowledgeOutbox && plan.Result().Outbox.EventKind == agentruntime.EventInputAccepted {
		fmt.Fprintln(os.Stdout, publisherProcessKillMarker+store.mode)
		os.Exit(86)
	}
	if err := store.RuntimeStateStore.PersistTransitionPlan(ctx, plan); err != nil {
		return err
	}
	if store.mode == "after_claim" && plan.Kind() == runtimestate.CommandClaimOutbox && plan.Result().Outbox.EventKind == agentruntime.EventInputAccepted {
		fmt.Fprintln(os.Stdout, publisherProcessKillMarker+store.mode)
		os.Exit(86)
	}
	return nil
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

func (dispatcher *publisherIntegrationDispatcher) waitForSession(ctx context.Context, kind CommandKind, tenant runtimecontent.TenantID, sessionID agentruntime.SessionID) bool {
	for {
		if dispatcher.countForSession(kind, tenant, sessionID) > 0 {
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

func (dispatcher *publisherIntegrationDispatcher) countForSession(kind CommandKind, tenant runtimecontent.TenantID, sessionID agentruntime.SessionID) int {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	count := 0
	for _, command := range dispatcher.commands {
		if command.Kind == kind && command.Tenant == string(tenant) && command.SessionID == string(sessionID) {
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

type auditPublisherRetention struct{}

func (auditPublisherRetention) RetainUntil(now time.Time) time.Time { return now.Add(time.Hour) }

func (auditPublisherRetention) RetainClassUntil(class runtimestate.DataClass, now time.Time) time.Time {
	switch class {
	case runtimestate.DataClassAudit:
		return now.Add(48 * time.Hour)
	case runtimestate.DataClassOutbox:
		return now.Add(24 * time.Hour)
	default:
		return now.Add(time.Hour)
	}
}

type auditNoopSessionPublisher struct{}

func (auditNoopSessionPublisher) StartSession(context.Context, SessionStart) error { return nil }

func (auditNoopSessionPublisher) SignalSession(context.Context, SessionStart, Command) error {
	return nil
}
