//go:build integration

package runtimemodel_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimeapi"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimemodel"
	"github.com/0x63616c/agent-runtime/internal/runtimepostgres"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// TestDurableModelProducerLossFinalizesGapAndReplays proves DAT-004 through
// the disposable PostgreSQL/MinIO authority. It recreates the model worker
// after the producer claim expires, reconciles the same operation as
// uncertain, and then replays the durable gap/finalization events by cursor.
func TestDurableModelProducerLossFinalizesGapAndReplays(t *testing.T) {
	ctx := context.Background()
	dsn := requiredModelEnvironment(t, "AR_RUNTIME_API_POSTGRES_DSN")
	endpoint := requiredModelEnvironment(t, "AR_RUNTIME_API_MINIO_ENDPOINT")
	access := requiredModelEnvironment(t, "AR_RUNTIME_API_MINIO_ACCESS_KEY")
	secret := requiredModelEnvironment(t, "AR_RUNTIME_API_MINIO_SECRET_KEY")
	bucket := requiredModelEnvironment(t, "AR_RUNTIME_API_MINIO_BUCKET")
	minioClient, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(access, secret, ""), Secure: false})
	if err != nil {
		t.Fatal(err)
	}
	if err := minioClient.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil && minio.ToErrorResponse(err).Code != "BucketAlreadyOwnedByYou" {
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
	content, err := runtimecontent.New("durable-model-producer-loss", objects)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 10, 14, 0, 0, 0, time.UTC)
	clockSource, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	store, err := runtimepostgres.NewRuntimeStateStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(clockSource, &durableModelIDs{})
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := runtimecontent.ParseTenantID("durable-model-producer-loss")
	principal, _ := runtimecontent.ParsePrincipalID("alice")
	adminScope := runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}
	ownerScope := runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}
	workerScope := runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}
	apply := func(mutation runtimestate.CompiledMutation) runtimestate.TransitionPlan {
		t.Helper()
		state, err := store.LoadRuntimeState(ctx, mutation.ReceiptBinding().Scope)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := planner.Plan(ctx, state, mutation)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.PersistTransitionPlan(ctx, plan); err != nil {
			t.Fatal(err)
		}
		return plan
	}
	must := func(mutation runtimestate.CompiledMutation, err error) runtimestate.CompiledMutation {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return mutation
	}
	body, err := content.StageAgentSpecificationBody(ctx, tenant, runtimecontent.AgentSpecificationBody{Name: "durable-model", ModelProfile: "balanced", Instructions: "recover model loss"})
	if err != nil {
		t.Fatal(err)
	}
	registered := apply(must(compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: adminScope, IdempotencyKey: "durable-model-register", Specification: body})))
	created := apply(must(compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: ownerScope, IdempotencyKey: "durable-model-session", RevisionID: registered.Result().Revision.RevisionID})))
	input, err := content.StageInputEnvelope(ctx, tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "recover the provider stream"}})
	if err != nil {
		t.Fatal(err)
	}
	accepted := apply(must(compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: ownerScope, IdempotencyKey: "durable-model-input", SessionID: created.Result().Session.SessionID, Input: input})))
	intent := apply(must(compiler.CompileBeginInvocationAttempt(runtimestate.BeginInvocationAttemptCommand{Scope: workerScope, IdempotencyKey: "durable-model-intent", SessionID: created.Result().Session.SessionID, TurnID: accepted.Result().Turn.TurnID, OperationID: "op_model_producer_loss_0001", ExpectedSessionVersion: accepted.Result().Session.Version, ExpectedTurnVersion: accepted.Result().Turn.Version})))

	// Simulate worker death after it has durably leased the operation but before
	// it can observe a provider terminal record. A later process must reconcile
	// the same operation rather than invoke a second external effect.
	intentOutbox := durableModelIntentOutbox(t, ctx, store, tenant)
	apply(must(compiler.CompileClaimOutbox(runtimestate.ClaimOutboxCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher}, IdempotencyKey: "lost-model-worker-claim", OutboxID: intentOutbox.OutboxID, ExpectedVersion: intentOutbox.Version, Claimer: "lost-model-worker", ClaimUntil: now.Add(2 * time.Minute)})))
	if err := clockSource.Advance(2*time.Minute + time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	pool.Close()

	// This fresh PostgreSQL adapter/compiler/planner/worker is the restarted
	// process. Its adapter deliberately reports the lost producer outcome as
	// uncertain; it must not call Invoke again.
	pool, err = pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store, err = runtimepostgres.NewRuntimeStateStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err = runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	planner, err = runtimestate.NewRuntimeStatePlanner(clockSource, &durableModelIDs{next: 100})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &durableModelAdapter{reconcile: runtimemodel.Response{Uncertain: true, Failure: &agentruntime.Failure{Code: agentruntime.FailureUnavailable, Message: "model producer disconnected before terminal output"}}}
	worker, err := runtimemodel.NewWorker(runtimemodel.WorkerConfig{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: clockSource, Content: content, Adapter: adapter, Claimer: "recovered-model-worker"})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.ScanOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err := worker.ScanOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if adapter.invoked != 0 || adapter.reconciled != 1 || adapter.operation != intent.Result().Invocation.OperationID {
		t.Fatalf("recovered adapter calls = invoke=%d reconcile=%d operation=%q", adapter.invoked, adapter.reconciled, adapter.operation)
	}
	state, err := store.LoadRuntimeState(ctx, workerScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Invocations) != 1 || state.Invocations[0].State != runtimestate.InvocationUncertain || len(state.Turns) != 1 || state.Turns[0].State != agentruntime.TurnFailed {
		t.Fatalf("recovered durable model state = invocations=%#v turns=%#v", state.Invocations, state.Turns)
	}
	if record := durableModelIntentOutbox(t, ctx, store, tenant); record.State != runtimestate.OutboxPublished {
		t.Fatalf("recovered model outbox = %#v, want published after terminal persistence", record)
	}

	apiRuntime, err := runtimeapi.NewStateRuntime(runtimeapi.StateRuntimeConfig{Content: content, Compiler: compiler, Planner: planner, Store: store, ModelProfiles: []string{"balanced"}})
	if err != nil {
		t.Fatal(err)
	}
	identity := runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}
	page, err := apiRuntime.Events(ctx, identity, created.Result().Session.SessionID, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) < 3 {
		t.Fatalf("durable event page = %#v, want prior events plus terminal gap", page)
	}
	beforeGap := page.Events[len(page.Events)-3].Cursor
	replay, err := apiRuntime.Events(ctx, identity, created.Result().Session.SessionID, beforeGap, 10)
	if err != nil {
		t.Fatal(err)
	}
	if replay.Gap != nil || len(replay.Events) != 2 || replay.Events[0].Kind != agentruntime.EventProducerGap || replay.Events[1].Kind != agentruntime.EventTurnFailed || replay.Events[0].Sequence >= replay.Events[1].Sequence {
		t.Fatalf("durable producer-loss replay = %#v, want ordered gap then terminal failure", replay)
	}
	duplicate, err := apiRuntime.Events(ctx, identity, created.Result().Session.SessionID, beforeGap, 10)
	if err != nil || len(duplicate.Events) != 2 || duplicate.Events[0] != replay.Events[0] || duplicate.Events[1] != replay.Events[1] {
		t.Fatalf("duplicate durable replay = %#v, %v; want the same bounded events", duplicate, err)
	}
}

func durableModelIntentOutbox(t *testing.T, ctx context.Context, store runtimestate.RuntimeStateStore, tenant runtimecontent.TenantID) runtimestate.OutboxRecord {
	t.Helper()
	page, err := store.ReadOutbox(ctx, runtimestate.OutboxQuery{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher}, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range page.Records {
		if record.InvocationID != "" && record.EventKind == "" {
			return record
		}
	}
	t.Fatalf("model invocation outbox = %#v, want one model intent", page.Records)
	return runtimestate.OutboxRecord{}
}

func requiredModelEnvironment(t *testing.T, name string) string {
	t.Helper()
	if value := os.Getenv(name); value != "" {
		return value
	}
	t.Fatalf("%s is required for durable model integration", name)
	return ""
}

type durableModelAdapter struct {
	reconcile  runtimemodel.Response
	invoked    int
	reconciled int
	operation  runtimestate.OperationID
}

func (adapter *durableModelAdapter) Invoke(_ context.Context, request runtimemodel.Request) (runtimemodel.Response, error) {
	adapter.invoked++
	adapter.operation = request.OperationID
	return runtimemodel.Response{}, fmt.Errorf("recovered model worker must not invoke %s", request.OperationID)
}

func (adapter *durableModelAdapter) Reconcile(_ context.Context, request runtimemodel.Request) (runtimemodel.Response, error) {
	adapter.reconciled++
	adapter.operation = request.OperationID
	return adapter.reconcile, nil
}

type durableModelIDs struct{ next uint64 }

func (ids *durableModelIDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	ids.next++
	return fmt.Sprintf("%s_%016d", kind, ids.next), nil
}
