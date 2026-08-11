//go:build integration

package runtimetool_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimepostgres"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	"github.com/0x63616c/agent-runtime/internal/runtimetool"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// TestDurableToolLifecyclePersistsDescriptorApprovalAndFinalization proves the
// state/object-store half of TMP-010 on the disposable PostgreSQL/MinIO stack.
func TestDurableToolLifecyclePersistsDescriptorApprovalAndFinalization(t *testing.T) {
	ctx := context.Background()
	dsn, endpoint, access, secret, bucket := requiredToolEnvironment(t, "AR_RUNTIME_API_POSTGRES_DSN"), requiredToolEnvironment(t, "AR_RUNTIME_API_MINIO_ENDPOINT"), requiredToolEnvironment(t, "AR_RUNTIME_API_MINIO_ACCESS_KEY"), requiredToolEnvironment(t, "AR_RUNTIME_API_MINIO_SECRET_KEY"), requiredToolEnvironment(t, "AR_RUNTIME_API_MINIO_BUCKET")
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
	content, err := runtimecontent.New("tool-durable-integration", objects)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store, err := runtimepostgres.NewRuntimeStateStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	source, _ := clock.NewFake(now)
	planner, err := runtimestate.NewRuntimeStatePlanner(source, &durableToolIDs{})
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := runtimecontent.ParseTenantID("durable-tool")
	principal, _ := runtimecontent.ParsePrincipalID("alice")
	adminScope := runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}
	ownerScope := runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}
	workerScope := runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}
	apply := func(m runtimestate.CompiledMutation) runtimestate.TransitionPlan {
		state, e := store.LoadRuntimeState(ctx, m.ReceiptBinding().Scope)
		if e != nil {
			t.Fatal(e)
		}
		plan, e := planner.Plan(ctx, state, m)
		if e != nil {
			t.Fatal(e)
		}
		if e = store.PersistTransitionPlan(ctx, plan); e != nil {
			t.Fatal(e)
		}
		return plan
	}
	body, err := content.StageAgentSpecificationBody(ctx, tenant, runtimecontent.AgentSpecificationBody{Name: "durable-tool", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	mutation, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: adminScope, IdempotencyKey: "durable-tool-register", Specification: body})
	if err != nil {
		t.Fatal(err)
	}
	registered := apply(mutation)
	mutation, err = compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-session", RevisionID: registered.Result().Revision.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	created := apply(mutation)
	input, err := content.StageInputEnvelope(ctx, tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "approve durable sandbox action"}})
	if err != nil {
		t.Fatal(err)
	}
	mutation, err = compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-input", SessionID: created.Result().Session.SessionID, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	accepted := apply(mutation)
	descriptor, err := content.StageToolActionDescriptor(ctx, tenant, []byte("durable sandbox action"))
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	session, turn := created.Result().Session.SessionID, accepted.Result().Turn.TurnID
	mutation, err = compiler.CompileRecordToolIntent(runtimestate.RecordToolIntentCommand{Scope: workerScope, IdempotencyKey: "durable-tool-intent", SessionID: session, TurnID: turn, ToolCallID: "tcall_1234567890ABCDEF", ToolName: "sandbox", ActionDigest: digest, PolicyRevisionDigest: digest, Descriptor: descriptor})
	if err != nil {
		t.Fatal(err)
	}
	apply(mutation)
	mutation, err = compiler.CompileRequestApproval(runtimestate.RequestApprovalCommand{Scope: workerScope, IdempotencyKey: "durable-tool-approval", SessionID: session, TurnID: turn, ToolCallID: "tcall_1234567890ABCDEF", ApprovalID: "appr_1234567890ABCDEF", ActionDigest: digest, PolicyRevisionDigest: digest, CapabilityDigest: digest, MaximumUses: 1, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	apply(mutation)
	mutation, err = compiler.CompileDecideApproval(runtimestate.DecideApprovalCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-approve", ApprovalID: "appr_1234567890ABCDEF", Decision: "approved"})
	if err != nil {
		t.Fatal(err)
	}
	apply(mutation)
	state, err := store.LoadRuntimeState(ctx, workerScope)
	if err != nil || len(state.Grants) != 1 {
		t.Fatalf("durable approval grant = %#v, %v", state.Grants, err)
	}
	grant := state.Grants[0].GrantID
	mutation, err = compiler.CompileConsumeCapabilityGrant(runtimestate.ConsumeCapabilityGrantCommand{Scope: workerScope, IdempotencyKey: "durable-tool-consume", SessionID: session, TurnID: turn, ToolCallID: "tcall_1234567890ABCDEF", GrantID: grant, PolicyRevisionDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	apply(mutation)
	mutation, err = compiler.CompileBeginToolExecution(runtimestate.BeginToolExecutionCommand{Scope: workerScope, IdempotencyKey: "durable-tool-begin", SessionID: session, TurnID: turn, ToolCallID: "tcall_1234567890ABCDEF", GrantID: grant, OperationID: "op_tool_durable_0001"})
	if err != nil {
		t.Fatal(err)
	}
	apply(mutation)
	worker, err := runtimetool.NewWorker(runtimetool.Config{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: &recordingAdapter{response: runtimetool.Response{Output: []byte("durably finalized")}}, Claimer: "durable-tool-worker"})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.ScanOnce(ctx); err != nil {
		t.Fatal(err)
	}
	state, err = store.LoadRuntimeState(ctx, workerScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.ToolExecutions) != 1 || state.ToolExecutions[0].State != runtimestate.ToolExecutionSucceeded {
		t.Fatalf("durable execution = %#v", state.ToolExecutions)
	}
	found := false
	for _, event := range state.Events {
		if event.Kind == agentruntime.EventSandboxOperationFinalized && event.OperationID == "op_tool_durable_0001" {
			found = true
		}
	}
	if !found {
		t.Fatalf("durable event replay lacks sandbox finalization: %#v", state.Events)
	}
}

func mustToolMutation(t *testing.T, mutation runtimestate.CompiledMutation, err error) runtimestate.CompiledMutation {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return mutation
}
func requiredToolEnvironment(t *testing.T, name string) string {
	t.Helper()
	if value := os.Getenv(name); value != "" {
		return value
	}
	t.Fatalf("%s is required for durable tool integration", name)
	return ""
}

type durableToolIDs struct{ next uint64 }

func (ids *durableToolIDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	ids.next++
	return fmt.Sprintf("%s_%016d", kind, ids.next), nil
}
