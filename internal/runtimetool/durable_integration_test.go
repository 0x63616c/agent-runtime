//go:build integration

package runtimetool_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimeapi"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimepostgres"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	"github.com/0x63616c/agent-runtime/internal/runtimetool"
	"github.com/0x63616c/agent-runtime/internal/sandboxcontrol"
	"github.com/0x63616c/agent-runtime/internal/sandboxcontrolapi"
	"github.com/0x63616c/agent-runtime/sandbox"
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
	descriptorBytes, err := sandbox.EncodeControlOperationRequest(sandbox.OperationRequest{ID: "op_tool_durable_0001", Kind: sandbox.OperationCloseSandbox, CloseSandbox: &sandbox.CloseSandboxRequest{SandboxID: "sbx_tool_durable_0001"}})
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := content.StageToolActionDescriptor(ctx, tenant, descriptorBytes)
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
	adapter, complete := newDurableHTTPSAdapter(t)
	worker, err := runtimetool.NewWorker(runtimetool.Config{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: adapter, Claimer: "durable-tool-worker"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- worker.ScanOnce(ctx) }()
	complete()
	if err := <-done; err != nil {
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
	pool.Close()
	pool, err = pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	store, err = runtimepostgres.NewRuntimeStateStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := runtimeapi.NewStateRuntime(runtimeapi.StateRuntimeConfig{Content: content, Compiler: compiler, Planner: planner, Store: store, ModelProfiles: []string{"balanced"}})
	if err != nil {
		t.Fatal(err)
	}
	page, err := restarted.InspectToolCalls(ctx, runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}, session, turn)
	if err != nil || len(page.Calls) != 1 || page.Truncated || page.Calls[0].State != agentruntime.ToolCallSucceeded || page.Calls[0].Approval == nil || page.Calls[0].Approval.State != agentruntime.ApprovalApproved || page.Calls[0].Grant == nil || page.Calls[0].Grant.Uses != 1 || page.Calls[0].Execution == nil || page.Calls[0].Execution.Failure != nil {
		t.Fatalf("restarted durable Tool inspection = %#v, %v", page, err)
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

// newDurableHTTPSAdapter exercises the concrete TLS control client. It drives
// only the control-plane ledger to a terminal state; it does not assert that a
// sandbox backend executed an external command.
func newDurableHTTPSAdapter(t *testing.T) (runtimetool.Adapter, func()) {
	t.Helper()
	controlClock, err := clock.NewFake(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	ledger := sandboxcontrol.NewMemoryLedger()
	limits := sandbox.ResourceLimits{MilliCPU: 100, MemoryBytes: 1024, RootDiskBytes: 1024, TmpfsBytes: 1024, PIDs: 10, ProcessCount: 10, OpenFiles: 10, Inodes: 10, Files: 10, Lifetime: time.Hour, ProducedOutputBytes: 1024, RetainedOutputBytes: 1024, TransferBytes: 1024, NetworkConnections: 10, VolumeBytes: 1024, SnapshotBytes: 1024}
	handler, err := sandboxcontrolapi.NewHandler(sandboxcontrolapi.Config{
		Store: ledger, Authenticator: durableControlAuthenticator{}, AssertionKey: bytes.Repeat([]byte{0x42}, 32), Entropy: bytes.NewReader(bytes.Repeat([]byte{0x99}, 128)), Clock: controlClock,
		BindingLifetime: time.Hour, Retention: time.Hour, WaitInterval: time.Millisecond,
		Wait: func(ctx context.Context, _ time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return nil
			}
		},
		Admission: sandbox.OperationAdmissionPolicy{Defaults: limits, Maximum: limits},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	roots := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	trust, err := sandbox.NewStaticTrustBundleSource(map[sandbox.TrustBundleRef]sandbox.TrustBundle{"trust/durable": {Version: "durable/v1", PEMRoots: roots}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := sandbox.NewClient(context.Background(), sandbox.ClientConfig{Endpoint: sandbox.Endpoint{URL: server.URL}, TLS: sandbox.TLSConfig{ServerName: server.Certificate().DNSNames[0], TrustBundleRef: "trust/durable"}, Credentials: durableControlCredentials{}, TrustBundles: trust, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(context.Background()) })
	adapter, err := runtimetool.NewSandboxAdapter(client)
	if err != nil {
		t.Fatal(err)
	}
	complete := func() {
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			operation, err := ledger.Get(context.Background(), "tenant-a:subject-a", "op_tool_durable_0001")
			if err == nil {
				operation, err = ledger.Transition(context.Background(), operation.Principal, operation.ID, operation.Version, sandboxcontrol.StateDispatched)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = ledger.Transition(context.Background(), operation.Principal, operation.ID, operation.Version, sandboxcontrol.StateSucceeded); err != nil {
					t.Fatal(err)
				}
				return
			}
			runtime.Gosched()
		}
		t.Fatal("concrete HTTPS sandbox-control adapter did not submit the durable operation")
	}
	return adapter, complete
}

type durableControlCredentials struct{}

func (durableControlCredentials) Apply(_ context.Context, sink sandbox.CredentialSink) error {
	return sink.SetAuthorization("Bearer", "durable-tool-token")
}

type durableControlAuthenticator struct{}

func (durableControlAuthenticator) Authenticate(ctx context.Context, authorization string) (sandboxcontrolapi.Identity, error) {
	if err := ctx.Err(); err != nil {
		return sandboxcontrolapi.Identity{}, err
	}
	if authorization != "Bearer durable-tool-token" {
		return sandboxcontrolapi.Identity{}, errors.New("denied")
	}
	return sandboxcontrolapi.Identity{Authority: "issuer", Tenant: "tenant-a", Subject: "subject-a", Principal: "tenant-a:subject-a"}, nil
}
