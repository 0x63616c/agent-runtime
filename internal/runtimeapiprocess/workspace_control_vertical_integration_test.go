//go:build integration

package runtimeapiprocess_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimeapiprocess"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimemodel"
	"github.com/0x63616c/agent-runtime/internal/runtimepostgres"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	"github.com/0x63616c/agent-runtime/internal/runtimetool"
	"github.com/0x63616c/agent-runtime/internal/sandboxcontrol"
	"github.com/0x63616c/agent-runtime/internal/sandboxcontrolapi"
	"github.com/0x63616c/agent-runtime/internal/toolschema"
	"github.com/0x63616c/agent-runtime/sandbox"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// TestWorkspaceApprovalDispatchesOnlyItsSealedActionToSandboxControl joins the
// presently separate M7 seams: a public Session starts a private model
// invocation, the owner approves it through the public API, and the private
// tool worker sends exactly the sealed canonical request to authenticated
// sandbox-control. The control operation is deliberately a copy-in request
// against the disposable in-memory control ledger: no guest, workspace mount,
// host path, or Firecracker capability is asserted by this test.
func TestWorkspaceApprovalDispatchesOnlyItsSealedActionToSandboxControl(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	applicationDSN := requiredRuntimeAPIEnvironment(t, "AR_RUNTIME_API_POSTGRES_DSN")
	workerDSN := requiredRuntimeAPIEnvironment(t, "AR_RUNTIME_API_WORKER_POSTGRES_DSN")
	endpoint := requiredRuntimeAPIEnvironment(t, "AR_RUNTIME_API_MINIO_ENDPOINT")
	access := requiredRuntimeAPIEnvironment(t, "AR_RUNTIME_API_MINIO_ACCESS_KEY")
	secret := requiredRuntimeAPIEnvironment(t, "AR_RUNTIME_API_MINIO_SECRET_KEY")
	bucket := requiredRuntimeAPIEnvironment(t, "AR_RUNTIME_API_MINIO_BUCKET")
	objects, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(access, secret, ""), Secure: false})
	if err != nil {
		t.Fatal(err)
	}
	if err := objects.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil && minio.ToErrorResponse(err).Code != "BucketAlreadyOwnedByYou" {
		t.Fatal(err)
	}
	config, err := runtimeapiprocess.Parse(strings.NewReader(fmt.Sprintf(`{"version":1,"profile":"local","listen_address":"127.0.0.1:0","storage":{"mode":"postgres","database_dsn_environment":"STATE_DSN","content":{"endpoint":%q,"access_key_environment":"CONTENT_ACCESS","secret_key_environment":"CONTENT_SECRET","bucket":%q}},"model_profiles":["balanced"],"max_request_bytes":4194304,"principals":[{"tenant":"workspace-control-e2e","principal":"admin","admin":true,"bearer_token_environment":"ADMIN_TOKEN"},{"tenant":"workspace-control-e2e","principal":"alice","admin":false,"bearer_token_environment":"ALICE_TOKEN"}]}`, "http://"+endpoint, bucket)))
	if err != nil {
		t.Fatal(err)
	}
	secrets := map[string]string{"STATE_DSN": applicationDSN, "CONTENT_ACCESS": access, "CONTENT_SECRET": secret, "ADMIN_TOKEN": "workspace-control-admin-token", "ALICE_TOKEN": "workspace-control-alice-token"}
	baseURL, stopAPI := startDurableRuntimeProcess(t, config, secrets)
	defer stopAPI()
	admin := durableProcessClient(t, baseURL, secrets["ADMIN_TOKEN"], &durableRequestIDs{})
	alice := durableProcessClient(t, baseURL, secrets["ALICE_TOKEN"], &durableRequestIDs{})
	if _, err := admin.CreateAgent(ctx, agentruntime.CreateAgentRequest{IdempotencyKey: "workspace-control-invalid-tool-schema", Name: "invalid-tool-schema", ModelProfile: "balanced", Instructions: "must fail closed", Tools: []agentruntime.ToolDefinition{{Name: "workspace.copy", Description: "invalid catalog schema", InputSchemaVersion: toolschema.VersionV1, InputSchema: []byte(`{"type":"array"}`)}}}); err == nil {
		t.Fatal("public Agent registration accepted an unsupported Tool input schema")
	}
	copySchema := []byte(`{"additionalProperties":false,"properties":{"copy_mode":{"enum":["safe"],"type":"string"}},"required":["copy_mode"],"type":"object"}`)
	agent, err := admin.CreateAgent(ctx, agentruntime.CreateAgentRequest{IdempotencyKey: "workspace-control-agent", Name: "workspace-control", ModelProfile: "balanced", Instructions: "request one approved workspace copy", Tools: []agentruntime.ToolDefinition{{Name: "workspace.copy", Description: "copy one declared artifact into a workspace", InputSchemaVersion: toolschema.VersionV1, InputSchema: copySchema}}})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := admin.GetAgentRevision(ctx, agent.ID, agent.RevisionID)
	if err != nil || len(registered.Tools) != 1 || registered.Tools[0].Name != "workspace.copy" || registered.Tools[0].InputSchemaVersion != toolschema.VersionV1 || !bytes.Equal(registered.Tools[0].InputSchema, copySchema) {
		t.Fatalf("public registered Tool schema = %#v, %v", registered.Tools, err)
	}
	policy, err := admin.CreatePolicy(ctx, agentruntime.CreatePolicyRequest{IdempotencyKey: "workspace-control-policy", Name: "workspace-copy", Rules: []agentruntime.PolicyRule{{ToolName: "workspace.copy", Decision: agentruntime.PolicyRequiresApproval}}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := alice.CreateSession(ctx, agentruntime.CreateSessionRequest{IdempotencyKey: "workspace-control-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := alice.SendInput(ctx, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "workspace-control-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "copy the approved report"}}})
	if err != nil {
		t.Fatal(err)
	}

	source, err := clock.NewFake(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, workerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store, err := runtimepostgres.NewRuntimeStateStore(pool, source)
	if err != nil {
		t.Fatal(err)
	}
	immutable, err := runtimecontent.NewMinIOImmutableClient(objects)
	if err != nil {
		t.Fatal(err)
	}
	contentObjects, err := runtimecontent.NewS3ImmutableObjects(immutable, bucket)
	if err != nil {
		t.Fatal(err)
	}
	content, err := runtimecontent.New("runtime-content", contentObjects)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(source, &workspaceControlIDs{})
	if err != nil {
		t.Fatal(err)
	}
	broker, err := runtimetool.NewBroker(runtimetool.BrokerConfig{Store: store, Compiler: compiler, Planner: planner, Clock: source})
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: "workspace-control-e2e", Principal: "alice", Authority: runtimestate.AuthorityRuntimeWorker})
	if err != nil || len(state.Sessions) != 1 || len(state.Turns) != 1 {
		t.Fatalf("load accepted public input for durable invocation: state=%#v, err=%v", state, err)
	}
	// The durable orchestrator is deliberately outside this focused vertical.
	// Start the same private invocation lease it would persist after accepting
	// the public input, so the model worker consumes a real durable command
	// rather than a test-only broker record.
	begin, err := compiler.CompileBeginInvocationAttempt(runtimestate.BeginInvocationAttemptCommand{
		Scope:                  runtimestate.MutationScope{Tenant: "workspace-control-e2e", Principal: "alice", Authority: runtimestate.AuthorityRuntimeWorker},
		IdempotencyKey:         "workspace-control-model-intent",
		SessionID:              session.ID,
		TurnID:                 accepted.Turn.ID,
		OperationID:            "op_workspace_control_model_01",
		ExpectedSessionVersion: state.Sessions[0].Version,
		ExpectedTurnVersion:    state.Turns[0].Version,
	})
	if err != nil {
		t.Fatalf("compile durable model invocation: %v", err)
	}
	if _, err := store.ApplyCompiledMutation(ctx, planner, begin); err != nil {
		t.Fatalf("persist durable model invocation: %v", err)
	}
	model, err := runtimemodel.NewWorker(runtimemodel.WorkerConfig{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: workspaceControlModel{policy: policy, now: source.Now()}, Broker: broker, Claimer: "workspace-control-model"})
	if err != nil {
		t.Fatal(err)
	}
	if err := model.ScanOnce(ctx); err != nil {
		t.Fatalf("run durable model-to-approval step: %v", err)
	}
	approvals, err := alice.ListApprovals(ctx)
	if err != nil || len(approvals.Approvals) != 1 || approvals.Approvals[0].State != agentruntime.ApprovalPending {
		t.Fatalf("public pending Workspace Approval = %#v, %v", approvals, err)
	}
	pending := approvals.Approvals[0]
	if pending.SessionID != session.ID || pending.TurnID != accepted.Turn.ID || pending.Action == nil || pending.Action.Target != "workspace-service" {
		t.Fatalf("public approval binding = %#v", pending)
	}
	if _, err := alice.DecideApproval(ctx, agentruntime.DecideApprovalRequest{ApprovalID: pending.ID, Decision: agentruntime.ApprovalApproved, IdempotencyKey: "workspace-control-approve"}); err != nil {
		t.Fatalf("approve Workspace action through public API: %v", err)
	}

	ledger, sandboxAdapter := workspaceControlAdapter(t, source)
	adapter := &recordingWorkspaceControlAdapter{delegate: sandboxAdapter}
	tool, err := runtimetool.NewWorker(runtimetool.Config{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: adapter, Claimer: "workspace-control-tool", LeaseScheduler: runtimetool.NewRealtimeLeaseScheduler()})
	if err != nil {
		t.Fatal(err)
	}
	completed := make(chan error, 1)
	go func() { completed <- tool.ScanOnce(ctx) }()
	principal := "workspace-control-e2e:alice"
	var operation sandboxcontrol.Operation
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		state, stateErr := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: "workspace-control-e2e", Principal: "alice", Authority: runtimestate.AuthorityRuntimeWorker})
		if stateErr == nil && len(state.ToolExecutions) == 1 {
			operation, err = ledger.Get(ctx, principal, string(state.ToolExecutions[0].OperationID))
			if err == nil {
				break
			}
		}
		runtime.Gosched()
	}
	if err != nil {
		state, stateErr := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: "workspace-control-e2e", Principal: "alice", Authority: runtimestate.AuthorityRuntimeWorker})
		var execution string
		if len(state.ToolExecutions) == 1 {
			record := state.ToolExecutions[0]
			failure := "<nil>"
			if record.Failure != nil {
				failure = fmt.Sprintf("%s: %s", record.Failure.Code, record.Failure.Message)
			}
			execution = fmt.Sprintf("operation=%s state=%s failure=%s", record.OperationID, record.State, failure)
		}
		select {
		case workerErr := <-completed:
			t.Fatalf("sandbox-control did not retain approved workspace action: %v; worker=%v; execution=%#v", err, workerErr, execution)
		default:
			t.Fatalf("sandbox-control did not retain approved workspace action: %v; execution=%#v; stateErr=%v", err, execution, stateErr)
		}
	}
	submitted, err := sandbox.DecodeControlOperationRequest([]byte(operation.DispatchBody))
	if err != nil || submitted.Kind != sandbox.OperationCopyIn || submitted.CopyIn == nil || submitted.CopyIn.SandboxID != "sbx_workspace_000000000001" || submitted.CopyIn.Destination != "/workspace/reports/approved.txt" {
		t.Fatalf("sealed control action = %#v, decode=%v", submitted, err)
	}
	if bytes.Contains([]byte(operation.DispatchBody), []byte("model-only")) {
		t.Fatalf("sandbox-control received model-only arguments: %q", operation.DispatchBody)
	}
	operation, err = ledger.Transition(ctx, principal, operation.ID, operation.Version, sandboxcontrol.StateDispatched)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Transition(ctx, principal, operation.ID, operation.Version, sandboxcontrol.StateSucceeded); err != nil {
		t.Fatal(err)
	}
	if err := <-completed; err != nil {
		t.Fatalf("finalize approved sandbox-control action: %v", err)
	}
	requests := adapter.requests()
	if len(requests) != 1 || string(requests[0].Arguments) != `{"copy_mode":"safe"}` {
		t.Fatalf("registered Tool schema arguments at authorized adapter = %#v", requests)
	}
	tools, err := alice.InspectToolCalls(ctx, session.ID, accepted.Turn.ID)
	if err != nil || len(tools.Calls) != 1 || tools.Calls[0].State != agentruntime.ToolCallSucceeded || tools.Calls[0].Execution == nil {
		t.Fatalf("public finalized tool projection = %#v, %v", tools, err)
	}
}

type workspaceControlIDs struct{ next uint64 }

func (ids *workspaceControlIDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	ids.next++
	return fmt.Sprintf("%s_%016d", kind, ids.next), nil
}

type workspaceControlModel struct {
	policy agentruntime.Policy
	now    time.Time
}

func (model workspaceControlModel) Invoke(_ context.Context, request runtimemodel.Request) (runtimemodel.Response, error) {
	return model.response(request)
}
func (model workspaceControlModel) Reconcile(_ context.Context, request runtimemodel.Request) (runtimemodel.Response, error) {
	return model.response(request)
}
func (model workspaceControlModel) response(request runtimemodel.Request) (runtimemodel.Response, error) {
	descriptor, err := sandbox.EncodeControlOperationRequest(sandbox.OperationRequest{ID: "op_model_000000000001", Kind: sandbox.OperationCopyIn, CopyIn: &sandbox.CopyInRequest{SandboxID: "sbx_workspace_000000000001", Source: sandbox.ArtifactRef{ID: "art_workspace_000000000001", MediaType: "text/plain", SizeBytes: 7, Digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}, Destination: "/workspace/reports/approved.txt", Options: sandbox.TransferOptions{Overwrite: sandbox.OverwriteFailIfExists}}})
	if err != nil {
		return runtimemodel.Response{}, err
	}
	return runtimemodel.Response{Tool: &runtimemodel.ToolRequest{ToolCallID: "tcall_workspace0000000", ApprovalID: "appr_workspace0000000", PolicyName: model.policy.Name, PolicyRevision: model.policy.Revision, ToolName: "workspace.copy", ActionDigest: "sha256:" + strings.Repeat("a", 64), CapabilityDigest: "sha256:" + strings.Repeat("b", 64), Action: agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"}, MaximumUses: 1, ExpiresAt: model.now.Add(time.Hour), Descriptor: descriptor, Arguments: []byte(`{"copy_mode":"safe"}`)}}, nil
}

// recordingWorkspaceControlAdapter makes the private adapter boundary visible
// to this vertical without granting the model a way to manufacture a control
// request. The delegate retains the production dispatch capability check.
type recordingWorkspaceControlAdapter struct {
	delegate *runtimetool.SandboxAdapter
	mu       sync.Mutex
	values   []runtimetool.Request
}

func (adapter *recordingWorkspaceControlAdapter) ExternalEffectContract() runtimetool.ExternalEffectContract {
	return adapter.delegate.ExternalEffectContract()
}

func (adapter *recordingWorkspaceControlAdapter) Execute(ctx context.Context, request runtimetool.Request) (runtimetool.Response, error) {
	adapter.record(request)
	return adapter.delegate.Execute(ctx, request)
}

func (adapter *recordingWorkspaceControlAdapter) Reconcile(ctx context.Context, request runtimetool.Request) (runtimetool.Response, error) {
	adapter.record(request)
	return adapter.delegate.Reconcile(ctx, request)
}

func (adapter *recordingWorkspaceControlAdapter) record(request runtimetool.Request) {
	copy := request
	copy.Descriptor = append([]byte(nil), request.Descriptor...)
	copy.Arguments = append([]byte(nil), request.Arguments...)
	adapter.mu.Lock()
	adapter.values = append(adapter.values, copy)
	adapter.mu.Unlock()
}

func (adapter *recordingWorkspaceControlAdapter) requests() []runtimetool.Request {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	values := make([]runtimetool.Request, len(adapter.values))
	for index, request := range adapter.values {
		values[index] = request
		values[index].Descriptor = append([]byte(nil), request.Descriptor...)
		values[index].Arguments = append([]byte(nil), request.Arguments...)
	}
	return values
}

func workspaceControlAdapter(t *testing.T, source clock.Clock) (*sandboxcontrol.MemoryLedger, *runtimetool.SandboxAdapter) {
	t.Helper()
	ledger := sandboxcontrol.NewMemoryLedger()
	limits := sandbox.ResourceLimits{MilliCPU: 100, MemoryBytes: 1024, RootDiskBytes: 1024, TmpfsBytes: 1024, PIDs: 10, ProcessCount: 10, OpenFiles: 10, Inodes: 10, Files: 10, Lifetime: time.Hour, ProducedOutputBytes: 1024, RetainedOutputBytes: 1024, TransferBytes: 1024, NetworkConnections: 10, VolumeBytes: 1024, SnapshotBytes: 1024}
	handler, err := sandboxcontrolapi.NewHandler(sandboxcontrolapi.Config{Store: ledger, Authenticator: workspaceControlAuthenticator{}, AssertionKey: bytes.Repeat([]byte{0x42}, 32), Entropy: bytes.NewReader(bytes.Repeat([]byte{0x99}, 128)), Clock: source, BindingLifetime: time.Hour, Retention: time.Hour, WaitInterval: time.Millisecond, Wait: func(ctx context.Context, _ time.Duration) error { return ctx.Err() }, Admission: sandbox.OperationAdmissionPolicy{Defaults: limits, Maximum: limits}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	roots := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	trust, err := sandbox.NewStaticTrustBundleSource(map[sandbox.TrustBundleRef]sandbox.TrustBundle{"trust/workspace-control": {Version: "workspace-control/v1", PEMRoots: roots}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := sandbox.NewClient(context.Background(), sandbox.ClientConfig{Endpoint: sandbox.Endpoint{URL: server.URL}, TLS: sandbox.TLSConfig{ServerName: server.Certificate().DNSNames[0], TrustBundleRef: "trust/workspace-control"}, Credentials: workspaceControlCredentials{}, TrustBundles: trust, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(context.Background()) })
	adapter, err := runtimetool.NewSandboxAdapter(client)
	if err != nil {
		t.Fatal(err)
	}
	return ledger, adapter
}

type workspaceControlCredentials struct{}

func (workspaceControlCredentials) Apply(_ context.Context, sink sandbox.CredentialSink) error {
	return sink.SetAuthorization("Bearer", "workspace-control-token")
}

type workspaceControlAuthenticator struct{}

func (workspaceControlAuthenticator) Authenticate(ctx context.Context, authorization string) (sandboxcontrolapi.Identity, error) {
	if err := ctx.Err(); err != nil {
		return sandboxcontrolapi.Identity{}, err
	}
	if authorization != "Bearer workspace-control-token" {
		return sandboxcontrolapi.Identity{}, fmt.Errorf("credential denied")
	}
	return sandboxcontrolapi.Identity{Authority: "workspace-control", Tenant: "workspace-control-e2e", Subject: "alice", Principal: "workspace-control-e2e:alice"}, nil
}
