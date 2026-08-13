//go:build integration

package runtimetool_test

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
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

const durableOversizedToolOutputBytes = 8<<20 + 1

// TestDurableBrokeredToolLifecyclePersistsApprovalAndFinalization proves the
// broker-to-artifact lifecycle against disposable PostgreSQL and MinIO. The
// only Tool-admission transition is Broker.Admit; the worker can execute only
// after the owner decision creates a bounded grant.
func TestDurableBrokeredToolLifecyclePersistsApprovalAndFinalization(t *testing.T) {
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
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	source, _ := clock.NewFake(now)
	store, err := runtimepostgres.NewRuntimeStateStore(pool, source)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(source, &durableToolIDs{})
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := runtimecontent.ParseTenantID(fmt.Sprintf("durable-tool-%x", time.Now().UnixNano()))
	principal, _ := runtimecontent.ParsePrincipalID("alice")
	adminScope := runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}
	ownerScope := runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}
	workerScope := runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}
	apply := func(m runtimestate.CompiledMutation) runtimestate.TransitionPlan {
		for attempt := 0; attempt < 64; attempt++ {
			state, e := store.LoadRuntimeState(ctx, m.ReceiptBinding().Scope)
			if e != nil {
				t.Fatal(e)
			}
			plan, e := planner.Plan(ctx, state, m)
			if e != nil {
				t.Fatal(e)
			}
			if e = store.PersistTransitionPlan(ctx, plan); e == nil {
				return plan
			} else if !errors.Is(e, runtimestate.ErrConflict) {
				t.Fatal(e)
			}
			runtime.Gosched()
		}
		t.Fatal("persist durable tool transition: repeated state conflict")
		return runtimestate.TransitionPlan{}
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
	mutation, err = compiler.CompileRegisterPolicyRevision(runtimestate.RegisterPolicyRevisionCommand{Scope: adminScope, IdempotencyKey: "durable-tool-policy", Name: "durable-tool-policy", Rules: []agentruntime.PolicyRule{{ToolName: "sandbox", Decision: agentruntime.PolicyRequiresApproval}}})
	if err != nil {
		t.Fatal(err)
	}
	apply(mutation)
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
	// This is a private opaque adapter descriptor, never a public projection or
	// a sandbox capability. The external test adapter receives only the
	// runtime-owned operation ID once the worker has durably consumed a grant.
	descriptorBytes := []byte(`{"action":"workspace.write","path":"notes.txt","credential":"audit-probe-secret"}`)
	descriptor, err := content.StageToolActionDescriptor(ctx, tenant, descriptorBytes)
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	session, turn := created.Result().Session.SessionID, accepted.Result().Turn.TurnID
	broker, err := runtimetool.NewBroker(runtimetool.BrokerConfig{Store: store, Compiler: compiler, Planner: planner, Clock: source})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := broker.Admit(ctx, runtimetool.AdmissionRequest{Tenant: tenant, Principal: principal, SessionID: session, TurnID: turn, ToolCallID: "tcall_1234567890ABCDEF", ApprovalID: "appr_1234567890ABCDEF", PolicyName: "durable-tool-policy", PolicyRevision: 1, ToolName: "sandbox", ActionDigest: digest, CapabilityDigest: digest, Action: agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"}, MaximumUses: 1, ExpiresAt: now.Add(time.Hour), Descriptor: descriptor, IdempotencyKey: "durable-tool-admission"})
	if err != nil || admission.ToolCallID != "tcall_1234567890ABCDEF" || admission.ApprovalID != "appr_1234567890ABCDEF" {
		t.Fatalf("durable broker admission = %#v, %v", admission, err)
	}
	publicRuntime, err := runtimeapi.NewStateRuntime(runtimeapi.StateRuntimeConfig{Content: content, Compiler: compiler, Planner: planner, Store: store, ModelProfiles: []string{"balanced"}})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := publicRuntime.DecideApproval(ctx, runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}, agentruntime.DecideApprovalRequest{ApprovalID: admission.ApprovalID, Decision: agentruntime.ApprovalApproved, IdempotencyKey: "durable-tool-approve"})
	if err != nil || decision.State != agentruntime.ApprovalApproved {
		t.Fatalf("durable public approval = %#v, %v", decision, err)
	}
	// The worker-owned consumption transition persists its single allowed use
	// before it can create an execution intent. A distinct retry cannot consume
	// the same durable grant a second time, and therefore cannot create a
	// second adapter operation.
	// The opaque grant ID is owned by the durable planner, so load the exact
	// approved record before issuing the worker-owned consumption transition.
	state, err := store.LoadRuntimeState(ctx, workerScope)
	if err != nil || len(state.Grants) != 1 {
		t.Fatalf("load approved durable grant = %#v, %v", state.Grants, err)
	}
	firstUse, err := compiler.CompileConsumeCapabilityGrant(runtimestate.ConsumeCapabilityGrantCommand{Scope: workerScope, IdempotencyKey: "durable-tool-first-use", GrantID: state.Grants[0].GrantID, ToolCallID: admission.ToolCallID, PolicyRevisionDigest: state.Grants[0].PolicyRevisionDigest, SessionID: session, TurnID: turn})
	if err != nil {
		t.Fatal(err)
	}
	apply(firstUse)
	secondUse, err := compiler.CompileConsumeCapabilityGrant(runtimestate.ConsumeCapabilityGrantCommand{Scope: workerScope, IdempotencyKey: "durable-tool-second-use", GrantID: state.Grants[0].GrantID, ToolCallID: admission.ToolCallID, PolicyRevisionDigest: state.Grants[0].PolicyRevisionDigest, SessionID: session, TurnID: turn})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = applyRejection(ctx, planner, store, secondUse); !errors.Is(err, runtimestate.ErrConflict) {
		t.Fatalf("second durable grant use = %v, want conflict", err)
	}
	state, err = store.LoadRuntimeState(ctx, workerScope)
	if err != nil || len(state.ToolExecutions) != 0 || len(state.Grants) != 1 || state.Grants[0].Uses != state.Grants[0].MaximumUses {
		t.Fatalf("exhausted durable grant created execution before dispatch = grants=%#v executions=%#v err=%v", state.Grants, state.ToolExecutions, err)
	}
	adapter := newDurableToolAdapter()
	worker, err := runtimetool.NewWorker(runtimetool.Config{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: adapter, Claimer: "durable-tool-worker", LeaseScheduler: newInertLeaseScheduler()})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.ScanOnce(ctx); err != nil {
		t.Fatal(err)
	}
	// A restart/replay finds the published outbox and immutable terminal state,
	// so it cannot submit the external application operation a second time.
	if err := worker.ScanOnce(ctx); err != nil {
		t.Fatal(err)
	}
	state, err = store.LoadRuntimeState(ctx, workerScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.ToolExecutions) != 1 || state.ToolExecutions[0].State != runtimestate.ToolExecutionSucceeded || len(state.Grants) != 1 || state.Grants[0].Uses != 1 || adapter.executes != 1 || adapter.reconciles != 0 {
		t.Fatalf("durable execution = %#v", state.ToolExecutions)
	}
	// A live worker can take longer than the fixed ten-second crash-recovery
	// lease. Its claim must be renewed and fenced through finalization so a
	// competing PostgreSQL worker cannot reclaim the exact operation midway.
	slowSessionMutation, err := compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-slow-session", RevisionID: registered.Result().Revision.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	slowSession := apply(slowSessionMutation).Result().Session.SessionID
	slowInput, err := content.StageInputEnvelope(ctx, tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "hold a healthy tool action beyond its original lease"}})
	if err != nil {
		t.Fatal(err)
	}
	slowInputMutation, err := compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-slow-input", SessionID: slowSession, Input: slowInput})
	if err != nil {
		t.Fatal(err)
	}
	slowTurn := apply(slowInputMutation).Result().Turn.TurnID
	slowDescriptor, err := content.StageToolActionDescriptor(ctx, tenant, descriptorBytes)
	if err != nil {
		t.Fatal(err)
	}
	slowAdmission, err := broker.Admit(ctx, runtimetool.AdmissionRequest{Tenant: tenant, Principal: principal, SessionID: slowSession, TurnID: slowTurn, ToolCallID: "tcall_1234567890ABCDEZ", ApprovalID: "appr_1234567890ABCDEZ", PolicyName: "durable-tool-policy", PolicyRevision: 1, ToolName: "sandbox", ActionDigest: digest, CapabilityDigest: digest, Action: agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"}, MaximumUses: 1, ExpiresAt: source.Now().Add(time.Hour), Descriptor: slowDescriptor, IdempotencyKey: "durable-tool-slow-admission"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publicRuntime.DecideApproval(ctx, runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}, agentruntime.DecideApprovalRequest{ApprovalID: slowAdmission.ApprovalID, Decision: agentruntime.ApprovalApproved, IdempotencyKey: "durable-tool-slow-approve"}); err != nil {
		t.Fatal(err)
	}
	slowAdapter := newBlockingDurableToolAdapter()
	renewal := newManualLeaseScheduler()
	liveWorker, err := runtimetool.NewWorker(runtimetool.Config{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: slowAdapter, Claimer: "durable-live-tool-worker", LeaseRenewalInterval: time.Millisecond, LeaseScheduler: renewal})
	if err != nil {
		t.Fatal(err)
	}
	competingWorker, err := runtimetool.NewWorker(runtimetool.Config{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: slowAdapter, Claimer: "durable-competing-tool-worker", LeaseRenewalInterval: time.Millisecond, LeaseScheduler: newInertLeaseScheduler()})
	if err != nil {
		t.Fatal(err)
	}
	liveDone := make(chan error, 1)
	go func() { liveDone <- liveWorker.ScanOnce(ctx) }()
	<-slowAdapter.started
	if err := source.Advance(6 * time.Second); err != nil {
		t.Fatal(err)
	}
	renewal.Tick()
	durableToolRenewalIsCurrent(t, ctx, store, tenant, slowAdmission.ToolCallID, "durable-live-tool-worker", source)
	if err := source.Advance(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := competingWorker.ScanOnce(ctx); err != nil {
		t.Fatalf("durable competing worker scan: %v", err)
	}
	if executes, reconciles := slowAdapter.calls(); executes != 1 || reconciles != 0 {
		t.Fatalf("durable competing worker touched live tool: %d/%d", executes, reconciles)
	}
	close(slowAdapter.release)
	if err := <-liveDone; err != nil {
		t.Fatalf("durable live worker completion: %v", err)
	}
	state, err = store.LoadRuntimeState(ctx, workerScope)
	if err != nil {
		t.Fatal(err)
	}
	if executes, reconciles := slowAdapter.calls(); executes != 1 || reconciles != 0 || !durableToolExecutionSucceeded(state.ToolExecutions, slowAdmission.ToolCallID) {
		t.Fatalf("durable renewed tool execution = calls %d/%d executions %#v", executes, reconciles, state.ToolExecutions)
	}
	// The durable records contain only bounded metadata; authorization and
	// execution lifecycles are append-only audit facts, never raw tool output.
	for _, kind := range []string{
		"decide_approval.authorized",
		"consume_capability_grant.committed",
		"begin_tool_execution.committed",
		"record_tool_execution_outcome.terminal",
		"capability_grant.exhausted",
	} {
		if !durableHasAuditKind(state.Audit, kind) {
			t.Fatalf("durable audit lacks %q: %#v", kind, state.Audit)
		}
	}
	var initialResult *runtimecontent.Reference
	for _, execution := range state.ToolExecutions {
		if execution.ToolCallID == admission.ToolCallID {
			initialResult = execution.Result
			break
		}
	}
	var initialArtifact *runtimestate.ArtifactRecord
	for index := range state.Artifacts {
		if initialResult != nil && state.Artifacts[index].Reference == *initialResult {
			initialArtifact = &state.Artifacts[index]
			break
		}
	}
	if len(state.Artifacts) != 2 || initialArtifact == nil || initialArtifact.Reference.SizeBytes > 8<<20 {
		t.Fatalf("durable tool output artifacts = %#v", state.Artifacts)
	}
	download, err := publicRuntime.ReadArtifact(ctx, runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}, initialArtifact.ArtifactID)
	if err != nil || strings.Contains(string(download.Body), "integration-output-secret") || !strings.Contains(string(download.Body), "[REDACTED]") {
		t.Fatalf("durable redacted output = %#v, %v", download, err)
	}
	// Read the exact object through the configured MinIO client as well as the
	// owner-authorized API. This makes the redaction claim about persisted
	// bytes, not merely about a projection returned by StateRuntime.
	artifactKey := string(tenant) + "/tool-durable-integration/v1/sha256/" + strings.TrimPrefix(initialArtifact.Reference.Digest, "sha256:")
	storedArtifact, err := minioClient.GetObject(ctx, bucket, artifactKey, minio.GetObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	storedBytes, readErr := io.ReadAll(storedArtifact)
	closeErr := storedArtifact.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(storedBytes, download.Body) || bytes.Contains(storedBytes, []byte("integration-output-secret")) || !bytes.Contains(storedBytes, []byte("[REDACTED]")) {
		t.Fatalf("persisted MinIO tool output was not redacted: size=%d owner_match=%t raw_secret=%t redaction=%t read=%v close=%v", len(storedBytes), bytes.Equal(storedBytes, download.Body), bytes.Contains(storedBytes, []byte("integration-output-secret")), bytes.Contains(storedBytes, []byte("[REDACTED]")), readErr, closeErr)
	}
	// The public Tool projection carries only the immutable Artifact reference;
	// the companion Product event announces finalization without copying output.
	toolPage, err := publicRuntime.InspectToolCalls(ctx, runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}, session, turn)
	if err != nil || len(toolPage.Calls) != 1 || toolPage.Calls[0].Execution == nil || toolPage.Calls[0].Execution.Result == nil || toolPage.Calls[0].Execution.Result.ID != initialArtifact.ArtifactID || toolPage.Calls[0].Execution.Result.SHA256 != strings.TrimPrefix(initialArtifact.Reference.Digest, "sha256:") {
		t.Fatalf("public durable tool result reference = %#v, %v", toolPage, err)
	}
	eventPage, err := publicRuntime.Events(ctx, runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}, session, "", 128)
	if err != nil || !durableHasPublicFinalization(eventPage.Events, turn) {
		t.Fatalf("public durable tool finalization event = %#v, %v", eventPage, err)
	}
	publicBytes, marshalErr := json.Marshal(struct {
		Tools  agentruntime.ToolCallPage `json:"tools"`
		Events agentruntime.EventPage    `json:"events"`
	}{Tools: toolPage, Events: eventPage})
	if marshalErr != nil || bytes.Contains(publicBytes, []byte("integration-output-secret")) || bytes.Contains(publicBytes, []byte("[REDACTED]")) {
		t.Fatalf("public durable tool result or event leaked output: tool_calls=%d events=%d raw_secret=%t redaction=%t err=%v", len(toolPage.Calls), len(eventPage.Events), bytes.Contains(publicBytes, []byte("integration-output-secret")), bytes.Contains(publicBytes, []byte("[REDACTED]")), marshalErr)
	}
	// A separate approved action returns an oversized secret-shaped response.
	// Snapshot the isolated tenant prefix after its descriptor is staged: its
	// failure must not add an Artifact object or any durable representation of
	// the oversized output.
	oversizedSessionMutation, err := compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-oversized-session", RevisionID: registered.Result().Revision.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	oversizedSession := apply(oversizedSessionMutation).Result().Session.SessionID
	oversizedInput, err := content.StageInputEnvelope(ctx, tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "oversized action must have no retained output"}})
	if err != nil {
		t.Fatal(err)
	}
	oversizedMutation, err := compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-oversized-input", SessionID: oversizedSession, Input: oversizedInput})
	if err != nil {
		t.Fatal(err)
	}
	oversizedTurn := apply(oversizedMutation).Result().Turn.TurnID
	oversizedDescriptor, err := content.StageToolActionDescriptor(ctx, tenant, []byte(`{"action":"workspace.write","path":"oversized.txt"}`))
	if err != nil {
		t.Fatal(err)
	}
	objectsBeforeOversized := durableMinIOObjectBodies(t, ctx, minioClient, bucket, string(tenant)+"/")
	oversized, err := broker.Admit(ctx, runtimetool.AdmissionRequest{Tenant: tenant, Principal: principal, SessionID: oversizedSession, TurnID: oversizedTurn, ToolCallID: "tcall_1234567890ABCDEN", ApprovalID: "appr_1234567890ABCDEN", PolicyName: "durable-tool-policy", PolicyRevision: 1, ToolName: "sandbox", ActionDigest: digest, CapabilityDigest: digest, Action: agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"}, MaximumUses: 1, ExpiresAt: source.Now().Add(time.Hour), Descriptor: oversizedDescriptor, IdempotencyKey: "durable-tool-oversized-admission"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publicRuntime.DecideApproval(ctx, runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}, agentruntime.DecideApprovalRequest{ApprovalID: oversized.ApprovalID, Decision: agentruntime.ApprovalApproved, IdempotencyKey: "durable-tool-oversized-approve"}); err != nil {
		t.Fatal(err)
	}
	oversizedAdapter := newOversizedDurableToolAdapter()
	oversizedWorker, err := runtimetool.NewWorker(runtimetool.Config{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: oversizedAdapter, Claimer: "durable-tool-oversized-worker", LeaseScheduler: newInertLeaseScheduler()})
	if err != nil {
		t.Fatal(err)
	}
	if err := oversizedWorker.ScanOnce(ctx); err != nil {
		t.Fatal(err)
	}
	state, err = store.LoadRuntimeState(ctx, workerScope)
	if err != nil {
		t.Fatal(err)
	}
	var oversizedExecution runtimestate.ToolExecutionRecord
	for _, execution := range state.ToolExecutions {
		if execution.ToolCallID == oversized.ToolCallID {
			oversizedExecution = execution
			break
		}
	}
	if oversizedAdapter.executes != 1 || oversizedExecution.State != runtimestate.ToolExecutionFailed || oversizedExecution.Result != nil || oversizedExecution.Failure == nil || oversizedExecution.Failure.Message != "tool output exceeds the safe retention limit" || len(state.Artifacts) != 2 {
		t.Fatalf("oversized durable tool outcome retained output: execution=%#v artifacts=%#v calls=%d", oversizedExecution, state.Artifacts, oversizedAdapter.executes)
	}
	objectsAfterOversized := durableMinIOObjectBodies(t, ctx, minioClient, bucket, string(tenant)+"/")
	if !durableMinIOObjectsEqual(objectsBeforeOversized, objectsAfterOversized) {
		t.Fatalf("oversized durable tool output created an object: before=%v after=%v", durableMinIOObjectKeys(objectsBeforeOversized), durableMinIOObjectKeys(objectsAfterOversized))
	}
	for key, value := range objectsAfterOversized {
		if bytes.Contains(value, []byte("integration-output-secret")) || bytes.Contains(value, []byte("oversized-output-secret")) {
			t.Fatalf("MinIO object %q retained a raw tool-output secret", key)
		}
	}
	oversizedPage, err := publicRuntime.InspectToolCalls(ctx, runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}, oversizedSession, oversizedTurn)
	if err != nil || len(oversizedPage.Calls) != 1 || oversizedPage.Calls[0].Execution == nil || oversizedPage.Calls[0].Execution.State != agentruntime.ToolCallFailed || oversizedPage.Calls[0].Execution.Result != nil || oversizedPage.Calls[0].Execution.Failure == nil || oversizedPage.Calls[0].Execution.Failure.Message != "tool output exceeds the safe retention limit" {
		t.Fatalf("public oversized durable tool result = %#v, %v", oversizedPage, err)
	}
	oversizedEvents, err := publicRuntime.Events(ctx, runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}, oversizedSession, "", 128)
	oversizedPublic, marshalErr := json.Marshal(struct {
		Tools  agentruntime.ToolCallPage `json:"tools"`
		Events agentruntime.EventPage    `json:"events"`
	}{Tools: oversizedPage, Events: oversizedEvents})
	if err != nil || marshalErr != nil || !durableHasPublicFinalization(oversizedEvents.Events, oversizedTurn) || bytes.Contains(oversizedPublic, []byte("oversized-output-secret")) {
		t.Fatalf("public oversized durable tool terminal state = tools=%#v events=%#v err=%v marshal=%v", oversizedPage, oversizedEvents, err, marshalErr)
	}
	// A grant can be revoked only before its execution intent. Once a real
	// external operation has a durable terminal observation, the owner receives
	// a stable conflict instead of a fictional undo claim.
	revoke, err := compiler.CompileRevokeCapabilityGrant(runtimestate.RevokeCapabilityGrantCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-revoke-after-execution", SessionID: session, TurnID: turn, ToolCallID: "tcall_1234567890ABCDEF", GrantID: state.Grants[0].GrantID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = applyRejection(ctx, planner, store, revoke); !errors.Is(err, runtimestate.ErrConflict) {
		t.Fatalf("revoke completed external operation = %v, want conflict", err)
	}
	found := false
	for _, event := range state.Events {
		if event.Kind == agentruntime.EventSandboxOperationFinalized && event.OperationID == state.ToolExecutions[0].OperationID {
			found = true
		}
	}
	if !found {
		t.Fatalf("durable event replay lacks sandbox finalization: %#v", state.Events)
	}
	// Reclaiming a lost publisher lease reuses the exact durable operation ID
	// and calls the adapter's status-only reconciliation seam. Its terminal
	// result must enter the same ordered, secret-free audit/outbox chain as a
	// first execution; it is not a second external submission.
	recoverySessionMutation, err := compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-recovery-session", RevisionID: registered.Result().Revision.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	recoverySession := apply(recoverySessionMutation).Result().Session.SessionID
	recoveryInput, err := content.StageInputEnvelope(ctx, tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "reconcile an interrupted action"}})
	if err != nil {
		t.Fatal(err)
	}
	recoveryMutation, err := compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-recovery-input", SessionID: recoverySession, Input: recoveryInput})
	if err != nil {
		t.Fatal(err)
	}
	recoveryTurn := apply(recoveryMutation).Result().Turn.TurnID
	recoveryDescriptor, err := content.StageToolActionDescriptor(ctx, tenant, descriptorBytes)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := broker.Admit(ctx, runtimetool.AdmissionRequest{Tenant: tenant, Principal: principal, SessionID: recoverySession, TurnID: recoveryTurn, ToolCallID: "tcall_1234567890ABCDEM", ApprovalID: "appr_1234567890ABCDEM", PolicyName: "durable-tool-policy", PolicyRevision: 1, ToolName: "sandbox", ActionDigest: digest, CapabilityDigest: digest, Action: agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"}, MaximumUses: 1, ExpiresAt: source.Now().Add(time.Hour), Descriptor: recoveryDescriptor, IdempotencyKey: "durable-tool-recovery-admission"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publicRuntime.DecideApproval(ctx, runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}, agentruntime.DecideApprovalRequest{ApprovalID: recovery.ApprovalID, Decision: agentruntime.ApprovalApproved, IdempotencyKey: "durable-tool-recovery-approve"}); err != nil {
		t.Fatal(err)
	}
	state, err = store.LoadRuntimeState(ctx, workerScope)
	if err != nil {
		t.Fatal(err)
	}
	var recoveryGrant runtimestate.CapabilityGrantRecord
	for _, grant := range state.Grants {
		if grant.ToolCallID == recovery.ToolCallID {
			recoveryGrant = grant
			break
		}
	}
	if recoveryGrant.GrantID == "" {
		t.Fatalf("recovery grant was not persisted: %#v", state.Grants)
	}
	recoveryConsume, err := compiler.CompileConsumeCapabilityGrant(runtimestate.ConsumeCapabilityGrantCommand{Scope: workerScope, IdempotencyKey: "durable-tool-recovery-consume", GrantID: recoveryGrant.GrantID, ToolCallID: recovery.ToolCallID, PolicyRevisionDigest: recoveryGrant.PolicyRevisionDigest, SessionID: recoverySession, TurnID: recoveryTurn})
	if err != nil {
		t.Fatal(err)
	}
	apply(recoveryConsume)
	recoveryOperationID := runtimestate.OperationID("op_tool_recovery_" + recoveryGrant.GrantID)
	recoveryBegin, err := compiler.CompileBeginToolExecution(runtimestate.BeginToolExecutionCommand{Scope: workerScope, IdempotencyKey: "durable-tool-recovery-begin", GrantID: recoveryGrant.GrantID, ToolCallID: recovery.ToolCallID, SessionID: recoverySession, TurnID: recoveryTurn, OperationID: recoveryOperationID})
	if err != nil {
		t.Fatal(err)
	}
	apply(recoveryBegin)
	state, err = store.LoadRuntimeState(ctx, workerScope)
	if err != nil {
		t.Fatal(err)
	}
	var recoveryOutbox runtimestate.OutboxRecord
	for _, record := range state.Outbox {
		if record.Aggregate == "tool_execution" && record.ToolCallID == recovery.ToolCallID && record.OperationID == recoveryOperationID {
			recoveryOutbox = record
			break
		}
	}
	if recoveryOutbox.OutboxID == "" {
		t.Fatalf("recovery execution outbox was not persisted: %#v", state.Outbox)
	}
	recoveryClaim, err := compiler.CompileClaimOutbox(runtimestate.ClaimOutboxCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher}, IdempotencyKey: "durable-tool-recovery-lost-claim", OutboxID: recoveryOutbox.OutboxID, ExpectedVersion: recoveryOutbox.Version, Claimer: "lost-durable-tool-worker", ClaimUntil: source.Now().Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	apply(recoveryClaim)
	if err := source.Advance(time.Second + time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	if err := worker.ScanOnce(ctx); err != nil {
		t.Fatal(err)
	}
	state, err = store.LoadRuntimeState(ctx, workerScope)
	if err != nil || !durableToolExecutionSucceeded(state.ToolExecutions, recovery.ToolCallID) || adapter.executes != 1 || adapter.reconciles != 1 || !durableHasAuditToolCall(state.Audit, recovery.ToolCallID, "record_tool_execution_outcome.terminal") {
		t.Fatalf("recovered durable execution = executions=%#v calls=%d/%d audit=%#v err=%v", state.ToolExecutions, adapter.executes, adapter.reconciles, state.Audit, err)
	}
	executionsBeforeTerminalGrantChecks := len(state.ToolExecutions)
	// A second brokered approval proves that a grant is checked by the durable
	// worker immediately before dispatch: advancing past its exact expiry
	// produces no external adapter call and no execution intent.
	expiringInput, err := content.StageInputEnvelope(ctx, tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "expired action must not run"}})
	if err != nil {
		t.Fatal(err)
	}
	expiringMutation, err := compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-expiring-input", SessionID: session, Input: expiringInput})
	if err != nil {
		t.Fatal(err)
	}
	expiringTurn := apply(expiringMutation).Result().Turn.TurnID
	expiringDescriptor, err := content.StageToolActionDescriptor(ctx, tenant, descriptorBytes)
	if err != nil {
		t.Fatal(err)
	}
	expiring, err := broker.Admit(ctx, runtimetool.AdmissionRequest{Tenant: tenant, Principal: principal, SessionID: session, TurnID: expiringTurn, ToolCallID: "tcall_1234567890ABCDEG", ApprovalID: "appr_1234567890ABCDEG", PolicyName: "durable-tool-policy", PolicyRevision: 1, ToolName: "sandbox", ActionDigest: digest, CapabilityDigest: digest, Action: agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"}, MaximumUses: 1, ExpiresAt: source.Now().Add(time.Second), Descriptor: expiringDescriptor, IdempotencyKey: "durable-tool-expiring-admission"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publicRuntime.DecideApproval(ctx, runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}, agentruntime.DecideApprovalRequest{ApprovalID: expiring.ApprovalID, Decision: agentruntime.ApprovalApproved, IdempotencyKey: "durable-tool-expiring-approve"}); err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(time.Second + time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	if err := worker.ScanOnce(ctx); err != nil {
		t.Fatal(err)
	}
	state, err = store.LoadRuntimeState(ctx, workerScope)
	if err != nil || len(state.ToolExecutions) != executionsBeforeTerminalGrantChecks || adapter.executes != 1 || adapter.reconciles != 1 || !durableHasAuditKind(state.Audit, "capability_grant.expired") {
		t.Fatalf("expired durable grant = executions=%#v calls=%d/%d audit=%#v err=%v", state.ToolExecutions, adapter.executes, adapter.reconciles, state.Audit, err)
	}
	// Owner revocation before the worker records an execution intent is also a
	// durable terminal boundary.  The worker must see the persisted withdrawal,
	// retain it in the audit history, and never hand this operation to the
	// external adapter.
	revokedSessionMutation, err := compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-revoked-session", RevisionID: registered.Result().Revision.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	revokedSession := apply(revokedSessionMutation).Result().Session.SessionID
	revokedInput, err := content.StageInputEnvelope(ctx, tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "revoked action must not run"}})
	if err != nil {
		t.Fatal(err)
	}
	revokedMutation, err := compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-revoked-input", SessionID: revokedSession, Input: revokedInput})
	if err != nil {
		t.Fatal(err)
	}
	revokedTurn := apply(revokedMutation).Result().Turn.TurnID
	revokedDescriptor, err := content.StageToolActionDescriptor(ctx, tenant, descriptorBytes)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := broker.Admit(ctx, runtimetool.AdmissionRequest{Tenant: tenant, Principal: principal, SessionID: revokedSession, TurnID: revokedTurn, ToolCallID: "tcall_1234567890ABCDEI", ApprovalID: "appr_1234567890ABCDEI", PolicyName: "durable-tool-policy", PolicyRevision: 1, ToolName: "sandbox", ActionDigest: digest, CapabilityDigest: digest, Action: agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"}, MaximumUses: 1, ExpiresAt: source.Now().Add(time.Hour), Descriptor: revokedDescriptor, IdempotencyKey: "durable-tool-revoked-admission"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publicRuntime.DecideApproval(ctx, runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}, agentruntime.DecideApprovalRequest{ApprovalID: revoked.ApprovalID, Decision: agentruntime.ApprovalApproved, IdempotencyKey: "durable-tool-revoked-approve"}); err != nil {
		t.Fatal(err)
	}
	state, err = store.LoadRuntimeState(ctx, workerScope)
	if err != nil {
		t.Fatal(err)
	}
	var revokedGrant runtimestate.CapabilityGrantRecord
	for _, grant := range state.Grants {
		if grant.ToolCallID == revoked.ToolCallID {
			revokedGrant = grant
			break
		}
	}
	if revokedGrant.GrantID == "" {
		t.Fatalf("approved revoked grant was not persisted: %#v", state.Grants)
	}
	revokeBeforeIntent, err := compiler.CompileRevokeCapabilityGrant(runtimestate.RevokeCapabilityGrantCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-revoke-before-intent", SessionID: revokedSession, TurnID: revokedTurn, ToolCallID: revoked.ToolCallID, GrantID: revokedGrant.GrantID})
	if err != nil {
		t.Fatal(err)
	}
	apply(revokeBeforeIntent)
	if err := worker.ScanOnce(ctx); err != nil {
		t.Fatal(err)
	}
	state, err = store.LoadRuntimeState(ctx, workerScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.ToolExecutions) != executionsBeforeTerminalGrantChecks || adapter.executes != 1 || adapter.reconciles != 1 || !durableGrantRevokedWithoutUse(state.Grants, revoked.ToolCallID) || !durableHasAuditKind(state.Audit, "capability_grant.revoked") || !durableHasAuditKind(state.Audit, "revoke_capability_grant.terminal") {
		t.Fatalf("revoked durable grant dispatched or lost terminal audit: executions=%#v calls=%d/%d grants=%#v audit=%#v", state.ToolExecutions, adapter.executes, adapter.reconciles, state.Grants, state.Audit)
	}
	// Cancellation reaches the same worker through the public owner API.  It
	// may leave the bounded grant as retained metadata, but the cancelled Turn
	// is authoritative: no consumption, execution intent, or adapter dispatch
	// can occur after its durable terminal transition.
	cancelledSessionMutation, err := compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-cancelled-session", RevisionID: registered.Result().Revision.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	cancelledSession := apply(cancelledSessionMutation).Result().Session.SessionID
	cancelledInput, err := content.StageInputEnvelope(ctx, tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "cancelled action must not run"}})
	if err != nil {
		t.Fatal(err)
	}
	cancelledMutation, err := compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-cancelled-input", SessionID: cancelledSession, Input: cancelledInput})
	if err != nil {
		t.Fatal(err)
	}
	cancelledTurn := apply(cancelledMutation).Result().Turn.TurnID
	cancelledDescriptor, err := content.StageToolActionDescriptor(ctx, tenant, descriptorBytes)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, err := broker.Admit(ctx, runtimetool.AdmissionRequest{Tenant: tenant, Principal: principal, SessionID: cancelledSession, TurnID: cancelledTurn, ToolCallID: "tcall_1234567890ABCDEJ", ApprovalID: "appr_1234567890ABCDEJ", PolicyName: "durable-tool-policy", PolicyRevision: 1, ToolName: "sandbox", ActionDigest: digest, CapabilityDigest: digest, Action: agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"}, MaximumUses: 1, ExpiresAt: source.Now().Add(time.Hour), Descriptor: cancelledDescriptor, IdempotencyKey: "durable-tool-cancelled-admission"})
	if err != nil {
		t.Fatal(err)
	}
	cancelledTurnState, err := publicRuntime.CancelTurn(ctx, runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}, agentruntime.CancelTurnRequest{SessionID: cancelledSession, TurnID: cancelledTurn, IdempotencyKey: "durable-tool-cancel-before-intent"})
	if err != nil || cancelledTurnState.State != agentruntime.TurnCancelled {
		t.Fatalf("cancel approved durable turn = %#v, %v", cancelledTurnState, err)
	}
	if err := worker.ScanOnce(ctx); err != nil {
		t.Fatal(err)
	}
	state, err = store.LoadRuntimeState(ctx, workerScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.ToolExecutions) != executionsBeforeTerminalGrantChecks || adapter.executes != 1 || adapter.reconciles != 1 || durableHasGrant(state.Grants, cancelled.ToolCallID) || !durableHasAuditToolCall(state.Audit, cancelled.ToolCallID, "approval.cancelled") || !durableHasAuditKind(state.Audit, "cancel_turn.terminal") {
		t.Fatalf("cancelled durable turn dispatched or lost terminal audit: executions=%#v calls=%d/%d grants=%#v audit=%#v", state.ToolExecutions, adapter.executes, adapter.reconciles, state.Grants, state.Audit)
	}
	// A conscious owner denial is a terminal approval resolution, distinct from
	// admission-policy refusal below. It remains safe to inspect publicly and
	// never grants authority or reaches the worker.
	deniedApprovalSessionMutation, err := compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-approval-denied-session", RevisionID: registered.Result().Revision.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	deniedApprovalSession := apply(deniedApprovalSessionMutation).Result().Session.SessionID
	deniedApprovalInput, err := content.StageInputEnvelope(ctx, tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "denied approval must not run"}})
	if err != nil {
		t.Fatal(err)
	}
	deniedApprovalMutation, err := compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-approval-denied-input", SessionID: deniedApprovalSession, Input: deniedApprovalInput})
	if err != nil {
		t.Fatal(err)
	}
	deniedApprovalTurn := apply(deniedApprovalMutation).Result().Turn.TurnID
	deniedApprovalDescriptor, err := content.StageToolActionDescriptor(ctx, tenant, descriptorBytes)
	if err != nil {
		t.Fatal(err)
	}
	deniedApproval, err := broker.Admit(ctx, runtimetool.AdmissionRequest{Tenant: tenant, Principal: principal, SessionID: deniedApprovalSession, TurnID: deniedApprovalTurn, ToolCallID: "tcall_1234567890ABCDEO", ApprovalID: "appr_1234567890ABCDEO", PolicyName: "durable-tool-policy", PolicyRevision: 1, ToolName: "sandbox", ActionDigest: digest, CapabilityDigest: digest, Action: agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"}, MaximumUses: 1, ExpiresAt: source.Now().Add(time.Hour), Descriptor: deniedApprovalDescriptor, IdempotencyKey: "durable-tool-approval-denied-admission"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publicRuntime.DecideApproval(ctx, runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}, agentruntime.DecideApprovalRequest{ApprovalID: deniedApproval.ApprovalID, Decision: agentruntime.ApprovalDenied, IdempotencyKey: "durable-tool-approval-denied"}); err != nil {
		t.Fatal(err)
	}
	deniedApprovalPage, err := publicRuntime.InspectToolCalls(ctx, runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}, deniedApprovalSession, deniedApprovalTurn)
	if err != nil || len(deniedApprovalPage.Calls) != 1 || deniedApprovalPage.Calls[0].Approval == nil || deniedApprovalPage.Calls[0].Approval.State != agentruntime.ApprovalDenied || deniedApprovalPage.Calls[0].Grant != nil || deniedApprovalPage.Calls[0].Execution != nil {
		t.Fatalf("public denied approval state = %#v, %v", deniedApprovalPage, err)
	}
	// A policy refusal must be just as durable and correlated as a pending or
	// approved request, while retaining no descriptor and exposing no policy
	// enumeration result to the caller.
	deniedSessionMutation, err := compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-denied-session", RevisionID: registered.Result().Revision.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	deniedSession := apply(deniedSessionMutation).Result().Session.SessionID
	deniedInput, err := content.StageInputEnvelope(ctx, tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "denied action must not run"}})
	if err != nil {
		t.Fatal(err)
	}
	deniedMutation, err := compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-denied-input", SessionID: deniedSession, Input: deniedInput})
	if err != nil {
		t.Fatal(err)
	}
	deniedTurn := apply(deniedMutation).Result().Turn.TurnID
	deniedDescriptor, err := content.StageToolActionDescriptor(ctx, tenant, descriptorBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Admit(ctx, runtimetool.AdmissionRequest{Tenant: tenant, Principal: principal, SessionID: deniedSession, TurnID: deniedTurn, ToolCallID: "tcall_1234567890ABCDEK", ApprovalID: "appr_1234567890ABCDEK", PolicyName: "durable-tool-policy", PolicyRevision: 1, ToolName: "not-authorized", ActionDigest: digest, CapabilityDigest: digest, Action: agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"}, MaximumUses: 1, ExpiresAt: source.Now().Add(time.Hour), Descriptor: deniedDescriptor, IdempotencyKey: "durable-tool-denied-admission"}); !errors.Is(err, runtimetool.ErrDenied) {
		t.Fatalf("durable denied tool admission = %v, want denied", err)
	}
	state, err = store.LoadRuntimeState(ctx, workerScope)
	if err != nil || len(state.ToolExecutions) != executionsBeforeTerminalGrantChecks || adapter.executes != 1 || adapter.reconciles != 1 || durableHasToolIntent(state.ToolIntents, "tcall_1234567890ABCDEK") {
		t.Fatalf("denied durable admission retained authority or dispatched: executions=%#v calls=%d intents=%#v err=%v", state.ToolExecutions, adapter.executes, state.ToolIntents, err)
	}
	unknownDescriptor, err := content.StageToolActionDescriptor(ctx, tenant, descriptorBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Admit(ctx, runtimetool.AdmissionRequest{Tenant: tenant, Principal: principal, SessionID: deniedSession, TurnID: deniedTurn, ToolCallID: "tcall_1234567890ABCDEL", ApprovalID: "appr_1234567890ABCDEL", PolicyName: "unavailable-policy", PolicyRevision: 99, ToolName: "not-authorized", ActionDigest: digest, CapabilityDigest: digest, Action: agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"}, MaximumUses: 1, ExpiresAt: source.Now().Add(time.Hour), Descriptor: unknownDescriptor, IdempotencyKey: "durable-tool-unavailable-policy"}); !errors.Is(err, runtimetool.ErrDenied) {
		t.Fatalf("durable unavailable-policy admission = %v, want denied", err)
	}
	state, err = store.LoadRuntimeState(ctx, workerScope)
	if err != nil || len(state.ToolExecutions) != executionsBeforeTerminalGrantChecks || adapter.executes != 1 || adapter.reconciles != 1 || durableHasToolIntent(state.ToolIntents, "tcall_1234567890ABCDEL") {
		t.Fatalf("unavailable-policy durable admission retained authority or dispatched: executions=%#v calls=%d intents=%#v err=%v", state.ToolExecutions, adapter.executes, state.ToolIntents, err)
	}
	lateSessionMutation, err := compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-late-session", RevisionID: registered.Result().Revision.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	lateSession := apply(lateSessionMutation).Result().Session.SessionID
	lateInput, err := content.StageInputEnvelope(ctx, tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "late approval must not run"}})
	if err != nil {
		t.Fatal(err)
	}
	lateMutation, err := compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-late-input", SessionID: lateSession, Input: lateInput})
	if err != nil {
		t.Fatal(err)
	}
	lateTurn := apply(lateMutation).Result().Turn.TurnID
	lateDescriptor, err := content.StageToolActionDescriptor(ctx, tenant, descriptorBytes)
	if err != nil {
		t.Fatal(err)
	}
	late, err := broker.Admit(ctx, runtimetool.AdmissionRequest{Tenant: tenant, Principal: principal, SessionID: lateSession, TurnID: lateTurn, ToolCallID: "tcall_1234567890ABCDEH", ApprovalID: "appr_1234567890ABCDEH", PolicyName: "durable-tool-policy", PolicyRevision: 1, ToolName: "sandbox", ActionDigest: digest, CapabilityDigest: digest, Action: agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"}, MaximumUses: 1, ExpiresAt: source.Now().Add(time.Second), Descriptor: lateDescriptor, IdempotencyKey: "durable-tool-late-admission"})
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	pool.Close()
	pool, err = pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	store, err = runtimepostgres.NewRuntimeStateStore(pool, source)
	if err != nil {
		t.Fatal(err)
	}
	broker, err = runtimetool.NewBroker(runtimetool.BrokerConfig{Store: store, Compiler: compiler, Planner: planner, Clock: source})
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := runtimeapi.NewStateRuntime(runtimeapi.StateRuntimeConfig{Content: content, Compiler: compiler, Planner: planner, Store: store, ModelProfiles: []string{"balanced"}})
	if err != nil {
		t.Fatal(err)
	}
	// The reopened public runtime must preserve the expiry decision and refuse a
	// late owner replay.  This is a safe terminal conflict, not a new grant or
	// a second dispatch after reconnect.
	if _, err := restarted.DecideApproval(ctx, runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}, agentruntime.DecideApprovalRequest{ApprovalID: late.ApprovalID, Decision: agentruntime.ApprovalApproved, IdempotencyKey: "durable-tool-late-replay"}); err == nil {
		t.Fatal("late durable approval decision succeeded after expiry")
	}
	expiredApproval, err := restarted.InspectApproval(ctx, runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}, late.ApprovalID)
	if err != nil || expiredApproval.State != agentruntime.ApprovalExpired {
		t.Fatalf("restarted expired approval = %#v, %v", expiredApproval, err)
	}
	page, err := restarted.InspectToolCalls(ctx, runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}, session, turn)
	if err != nil || len(page.Calls) != 1 || page.Truncated || page.Calls[0].State != agentruntime.ToolCallSucceeded || page.Calls[0].Approval == nil || page.Calls[0].Approval.State != agentruntime.ApprovalApproved || page.Calls[0].Grant == nil || page.Calls[0].Grant.Uses != 1 || page.Calls[0].Execution == nil || page.Calls[0].Execution.Failure != nil {
		t.Fatalf("restarted durable Tool inspection = %#v, %v", page, err)
	}
	state, err = store.LoadRuntimeState(ctx, workerScope)
	if err != nil {
		t.Fatal(err)
	}
	artifactsBeforeUncertain := len(state.Artifacts)
	// A worker may have submitted an external operation before losing its
	// acknowledgement. After the lease expires and the process restarts, the
	// replacement worker is allowed to observe only that exact operation ID.
	// When the external status remains unknown, it must retain uncertainty
	// rather than invent success or submit the effect again.
	uncertainSessionMutation, err := compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-uncertain-session", RevisionID: registered.Result().Revision.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	uncertainSession := apply(uncertainSessionMutation).Result().Session.SessionID
	uncertainInput, err := content.StageInputEnvelope(ctx, tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "unknown external effect must reconcile safely"}})
	if err != nil {
		t.Fatal(err)
	}
	uncertainMutation, err := compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: ownerScope, IdempotencyKey: "durable-tool-uncertain-input", SessionID: uncertainSession, Input: uncertainInput})
	if err != nil {
		t.Fatal(err)
	}
	uncertainTurn := apply(uncertainMutation).Result().Turn.TurnID
	uncertainDescriptor, err := content.StageToolActionDescriptor(ctx, tenant, descriptorBytes)
	if err != nil {
		t.Fatal(err)
	}
	uncertainAdmission, err := broker.Admit(ctx, runtimetool.AdmissionRequest{Tenant: tenant, Principal: principal, SessionID: uncertainSession, TurnID: uncertainTurn, ToolCallID: "tcall_1234567890ABCDEQ", ApprovalID: "appr_1234567890ABCDEQ", PolicyName: "durable-tool-policy", PolicyRevision: 1, ToolName: "sandbox", ActionDigest: digest, CapabilityDigest: digest, Action: agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"}, MaximumUses: 1, ExpiresAt: source.Now().Add(time.Hour), Descriptor: uncertainDescriptor, IdempotencyKey: "durable-tool-uncertain-admission"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.DecideApproval(ctx, runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}, agentruntime.DecideApprovalRequest{ApprovalID: uncertainAdmission.ApprovalID, Decision: agentruntime.ApprovalApproved, IdempotencyKey: "durable-tool-uncertain-approve"}); err != nil {
		t.Fatal(err)
	}
	acceptedAdapter := newAcceptedThenLostDurableToolAdapter()
	initialWorker, err := runtimetool.NewWorker(runtimetool.Config{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: acceptedAdapter, Claimer: "durable-tool-lost-after-acceptance-worker", LeaseScheduler: newInertLeaseScheduler()})
	if err != nil {
		t.Fatal(err)
	}
	runWorkerUntilAcceptedEffectIsLost(t, ctx, initialWorker)
	state, err = store.LoadRuntimeState(ctx, workerScope)
	if err != nil {
		t.Fatal(err)
	}
	var uncertainExecution runtimestate.ToolExecutionRecord
	var uncertainOutbox runtimestate.OutboxRecord
	for _, execution := range state.ToolExecutions {
		if execution.ToolCallID == uncertainAdmission.ToolCallID {
			uncertainExecution = execution
			break
		}
	}
	if uncertainExecution.OperationID == "" || uncertainExecution.State != runtimestate.ToolExecutionIntent || acceptedAdapter.executes != 1 || acceptedAdapter.acceptedOperationID != uncertainExecution.OperationID {
		t.Fatalf("initial external effect was not accepted before worker loss: execution=%#v adapter=%#v", uncertainExecution, acceptedAdapter)
	}
	for _, record := range state.Outbox {
		if record.Aggregate == "tool_execution" && record.ToolCallID == uncertainAdmission.ToolCallID && record.OperationID == uncertainExecution.OperationID {
			uncertainOutbox = record
			break
		}
	}
	if uncertainOutbox.OutboxID == "" || uncertainOutbox.State != runtimestate.OutboxClaimed || uncertainOutbox.ClaimUntil == nil {
		t.Fatalf("accepted external effect did not retain its lost claim: %#v", uncertainOutbox)
	}
	uncertainOperationID := uncertainExecution.OperationID
	if err := source.Advance(11 * time.Second); err != nil {
		t.Fatal(err)
	}
	pool.Close()
	pool, err = pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	store, err = runtimepostgres.NewRuntimeStateStore(pool, source)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err = runtimeapi.NewStateRuntime(runtimeapi.StateRuntimeConfig{Content: content, Compiler: compiler, Planner: planner, Store: store, ModelProfiles: []string{"balanced"}})
	if err != nil {
		t.Fatal(err)
	}
	uncertainAdapter := newUncertainDurableToolAdapter()
	uncertainWorker, err := runtimetool.NewWorker(runtimetool.Config{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: uncertainAdapter, Claimer: "durable-tool-uncertain-recovery-worker", LeaseScheduler: newInertLeaseScheduler()})
	if err != nil {
		t.Fatal(err)
	}
	if err := uncertainWorker.ScanOnce(ctx); err != nil {
		t.Fatal(err)
	}
	state, err = store.LoadRuntimeState(ctx, workerScope)
	if err != nil {
		t.Fatal(err)
	}
	uncertainExecution = runtimestate.ToolExecutionRecord{}
	for _, execution := range state.ToolExecutions {
		if execution.OperationID == uncertainOperationID {
			uncertainExecution = execution
			break
		}
	}
	if uncertainExecution.State != runtimestate.ToolExecutionUncertain || uncertainExecution.Result != nil || uncertainExecution.Failure == nil || uncertainExecution.Failure.Message != "external operation status is unknown" || uncertainAdapter.executes != 0 || uncertainAdapter.reconciles != 1 || uncertainAdapter.reconciledOperationID != uncertainOperationID || len(state.Artifacts) != artifactsBeforeUncertain {
		t.Fatalf("uncertain durable recovery resubmitted or retained a false result: execution=%#v adapter=%#v artifacts=%#v", uncertainExecution, uncertainAdapter, state.Artifacts)
	}
	uncertainPage, err := restarted.InspectToolCalls(ctx, runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}, uncertainSession, uncertainTurn)
	if err != nil || len(uncertainPage.Calls) != 1 || uncertainPage.Calls[0].State != agentruntime.ToolCallUncertain || uncertainPage.Calls[0].Execution == nil || uncertainPage.Calls[0].Execution.Result != nil || uncertainPage.Calls[0].Execution.Failure == nil || uncertainPage.Calls[0].Execution.Failure.Message != "external operation status is unknown" {
		t.Fatalf("public uncertain durable tool result = %#v, %v", uncertainPage, err)
	}
	uncertainEvents, err := restarted.Events(ctx, runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}, uncertainSession, "", 128)
	uncertainPublic, marshalErr := json.Marshal(struct {
		Tools  agentruntime.ToolCallPage `json:"tools"`
		Events agentruntime.EventPage    `json:"events"`
	}{Tools: uncertainPage, Events: uncertainEvents})
	if err != nil || marshalErr != nil || !durableHasPublicFinalization(uncertainEvents.Events, uncertainTurn) || bytes.Contains(uncertainPublic, []byte("audit-probe-secret")) {
		t.Fatalf("public uncertain durable tool terminal state = tools=%#v events=%#v err=%v marshal=%v", uncertainPage, uncertainEvents, err, marshalErr)
	}
	// The public projection distinguishes every approval terminal path without
	// carrying action descriptors or capability values. Each state was written
	// through PostgreSQL before this SDK inspection, including expiry across the
	// reopened runtime and cancellation before any execution intent.
	for _, expected := range []struct {
		session agentruntime.SessionID
		turn    agentruntime.TurnID
		kind    agentruntime.EventKind
	}{
		{session: session, turn: turn, kind: agentruntime.EventApprovalResolved},
		{session: deniedApprovalSession, turn: deniedApprovalTurn, kind: agentruntime.EventApprovalResolved},
		{session: lateSession, turn: lateTurn, kind: agentruntime.EventApprovalExpired},
		{session: cancelledSession, turn: cancelledTurn, kind: agentruntime.EventApprovalCancelled},
	} {
		events, err := restarted.Events(ctx, runtimeapi.Identity{Tenant: string(tenant), Principal: string(principal)}, expected.session, "", 128)
		encoded, marshalErr := json.Marshal(events)
		if err != nil || marshalErr != nil || !durableHasApprovalLifecycleEvent(events.Events, expected.turn, expected.kind) || bytes.Contains(encoded, []byte("audit-probe-secret")) || bytes.Contains(encoded, descriptorBytes) {
			t.Fatalf("public approval lifecycle events = %#v err=%v marshal=%v", events, err, marshalErr)
		}
	}
	state, err = store.LoadRuntimeState(ctx, workerScope)
	if err != nil {
		t.Fatal(err)
	}
	auditPage, err := store.ReadAudit(ctx, runtimestate.AuditQuery{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityAuditReader}, Limit: 4096})
	if err != nil {
		t.Fatal(err)
	}
	outboxPage, err := store.ReadOutbox(ctx, runtimestate.OutboxQuery{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher}, Limit: 4096})
	if err != nil {
		t.Fatal(err)
	}
	durableToolAuditAndOutboxAreOrderedAndRedacted(t, auditPage.Facts, outboxPage.Records, registered.Result().Revision.RevisionID, state.Policies[0].Digest, digest, admission.ToolCallID)
	for _, expected := range []struct {
		kind, toolCallID string
	}{
		{kind: "record_tool_execution_outcome", toolCallID: recovery.ToolCallID},
		{kind: "capability_grant.expired", toolCallID: expiring.ToolCallID},
		{kind: "capability_grant.revoked", toolCallID: revoked.ToolCallID},
		{kind: "approval.cancelled", toolCallID: cancelled.ToolCallID},
		{kind: "approval.denied", toolCallID: deniedApproval.ToolCallID},
		{kind: "approval.expired", toolCallID: late.ToolCallID},
	} {
		_ = durableToolAuditFact(t, auditPage.Facts, outboxPage.Records, expected.kind, expected.toolCallID, registered.Result().Revision.RevisionID, digest)
	}
	durableToolLifecycleRoutesAreOrderedAndCorrelated(t, state.Events, auditPage.Facts, outboxPage.Records, []durableToolLifecycleExpectation{
		{eventKind: agentruntime.EventApprovalResolved, auditKind: "approval.approved", toolCallID: admission.ToolCallID, turnID: turn},
		{eventKind: agentruntime.EventSandboxOperationFinalized, auditKind: "record_tool_execution_outcome", toolCallID: admission.ToolCallID, turnID: turn},
		{eventKind: agentruntime.EventApprovalCancelled, auditKind: "approval.cancelled", toolCallID: cancelled.ToolCallID, turnID: cancelledTurn},
		{eventKind: agentruntime.EventApprovalResolved, auditKind: "approval.denied", toolCallID: deniedApproval.ToolCallID, turnID: deniedApprovalTurn},
		{eventKind: agentruntime.EventApprovalExpired, auditKind: "approval.expired", toolCallID: late.ToolCallID, turnID: lateTurn},
	})
	knownDenial := durableToolAuditFact(t, auditPage.Facts, outboxPage.Records, "tool.admission_denied", "tcall_1234567890ABCDEK", registered.Result().Revision.RevisionID, digest)
	if knownDenial.PolicyRevisionDigest != state.Policies[0].Digest {
		t.Fatalf("known-policy denial audit digest = %q, want %q", knownDenial.PolicyRevisionDigest, state.Policies[0].Digest)
	}
	unknownDenial := durableToolAuditFact(t, auditPage.Facts, outboxPage.Records, "tool.admission_denied", "tcall_1234567890ABCDEL", registered.Result().Revision.RevisionID, digest)
	if unknownDenial.PolicyRevisionDigest == "" || unknownDenial.PolicyRevisionDigest == state.Policies[0].Digest {
		t.Fatalf("unavailable-policy denial audit digest = %q, want distinct bounded commitment", unknownDenial.PolicyRevisionDigest)
	}
	if _, err := store.ReadAudit(ctx, runtimestate.AuditQuery{Scope: ownerScope, Limit: 1}); !errors.Is(err, runtimestate.ErrNotFoundOrDenied) {
		t.Fatalf("owner audit enumeration = %v, want not found or denied", err)
	}
	if _, err := store.ReadOutbox(ctx, runtimestate.OutboxQuery{Scope: ownerScope, Limit: 1}); !errors.Is(err, runtimestate.ErrNotFoundOrDenied) {
		t.Fatalf("owner outbox enumeration = %v, want not found or denied", err)
	}
}

func durableToolAuditAndOutboxAreOrderedAndRedacted(t *testing.T, facts []runtimestate.AuditFactRecord, records []runtimestate.OutboxRecord, revisionID agentruntime.AgentRevisionID, policyDigest, capabilityScopeDigest, toolCallID string) {
	t.Helper()
	want := []string{
		"tool.approval_requested",
		"approval.approved",
		"capability_grant.consumed",
		"tool.execution_intended",
		"record_tool_execution_outcome",
		"capability_grant.exhausted",
	}
	found := map[string]int{}
	foundRoutes := map[string]int{}
	routes := map[runtimestate.AuditFactID]int{}
	for index, record := range records {
		if record.AuditFactID != "" {
			routes[record.AuditFactID] = index
		}
	}
	for index, fact := range facts {
		if fact.ToolCallID != toolCallID || fact.AgentRevisionID != revisionID || fact.PolicyRevisionDigest != policyDigest || fact.CapabilityScopeDigest != capabilityScopeDigest || fact.OperationID == "" {
			continue
		}
		route, exists := routes[fact.AuditFactID]
		if !exists {
			t.Fatalf("audit fact %q (%q) has no linked outbox route", fact.Kind, fact.AuditFactID)
		}
		if records[route].OperationID != fact.OperationID {
			t.Fatalf("audit fact %q (%q) and route operation disagree: fact=%q route=%q", fact.Kind, fact.AuditFactID, fact.OperationID, records[route].OperationID)
		}
		for _, kind := range want {
			if fact.Kind == kind {
				found[kind] = index
				foundRoutes[kind] = route
			}
		}
	}
	previousFact, previousRoute := -1, -1
	for _, kind := range want {
		factIndex, exists := found[kind]
		routeIndex := foundRoutes[kind]
		if !exists || factIndex <= previousFact || routeIndex <= previousRoute {
			t.Fatalf("audit/outbox order %q = fact:%d route:%d exists=%t after=fact:%d route:%d", kind, factIndex, routeIndex, exists, previousFact, previousRoute)
		}
		previousFact, previousRoute = factIndex, routeIndex
	}
	encoded, err := json.Marshal(struct {
		Facts  []runtimestate.AuditFactRecord
		Outbox []runtimestate.OutboxRecord
	}{Facts: facts, Outbox: records})
	if err != nil || bytes.Contains(encoded, []byte("audit-probe-secret")) || bytes.Contains(encoded, []byte("integration-output-secret")) {
		t.Fatalf("durable audit/outbox leaked a secret: %q err=%v", encoded, err)
	}
}

func durableToolAuditFact(t *testing.T, facts []runtimestate.AuditFactRecord, records []runtimestate.OutboxRecord, kind, toolCallID string, revisionID agentruntime.AgentRevisionID, capabilityScopeDigest string) runtimestate.AuditFactRecord {
	t.Helper()
	routes := map[runtimestate.AuditFactID]runtimestate.OutboxRecord{}
	for _, record := range records {
		if record.AuditFactID != "" {
			routes[record.AuditFactID] = record
		}
	}
	for _, fact := range facts {
		if fact.Kind == kind && fact.ToolCallID == toolCallID {
			route, exists := routes[fact.AuditFactID]
			if fact.AgentRevisionID != revisionID || fact.CapabilityScopeDigest != capabilityScopeDigest || fact.PolicyRevisionDigest == "" || fact.OperationID == "" || !exists || route.OperationID != fact.OperationID {
				t.Fatalf("durable %s audit fact lacks a required safe correlation or linked route", kind)
			}
			return fact
		}
	}
	t.Fatalf("durable audit lacks %q for %q", kind, toolCallID)
	return runtimestate.AuditFactRecord{}
}

type durableToolLifecycleExpectation struct {
	eventKind  agentruntime.EventKind
	auditKind  string
	toolCallID string
	turnID     agentruntime.TurnID
}

func durableToolLifecycleRoutesAreOrderedAndCorrelated(t *testing.T, events []runtimestate.ProductEventRecord, facts []runtimestate.AuditFactRecord, records []runtimestate.OutboxRecord, expected []durableToolLifecycleExpectation) {
	t.Helper()
	previousEvent, previousFact, previousRoute := -1, -1, -1
	for _, want := range expected {
		eventIndex, factIndex, routeIndex := -1, -1, -1
		var event runtimestate.ProductEventRecord
		var fact runtimestate.AuditFactRecord
		for index, candidate := range events {
			if candidate.Kind == want.eventKind && candidate.TurnID == want.turnID {
				eventIndex, event = index, candidate
				break
			}
		}
		for index, candidate := range facts {
			if candidate.Kind == want.auditKind && candidate.ToolCallID == want.toolCallID {
				factIndex, fact = index, candidate
				break
			}
		}
		for index, candidate := range records {
			if candidate.EventID == event.EventID && candidate.EventKind == event.Kind && candidate.TurnID == want.turnID {
				routeIndex = index
				if candidate.AuditFactID != fact.AuditFactID || candidate.OperationID != fact.OperationID {
					t.Fatalf("terminal %q event route lacks exact audit correlation: route=%#v fact=%#v", want.auditKind, candidate, fact)
				}
				break
			}
		}
		if eventIndex <= previousEvent || factIndex <= previousFact || routeIndex <= previousRoute {
			t.Fatalf("terminal product-event/audit/outbox order %q = event:%d fact:%d route:%d after event:%d fact:%d route:%d", want.auditKind, eventIndex, factIndex, routeIndex, previousEvent, previousFact, previousRoute)
		}
		previousEvent, previousFact, previousRoute = eventIndex, factIndex, routeIndex
	}
}

func durableHasPublicFinalization(events []agentruntime.Event, turnID agentruntime.TurnID) bool {
	for _, event := range events {
		if event.Kind == agentruntime.EventSandboxOperationFinalized && event.TurnID == turnID {
			return true
		}
	}
	return false
}

func durableHasApprovalLifecycleEvent(events []agentruntime.Event, turnID agentruntime.TurnID, kind agentruntime.EventKind) bool {
	for _, event := range events {
		if event.TurnID == turnID && event.Kind == kind {
			return true
		}
	}
	return false
}

func durableMinIOObjectBodies(t *testing.T, ctx context.Context, client *minio.Client, bucket, prefix string) map[string][]byte {
	t.Helper()
	bodies := map[string][]byte{}
	for object := range client.ListObjects(ctx, bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if object.Err != nil {
			t.Fatal(object.Err)
		}
		reader, err := client.GetObject(ctx, bucket, object.Key, minio.GetObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read MinIO object %q: read=%v close=%v", object.Key, readErr, closeErr)
		}
		bodies[object.Key] = body
	}
	return bodies
}

func durableMinIOObjectsEqual(left, right map[string][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for key, leftBody := range left {
		rightBody, exists := right[key]
		if !exists || !bytes.Equal(leftBody, rightBody) {
			return false
		}
	}
	return true
}

func durableMinIOObjectKeys(objects map[string][]byte) []string {
	keys := make([]string, 0, len(objects))
	for key := range objects {
		keys = append(keys, key)
	}
	return keys
}

func mustToolMutation(t *testing.T, mutation runtimestate.CompiledMutation, err error) runtimestate.CompiledMutation {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return mutation
}

func applyRejection(ctx context.Context, planner *runtimestate.RuntimeStatePlanner, store runtimestate.RuntimeStateStore, mutation runtimestate.CompiledMutation) (runtimestate.TransitionPlan, error) {
	state, err := store.LoadRuntimeState(ctx, mutation.ReceiptBinding().Scope)
	if err != nil {
		return runtimestate.TransitionPlan{}, err
	}
	return planner.Plan(ctx, state, mutation)
}
func requiredToolEnvironment(t *testing.T, name string) string {
	t.Helper()
	if value := os.Getenv(name); value != "" {
		return value
	}
	t.Fatalf("%s is required for durable tool integration", name)
	return ""
}

func durableHasAuditKind(facts []runtimestate.AuditFactRecord, want string) bool {
	for _, fact := range facts {
		if fact.Kind == want {
			return true
		}
	}
	return false
}

func durableGrantRevokedWithoutUse(grants []runtimestate.CapabilityGrantRecord, toolCallID string) bool {
	for _, grant := range grants {
		if grant.ToolCallID == toolCallID {
			return grant.RevokedAt != nil && grant.Uses == 0
		}
	}
	return false
}

func durableHasGrant(grants []runtimestate.CapabilityGrantRecord, toolCallID string) bool {
	for _, grant := range grants {
		if grant.ToolCallID == toolCallID {
			return true
		}
	}
	return false
}

func durableHasToolIntent(intents []runtimestate.ToolIntentRecord, toolCallID string) bool {
	for _, intent := range intents {
		if intent.ToolCallID == toolCallID {
			return true
		}
	}
	return false
}

func durableToolExecutionSucceeded(executions []runtimestate.ToolExecutionRecord, toolCallID string) bool {
	for _, execution := range executions {
		if execution.ToolCallID == toolCallID && execution.State == runtimestate.ToolExecutionSucceeded {
			return true
		}
	}
	return false
}

func durableHasAuditToolCall(facts []runtimestate.AuditFactRecord, toolCallID, kind string) bool {
	for _, fact := range facts {
		if fact.ToolCallID == toolCallID && fact.Kind == kind {
			return true
		}
	}
	return false
}

type durableToolIDs struct{ next uint64 }

func (ids *durableToolIDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	ids.next++
	return fmt.Sprintf("%s_%016d", kind, ids.next), nil
}

func durableToolRenewalIsCurrent(t *testing.T, ctx context.Context, store runtimestate.RuntimeStateStore, tenant runtimecontent.TenantID, toolCallID, claimer string, source *clock.Fake) {
	t.Helper()
	page, err := store.ReadOutbox(ctx, runtimestate.OutboxQuery{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher}, Limit: 4096})
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range page.Records {
		if record.ToolCallID == toolCallID && record.ClaimedBy == claimer && record.ClaimUntil != nil && record.ClaimUntil.After(source.Now()) && record.Version > 2 {
			return
		}
	}
	t.Fatalf("durable live claim was not renewed for %s", toolCallID)
}

type blockingDurableToolAdapter struct {
	mu                   sync.Mutex
	executes, reconciles int
	started              chan struct{}
	release              chan struct{}
	startOnce            sync.Once
}

func newBlockingDurableToolAdapter() *blockingDurableToolAdapter {
	return &blockingDurableToolAdapter{started: make(chan struct{}), release: make(chan struct{})}
}

func (adapter *blockingDurableToolAdapter) ExternalEffectContract() runtimetool.ExternalEffectContract {
	return runtimetool.ExternalEffectContract{IdempotencyKey: "operation_id", Reconciles: true}
}

func (adapter *blockingDurableToolAdapter) Execute(context.Context, runtimetool.Request) (runtimetool.Response, error) {
	adapter.mu.Lock()
	adapter.executes++
	adapter.mu.Unlock()
	adapter.startOnce.Do(func() { close(adapter.started) })
	<-adapter.release
	return runtimetool.Response{Output: []byte("durable slow but healthy result")}, nil
}

func (adapter *blockingDurableToolAdapter) Reconcile(context.Context, runtimetool.Request) (runtimetool.Response, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.reconciles++
	return runtimetool.Response{Output: []byte("unexpected durable reconcile")}, nil
}

func (adapter *blockingDurableToolAdapter) calls() (int, int) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return adapter.executes, adapter.reconciles
}

// durableToolAdapter is the disposable external-effect seam for this
// PostgreSQL/MinIO lifecycle proof. It accepts only the runtime-owned
// operation identity and returns a bounded safe result; it does not model a
// sandbox or create any Firecracker isolation claim.
type durableToolAdapter struct {
	executes, reconciles int
	output               []byte
}

func newDurableToolAdapter() *durableToolAdapter { return &durableToolAdapter{} }

func newOversizedDurableToolAdapter() *durableToolAdapter {
	return &durableToolAdapter{output: bytes.Repeat([]byte("oversized-output-secret"), durableOversizedToolOutputBytes/len("oversized-output-secret")+1)}
}

func (adapter *durableToolAdapter) ExternalEffectContract() runtimetool.ExternalEffectContract {
	return runtimetool.ExternalEffectContract{IdempotencyKey: "operation_id", Reconciles: true}
}

func (adapter *durableToolAdapter) Execute(_ context.Context, request runtimetool.Request) (runtimetool.Response, error) {
	adapter.executes++
	if adapter.output != nil {
		return runtimetool.Response{Output: append([]byte(nil), adapter.output...), MediaType: "text/plain"}, nil
	}
	return runtimetool.Response{Output: []byte(`{"result":"workspace action completed","token=integration-output-secret","operation_id":"` + string(request.OperationID) + `"}`), MediaType: "application/json"}, nil
}

func (adapter *durableToolAdapter) Reconcile(_ context.Context, request runtimetool.Request) (runtimetool.Response, error) {
	adapter.reconciles++
	return runtimetool.Response{Output: []byte(`{"result":"workspace action reconciled","operation_id":"` + string(request.OperationID) + `"}`), MediaType: "application/json"}, nil
}

var errDurableToolProcessLostAfterAcceptance = errors.New("durable tool worker lost after external acceptance")

// acceptedThenLostDurableToolAdapter models a provider that has accepted the
// operation ID before the worker process disappears. Its panic is recovered by
// the integration harness, leaving the claimed durable intent unacknowledged.
type acceptedThenLostDurableToolAdapter struct {
	executes            int
	acceptedOperationID runtimestate.OperationID
}

func newAcceptedThenLostDurableToolAdapter() *acceptedThenLostDurableToolAdapter {
	return &acceptedThenLostDurableToolAdapter{}
}

func (adapter *acceptedThenLostDurableToolAdapter) ExternalEffectContract() runtimetool.ExternalEffectContract {
	return runtimetool.ExternalEffectContract{IdempotencyKey: "operation_id", Reconciles: true}
}

func (adapter *acceptedThenLostDurableToolAdapter) Execute(_ context.Context, request runtimetool.Request) (runtimetool.Response, error) {
	adapter.executes++
	adapter.acceptedOperationID = request.OperationID
	panic(errDurableToolProcessLostAfterAcceptance)
}

func (adapter *acceptedThenLostDurableToolAdapter) Reconcile(_ context.Context, _ runtimetool.Request) (runtimetool.Response, error) {
	return runtimetool.Response{Failure: &agentruntime.Failure{Code: agentruntime.FailureInternal, Message: "lost worker adapter cannot reconcile"}}, nil
}

func runWorkerUntilAcceptedEffectIsLost(t *testing.T, ctx context.Context, worker *runtimetool.Worker) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != errDurableToolProcessLostAfterAcceptance {
			t.Fatalf("worker loss after external acceptance = %#v, want %v", recovered, errDurableToolProcessLostAfterAcceptance)
		}
	}()
	if err := worker.ScanOnce(ctx); err != nil {
		t.Fatal(err)
	}
	t.Fatal("worker completed after external acceptance, want simulated process loss")
}

// uncertainDurableToolAdapter models an external provider that accepted an
// operation before its acknowledgement was lost, then cannot expose its final
// status after the worker restarts. Reconcile is intentionally the only path
// the proof permits after the durable lease has expired.
type uncertainDurableToolAdapter struct {
	executes, reconciles  int
	reconciledOperationID runtimestate.OperationID
}

func newUncertainDurableToolAdapter() *uncertainDurableToolAdapter {
	return &uncertainDurableToolAdapter{}
}

func (adapter *uncertainDurableToolAdapter) ExternalEffectContract() runtimetool.ExternalEffectContract {
	return runtimetool.ExternalEffectContract{IdempotencyKey: "operation_id", Reconciles: true}
}

func (adapter *uncertainDurableToolAdapter) Execute(_ context.Context, _ runtimetool.Request) (runtimetool.Response, error) {
	adapter.executes++
	return runtimetool.Response{Failure: &agentruntime.Failure{Code: agentruntime.FailureInternal, Message: "unexpected external effect resubmission"}}, nil
}

func (adapter *uncertainDurableToolAdapter) Reconcile(_ context.Context, request runtimetool.Request) (runtimetool.Response, error) {
	adapter.reconciles++
	adapter.reconciledOperationID = request.OperationID
	return runtimetool.Response{Uncertain: true, Failure: &agentruntime.Failure{Code: agentruntime.FailureUnavailable, Message: "external operation status is unknown"}}, nil
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
