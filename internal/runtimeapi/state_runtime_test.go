package runtimeapi_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimeapi"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/cockroachdb/errors"
)

func TestNewStateRuntimeRequiresTheCompleteStateAndContentAuthority(t *testing.T) {
	if _, err := runtimeapi.NewStateRuntime(runtimeapi.StateRuntimeConfig{}); err == nil {
		t.Fatal("NewStateRuntime(empty) error = nil")
	}
}

func TestStateRuntimeServesTheCompletePublicLifecycleThroughContentAndMemoryState(t *testing.T) {
	runtime := newMemoryStateRuntime(t)
	ctx := context.Background()
	admin := runtimeapi.Identity{Tenant: "tenant-a", Principal: "admin", Admin: true}
	alice := runtimeapi.Identity{Tenant: "tenant-a", Principal: "alice"}
	bob := runtimeapi.Identity{Tenant: "tenant-a", Principal: "bob"}

	agent, err := runtime.CreateAgent(ctx, admin, agentruntime.CreateAgentRequest{IdempotencyKey: "create-agent", Name: "assistant", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatalf("create Agent: %v", err)
	}
	if replay, err := runtime.CreateAgent(ctx, admin, agentruntime.CreateAgentRequest{IdempotencyKey: "create-agent", Name: "assistant", ModelProfile: "balanced", Instructions: "safe"}); err != nil || !reflect.DeepEqual(replay, agent) {
		t.Fatalf("replay create Agent = %#v, %v; want %#v, nil", replay, err, agent)
	}
	if _, err := runtime.GetAgentRevision(ctx, admin, agent.ID, agent.RevisionID); err != nil {
		t.Fatalf("read Agent revision: %v", err)
	}
	revised, err := runtime.ReviseAgent(ctx, admin, agentruntime.ReviseAgentRequest{AgentID: agent.ID, IdempotencyKey: "revise-agent", ModelProfile: "balanced", Instructions: "safer"})
	if err != nil || revised.Revision != 2 {
		t.Fatalf("revise Agent = %#v, %v; want revision 2", revised, err)
	}
	if replay, err := runtime.ReviseAgent(ctx, admin, agentruntime.ReviseAgentRequest{AgentID: agent.ID, IdempotencyKey: "revise-agent", ModelProfile: "balanced", Instructions: "safer"}); err != nil || !reflect.DeepEqual(replay, revised) {
		t.Fatalf("replay revision = %#v, %v; want %#v, nil", replay, err, revised)
	}

	session, err := runtime.CreateSession(ctx, alice, agentruntime.CreateSessionRequest{IdempotencyKey: "create-session", AgentRevision: revised.RevisionID})
	if err != nil {
		t.Fatalf("create Session: %v", err)
	}
	accepted, err := runtime.SendInput(ctx, alice, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "send-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "hello"}}})
	if err != nil {
		t.Fatalf("send Input: %v", err)
	}
	if replay, err := runtime.SendInput(ctx, alice, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "send-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "hello"}}}); err != nil || !reflect.DeepEqual(replay, accepted) {
		t.Fatalf("replay Input = %#v, %v; want %#v, nil", replay, err, accepted)
	}
	status, err := runtime.IdempotencyStatus(ctx, alice, "send-input")
	if err != nil || status.Command != "admit_input" || status.SessionID != session.ID || status.TurnID != accepted.Turn.ID {
		t.Fatalf("idempotency status = %#v, %v; want retained caller receipt", status, err)
	}
	if _, err := runtime.IdempotencyStatus(ctx, bob, "send-input"); !hasFailure(err, agentruntime.FailureNotFound) {
		t.Fatalf("cross-principal idempotency status error = %v, want safe not-found", err)
	}
	if got, err := runtime.InspectTurn(ctx, alice, session.ID, accepted.Turn.ID); err != nil || got.State != agentruntime.TurnRunning {
		t.Fatalf("inspect running Turn = %#v, %v", got, err)
	}
	page, err := runtime.Events(ctx, alice, session.ID, "", 2)
	if err != nil || len(page.Events) != 2 || page.NextCursor == "" {
		t.Fatalf("first event page = %#v, %v", page, err)
	}
	if page, err = runtime.Events(ctx, alice, session.ID, page.NextCursor, 10); err != nil || len(page.Events) == 0 {
		t.Fatalf("resumed event page = %#v, %v", page, err)
	}
	if got, err := runtime.CancelTurn(ctx, alice, agentruntime.CancelTurnRequest{SessionID: session.ID, TurnID: accepted.Turn.ID, IdempotencyKey: "cancel-turn"}); err != nil || got.State != agentruntime.TurnCancelled {
		t.Fatalf("cancel Turn = %#v, %v", got, err)
	}
	if got, err := runtime.CloseSession(ctx, alice, agentruntime.CloseSessionRequest{SessionID: session.ID, IdempotencyKey: "close-session"}); err != nil || got.State != agentruntime.SessionCompleted {
		t.Fatalf("close Session = %#v, %v", got, err)
	}
	if _, err := runtime.InspectSession(ctx, bob, session.ID); !hasFailure(err, agentruntime.FailureNotFound) {
		t.Fatalf("cross-principal inspection error = %v, want safe not-found", err)
	}
}

func TestStateRuntimeReadsOnlyStateAuthorizedArtifactBytes(t *testing.T) {
	runtime, content, compiler, store, _ := newMemoryStateAuthority(t)
	ctx := context.Background()
	admin := runtimeapi.Identity{Tenant: "tenant-a", Principal: "admin", Admin: true}
	alice := runtimeapi.Identity{Tenant: "tenant-a", Principal: "alice"}
	bob := runtimeapi.Identity{Tenant: "tenant-a", Principal: "bob"}
	agent, err := runtime.CreateAgent(ctx, admin, agentruntime.CreateAgentRequest{IdempotencyKey: "artifact-agent", Name: "assistant", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatalf("create Agent: %v", err)
	}
	session, err := runtime.CreateSession(ctx, alice, agentruntime.CreateSessionRequest{IdempotencyKey: "artifact-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatalf("create Session: %v", err)
	}
	accepted, err := runtime.SendInput(ctx, alice, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "artifact-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "produce artifact"}}})
	if err != nil {
		t.Fatalf("send Input: %v", err)
	}
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("alice")
	handoff, err := content.StageArtifact(ctx, tenant, "text/plain", []byte("approved report"))
	if err != nil {
		t.Fatalf("stage artifact: %v", err)
	}
	mutation, err := compiler.CompileRegisterArtifact(runtimestate.RegisterArtifactCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "artifact-record", SessionID: session.ID, TurnID: accepted.Turn.ID, Artifact: handoff})
	if err != nil {
		t.Fatalf("compile artifact: %v", err)
	}
	plan, err := store.Apply(ctx, mutation)
	if err != nil {
		t.Fatalf("persist artifact: %v", err)
	}
	artifact, err := runtime.ReadArtifact(ctx, alice, plan.Result().Artifact.ArtifactID)
	if err != nil || string(artifact.Body) != "approved report" || artifact.Artifact.SHA256 == "" {
		t.Fatalf("read artifact = %#v, %v", artifact, err)
	}
	artifactInput, err := runtime.SendInput(ctx, alice, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "artifact-reference-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentArtifact, Artifact: &artifact.Artifact}}})
	if err != nil || len(artifactInput.Input.Parts) != 1 || artifactInput.Input.Parts[0].Artifact == nil || *artifactInput.Input.Parts[0].Artifact != artifact.Artifact {
		t.Fatalf("send authorized Artifact Input = %#v, %v", artifactInput, err)
	}
	forged := artifact.Artifact
	forged.SHA256 = strings.Repeat("0", 64)
	if _, err := runtime.SendInput(ctx, alice, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "forged-artifact-reference", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentArtifact, Artifact: &forged}}}); !hasFailure(err, agentruntime.FailureNotFound) {
		t.Fatalf("send forged Artifact Input error = %v, want safe not-found", err)
	}
	bobSession, err := runtime.CreateSession(ctx, bob, agentruntime.CreateSessionRequest{IdempotencyKey: "artifact-bob-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatalf("create cross-principal Artifact Session: %v", err)
	}
	if _, err := runtime.SendInput(ctx, bob, agentruntime.SendInputRequest{SessionID: bobSession.ID, IdempotencyKey: "cross-principal-artifact-reference", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentArtifact, Artifact: &artifact.Artifact}}}); !hasFailure(err, agentruntime.FailureNotFound) {
		t.Fatalf("send cross-principal Artifact Input error = %v, want safe not-found", err)
	}
	if _, err := runtime.ReadArtifact(ctx, bob, plan.Result().Artifact.ArtifactID); !hasFailure(err, agentruntime.FailureNotFound) {
		t.Fatalf("cross-principal artifact read error = %v, want safe not-found", err)
	}
}

func TestStateRuntimeInspectsAndDecidesOwnerApprovalIdempotently(t *testing.T) {
	runtime, content, compiler, store, _ := newMemoryStateAuthority(t)
	ctx := context.Background()
	admin := runtimeapi.Identity{Tenant: "tenant-a", Principal: "admin", Admin: true}
	alice := runtimeapi.Identity{Tenant: "tenant-a", Principal: "alice"}
	bob := runtimeapi.Identity{Tenant: "tenant-a", Principal: "bob"}
	agent, err := runtime.CreateAgent(ctx, admin, agentruntime.CreateAgentRequest{IdempotencyKey: "approval-agent", Name: "assistant", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatalf("create Agent: %v", err)
	}
	session, err := runtime.CreateSession(ctx, alice, agentruntime.CreateSessionRequest{IdempotencyKey: "approval-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatalf("create Session: %v", err)
	}
	accepted, err := runtime.SendInput(ctx, alice, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "approval-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "write file"}}})
	if err != nil {
		t.Fatalf("send Input: %v", err)
	}
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("alice")
	digest := "sha256:" + strings.Repeat("a", 64)
	descriptor, err := content.StageToolActionDescriptor(ctx, tenant, []byte("write action"))
	if err != nil {
		t.Fatal(err)
	}
	intent, err := compiler.CompileRecordToolIntent(runtimestate.RecordToolIntentCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "approval-intent", SessionID: session.ID, TurnID: accepted.Turn.ID, ToolCallID: "tcall_1234567890ABCDEF", ToolName: "write", ActionDigest: digest, PolicyRevisionDigest: digest, Descriptor: descriptor})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, intent); err != nil {
		t.Fatal(err)
	}
	request, err := compiler.CompileRequestApproval(runtimestate.RequestApprovalCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "approval-request", SessionID: session.ID, TurnID: accepted.Turn.ID, ToolCallID: "tcall_1234567890ABCDEF", ApprovalID: "appr_1234567890ABCDEF", ActionDigest: digest, PolicyRevisionDigest: digest, CapabilityDigest: digest, MaximumUses: 1, ExpiresAt: time.Date(2026, 8, 10, 13, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, request); err != nil {
		t.Fatal(err)
	}
	approvalID, _ := agentruntime.ParseApprovalID("appr_1234567890ABCDEF")
	pending, err := runtime.InspectApproval(ctx, alice, approvalID)
	if err != nil || pending.State != agentruntime.ApprovalPending || pending.SessionID != session.ID || pending.TurnID != accepted.Turn.ID {
		t.Fatalf("inspect pending Approval = %#v, %v", pending, err)
	}
	if _, err := runtime.InspectApproval(ctx, bob, approvalID); !hasFailure(err, agentruntime.FailureNotFound) {
		t.Fatalf("cross-principal inspect Approval error = %v, want safe not-found", err)
	}
	decision, err := runtime.DecideApproval(ctx, alice, agentruntime.DecideApprovalRequest{ApprovalID: approvalID, Decision: agentruntime.ApprovalApproved, IdempotencyKey: "approval-decision"})
	if err != nil || decision.State != agentruntime.ApprovalApproved {
		t.Fatalf("approve = %#v, %v", decision, err)
	}
	if replay, err := runtime.DecideApproval(ctx, alice, agentruntime.DecideApprovalRequest{ApprovalID: approvalID, Decision: agentruntime.ApprovalApproved, IdempotencyKey: "approval-decision"}); err != nil || !reflect.DeepEqual(replay, decision) {
		t.Fatalf("replay decision = %#v, %v; want %#v, nil", replay, err, decision)
	}
}

func TestStateRuntimePersistsApprovalExpiryBeforeRefusingLateDecision(t *testing.T) {
	runtime, content, compiler, store, fakeClock := newMemoryStateAuthority(t)
	ctx := context.Background()
	admin := runtimeapi.Identity{Tenant: "tenant-a", Principal: "admin", Admin: true}
	alice := runtimeapi.Identity{Tenant: "tenant-a", Principal: "alice"}
	agent, err := runtime.CreateAgent(ctx, admin, agentruntime.CreateAgentRequest{IdempotencyKey: "expired-approval-agent", Name: "assistant", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatalf("create Agent: %v", err)
	}
	session, err := runtime.CreateSession(ctx, alice, agentruntime.CreateSessionRequest{IdempotencyKey: "expired-approval-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatalf("create Session: %v", err)
	}
	accepted, err := runtime.SendInput(ctx, alice, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "expired-approval-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "write file"}}})
	if err != nil {
		t.Fatalf("send Input: %v", err)
	}
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("alice")
	digest := "sha256:" + strings.Repeat("b", 64)
	descriptor, err := content.StageToolActionDescriptor(ctx, tenant, []byte("write action"))
	if err != nil {
		t.Fatal(err)
	}
	intent, err := compiler.CompileRecordToolIntent(runtimestate.RecordToolIntentCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "expired-approval-intent", SessionID: session.ID, TurnID: accepted.Turn.ID, ToolCallID: "tcall_1234567890ABCDEF", ToolName: "write", ActionDigest: digest, PolicyRevisionDigest: digest, Descriptor: descriptor})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, intent); err != nil {
		t.Fatal(err)
	}
	expiresAt := fakeClock.Now().Add(time.Minute)
	request, err := compiler.CompileRequestApproval(runtimestate.RequestApprovalCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "expired-approval-request", SessionID: session.ID, TurnID: accepted.Turn.ID, ToolCallID: "tcall_1234567890ABCDEF", ApprovalID: "appr_1234567890ABCDEF", ActionDigest: digest, PolicyRevisionDigest: digest, CapabilityDigest: digest, MaximumUses: 1, ExpiresAt: expiresAt})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, request); err != nil {
		t.Fatal(err)
	}
	if err := fakeClock.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	approvalID, _ := agentruntime.ParseApprovalID("appr_1234567890ABCDEF")
	if _, err := runtime.DecideApproval(ctx, alice, agentruntime.DecideApprovalRequest{ApprovalID: approvalID, Decision: agentruntime.ApprovalApproved, IdempotencyKey: "expired-approval-decision"}); !hasFailure(err, agentruntime.FailureConflict) {
		t.Fatalf("late decision error = %v, want safe conflict", err)
	}
	expired, err := runtime.InspectApproval(ctx, alice, approvalID)
	if err != nil || expired.State != agentruntime.ApprovalExpired || expired.DecidedAt != nil {
		t.Fatalf("inspect expired Approval = %#v, %v", expired, err)
	}
	state, err := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant})
	if err != nil {
		t.Fatalf("load expired Approval state: %v", err)
	}
	foundExpiryAudit := false
	for _, fact := range state.Audit {
		foundExpiryAudit = foundExpiryAudit || fact.Kind == "approval.expired"
	}
	if !foundExpiryAudit {
		t.Fatalf("expiry audit facts = %#v, want approval.expired", state.Audit)
	}
}

func TestStateRuntimeAdministratorsManageImmutablePolicyRevisions(t *testing.T) {
	t.Parallel()

	runtime := newMemoryStateRuntime(t)
	ctx := context.Background()
	admin := runtimeapi.Identity{Tenant: "tenant-a", Principal: "admin", Admin: true}
	member := runtimeapi.Identity{Tenant: "tenant-a", Principal: "member"}
	policy, err := runtime.CreatePolicy(ctx, admin, agentruntime.CreatePolicyRequest{
		IdempotencyKey: "create-policy",
		Name:           "workspace-write",
		Rules:          []agentruntime.PolicyRule{{ToolName: "write", Decision: agentruntime.PolicyRequiresApproval}},
	})
	if err != nil || policy.Name != "workspace-write" || policy.Revision != 1 || policy.Digest == "" {
		t.Fatalf("create policy = %#v, %v", policy, err)
	}
	if replay, err := runtime.CreatePolicy(ctx, admin, agentruntime.CreatePolicyRequest{
		IdempotencyKey: "create-policy",
		Name:           "workspace-write",
		Rules:          []agentruntime.PolicyRule{{ToolName: "write", Decision: agentruntime.PolicyRequiresApproval}},
	}); err != nil || !reflect.DeepEqual(replay, policy) {
		t.Fatalf("replay policy = %#v, %v; want %#v", replay, err, policy)
	}
	if _, err := runtime.CreatePolicy(ctx, member, agentruntime.CreatePolicyRequest{IdempotencyKey: "forbidden-policy", Name: "other", Rules: []agentruntime.PolicyRule{{ToolName: "write", Decision: agentruntime.PolicyDenied}}}); !hasFailure(err, agentruntime.FailureInvalidInput) {
		t.Fatalf("non-admin policy creation error = %v, want safe admin refusal", err)
	}
	revised, err := runtime.RevisePolicy(ctx, admin, agentruntime.RevisePolicyRequest{
		IdempotencyKey:   "revise-policy",
		Name:             policy.Name,
		ExpectedRevision: policy.Revision,
		Rules:            []agentruntime.PolicyRule{{ToolName: "write", Decision: agentruntime.PolicyDenied}},
	})
	if err != nil || revised.Revision != 2 || revised.Digest == policy.Digest {
		t.Fatalf("revise policy = %#v, %v", revised, err)
	}
	if previous, err := runtime.GetPolicy(ctx, admin, policy.Name, 1); err != nil || !reflect.DeepEqual(previous, policy) {
		t.Fatalf("read immutable prior policy = %#v, %v; want %#v", previous, err, policy)
	}
}

func TestStateRuntimeHTTPAndSDKKeepPolicyAdministrationSeparateFromSessionCallers(t *testing.T) {
	runtime := newMemoryStateRuntime(t)
	handler, err := runtimeapi.NewHandler(runtimeapi.Config{
		Runtime: runtime,
		Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{
			"admin-token-000000": {Tenant: "tenant-a", Principal: "admin", Admin: true},
			"alice-token-000000": {Tenant: "tenant-a", Principal: "alice"},
		}},
		RequestIDs: &requestIDs{},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	admin := newStateRuntimeHTTPClient(t, server.URL, "admin-token-000000")
	policy, err := admin.CreatePolicy(context.Background(), agentruntime.CreatePolicyRequest{IdempotencyKey: "http-create-policy", Name: "workspace-write", Rules: []agentruntime.PolicyRule{{ToolName: "write", Decision: agentruntime.PolicyRequiresApproval}}})
	if err != nil || policy.Revision != 1 {
		t.Fatalf("SDK create Policy = %#v, %v", policy, err)
	}
	if got, err := admin.GetPolicy(context.Background(), policy.Name, policy.Revision); err != nil || !reflect.DeepEqual(got, policy) {
		t.Fatalf("SDK get Policy = %#v, %v; want %#v", got, err, policy)
	}
	alice := newStateRuntimeHTTPClient(t, server.URL, "alice-token-000000")
	if _, err := alice.GetPolicy(context.Background(), policy.Name, policy.Revision); !hasFailure(err, agentruntime.FailureNotFound) {
		t.Fatalf("non-admin Policy read error = %v, want non-enumerating denial", err)
	}
}

func TestStateRuntimeHTTPAndSDKExposeExpiredApprovalAndItsDurableReceipt(t *testing.T) {
	runtime, content, compiler, store, fakeClock := newMemoryStateAuthority(t)
	ctx := context.Background()
	admin := runtimeapi.Identity{Tenant: "tenant-a", Principal: "admin", Admin: true}
	alice := runtimeapi.Identity{Tenant: "tenant-a", Principal: "alice"}
	agent, err := runtime.CreateAgent(ctx, admin, agentruntime.CreateAgentRequest{IdempotencyKey: "http-expiry-agent", Name: "assistant", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatalf("create Agent: %v", err)
	}
	session, err := runtime.CreateSession(ctx, alice, agentruntime.CreateSessionRequest{IdempotencyKey: "http-expiry-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatalf("create Session: %v", err)
	}
	accepted, err := runtime.SendInput(ctx, alice, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "http-expiry-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "write file"}}})
	if err != nil {
		t.Fatalf("send Input: %v", err)
	}
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("alice")
	digest := "sha256:" + strings.Repeat("c", 64)
	descriptor, err := content.StageToolActionDescriptor(ctx, tenant, []byte("write action"))
	if err != nil {
		t.Fatal(err)
	}
	intent, err := compiler.CompileRecordToolIntent(runtimestate.RecordToolIntentCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "http-expiry-intent", SessionID: session.ID, TurnID: accepted.Turn.ID, ToolCallID: "tcall_1234567890ABCDEF", ToolName: "write", ActionDigest: digest, PolicyRevisionDigest: digest, Descriptor: descriptor})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, intent); err != nil {
		t.Fatal(err)
	}
	request, err := compiler.CompileRequestApproval(runtimestate.RequestApprovalCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "http-expiry-request", SessionID: session.ID, TurnID: accepted.Turn.ID, ToolCallID: "tcall_1234567890ABCDEF", ApprovalID: "appr_1234567890ABCDEF", ActionDigest: digest, PolicyRevisionDigest: digest, CapabilityDigest: digest, MaximumUses: 1, ExpiresAt: fakeClock.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, request); err != nil {
		t.Fatal(err)
	}
	if err := fakeClock.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	handler, err := runtimeapi.NewHandler(runtimeapi.Config{Runtime: runtime, Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{"alice-token-000000": alice}}, RequestIDs: &requestIDs{}})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	credential, err := agentruntime.NewStaticBearerCredential("alice-token-000000")
	if err != nil {
		t.Fatalf("new credential: %v", err)
	}
	client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: server.URL, HTTPClient: http.DefaultClient, Credentials: credential, RequestIDs: &requestIDs{}})
	if err != nil {
		t.Fatalf("new SDK client: %v", err)
	}
	approvalID, _ := agentruntime.ParseApprovalID("appr_1234567890ABCDEF")
	_, err = client.DecideApproval(ctx, agentruntime.DecideApprovalRequest{ApprovalID: approvalID, Decision: agentruntime.ApprovalApproved, IdempotencyKey: "http-expiry-decision"})
	if !hasFailure(err, agentruntime.FailureConflict) {
		t.Fatalf("SDK late approval decision error = %v, want safe conflict", err)
	}
	if _, err := client.DecideApproval(ctx, agentruntime.DecideApprovalRequest{ApprovalID: approvalID, Decision: agentruntime.ApprovalApproved, IdempotencyKey: "http-expiry-decision"}); !hasFailure(err, agentruntime.FailureConflict) {
		t.Fatalf("SDK replayed late approval decision error = %v, want safe conflict", err)
	}
	expired, err := client.InspectApproval(ctx, approvalID)
	if err != nil || expired.State != agentruntime.ApprovalExpired {
		t.Fatalf("SDK inspect expired Approval = %#v, %v", expired, err)
	}
	status, err := client.IdempotencyStatus(ctx, "http-expiry-decision")
	if err != nil || status.Command != string(runtimestate.CommandDecideApproval) {
		t.Fatalf("SDK idempotency status = %#v, %v", status, err)
	}
	state, err := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant})
	if err != nil {
		t.Fatalf("load approval state after HTTP replay: %v", err)
	}
	expiryAudits := 0
	for _, fact := range state.Audit {
		if fact.Kind == "approval.expired" {
			expiryAudits++
		}
	}
	if expiryAudits != 1 {
		t.Fatalf("approval expiry audit count = %d, want 1", expiryAudits)
	}
}

func TestStateRuntimeHTTPAndSDKRejectExpiredMutationReceiptWithoutReplayingWork(t *testing.T) {
	runtime, _, _, _, fakeClock := newMemoryStateAuthorityWithRetention(t, testRetention{duration: time.Minute})
	handler, err := runtimeapi.NewHandler(runtimeapi.Config{Runtime: runtime, Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{
		"admin-token-000000": {Tenant: "tenant-a", Principal: "admin", Admin: true},
		"alice-token-000000": {Tenant: "tenant-a", Principal: "alice"},
	}}, RequestIDs: &requestIDs{}})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	admin := newStateRuntimeHTTPClient(t, server.URL, "admin-token-000000")
	alice := newStateRuntimeHTTPClient(t, server.URL, "alice-token-000000")
	ctx := context.Background()
	agent, err := admin.CreateAgent(ctx, agentruntime.CreateAgentRequest{IdempotencyKey: "receipt-expiry-agent", Name: "assistant", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatalf("create Agent: %v", err)
	}
	session, err := alice.CreateSession(ctx, agentruntime.CreateSessionRequest{IdempotencyKey: "receipt-expiry-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatalf("create Session: %v", err)
	}
	request := agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "receipt-expiry-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "accepted once"}}}
	accepted, err := alice.SendInput(ctx, request)
	if err != nil {
		t.Fatalf("send Input: %v", err)
	}
	if err := fakeClock.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.SendInput(ctx, request); !hasFailure(err, agentruntime.FailureConflict) {
		t.Fatalf("expired replay error = %v, want safe conflict", err)
	}
	if _, err := alice.IdempotencyStatus(ctx, request.IdempotencyKey); !hasFailure(err, agentruntime.FailureConflict) {
		t.Fatalf("expired receipt status error = %v, want safe conflict", err)
	}
	fresh, err := alice.SendInput(ctx, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "receipt-expiry-input-fresh", Parts: request.Parts})
	if err != nil || fresh.Turn.ID == accepted.Turn.ID {
		t.Fatalf("fresh post-expiry Input = %#v, %v; want a distinct accepted Turn", fresh, err)
	}
}

func newMemoryStateRuntime(t *testing.T) *runtimeapi.StateRuntime {
	runtime, _, _, _, _ := newMemoryStateAuthority(t)
	return runtime
}

func newMemoryStateAuthority(t *testing.T) (*runtimeapi.StateRuntime, *runtimecontent.Store, *runtimestate.Compiler, *runtimestate.MemoryRuntimeStateStore, *clock.Fake) {
	return newMemoryStateAuthorityWithRetention(t, nil)
}

func newMemoryStateAuthorityWithRetention(t *testing.T, retention runtimestate.RetentionPolicy) (*runtimeapi.StateRuntime, *runtimecontent.Store, *runtimestate.Compiler, *runtimestate.MemoryRuntimeStateStore, *clock.Fake) {
	t.Helper()
	objects := &stateRuntimeObjects{values: map[string][]byte{}}
	content, err := runtimecontent.New("runtime-content", objects)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	fakeClock, err := clock.NewFake(time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	options := []runtimestate.PlannerOption{}
	if retention != nil {
		options = append(options, runtimestate.WithRetentionPolicy(retention))
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(fakeClock, &stateRuntimeIDs{}, options...)
	if err != nil {
		t.Fatal(err)
	}
	store, err := runtimestate.NewMemoryRuntimeStateStore(planner)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := runtimeapi.NewStateRuntime(runtimeapi.StateRuntimeConfig{Content: content, Compiler: compiler, Planner: planner, Store: store, ModelProfiles: []string{"balanced"}})
	if err != nil {
		t.Fatal(err)
	}
	return runtime, content, compiler, store, fakeClock
}

func newStateRuntimeHTTPClient(t *testing.T, baseURL, token string) *agentruntime.Client {
	t.Helper()
	credential, err := agentruntime.NewStaticBearerCredential(token)
	if err != nil {
		t.Fatalf("new credential: %v", err)
	}
	client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: baseURL, HTTPClient: http.DefaultClient, Credentials: credential, RequestIDs: &requestIDs{}})
	if err != nil {
		t.Fatalf("new SDK client: %v", err)
	}
	return client
}

type testRetention struct{ duration time.Duration }

func (retention testRetention) RetainUntil(now time.Time) time.Time {
	return now.Add(retention.duration)
}

type stateRuntimeObjects struct{ values map[string][]byte }

func (objects *stateRuntimeObjects) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	if _, exists := objects.values[key]; exists {
		return false, nil
	}
	objects.values[key] = append([]byte(nil), value...)
	return true, nil
}

func (objects *stateRuntimeObjects) Get(_ context.Context, key string, _ int) ([]byte, error) {
	return append([]byte(nil), objects.values[key]...), nil
}

type stateRuntimeIDs struct{ next uint64 }

func (ids *stateRuntimeIDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	ids.next++
	return string(kind) + "_" + fmt.Sprintf("%016d", ids.next), nil
}

func hasFailure(err error, code agentruntime.FailureCode) bool {
	var runtimeError *agentruntime.Error
	return errors.As(err, &runtimeError) && runtimeError.Failure.Code == code
}
