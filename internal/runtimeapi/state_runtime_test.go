package runtimeapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

func TestStateRuntimeHTTPAndSDKProjectCancelledSession(t *testing.T) {
	runtime := newMemoryStateRuntime(t)
	handler, err := runtimeapi.NewHandler(runtimeapi.Config{Runtime: runtime, Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{
		"admin-token-000000": {Tenant: "tenant-a", Principal: "admin", Admin: true},
		"alice-token-000000": {Tenant: "tenant-a", Principal: "alice"},
	}}, RequestIDs: &requestIDs{}})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	ctx := context.Background()
	admin := newStateRuntimeHTTPClient(t, server.URL, "admin-token-000000")
	alice := newStateRuntimeHTTPClient(t, server.URL, "alice-token-000000")
	agent, err := admin.CreateAgent(ctx, agentruntime.CreateAgentRequest{IdempotencyKey: "cancel-session-agent", Name: "assistant", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatalf("create Agent: %v", err)
	}
	session, err := alice.CreateSession(ctx, agentruntime.CreateSessionRequest{IdempotencyKey: "cancel-session-create", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatalf("create Session: %v", err)
	}
	cancelled, err := alice.CancelSession(ctx, agentruntime.CancelSessionRequest{SessionID: session.ID, IdempotencyKey: "cancel-session"})
	if err != nil || cancelled.State != agentruntime.SessionCancelled {
		t.Fatalf("cancel Session = %#v, %v", cancelled, err)
	}
	if replay, err := alice.CancelSession(ctx, agentruntime.CancelSessionRequest{SessionID: session.ID, IdempotencyKey: "cancel-session"}); err != nil || replay != cancelled {
		t.Fatalf("cancel Session replay = %#v, %v; want %#v", replay, err, cancelled)
	}
	view, err := alice.InspectSession(ctx, session.ID)
	if err != nil || view.Session.State != agentruntime.SessionCancelled {
		t.Fatalf("inspect cancelled Session = %#v, %v", view, err)
	}
	page, err := alice.Events(ctx, session.ID, "", 10)
	if err != nil || len(page.Events) != 2 || page.Events[1].Kind != agentruntime.EventSessionCancelled {
		t.Fatalf("cancelled Session events = %#v, %v", page, err)
	}
	if _, err := alice.SendInput(ctx, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "cancelled-session-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "must reject"}}}); !hasFailure(err, agentruntime.FailureConflict) {
		t.Fatalf("input to cancelled Session error = %v, want conflict", err)
	}
}

func TestStateRuntimeHTTPAndSDKRejectUnconfiguredProfilesAndProviderCredentialFields(t *testing.T) {
	runtime := newMemoryStateRuntime(t)
	handler, err := runtimeapi.NewHandler(runtimeapi.Config{Runtime: runtime, Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{
		"admin-token-000000": {Tenant: "tenant-a", Principal: "admin", Admin: true},
	}}, RequestIDs: &requestIDs{}})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	admin := newStateRuntimeHTTPClient(t, server.URL, "admin-token-000000")
	if _, err := admin.CreateAgent(context.Background(), agentruntime.CreateAgentRequest{IdempotencyKey: "unconfigured-profile", Name: "assistant", ModelProfile: "provider-direct", Instructions: "safe"}); !hasFailure(err, agentruntime.FailureInvalidInput) {
		t.Fatalf("SDK create Agent with unconfigured profile error = %v, want invalid input", err)
	}

	request, err := http.NewRequest(http.MethodPost, server.URL+"/v1/admin/agents", strings.NewReader(`{"name":"assistant","model_profile":"balanced","instructions":"safe","provider_credential":"must-not-cross-the-public-contract"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer admin-token-000000")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "provider-credential-field")
	request.Header.Set("X-Request-ID", "req_0000000000000001")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read provider-credential rejection = %v, %v", readErr, closeErr)
	}
	if response.StatusCode != http.StatusBadRequest || strings.Contains(string(body), "must-not-cross-the-public-contract") {
		t.Fatalf("provider credential field status/body = %d %q, want bounded non-leaking bad request", response.StatusCode, body)
	}
}

func TestStateRuntimeHTTPAndSDKEnforceRequestAndEventLimits(t *testing.T) {
	runtime := newMemoryStateRuntime(t)
	handler, err := runtimeapi.NewHandler(runtimeapi.Config{Runtime: runtime, MaxRequestBytes: 3 << 20, Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{
		"admin-token-000000": {Tenant: "tenant-a", Principal: "admin", Admin: true},
		"alice-token-000000": {Tenant: "tenant-a", Principal: "alice"},
	}}, RequestIDs: &requestIDs{}})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	overlong := `{"name":"assistant","model_profile":"balanced","instructions":"` + strings.Repeat("x", 3<<20) + `"}`
	request, err := http.NewRequest(http.MethodPost, server.URL+"/v1/admin/agents", strings.NewReader(overlong))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer admin-token-000000")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "overlong-request")
	request.Header.Set("X-Request-ID", "req_0000000000000001")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("overlong request status = %d, want %d", response.StatusCode, http.StatusBadRequest)
	}

	ctx := context.Background()
	admin := newStateRuntimeHTTPClient(t, server.URL, "admin-token-000000")
	alice := newStateRuntimeHTTPClient(t, server.URL, "alice-token-000000")
	agent, err := admin.CreateAgent(ctx, agentruntime.CreateAgentRequest{IdempotencyKey: "limit-agent", Name: "assistant", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatalf("create Agent: %v", err)
	}
	session, err := alice.CreateSession(ctx, agentruntime.CreateSessionRequest{IdempotencyKey: "limit-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatalf("create Session: %v", err)
	}
	for _, limit := range []int{0, 1001} {
		if _, err := alice.Events(ctx, session.ID, "", limit); !hasFailure(err, agentruntime.FailureInvalidInput) {
			t.Fatalf("SDK Events limit %d error = %v, want invalid input", limit, err)
		}
	}
}

func TestStateRuntimeHTTPInspectionExcludesBackendExecutionIdentifiers(t *testing.T) {
	runtime := newMemoryStateRuntime(t)
	handler, err := runtimeapi.NewHandler(runtimeapi.Config{Runtime: runtime, Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{
		"admin-token-000000": {Tenant: "tenant-a", Principal: "admin", Admin: true},
		"alice-token-000000": {Tenant: "tenant-a", Principal: "alice"},
	}}, RequestIDs: &requestIDs{}})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	ctx := context.Background()
	admin := newStateRuntimeHTTPClient(t, server.URL, "admin-token-000000")
	alice := newStateRuntimeHTTPClient(t, server.URL, "alice-token-000000")
	agent, err := admin.CreateAgent(ctx, agentruntime.CreateAgentRequest{IdempotencyKey: "inspection-agent", Name: "assistant", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatalf("create Agent: %v", err)
	}
	session, err := alice.CreateSession(ctx, agentruntime.CreateSessionRequest{IdempotencyKey: "inspection-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatalf("create Session: %v", err)
	}
	if _, err := alice.SendInput(ctx, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "inspection-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "inspect only runtime-owned IDs"}}}); err != nil {
		t.Fatalf("send Input: %v", err)
	}

	request, err := http.NewRequest(http.MethodGet, server.URL+"/v1/sessions/"+session.ID.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer alice-token-000000")
	request.Header.Set("X-Request-ID", "req_0000000000000001")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read Session inspection = %v, %v", readErr, closeErr)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("inspect Session status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	var inspection any
	if err := json.Unmarshal(body, &inspection); err != nil {
		t.Fatalf("decode Session inspection: %v", err)
	}
	assertNoBackendExecutionIdentifier(t, inspection)
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
	if err != nil || pending.State != agentruntime.ApprovalPending || pending.SessionID != session.ID || pending.TurnID != accepted.Turn.ID || pending.Requester != "alice" || pending.PolicyRevision != digest {
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

func TestStateRuntimeHTTPAndSDKAuthorizationMatrixKeepsAdminAndOwnerScopesNonEnumerating(t *testing.T) {
	runtime, content, compiler, store, _ := newMemoryStateAuthority(t)
	ctx := context.Background()
	adminIdentity := runtimeapi.Identity{Tenant: "tenant-a", Principal: "admin", Admin: true}
	aliceIdentity := runtimeapi.Identity{Tenant: "tenant-a", Principal: "alice"}
	bobIdentity := runtimeapi.Identity{Tenant: "tenant-a", Principal: "bob"}
	foreignAdminIdentity := runtimeapi.Identity{Tenant: "tenant-b", Principal: "admin", Admin: true}

	agent, err := runtime.CreateAgent(ctx, adminIdentity, agentruntime.CreateAgentRequest{IdempotencyKey: "matrix-create-agent", Name: "matrix-agent", ModelProfile: "balanced", Instructions: "keep matrix-private instructions private"})
	if err != nil {
		t.Fatalf("create matrix Agent: %v", err)
	}
	if _, err := runtime.ReviseAgent(ctx, adminIdentity, agentruntime.ReviseAgentRequest{AgentID: agent.ID, IdempotencyKey: "matrix-revise-agent", ModelProfile: "balanced", Instructions: "revised private matrix instructions"}); err != nil {
		t.Fatalf("revise matrix Agent: %v", err)
	}
	policy, err := runtime.CreatePolicy(ctx, adminIdentity, agentruntime.CreatePolicyRequest{IdempotencyKey: "matrix-create-policy", Name: "matrix-policy", Rules: []agentruntime.PolicyRule{{ToolName: "write", Decision: agentruntime.PolicyRequiresApproval}}})
	if err != nil {
		t.Fatalf("create matrix Policy: %v", err)
	}
	if _, err := runtime.RevisePolicy(ctx, adminIdentity, agentruntime.RevisePolicyRequest{IdempotencyKey: "matrix-revise-policy", Name: policy.Name, ExpectedRevision: policy.Revision, Rules: []agentruntime.PolicyRule{{ToolName: "write", Decision: agentruntime.PolicyDenied}}}); err != nil {
		t.Fatalf("revise matrix Policy: %v", err)
	}

	session, err := runtime.CreateSession(ctx, aliceIdentity, agentruntime.CreateSessionRequest{IdempotencyKey: "matrix-create-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatalf("create matrix Session: %v", err)
	}
	accepted, err := runtime.SendInput(ctx, aliceIdentity, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "matrix-send-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "matrix-private input"}}})
	if err != nil {
		t.Fatalf("send matrix Input: %v", err)
	}
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("alice")
	workerScope := runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}
	handoff, err := content.StageArtifact(ctx, tenant, "text/plain", []byte("matrix-private artifact body"))
	if err != nil {
		t.Fatalf("stage matrix Artifact: %v", err)
	}
	artifactMutation, err := compiler.CompileRegisterArtifact(runtimestate.RegisterArtifactCommand{Scope: workerScope, IdempotencyKey: "matrix-register-artifact", SessionID: session.ID, TurnID: accepted.Turn.ID, Artifact: handoff})
	if err != nil {
		t.Fatalf("compile matrix Artifact: %v", err)
	}
	artifactPlan, err := store.Apply(ctx, artifactMutation)
	if err != nil {
		t.Fatalf("persist matrix Artifact: %v", err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	descriptor, err := content.StageToolActionDescriptor(ctx, tenant, []byte("matrix-private tool descriptor"))
	if err != nil {
		t.Fatalf("stage matrix Tool descriptor: %v", err)
	}
	intent, err := compiler.CompileRecordToolIntent(runtimestate.RecordToolIntentCommand{Scope: workerScope, IdempotencyKey: "matrix-tool-intent", SessionID: session.ID, TurnID: accepted.Turn.ID, ToolCallID: "tcall_1234567890ABCDEF", ToolName: "write", ActionDigest: digest, PolicyRevisionDigest: digest, Descriptor: descriptor})
	if err != nil {
		t.Fatalf("compile matrix Tool intent: %v", err)
	}
	if _, err := store.Apply(ctx, intent); err != nil {
		t.Fatalf("persist matrix Tool intent: %v", err)
	}
	approvalMutation, err := compiler.CompileRequestApproval(runtimestate.RequestApprovalCommand{Scope: workerScope, IdempotencyKey: "matrix-approval-request", SessionID: session.ID, TurnID: accepted.Turn.ID, ToolCallID: "tcall_1234567890ABCDEF", ApprovalID: "appr_1234567890ABCDEF", ActionDigest: digest, PolicyRevisionDigest: digest, CapabilityDigest: digest, MaximumUses: 1, ExpiresAt: time.Date(2026, 8, 10, 13, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("compile matrix Approval: %v", err)
	}
	if _, err := store.Apply(ctx, approvalMutation); err != nil {
		t.Fatalf("persist matrix Approval: %v", err)
	}
	approvalID, err := agentruntime.ParseApprovalID("appr_1234567890ABCDEF")
	if err != nil {
		t.Fatal(err)
	}

	handler, err := runtimeapi.NewHandler(runtimeapi.Config{Runtime: runtime, Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{
		"admin-token-000000":   adminIdentity,
		"alice-token-000000":   aliceIdentity,
		"bob-token-00000000":   bobIdentity,
		"foreign-token-000000": foreignAdminIdentity,
	}}, RequestIDs: &requestIDs{}})
	if err != nil {
		t.Fatalf("new authorization-matrix handler: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	admin := newStateRuntimeHTTPClient(t, server.URL, "admin-token-000000")
	alice := newStateRuntimeHTTPClient(t, server.URL, "alice-token-000000")
	bob := newStateRuntimeHTTPClient(t, server.URL, "bob-token-00000000")
	foreignAdmin := newStateRuntimeHTTPClient(t, server.URL, "foreign-token-000000")

	httpAgent, err := admin.CreateAgent(ctx, agentruntime.CreateAgentRequest{IdempotencyKey: "matrix-http-create-agent", Name: "matrix-http-agent", ModelProfile: "balanced", Instructions: "administrator-owned HTTP catalog entry"})
	if err != nil {
		t.Fatalf("admin creates matrix HTTP Agent: %v", err)
	}
	if _, err := admin.ReviseAgent(ctx, agentruntime.ReviseAgentRequest{AgentID: httpAgent.ID, IdempotencyKey: "matrix-http-revise-agent", ModelProfile: "balanced", Instructions: "revised administrator-owned HTTP catalog entry"}); err != nil {
		t.Fatalf("admin revises matrix HTTP Agent: %v", err)
	}
	httpPolicy, err := admin.CreatePolicy(ctx, agentruntime.CreatePolicyRequest{IdempotencyKey: "matrix-http-create-policy", Name: "matrix-http-policy", Rules: []agentruntime.PolicyRule{{ToolName: "write", Decision: agentruntime.PolicyRequiresApproval}}})
	if err != nil {
		t.Fatalf("admin creates matrix HTTP Policy: %v", err)
	}
	if _, err := admin.RevisePolicy(ctx, agentruntime.RevisePolicyRequest{IdempotencyKey: "matrix-http-revise-policy", Name: httpPolicy.Name, ExpectedRevision: httpPolicy.Revision, Rules: []agentruntime.PolicyRule{{ToolName: "write", Decision: agentruntime.PolicyDenied}}}); err != nil {
		t.Fatalf("admin revises matrix HTTP Policy: %v", err)
	}
	if _, err := admin.GetAgentRevision(ctx, agent.ID, agent.RevisionID); err != nil {
		t.Fatalf("admin reads matrix Agent: %v", err)
	}
	if _, err := admin.GetPolicy(ctx, policy.Name, policy.Revision); err != nil {
		t.Fatalf("admin reads matrix Policy: %v", err)
	}
	if download, err := runtime.ReadArtifact(ctx, aliceIdentity, artifactPlan.Result().Artifact.ArtifactID); err != nil || string(download.Body) != "matrix-private artifact body" {
		t.Fatalf("owner reads matrix Artifact through state authority = %#v, %v", download, err)
	}
	if _, err := alice.InspectApproval(ctx, approvalID); err != nil {
		t.Fatalf("owner inspects matrix Approval: %v", err)
	}
	if _, err := alice.IdempotencyStatus(ctx, "matrix-send-input"); err != nil {
		t.Fatalf("owner reads matrix receipt: %v", err)
	}
	if _, err := alice.InspectToolCalls(ctx, session.ID, accepted.Turn.ID); err != nil {
		t.Fatalf("owner inspects matrix Tool lifecycle: %v", err)
	}

	type deniedRoute struct {
		name string
		call func(*agentruntime.Client) error
	}
	deniedForAnyTenant := []deniedRoute{
		{name: "revise Agent", call: func(client *agentruntime.Client) error {
			_, err := client.ReviseAgent(ctx, agentruntime.ReviseAgentRequest{AgentID: agent.ID, IdempotencyKey: "matrix-denied-revise-agent", ModelProfile: "balanced", Instructions: "attempted mutation"})
			return err
		}},
		{name: "get Agent revision", call: func(client *agentruntime.Client) error {
			_, err := client.GetAgentRevision(ctx, agent.ID, agent.RevisionID)
			return err
		}},
		{name: "revise Policy", call: func(client *agentruntime.Client) error {
			_, err := client.RevisePolicy(ctx, agentruntime.RevisePolicyRequest{IdempotencyKey: "matrix-denied-revise-policy", Name: policy.Name, ExpectedRevision: policy.Revision, Rules: []agentruntime.PolicyRule{{ToolName: "write", Decision: agentruntime.PolicyDenied}}})
			return err
		}},
		{name: "get Policy", call: func(client *agentruntime.Client) error {
			_, err := client.GetPolicy(ctx, policy.Name, policy.Revision)
			return err
		}},
		{name: "read Artifact", call: func(client *agentruntime.Client) error {
			_, err := client.ReadArtifact(ctx, artifactPlan.Result().Artifact.ArtifactID)
			return err
		}},
		{name: "inspect Approval", call: func(client *agentruntime.Client) error { _, err := client.InspectApproval(ctx, approvalID); return err }},
		{name: "decide Approval", call: func(client *agentruntime.Client) error {
			_, err := client.DecideApproval(ctx, agentruntime.DecideApprovalRequest{ApprovalID: approvalID, Decision: agentruntime.ApprovalDenied, IdempotencyKey: "matrix-denied-decision"})
			return err
		}},
		{name: "read receipt", call: func(client *agentruntime.Client) error {
			_, err := client.IdempotencyStatus(ctx, "matrix-send-input")
			return err
		}},
		{name: "send Input", call: func(client *agentruntime.Client) error {
			_, err := client.SendInput(ctx, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "matrix-denied-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "attempted cross-owner input"}}})
			return err
		}},
		{name: "inspect Session", call: func(client *agentruntime.Client) error { _, err := client.InspectSession(ctx, session.ID); return err }},
		{name: "inspect Turn", call: func(client *agentruntime.Client) error {
			_, err := client.InspectTurn(ctx, session.ID, accepted.Turn.ID)
			return err
		}},
		{name: "inspect Tool lifecycle", call: func(client *agentruntime.Client) error {
			_, err := client.InspectToolCalls(ctx, session.ID, accepted.Turn.ID)
			return err
		}},
		{name: "read Events", call: func(client *agentruntime.Client) error { _, err := client.Events(ctx, session.ID, "", 1); return err }},
		{name: "cancel Turn", call: func(client *agentruntime.Client) error {
			_, err := client.CancelTurn(ctx, agentruntime.CancelTurnRequest{SessionID: session.ID, TurnID: accepted.Turn.ID, IdempotencyKey: "matrix-denied-cancel"})
			return err
		}},
		{name: "close Session", call: func(client *agentruntime.Client) error {
			_, err := client.CloseSession(ctx, agentruntime.CloseSessionRequest{SessionID: session.ID, IdempotencyKey: "matrix-denied-close"})
			return err
		}},
	}
	for _, actor := range []struct {
		name   string
		client *agentruntime.Client
	}{{name: "same-tenant non-admin", client: bob}, {name: "cross-tenant admin", client: foreignAdmin}} {
		for _, route := range deniedForAnyTenant {
			expected := agentruntime.FailureNotFound
			if actor.name == "cross-tenant admin" && route.name == "revise Policy" {
				// Policy revision uses an expected-version precondition. A tenant
				// that cannot see the named policy receives the same safe conflict
				// as a stale revision, never policy metadata.
				expected = agentruntime.FailureConflict
			}
			assertNonEnumeratingMatrixDenial(t, actor.name+" "+route.name, expected, route.call(actor.client))
		}
	}
	for _, route := range []deniedRoute{
		{name: "create Agent", call: func(client *agentruntime.Client) error {
			_, err := client.CreateAgent(ctx, agentruntime.CreateAgentRequest{IdempotencyKey: "matrix-denied-create-agent", Name: "forbidden-agent", ModelProfile: "balanced", Instructions: "attempted catalog mutation"})
			return err
		}},
		{name: "create Policy", call: func(client *agentruntime.Client) error {
			_, err := client.CreatePolicy(ctx, agentruntime.CreatePolicyRequest{IdempotencyKey: "matrix-denied-create-policy", Name: "forbidden-policy", Rules: []agentruntime.PolicyRule{{ToolName: "write", Decision: agentruntime.PolicyDenied}}})
			return err
		}},
	} {
		assertNonEnumeratingMatrixDenial(t, "same-tenant non-admin "+route.name, agentruntime.FailureNotFound, route.call(bob))
	}
}

func assertNonEnumeratingMatrixDenial(t *testing.T, operation string, expected agentruntime.FailureCode, err error) {
	t.Helper()
	if !hasFailure(err, expected) {
		t.Fatalf("%s error = %v, want safe non-enumerating %s", operation, err, expected)
	}
	for _, forbidden := range []string{"matrix-private", "alice-token-000000", "bob-token-00000000", "foreign-token-000000"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("%s error leaked %q: %v", operation, forbidden, err)
		}
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

func TestStateRuntimeHTTPAndSDKAuthorizationMatrixUsesFakeApprovalClock(t *testing.T) {
	runtime, content, compiler, store, fakeClock := newMemoryStateAuthority(t)
	ctx := context.Background()
	admin := runtimeapi.Identity{Tenant: "tenant-a", Principal: "admin", Admin: true}
	alice := runtimeapi.Identity{Tenant: "tenant-a", Principal: "alice"}
	bob := runtimeapi.Identity{Tenant: "tenant-a", Principal: "bob"}
	agent, err := runtime.CreateAgent(ctx, admin, agentruntime.CreateAgentRequest{IdempotencyKey: "matrix-agent", Name: "assistant", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("alice")
	workerScope := runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}
	digest := "sha256:" + strings.Repeat("d", 64)
	type seeded struct {
		approval agentruntime.ApprovalID
		session  agentruntime.SessionID
		turn     agentruntime.TurnID
	}
	seed := func(label, suffix string, expiresAt time.Time) seeded {
		session, e := runtime.CreateSession(ctx, alice, agentruntime.CreateSessionRequest{IdempotencyKey: "matrix-session-" + label, AgentRevision: agent.RevisionID})
		if e != nil {
			t.Fatal(e)
		}
		accepted, e := runtime.SendInput(ctx, alice, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "matrix-input-" + label, Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: label}}})
		if e != nil {
			t.Fatal(e)
		}
		descriptor, e := content.StageToolActionDescriptor(ctx, tenant, []byte("write "+label))
		if e != nil {
			t.Fatal(e)
		}
		toolCallID, approvalID := "tcall_"+suffix, "appr_"+suffix
		intent, e := compiler.CompileRecordToolIntent(runtimestate.RecordToolIntentCommand{Scope: workerScope, IdempotencyKey: "matrix-intent-" + label, SessionID: session.ID, TurnID: accepted.Turn.ID, ToolCallID: toolCallID, ToolName: "write", ActionDigest: digest, PolicyRevisionDigest: digest, Descriptor: descriptor})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = store.Apply(ctx, intent); e != nil {
			t.Fatal(e)
		}
		request, e := compiler.CompileRequestApproval(runtimestate.RequestApprovalCommand{Scope: workerScope, IdempotencyKey: "matrix-approval-" + label, SessionID: session.ID, TurnID: accepted.Turn.ID, ToolCallID: toolCallID, ApprovalID: approvalID, ActionDigest: digest, PolicyRevisionDigest: digest, CapabilityDigest: digest, MaximumUses: 1, ExpiresAt: expiresAt})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = store.Apply(ctx, request); e != nil {
			t.Fatal(e)
		}
		id, _ := agentruntime.ParseApprovalID(approvalID)
		return seeded{approval: id, session: session.ID, turn: accepted.Turn.ID}
	}
	handler, err := runtimeapi.NewHandler(runtimeapi.Config{Runtime: runtime, Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{"alice-token-000000": alice, "bob-token-00000000": bob}}, RequestIDs: &requestIDs{}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	aliceClient, bobClient := newStateRuntimeHTTPClient(t, server.URL, "alice-token-000000"), newStateRuntimeHTTPClient(t, server.URL, "bob-token-00000000")
	approved := seed("approved", "1234567890ABCDEA", fakeClock.Now().Add(time.Minute))
	if _, err := bobClient.InspectApproval(ctx, approved.approval); !hasFailure(err, agentruntime.FailureNotFound) {
		t.Fatalf("cross-principal inspection = %v, want safe not-found", err)
	}
	if _, err := bobClient.DecideApproval(ctx, agentruntime.DecideApprovalRequest{ApprovalID: approved.approval, Decision: agentruntime.ApprovalApproved, IdempotencyKey: "matrix-bob"}); !hasFailure(err, agentruntime.FailureNotFound) {
		t.Fatalf("cross-principal decision = %v, want safe not-found", err)
	}
	raw, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/approvals/"+approved.approval.String()+"/decide", strings.NewReader(`{"decision":"approved","scope":{"maximum_uses":2}}`))
	if err != nil {
		t.Fatal(err)
	}
	raw.Header.Set("Authorization", "Bearer alice-token-000000")
	raw.Header.Set("Idempotency-Key", "matrix-scope")
	raw.Header.Set("X-Request-ID", "req_0000000000000001")
	response, err := http.DefaultClient.Do(raw)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("scope-bearing public decision status = %d, want %d", response.StatusCode, http.StatusBadRequest)
	}
	decision, err := aliceClient.DecideApproval(ctx, agentruntime.DecideApprovalRequest{ApprovalID: approved.approval, Decision: agentruntime.ApprovalApproved, IdempotencyKey: "matrix-approve"})
	if err != nil || decision.State != agentruntime.ApprovalApproved {
		t.Fatalf("owner approve = %#v, %v", decision, err)
	}
	if replay, e := aliceClient.DecideApproval(ctx, agentruntime.DecideApprovalRequest{ApprovalID: approved.approval, Decision: agentruntime.ApprovalApproved, IdempotencyKey: "matrix-approve"}); e != nil || !reflect.DeepEqual(replay, decision) {
		t.Fatalf("approve replay = %#v, %v", replay, e)
	}
	denied := seed("denied", "1234567890ABCDEB", fakeClock.Now().Add(time.Minute))
	if result, e := aliceClient.DecideApproval(ctx, agentruntime.DecideApprovalRequest{ApprovalID: denied.approval, Decision: agentruntime.ApprovalDenied, IdempotencyKey: "matrix-deny"}); e != nil || result.State != agentruntime.ApprovalDenied {
		t.Fatalf("owner deny = %#v, %v", result, e)
	}
	expired := seed("expired", "1234567890ABCDEC", fakeClock.Now().Add(time.Minute))
	if err := fakeClock.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := aliceClient.DecideApproval(ctx, agentruntime.DecideApprovalRequest{ApprovalID: expired.approval, Decision: agentruntime.ApprovalApproved, IdempotencyKey: "matrix-expired"}); !hasFailure(err, agentruntime.FailureConflict) {
		t.Fatalf("late decision = %v, want conflict", err)
	}
	if result, e := aliceClient.InspectApproval(ctx, expired.approval); e != nil || result.State != agentruntime.ApprovalExpired || result.DecidedAt != nil {
		t.Fatalf("expired public approval = %#v, %v", result, e)
	}
	for _, value := range []seeded{approved, denied, expired} {
		if page, e := aliceClient.InspectToolCalls(ctx, value.session, value.turn); e != nil || len(page.Calls) != 1 || page.Calls[0].Execution != nil {
			t.Fatalf("public decision dispatched Tool = %#v, %v", page, e)
		}
	}
}

func TestStateRuntimeHTTPAndSDKExposeProviderNeutralUsageAndSafeModelFailure(t *testing.T) {
	runtime, _, compiler, store, _ := newMemoryStateAuthority(t)
	ctx := context.Background()
	admin := runtimeapi.Identity{Tenant: "tenant-a", Principal: "admin", Admin: true}
	alice := runtimeapi.Identity{Tenant: "tenant-a", Principal: "alice"}
	agent, err := runtime.CreateAgent(ctx, admin, agentruntime.CreateAgentRequest{IdempotencyKey: "usage-agent", Name: "assistant", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatalf("create Agent: %v", err)
	}
	session, err := runtime.CreateSession(ctx, alice, agentruntime.CreateSessionRequest{IdempotencyKey: "usage-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatalf("create Session: %v", err)
	}
	accepted, err := runtime.SendInput(ctx, alice, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "usage-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "produce a bounded outcome"}}})
	if err != nil {
		t.Fatalf("send Input: %v", err)
	}
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("alice")
	workerScope := runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}
	state, err := store.LoadRuntimeState(ctx, workerScope)
	if err != nil {
		t.Fatal(err)
	}
	begin, err := compiler.CompileBeginInvocationAttempt(runtimestate.BeginInvocationAttemptCommand{Scope: workerScope, IdempotencyKey: "usage-invocation", SessionID: session.ID, TurnID: accepted.Turn.ID, OperationID: "op_model_usage_0001", ExpectedSessionVersion: state.Sessions[0].Version, ExpectedTurnVersion: state.Turns[0].Version})
	if err != nil {
		t.Fatal(err)
	}
	beginPlan, err := store.Apply(ctx, begin)
	if err != nil {
		t.Fatal(err)
	}
	inputTokens := uint64(42)
	failure := &agentruntime.Failure{Code: agentruntime.FailureUnavailable, Message: "model outcome is unavailable", Retryable: true}
	invocation := beginPlan.Result().Invocation
	outcome, err := compiler.CompileRecordInvocationOutcome(runtimestate.RecordInvocationOutcomeCommand{Scope: workerScope, IdempotencyKey: "usage-outcome", SessionID: session.ID, TurnID: accepted.Turn.ID, OperationID: invocation.OperationID, Ordinal: invocation.Ordinal, Fence: invocation.Fence, Outcome: runtimestate.InvocationFailed, Failure: failure, Usage: &runtimestate.ModelUsage{InputTokens: &inputTokens}, ExpectedSessionVersion: beginPlan.Result().Session.Version, ExpectedTurnVersion: beginPlan.Result().Turn.Version})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, outcome); err != nil {
		t.Fatal(err)
	}
	settle, err := compiler.CompileSettleTurn(runtimestate.SettleTurnCommand{Scope: workerScope, IdempotencyKey: "usage-settle", SessionID: session.ID, TurnID: accepted.Turn.ID, ExpectedSessionVersion: beginPlan.Result().Session.Version, ExpectedTurnVersion: beginPlan.Result().Turn.Version, Outcome: runtimestate.TerminalOutcome{OperationID: invocation.OperationID, Ordinal: invocation.Ordinal, Fence: invocation.Fence, State: agentruntime.TurnFailed, Failure: failure}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, settle); err != nil {
		t.Fatal(err)
	}
	handler, err := runtimeapi.NewHandler(runtimeapi.Config{Runtime: runtime, Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{"alice-token-000000": alice}}, RequestIDs: &requestIDs{}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	turn, err := newStateRuntimeHTTPClient(t, server.URL, "alice-token-000000").InspectTurn(ctx, session.ID, accepted.Turn.ID)
	if err != nil || turn.State != agentruntime.TurnFailed || turn.Failure == nil || turn.Failure.Code != agentruntime.FailureUnavailable || turn.Usage == nil || turn.Usage.InputTokens == nil || *turn.Usage.InputTokens != inputTokens || turn.Usage.OutputTokens != nil {
		t.Fatalf("SDK inspect model outcome = %#v, %v; want safe failure and unknown output usage", turn, err)
	}
}

func TestStateRuntimeHTTPAndSDKExposeFinalizedModelOutputArtifact(t *testing.T) {
	runtime, content, compiler, store, _ := newMemoryStateAuthority(t)
	ctx := context.Background()
	admin := runtimeapi.Identity{Tenant: "tenant-a", Principal: "admin", Admin: true}
	alice := runtimeapi.Identity{Tenant: "tenant-a", Principal: "alice"}
	agent, err := runtime.CreateAgent(ctx, admin, agentruntime.CreateAgentRequest{IdempotencyKey: "output-agent", Name: "assistant", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := runtime.CreateSession(ctx, alice, agentruntime.CreateSessionRequest{IdempotencyKey: "output-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := runtime.SendInput(ctx, alice, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "output-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "persist model output"}}})
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("alice")
	workerScope := runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}
	state, err := store.LoadRuntimeState(ctx, workerScope)
	if err != nil {
		t.Fatal(err)
	}
	begin, err := compiler.CompileBeginInvocationAttempt(runtimestate.BeginInvocationAttemptCommand{Scope: workerScope, IdempotencyKey: "output-invocation", SessionID: session.ID, TurnID: accepted.Turn.ID, OperationID: "op_model_output_0001", ExpectedSessionVersion: state.Sessions[0].Version, ExpectedTurnVersion: state.Turns[0].Version})
	if err != nil {
		t.Fatal(err)
	}
	beginPlan, err := store.Apply(ctx, begin)
	if err != nil {
		t.Fatal(err)
	}
	handoff, err := content.StageArtifact(ctx, tenant, "text/plain; charset=utf-8", []byte("durably normalized model output"))
	if err != nil {
		t.Fatal(err)
	}
	registered, err := compiler.CompileRegisterArtifact(runtimestate.RegisterArtifactCommand{Scope: workerScope, IdempotencyKey: "output-artifact", SessionID: session.ID, TurnID: accepted.Turn.ID, Artifact: handoff})
	if err != nil {
		t.Fatal(err)
	}
	artifactPlan, err := store.Apply(ctx, registered)
	if err != nil {
		t.Fatal(err)
	}
	invocation := beginPlan.Result().Invocation
	resultReference := artifactPlan.Result().Artifact.Reference
	outcome, err := compiler.CompileRecordInvocationOutcome(runtimestate.RecordInvocationOutcomeCommand{Scope: workerScope, IdempotencyKey: "output-outcome", SessionID: session.ID, TurnID: accepted.Turn.ID, OperationID: invocation.OperationID, Ordinal: invocation.Ordinal, Fence: invocation.Fence, Outcome: runtimestate.InvocationSucceeded, Result: &resultReference, ExpectedSessionVersion: beginPlan.Result().Session.Version, ExpectedTurnVersion: beginPlan.Result().Turn.Version})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, outcome); err != nil {
		t.Fatal(err)
	}
	settle, err := compiler.CompileSettleTurn(runtimestate.SettleTurnCommand{Scope: workerScope, IdempotencyKey: "output-settle", SessionID: session.ID, TurnID: accepted.Turn.ID, ExpectedSessionVersion: beginPlan.Result().Session.Version, ExpectedTurnVersion: beginPlan.Result().Turn.Version, Outcome: runtimestate.TerminalOutcome{OperationID: invocation.OperationID, Ordinal: invocation.Ordinal, Fence: invocation.Fence, State: agentruntime.TurnSucceeded}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, settle); err != nil {
		t.Fatal(err)
	}
	handler, err := runtimeapi.NewHandler(runtimeapi.Config{Runtime: runtime, Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{"alice-token-000000": alice}}, RequestIDs: &requestIDs{}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client := newStateRuntimeHTTPClient(t, server.URL, "alice-token-000000")
	turn, err := client.InspectTurn(ctx, session.ID, accepted.Turn.ID)
	if err != nil || turn.State != agentruntime.TurnSucceeded || turn.Output == nil || *turn.Output != (agentruntime.ArtifactReference{ID: artifactPlan.Result().Artifact.ArtifactID, MediaType: "text/plain; charset=utf-8", SizeBytes: int64(len("durably normalized model output")), SHA256: strings.TrimPrefix(artifactPlan.Result().Artifact.Reference.Digest, "sha256:")}) {
		t.Fatalf("SDK finalized model output = %#v, %v", turn, err)
	}
	stream, err := client.OpenArtifact(ctx, turn.Output.ID)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(stream.Body)
	closeErr := stream.Body.Close()
	if readErr != nil || closeErr != nil || string(body) != "durably normalized model output" {
		t.Fatalf("SDK read finalized model output = %q read=%v close=%v", body, readErr, closeErr)
	}
}

func TestStateRuntimeHTTPAndSDKInspectOwnerScopedToolLifecycle(t *testing.T) {
	runtime, content, compiler, store, _ := newMemoryStateAuthority(t)
	ctx := context.Background()
	admin := runtimeapi.Identity{Tenant: "tenant-a", Principal: "admin", Admin: true}
	alice := runtimeapi.Identity{Tenant: "tenant-a", Principal: "alice"}
	bob := runtimeapi.Identity{Tenant: "tenant-a", Principal: "bob"}
	agent, err := runtime.CreateAgent(ctx, admin, agentruntime.CreateAgentRequest{IdempotencyKey: "tool-inspection-agent", Name: "assistant", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatalf("create Agent: %v", err)
	}
	session, err := runtime.CreateSession(ctx, alice, agentruntime.CreateSessionRequest{IdempotencyKey: "tool-inspection-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatalf("create Session: %v", err)
	}
	accepted, err := runtime.SendInput(ctx, alice, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "tool-inspection-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "write the report"}}})
	if err != nil {
		t.Fatalf("send Input: %v", err)
	}
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("alice")
	workerScope := runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}
	digest := "sha256:" + strings.Repeat("a", 64)
	descriptor, err := content.StageToolActionDescriptor(ctx, tenant, []byte("private tool descriptor"))
	if err != nil {
		t.Fatal(err)
	}
	intent, err := compiler.CompileRecordToolIntent(runtimestate.RecordToolIntentCommand{Scope: workerScope, IdempotencyKey: "tool-inspection-intent", SessionID: session.ID, TurnID: accepted.Turn.ID, ToolCallID: "tcall_1234567890ABCDEF", ToolName: "write", ActionDigest: digest, PolicyRevisionDigest: digest, Descriptor: descriptor})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, intent); err != nil {
		t.Fatal(err)
	}
	approvalRequest, err := compiler.CompileRequestApproval(runtimestate.RequestApprovalCommand{Scope: workerScope, IdempotencyKey: "tool-inspection-approval", SessionID: session.ID, TurnID: accepted.Turn.ID, ToolCallID: "tcall_1234567890ABCDEF", ApprovalID: "appr_1234567890ABCDEF", ActionDigest: digest, PolicyRevisionDigest: digest, CapabilityDigest: digest, MaximumUses: 1, ExpiresAt: time.Date(2026, 8, 10, 13, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, approvalRequest); err != nil {
		t.Fatal(err)
	}
	handler, err := runtimeapi.NewHandler(runtimeapi.Config{Runtime: runtime, Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{"alice-token-000000": alice, "bob-token-00000000": bob}}, RequestIDs: &requestIDs{}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	aliceClient := newStateRuntimeHTTPClient(t, server.URL, "alice-token-000000")
	pending, err := aliceClient.InspectToolCalls(ctx, session.ID, accepted.Turn.ID)
	if err != nil || len(pending.Calls) != 1 || pending.Calls[0].Name != "write" || pending.Calls[0].State != agentruntime.ToolCallAwaitingApproval || pending.Calls[0].Approval == nil || pending.Calls[0].Approval.State != agentruntime.ApprovalPending || pending.Calls[0].Approval.ToolCallID != "tcall_1234567890ABCDEF" || pending.Calls[0].Grant != nil || pending.Calls[0].Execution != nil {
		t.Fatalf("SDK inspect pending Tool call = %#v, %v", pending, err)
	}
	if pendingTurn, err := aliceClient.InspectTurn(ctx, session.ID, accepted.Turn.ID); err != nil || pendingTurn.State != agentruntime.TurnWaitingForApproval || pendingTurn.CompletedAt != nil {
		t.Fatalf("SDK inspect pending approval Turn = %#v, %v", pendingTurn, err)
	}
	approvalID, _ := agentruntime.ParseApprovalID("appr_1234567890ABCDEF")
	if _, err := aliceClient.DecideApproval(ctx, agentruntime.DecideApprovalRequest{ApprovalID: approvalID, Decision: agentruntime.ApprovalApproved, IdempotencyKey: "tool-inspection-decision"}); err != nil {
		t.Fatal(err)
	}
	state, err := store.LoadRuntimeState(ctx, workerScope)
	if err != nil || len(state.Grants) != 1 {
		t.Fatalf("load approved grant = %#v, %v", state.Grants, err)
	}
	grant := state.Grants[0]
	consume, err := compiler.CompileConsumeCapabilityGrant(runtimestate.ConsumeCapabilityGrantCommand{Scope: workerScope, IdempotencyKey: "tool-inspection-consume", SessionID: session.ID, TurnID: accepted.Turn.ID, ToolCallID: "tcall_1234567890ABCDEF", GrantID: grant.GrantID, PolicyRevisionDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, consume); err != nil {
		t.Fatal(err)
	}
	begin, err := compiler.CompileBeginToolExecution(runtimestate.BeginToolExecutionCommand{Scope: workerScope, IdempotencyKey: "tool-inspection-begin", SessionID: session.ID, TurnID: accepted.Turn.ID, ToolCallID: "tcall_1234567890ABCDEF", GrantID: grant.GrantID, OperationID: "op_tool_inspection_0001"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, begin); err != nil {
		t.Fatal(err)
	}
	failure := &agentruntime.Failure{Code: agentruntime.FailureUnavailable, Message: "tool outcome is uncertain", Retryable: true}
	outcome, err := compiler.CompileRecordToolExecutionOutcome(runtimestate.RecordToolExecutionOutcomeCommand{Scope: workerScope, IdempotencyKey: "tool-inspection-outcome", SessionID: session.ID, TurnID: accepted.Turn.ID, ToolCallID: "tcall_1234567890ABCDEF", OperationID: "op_tool_inspection_0001", Outcome: runtimestate.ToolExecutionUncertain, Failure: failure})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, outcome); err != nil {
		t.Fatal(err)
	}
	terminal, err := aliceClient.InspectToolCalls(ctx, session.ID, accepted.Turn.ID)
	if err != nil || len(terminal.Calls) != 1 || terminal.Calls[0].State != agentruntime.ToolCallUncertain || terminal.Calls[0].Approval == nil || terminal.Calls[0].Approval.State != agentruntime.ApprovalApproved || terminal.Calls[0].Grant == nil || terminal.Calls[0].Grant.Uses != 1 || terminal.Calls[0].Grant.MaximumUses != 1 || terminal.Calls[0].Execution == nil || terminal.Calls[0].Execution.Failure == nil || terminal.Calls[0].Execution.Failure.Code != agentruntime.FailureUnavailable {
		t.Fatalf("SDK inspect terminal Tool call = %#v, %v", terminal, err)
	}
	if _, err := newStateRuntimeHTTPClient(t, server.URL, "bob-token-00000000").InspectToolCalls(ctx, session.ID, accepted.Turn.ID); !hasFailure(err, agentruntime.FailureNotFound) {
		t.Fatalf("cross-principal Tool inspection error = %v, want safe not-found", err)
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

func (objects *stateRuntimeObjects) Open(_ context.Context, key string, _ int) (io.ReadCloser, error) {
	value, exists := objects.values[key]
	if !exists {
		return nil, fmt.Errorf("immutable object %q is unavailable", key)
	}
	return io.NopCloser(bytes.NewReader(value)), nil
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

func assertNoBackendExecutionIdentifier(t *testing.T, value any) {
	t.Helper()
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			assertNoBackendExecutionIdentifier(t, item)
		}
	case map[string]any:
		for key, item := range typed {
			switch key {
			case "workflow_id", "run_id", "task_queue", "temporal_workflow_id", "database_position", "backend_id":
				t.Fatalf("Session inspection exposed forbidden backend identifier field %q", key)
			}
			assertNoBackendExecutionIdentifier(t, item)
		}
	}
}
