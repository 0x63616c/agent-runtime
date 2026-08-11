package runtimeapi_test

import (
	"context"
	"fmt"
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
	if _, err := runtime.ReadArtifact(ctx, bob, plan.Result().Artifact.ArtifactID); !hasFailure(err, agentruntime.FailureNotFound) {
		t.Fatalf("cross-principal artifact read error = %v, want safe not-found", err)
	}
}

func TestStateRuntimeInspectsAndDecidesOwnerApprovalIdempotently(t *testing.T) {
	runtime, _, compiler, store, _ := newMemoryStateAuthority(t)
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
	intent, err := compiler.CompileRecordToolIntent(runtimestate.RecordToolIntentCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "approval-intent", SessionID: session.ID, TurnID: accepted.Turn.ID, ToolCallID: "tcall_1234567890ABCDEF", ToolName: "write", ActionDigest: digest, PolicyRevisionDigest: digest})
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
	runtime, _, compiler, store, fakeClock := newMemoryStateAuthority(t)
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
	intent, err := compiler.CompileRecordToolIntent(runtimestate.RecordToolIntentCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "expired-approval-intent", SessionID: session.ID, TurnID: accepted.Turn.ID, ToolCallID: "tcall_1234567890ABCDEF", ToolName: "write", ActionDigest: digest, PolicyRevisionDigest: digest})
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

func newMemoryStateRuntime(t *testing.T) *runtimeapi.StateRuntime {
	runtime, _, _, _, _ := newMemoryStateAuthority(t)
	return runtime
}

func newMemoryStateAuthority(t *testing.T) (*runtimeapi.StateRuntime, *runtimecontent.Store, *runtimestate.Compiler, *runtimestate.MemoryRuntimeStateStore, *clock.Fake) {
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
	planner, err := runtimestate.NewRuntimeStatePlanner(fakeClock, &stateRuntimeIDs{})
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
