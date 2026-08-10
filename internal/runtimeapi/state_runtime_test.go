package runtimeapi_test

import (
	"context"
	"fmt"
	"reflect"
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
	runtime, content, compiler, store := newMemoryStateAuthority(t)
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

func newMemoryStateRuntime(t *testing.T) *runtimeapi.StateRuntime {
	runtime, _, _, _ := newMemoryStateAuthority(t)
	return runtime
}

func newMemoryStateAuthority(t *testing.T) (*runtimeapi.StateRuntime, *runtimecontent.Store, *runtimestate.Compiler, *runtimestate.MemoryRuntimeStateStore) {
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
	return runtime, content, compiler, store
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
