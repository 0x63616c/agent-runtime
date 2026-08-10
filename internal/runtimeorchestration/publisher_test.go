package runtimeorchestration_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimeorchestration"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestPublisherDerivesTemporalRoutesOnlyFromClaimedDurableOutbox(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	content, err := runtimecontent.New("runtime-content", &publisherObjects{values: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := runtimecontent.ParseTenantID("tenant-a")
	principal, _ := runtimecontent.ParsePrincipalID("principal-a")
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	timeSource, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(timeSource, &publisherIDs{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := runtimestate.NewMemoryRuntimeStateStore(planner)
	if err != nil {
		t.Fatal(err)
	}
	body, err := content.StageAgentSpecificationBody(ctx, tenant, runtimecontent.AgentSpecificationBody{Name: "publisher", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	registration, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "register", Specification: body})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := store.Apply(ctx, registration)
	if err != nil {
		t.Fatal(err)
	}
	created, err := compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}, IdempotencyKey: "create-session", RevisionID: registered.Result().Revision.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	sessionPlan, err := store.Apply(ctx, created)
	if err != nil {
		t.Fatal(err)
	}
	input, err := content.StageInputEnvelope(ctx, tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "hello"}})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := compiler.CompileAdmitInput(runtimestate.AdmitInputCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}, IdempotencyKey: "input", SessionID: sessionPlan.Result().Session.SessionID, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, accepted); err != nil {
		t.Fatal(err)
	}
	temporal := &recordingPublisher{}
	publisher, err := runtimeorchestration.NewPublisher(runtimeorchestration.PublisherConfig{Store: store, Tenants: store, Compiler: compiler, Planner: planner, Clock: timeSource, Publisher: temporal, Claimer: "orchestration-codec"})
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.ScanOnce(ctx); err != nil {
		t.Fatalf("scan durable outbox: %v", err)
	}
	if len(temporal.starts) != 1 || temporal.starts[0].SessionID != sessionPlan.Result().Session.SessionID.String() {
		t.Fatalf("starts = %#v, want durable Session start", temporal.starts)
	}
	if len(temporal.commands) != 1 || temporal.commands[0].Kind != runtimeorchestration.CommandInputAccepted || temporal.commands[0].OutboxID == "" {
		t.Fatalf("commands = %#v, want one state-derived input route", temporal.commands)
	}
	dispatcher, err := runtimeorchestration.NewDurableStateDispatcher(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.Dispatch(ctx, temporal.commands[0]); err != nil {
		t.Fatalf("recheck published durable route: %v", err)
	}
	if err := dispatcher.Dispatch(ctx, runtimeorchestration.Command{Tenant: "tenant-a", OutboxID: "forged", SessionID: sessionPlan.Result().Session.SessionID.String(), Kind: runtimeorchestration.CommandInputAccepted, Sequence: 999}); err == nil {
		t.Fatal("forged Temporal command was accepted without a durable outbox route")
	}
	if err := publisher.ScanOnce(ctx); err != nil {
		t.Fatalf("rescan published durable outbox: %v", err)
	}
	if len(temporal.starts) != 1 || len(temporal.commands) != 1 {
		t.Fatalf("rescan redelivered published routes: starts=%#v commands=%#v", temporal.starts, temporal.commands)
	}
}

type recordingPublisher struct {
	starts   []runtimeorchestration.SessionStart
	commands []runtimeorchestration.Command
}

func (publisher *recordingPublisher) StartSession(_ context.Context, start runtimeorchestration.SessionStart) error {
	publisher.starts = append(publisher.starts, start)
	return nil
}

func (publisher *recordingPublisher) SignalSession(_ context.Context, _ runtimeorchestration.SessionStart, command runtimeorchestration.Command) error {
	publisher.commands = append(publisher.commands, command)
	return nil
}

type publisherObjects struct{ values map[string][]byte }

func (objects *publisherObjects) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	if _, exists := objects.values[key]; exists {
		return false, nil
	}
	objects.values[key] = append([]byte(nil), value...)
	return true, nil
}

func (objects *publisherObjects) Get(_ context.Context, key string, _ int) ([]byte, error) {
	return append([]byte(nil), objects.values[key]...), nil
}

type publisherIDs struct{ next uint64 }

func (ids *publisherIDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	ids.next++
	return fmt.Sprintf("%s_%016d", kind, ids.next), nil
}
