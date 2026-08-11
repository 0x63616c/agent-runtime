package runtimeorchestration_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

func TestPublisherReclaimsAnUnacknowledgedRouteAfterProcessLoss(t *testing.T) {
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
	memory, err := runtimestate.NewMemoryRuntimeStateStore(planner)
	if err != nil {
		t.Fatal(err)
	}
	store := &failFirstAcknowledgementStore{MemoryRuntimeStateStore: memory}
	body, err := content.StageAgentSpecificationBody(ctx, tenant, runtimecontent.AgentSpecificationBody{Name: "reclaim", ModelProfile: "balanced", Instructions: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "register", Specification: body})
	if err != nil {
		t.Fatal(err)
	}
	registeredPlan, err := store.Apply(ctx, registered)
	if err != nil {
		t.Fatal(err)
	}
	created, err := compiler.CompileCreateSession(runtimestate.CreateSessionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner}, IdempotencyKey: "create-session", RevisionID: registeredPlan.Result().Revision.RevisionID})
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
	if err := publisher.ScanOnce(ctx); err == nil {
		t.Fatal("publish result = nil, want simulated acknowledgement-loss error")
	}
	if len(temporal.commands) != 1 {
		t.Fatalf("commands after lost acknowledgement = %#v, want one delivered route", temporal.commands)
	}
	claimedState, err := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAuditOperation(claimedState.Audit, "outbox.claimed", "temporal-claim-"+temporal.commands[0].OutboxID+"-") || hasAuditOperation(claimedState.Audit, "outbox.published", "temporal-ack-"+temporal.commands[0].OutboxID+"-") {
		t.Fatalf("audit after lost acknowledgement = %#v, want claimed fact without published fact", claimedState.Audit)
	}
	if err := timeSource.Advance(2*time.Minute + time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	if err := publisher.ScanOnce(ctx); err != nil {
		t.Fatalf("reclaim expired durable outbox route: %v", err)
	}
	if len(temporal.commands) != 2 || temporal.commands[0] != temporal.commands[1] {
		t.Fatalf("commands after reclaim = %#v, want exactly one duplicate durable route", temporal.commands)
	}
	publishedState, err := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAuditOperation(publishedState.Audit, "outbox.published", "temporal-ack-"+temporal.commands[0].OutboxID+"-") {
		t.Fatalf("audit after recovered acknowledgement = %#v, want published fact", publishedState.Audit)
	}
	page, err := store.ReadOutbox(ctx, runtimestate.OutboxQuery{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityOutboxPublisher}, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range page.Records {
		if string(record.OutboxID) == temporal.commands[0].OutboxID {
			if record.State != runtimestate.OutboxPublished {
				t.Fatalf("reclaimed input route = %#v, want published", record)
			}
			return
		}
	}
	t.Fatalf("outbox after reclaim = %#v, want the delivered input route", page.Records)
}

func hasAuditOperation(facts []runtimestate.AuditFactRecord, kind, operationPrefix string) bool {
	for _, fact := range facts {
		if fact.Kind == kind && strings.HasPrefix(string(fact.OperationID), operationPrefix) {
			return true
		}
	}
	return false
}

// failFirstAcknowledgementStore simulates the narrow crash window after a
// Temporal route succeeds but before its durable acknowledgement commits.
// The durable lease must be reclaimable; the workflow is responsible for
// treating the repeated route as a deterministic no-op.
type failFirstAcknowledgementStore struct {
	*runtimestate.MemoryRuntimeStateStore
	failed bool
}

func (store *failFirstAcknowledgementStore) PersistTransitionPlan(ctx context.Context, plan runtimestate.TransitionPlan) error {
	if plan.Kind() == runtimestate.CommandAcknowledgeOutbox && plan.Result().Outbox.EventKind == agentruntime.EventInputAccepted && !store.failed {
		store.failed = true
		return errors.New("simulated process loss before outbox acknowledgement")
	}
	return store.MemoryRuntimeStateStore.PersistTransitionPlan(ctx, plan)
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
