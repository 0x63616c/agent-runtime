package runtimestate_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestRuntimeStateStoreDefinesTheCompleteInitialLifecycle(t *testing.T) {
	store := reflect.TypeOf((*runtimestate.RuntimeStateStore)(nil)).Elem()
	for _, name := range []string{
		"RegisterAgentRevision", "CreateSession", "AdmitInput",
		"BeginInvocationAttempt", "RecordInvocationOutcome", "SettleTurn",
		"CancelTurn", "CloseSession", "GetAgentRevision", "GetSessionView",
		"GetTurn", "ReadEvents", "GetMutationReceipt", "ReadAudit",
		"ReadOutbox", "ClaimOutbox", "AcknowledgeOutbox",
	} {
		if _, ok := store.MethodByName(name); !ok {
			t.Fatalf("RuntimeStateStore missing %s", name)
		}
	}
}

func TestLifecycleCommandsUseOpaqueContentHandoffsAndMetadataResults(t *testing.T) {
	register := reflect.TypeOf(runtimestate.RegisterAgentRevisionCommand{})
	field, ok := register.FieldByName("Specification")
	if !ok || field.Type != reflect.TypeOf(runtimecontent.ContentHandoff{}) {
		t.Fatalf("RegisterAgentRevisionCommand.Specification = %v, want opaque content handoff", field.Type)
	}
	admit := reflect.TypeOf(runtimestate.AdmitInputCommand{})
	field, ok = admit.FieldByName("Input")
	if !ok || field.Type != reflect.TypeOf(runtimecontent.ContentHandoff{}) {
		t.Fatalf("AdmitInputCommand.Input = %v, want opaque content handoff", field.Type)
	}

	for _, record := range []reflect.Type{
		reflect.TypeOf(runtimestate.AgentRevisionRecord{}),
		reflect.TypeOf(runtimestate.InputRecord{}),
		reflect.TypeOf(runtimestate.ProductEventRecord{}),
		reflect.TypeOf(runtimestate.OutboxRecord{}),
	} {
		for _, forbidden := range []string{"Instructions", "Parts", "StorageKey", "ObjectKey", "TemporalWorkflowID", "TemporalRunID"} {
			if _, found := record.FieldByName(forbidden); found {
				t.Fatalf("%s exposes prohibited %s", record.Name(), forbidden)
			}
		}
	}
}

func TestRecordsAndResultsDefensivelyCloneMutableMetadata(t *testing.T) {
	created := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	wantCreated := created
	failedAt := created.Add(time.Minute)
	record := runtimestate.TurnRecord{
		Failure:   &agentruntime.Failure{Code: agentruntime.FailureUnavailable, Details: map[string]string{"phase": "provider"}},
		StartedAt: &created, CompletedAt: &failedAt,
	}
	clone := record.Clone()
	record.Failure.Details["phase"] = "changed"
	*record.StartedAt = record.StartedAt.Add(time.Hour)
	if got := clone.Failure.Details["phase"]; got != "provider" {
		t.Fatalf("failure clone = %q, want independent metadata", got)
	}
	if !clone.StartedAt.Equal(wantCreated) {
		t.Fatalf("started time = %v, want %v", clone.StartedAt, wantCreated)
	}

	page := runtimestate.EventPage{Events: []runtimestate.ProductEventRecord{{Sequence: 1}}}
	clonedPage := page.Clone()
	page.Events[0].Sequence = 2
	if clonedPage.Events[0].Sequence != 1 {
		t.Fatalf("event page aliases mutable event slice")
	}

	result := runtimestate.SettleTurnResult{Promoted: &runtimestate.TurnRecord{Failure: &agentruntime.Failure{Details: map[string]string{"safe": "value"}}}}
	clonedResult := result.Clone()
	result.Promoted.Failure.Details["safe"] = "changed"
	if got := clonedResult.Promoted.Failure.Details["safe"]; got != "value" {
		t.Fatalf("settle result aliases promoted Turn failure: %q", got)
	}
}

func TestScopeAndRequestDigestAreExplicitOnEveryMutation(t *testing.T) {
	type command interface {
		CommandScope() runtimestate.MutationScope
		CanonicalRequestDigest() runtimestate.RequestDigest
	}
	commands := []command{
		runtimestate.RegisterAgentRevisionCommand{}, runtimestate.CreateSessionCommand{},
		runtimestate.AdmitInputCommand{}, runtimestate.BeginInvocationAttemptCommand{},
		runtimestate.RecordInvocationOutcomeCommand{}, runtimestate.SettleTurnCommand{},
		runtimestate.CancelTurnCommand{}, runtimestate.CloseSessionCommand{},
	}
	for _, mutation := range commands {
		if mutation.CommandScope().Tenant != "" || mutation.CanonicalRequestDigest() != "" {
			t.Fatalf("zero mutation unexpectedly carries scope/digest: %#v", mutation)
		}
	}
}

func TestStoreFailureVocabularyDoesNotExposeAnAdapter(t *testing.T) {
	seen := map[error]struct{}{}
	for _, err := range []error{
		runtimestate.ErrConflict, runtimestate.ErrNotFoundOrDenied,
		runtimestate.ErrUnavailable, runtimestate.ErrIntegrity, runtimestate.ErrReceiptExpired,
	} {
		if err == nil || errors.Is(err, context.Canceled) {
			t.Fatalf("invalid store failure %v", err)
		}
		if _, exists := seen[err]; exists {
			t.Fatalf("duplicate store failure %v", err)
		}
		seen[err] = struct{}{}
	}
}
