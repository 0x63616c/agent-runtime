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

func TestRuntimeStateStorePersistsOnlyCompilerPlannerOutput(t *testing.T) {
	store := reflect.TypeOf((*runtimestate.RuntimeStateStore)(nil)).Elem()
	for _, name := range []string{
		"LoadRuntimeState", "PersistTransitionPlan", "GetAgentRevision", "GetSessionView",
		"GetTurn", "GetInvocation", "ReadEvents", "GetMutationReceipt", "ReadAudit",
		"ReadOutbox", "AuthorizeAgentSpecificationBodyRead", "AuthorizeInputEnvelopeRead",
	} {
		if _, ok := store.MethodByName(name); !ok {
			t.Fatalf("RuntimeStateStore missing %s", name)
		}
	}
}

func TestOutboxRecoveryCarriesTheExactFencedInvocationRoute(t *testing.T) {
	record := reflect.TypeOf(runtimestate.OutboxRecord{})
	for _, field := range []string{
		"Tenant", "Principal", "SessionID", "TurnID", "InvocationID", "OperationID",
		"InvocationOrdinal", "InvocationFence", "SessionVersion", "TurnVersion",
	} {
		if _, ok := record.FieldByName(field); !ok {
			t.Fatalf("OutboxRecord missing recovery route %s", field)
		}
	}
	store := reflect.TypeOf((*runtimestate.RuntimeStateStore)(nil)).Elem()
	method, ok := store.MethodByName("GetInvocation")
	if !ok || method.Type.NumOut() != 2 || method.Type.Out(0) != reflect.TypeOf(runtimestate.InvocationRecord{}) {
		t.Fatalf("GetInvocation signature = %v, want scoped invocation query", method.Type)
	}
}

func TestOutboxMutationsDoNotExposeCallerForgedRequestDigests(t *testing.T) {
	for _, command := range []reflect.Type{reflect.TypeOf(runtimestate.ClaimOutboxCommand{}), reflect.TypeOf(runtimestate.AcknowledgeOutboxCommand{})} {
		if _, found := command.FieldByName("RequestDigest"); found {
			t.Fatalf("%s exposes a caller-forgeable request digest", command)
		}
	}
	store := reflect.TypeOf((*runtimestate.RuntimeStateStore)(nil)).Elem()
	for _, methodName := range []string{"ClaimOutbox", "AcknowledgeOutbox"} {
		if _, ok := store.MethodByName(methodName); ok {
			t.Fatalf("%s lets an adapter accept a raw command", methodName)
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

func TestPointerBearingCommandsTakeOwnedNormalizedSnapshots(t *testing.T) {
	local := time.Date(2026, 8, 10, 12, 0, 0, 0, time.FixedZone("local", -7*60*60))
	result := &runtimecontent.Reference{Digest: "sha256:one", MediaType: "application/test", SizeBytes: 1}
	failure := &agentruntime.Failure{Details: map[string]string{"phase": "before"}}
	command := runtimestate.RecordInvocationOutcomeCommand{
		Result: result, Failure: failure,
	}
	owned := command.Owned()
	result.Digest = "sha256:changed"
	failure.Details["phase"] = "changed"
	if owned.Result.Digest != "sha256:one" || owned.Failure.Details["phase"] != "before" {
		t.Fatalf("owned outcome command aliases caller-owned pointer metadata: %#v", owned)
	}

	claim := runtimestate.ClaimOutboxCommand{ClaimUntil: local}.Owned()
	if claim.ClaimUntil.Location() != time.UTC || !claim.ClaimUntil.Equal(local) {
		t.Fatalf("owned claim time = %v, want normalized UTC equivalent", claim.ClaimUntil)
	}
	settle := runtimestate.SettleTurnCommand{Outcome: runtimestate.TerminalOutcome{Failure: failure}}.Owned()
	failure.Details["phase"] = "changed again"
	if settle.Outcome.Failure.Details["phase"] != "changed" {
		t.Fatalf("owned terminal outcome aliases caller failure: %#v", settle.Outcome)
	}
}

func TestEveryMutationCommandOffersOwnedNormalization(t *testing.T) {
	for _, command := range []reflect.Type{
		reflect.TypeOf(runtimestate.RegisterAgentRevisionCommand{}),
		reflect.TypeOf(runtimestate.CreateSessionCommand{}),
		reflect.TypeOf(runtimestate.AdmitInputCommand{}),
		reflect.TypeOf(runtimestate.BeginInvocationAttemptCommand{}),
		reflect.TypeOf(runtimestate.RecordInvocationOutcomeCommand{}),
		reflect.TypeOf(runtimestate.SettleTurnCommand{}),
		reflect.TypeOf(runtimestate.CancelTurnCommand{}),
		reflect.TypeOf(runtimestate.CloseSessionCommand{}),
		reflect.TypeOf(runtimestate.ClaimOutboxCommand{}),
		reflect.TypeOf(runtimestate.AcknowledgeOutboxCommand{}),
	} {
		method, ok := command.MethodByName("Owned")
		if !ok || method.Type.NumOut() != 1 || method.Type.Out(0) != command {
			t.Fatalf("%s Owned signature = %v, want same-type owned snapshot", command, method.Type)
		}
	}
}

func TestScopeAndIdempotencyKeyAreExplicitButReceiptDigestIsCompilerOnly(t *testing.T) {
	for _, command := range []reflect.Type{
		reflect.TypeOf(runtimestate.RegisterAgentRevisionCommand{}), reflect.TypeOf(runtimestate.CreateSessionCommand{}),
		reflect.TypeOf(runtimestate.AdmitInputCommand{}), reflect.TypeOf(runtimestate.BeginInvocationAttemptCommand{}),
		reflect.TypeOf(runtimestate.RecordInvocationOutcomeCommand{}), reflect.TypeOf(runtimestate.SettleTurnCommand{}),
		reflect.TypeOf(runtimestate.CancelTurnCommand{}), reflect.TypeOf(runtimestate.CloseSessionCommand{}),
		reflect.TypeOf(runtimestate.ClaimOutboxCommand{}), reflect.TypeOf(runtimestate.AcknowledgeOutboxCommand{}),
	} {
		if _, found := command.FieldByName("Scope"); !found {
			t.Fatalf("%s lacks authenticated scope", command)
		}
		if _, found := command.FieldByName("IdempotencyKey"); !found {
			t.Fatalf("%s lacks idempotency key", command)
		}
		if _, found := command.FieldByName("RequestDigest"); found {
			t.Fatalf("%s exposes compiler-only receipt digest", command)
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
