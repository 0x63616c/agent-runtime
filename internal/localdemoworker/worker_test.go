package localdemoworker

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/roles"
	"github.com/0x63616c/agent-runtime/internal/runtimemodel"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/cockroachdb/errors"
)

func TestScanLoopRetriesOnlyTypedTransientStateUnavailable(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	err := scanLoop(ctx, func(context.Context) error {
		if calls.Add(1) == 1 {
			return errors.Wrap(runtimestate.ErrUnavailable, "schema migration is still starting")
		}
		cancel()
		return nil
	}, time.Millisecond)
	if err != nil {
		t.Fatalf("scanLoop() error = %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("scanLoop calls = %d, want 2 (one typed retry)", got)
	}
}

func TestScanLoopFailsClosedForNonTransientErrors(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("invalid local demo fixture authority")
	var calls atomic.Int32
	err := scanLoop(context.Background(), func(context.Context) error {
		calls.Add(1)
		return sentinel
	}, time.Millisecond)
	if !errors.Is(err, sentinel) {
		t.Fatalf("scanLoop() error = %v, want wrapped %v", err, sentinel)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("scanLoop calls = %d, want one fail-closed attempt", got)
	}
}

func TestModelFixtureUsesTheCanonicalApprovalSummaryForItsResearchTool(t *testing.T) {
	response := fixtureModelResponse(runtimemodel.Request{OperationID: "orchestration-invocation-outbox_1234567890ABCDEF"})
	if response.Tool == nil {
		t.Fatal("fixture response has no tool request")
	}
	if response.Tool.ToolName != "research" || response.Tool.PolicyName != "research-dossier-demo" || response.Tool.PolicyRevision != 1 {
		t.Fatalf("fixture policy request = %#v, want the declared research demo policy", response.Tool)
	}
	if response.Tool.Action.Verb != "write" || response.Tool.Action.Target != "artifact" {
		t.Fatalf("fixture approval summary = %#v, want canonical artifact write", response.Tool.Action)
	}
	if _, err := agentruntime.ParseApprovalID(response.Tool.ApprovalID); err != nil {
		t.Fatalf("fixture approval ID = %q, want public identifier: %v", response.Tool.ApprovalID, err)
	}
}

func TestDeclaredFixtureScenariosHaveOnlyFiniteApprovalLifetimes(t *testing.T) {
	for _, want := range []struct {
		scenario roles.LocalDemoFixtureScenario
		ttl      time.Duration
	}{
		{scenario: "workspace-approval-reset-v1", ttl: 10 * time.Minute},
		{scenario: "workspace-approval-expiry-v1", ttl: 2 * time.Second},
	} {
		t.Run(string(want.scenario), func(t *testing.T) {
			ttl, err := approvalTTLForScenario(want.scenario)
			if err != nil || ttl != want.ttl {
				t.Fatalf("scenario approval lifetime = %s, %v", ttl, err)
			}
			before := time.Now().UTC()
			response, err := (modelFixture{approvalTTL: ttl}).Invoke(t.Context(), runtimemodel.Request{OperationID: "orchestration-invocation-outbox_1234567890ABCDEF"})
			if err != nil || response.Tool == nil {
				t.Fatalf("invoke declared scenario = %#v, %v", response, err)
			}
			after := time.Now().UTC()
			if response.Tool.ExpiresAt.Before(before.Add(ttl)) || response.Tool.ExpiresAt.After(after.Add(ttl)) {
				t.Fatalf("tool expiry = %s, want bounded around now + %s", response.Tool.ExpiresAt, ttl)
			}
		})
	}
	if _, err := approvalTTLForScenario("ambient"); err == nil {
		t.Fatal("undeclared fixture scenario was accepted")
	}
}

func TestRandomIDsUseThePublicIdentifierPayloadLength(t *testing.T) {
	value, err := (randomIDs{}).NextIdentifier(runtimestate.IdentifierEvent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agentruntime.ParseEventID(value); err != nil {
		t.Fatalf("fixture event ID = %q, want public identifier: %v", value, err)
	}
}
