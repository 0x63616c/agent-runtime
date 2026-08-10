package toolpolicy_test

import (
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/approval"
	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/toolpolicy"
)

func TestEvaluateBuildsPendingApprovalOnlyForExactImmutableProjection(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 10, 16, 0, 0, 0, time.UTC)
	decision := toolpolicy.Evaluate(validIntent(t), validProjection(now), validApprovalID(t), now)
	if decision.Outcome() != toolpolicy.OutcomeRequiresApproval {
		t.Fatalf("outcome = %q, want require approval", decision.Outcome())
	}
	request, exists := decision.Approval()
	if !exists || request.State() != approval.StatePending {
		t.Fatalf("approval = %#v exists = %t, want pending approval", request, exists)
	}
	if request.Owner() != validIntent(t).Owner || request.SessionID() != validIntent(t).SessionID || request.TurnID() != validIntent(t).TurnID || request.ToolCallID() != validIntent(t).ToolCallID || request.ActionDigest() != validIntent(t).ActionDigest || request.PolicyRevisionDigest() != validIntent(t).PolicyRevisionDigest || request.Summary() != validProjection(now).Summary || request.ProposedScope() != validProjection(now).ProposedScope || !request.CreatedAt().Equal(now) || !request.ExpiresAt().Equal(validProjection(now).ExpiresAt) {
		t.Fatalf("approval did not preserve the exact immutable policy linkage: %#v", request)
	}
}

func TestEvaluateDeniesMismatchedTenantToolActionOrPolicyBeforeCreatingApproval(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 10, 16, 0, 0, 0, time.UTC)
	for name, mutate := range map[string]func(*toolpolicy.Intent, *toolpolicy.Projection){
		"tenant": func(intent *toolpolicy.Intent, _ *toolpolicy.Projection) {
			intent.Owner.TenantID = mustTenantID(t, "ten_AAAABBBBCCCCDDDD")
		},
		"tool":   func(intent *toolpolicy.Intent, _ *toolpolicy.Projection) { intent.ToolName = "other-tool" },
		"action": func(intent *toolpolicy.Intent, _ *toolpolicy.Projection) { intent.ActionDigest = digest('4') },
		"policy": func(intent *toolpolicy.Intent, _ *toolpolicy.Projection) { intent.PolicyRevisionDigest = digest('5') },
	} {
		t.Run(name, func(t *testing.T) {
			intent, projection := validIntent(t), validProjection(now)
			mutate(&intent, &projection)

			decision := toolpolicy.Evaluate(intent, projection, validApprovalID(t), now)
			if decision.Outcome() != toolpolicy.OutcomeDenied {
				t.Fatalf("outcome = %q, want denied", decision.Outcome())
			}
			if _, exists := decision.Approval(); exists {
				t.Fatal("mismatched projection constructed an approval")
			}
		})
	}
}

func TestEvaluateRefusesUnsafeOrBroaderProjectionBeforeCreatingApproval(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 10, 16, 0, 0, 0, time.UTC)
	for name, mutate := range map[string]func(*toolpolicy.Projection){
		"unsafe summary": func(projection *toolpolicy.Projection) {
			projection.Summary = approval.Summary{Verb: approval.SummaryVerb("read Authorization: Bearer secret"), Target: approval.SummaryArtifact}
		},
		"scope outlives approval": func(projection *toolpolicy.Projection) {
			projection.ProposedScope.ExpiresAt = projection.ExpiresAt.Add(time.Second)
		},
		"scope exceeds maximum uses": func(projection *toolpolicy.Projection) {
			projection.ProposedScope.MaximumUses = 33
		},
	} {
		t.Run(name, func(t *testing.T) {
			projection := validProjection(now)
			mutate(&projection)

			decision := toolpolicy.Evaluate(validIntent(t), projection, validApprovalID(t), now)
			if decision.Outcome() != toolpolicy.OutcomeDenied {
				t.Fatalf("outcome = %q, want denied", decision.Outcome())
			}
			if _, exists := decision.Approval(); exists {
				t.Fatal("invalid projection constructed an approval")
			}
		})
	}
}

func TestEvaluateDeniesAtProjectionExpiryWithInjectedClock(t *testing.T) {
	t.Parallel()

	startedAt := time.Date(2026, 8, 10, 16, 0, 0, 0, time.UTC)
	fakeClock, err := clock.NewFake(startedAt)
	if err != nil {
		t.Fatalf("new fake clock: %v", err)
	}
	projection := validProjection(startedAt)
	if err := fakeClock.Advance(projection.ExpiresAt.Sub(startedAt)); err != nil {
		t.Fatalf("advance fake clock: %v", err)
	}

	decision := toolpolicy.Evaluate(validIntent(t), projection, validApprovalID(t), fakeClock.Now())
	if decision.Outcome() != toolpolicy.OutcomeDenied {
		t.Fatalf("outcome = %q, want denied at exact projection expiry", decision.Outcome())
	}
	if _, exists := decision.Approval(); exists {
		t.Fatal("expired projection constructed an approval")
	}
}

func validIntent(t *testing.T) toolpolicy.Intent {
	t.Helper()
	sessionID, err := approval.ParseSessionID("sess_1234567890ABCDEF")
	if err != nil {
		t.Fatalf("parse session ID: %v", err)
	}
	turnID, err := approval.ParseTurnID("turn_1234567890ABCDEF")
	if err != nil {
		t.Fatalf("parse turn ID: %v", err)
	}
	toolCallID, err := approval.ParseToolCallID("tcall_1234567890ABCDEF")
	if err != nil {
		t.Fatalf("parse tool call ID: %v", err)
	}
	return toolpolicy.Intent{
		Owner:                approval.Actor{TenantID: mustTenantID(t, "ten_1234567890ABCDEF"), PrincipalID: mustPrincipalID(t, "prn_1234567890ABCDEF")},
		SessionID:            sessionID,
		TurnID:               turnID,
		ToolCallID:           toolCallID,
		ToolName:             "restart-service",
		ActionDigest:         digest('1'),
		PolicyRevisionDigest: digest('2'),
	}
}

func validProjection(now time.Time) toolpolicy.Projection {
	return toolpolicy.Projection{
		TenantID:             "ten_1234567890ABCDEF",
		ToolName:             "restart-service",
		ActionDigest:         digest('1'),
		PolicyRevisionDigest: digest('2'),
		Summary:              approval.Summary{Verb: approval.SummaryRestart, Target: approval.SummaryWorkspaceService},
		ProposedScope:        approval.Scope{CapabilityDigest: digest('3'), MaximumUses: 1, ExpiresAt: now.Add(4 * time.Minute)},
		ExpiresAt:            now.Add(5 * time.Minute),
	}
}

func validApprovalID(t *testing.T) approval.ID {
	t.Helper()
	value, err := approval.ParseID("appr_1234567890ABCDEF")
	if err != nil {
		t.Fatalf("parse approval ID: %v", err)
	}
	return value
}

func mustTenantID(t *testing.T, value string) approval.TenantID {
	t.Helper()
	parsed, err := approval.ParseTenantID(value)
	if err != nil {
		t.Fatalf("parse tenant ID: %v", err)
	}
	return parsed
}

func mustPrincipalID(t *testing.T, value string) approval.PrincipalID {
	t.Helper()
	parsed, err := approval.ParsePrincipalID(value)
	if err != nil {
		t.Fatalf("parse principal ID: %v", err)
	}
	return parsed
}

func digest(character rune) string {
	return "sha256:" + string(makeRunes(character, 64))
}

func makeRunes(character rune, count int) []rune {
	value := make([]rune, count)
	for index := range value {
		value[index] = character
	}
	return value
}
