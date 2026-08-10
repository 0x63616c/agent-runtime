package approval_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/approval"
	"github.com/0x63616c/agent-runtime/internal/clock"
)

func TestApprovalOwnerOrTenantAdminMayInspectAndDecideExactlyOnce(t *testing.T) {
	pending := validApproval(t)
	if pending.ID().String() != "appr_1234567890ABCDEF" || pending.ActionDigest() != "sha256:1111111111111111111111111111111111111111111111111111111111111111" {
		t.Fatalf("immutable approval identity/action projection = %q %q", pending.ID(), pending.ActionDigest())
	}
	owner := ownerActor(t)
	admin := adminActor(t)
	other := otherActor(t)
	if _, err := pending.Inspect(owner, pending.CreatedAt()); err != nil {
		t.Fatalf("owner inspect: %v", err)
	}
	if _, err := pending.Inspect(admin, pending.CreatedAt()); err != nil {
		t.Fatalf("tenant admin inspect: %v", err)
	}
	if _, err := pending.Inspect(other, pending.CreatedAt()); !errors.Is(err, approval.ErrNotFoundOrDenied) {
		t.Fatalf("unrelated principal inspect = %v, want safe refusal", err)
	}

	approved, err := pending.Decide(owner, approval.DecisionCommand{
		IdempotencyKey: "approve-1",
		Decision:       approval.DecisionApproved,
		GrantedScope: approval.Scope{
			CapabilityDigest: pending.ProposedScope().CapabilityDigest,
			MaximumUses:      1,
			ExpiresAt:        pending.ExpiresAt().Add(-time.Minute),
		},
	}, pending.CreatedAt().Add(time.Minute))
	if err != nil || approved.State() != approval.StateApproved {
		t.Fatalf("approve = %#v, %v", approved, err)
	}
	replayed, err := approved.Decide(owner, approval.DecisionCommand{
		IdempotencyKey: "approve-1", Decision: approval.DecisionApproved,
		GrantedScope: approval.Scope{CapabilityDigest: pending.ProposedScope().CapabilityDigest, MaximumUses: 1, ExpiresAt: pending.ExpiresAt().Add(-time.Minute)},
	}, pending.CreatedAt().Add(2*time.Minute))
	if err != nil || replayed != approved {
		t.Fatalf("exact decision replay = %#v, %v", replayed, err)
	}
	if _, err := approved.Decide(admin, approval.DecisionCommand{IdempotencyKey: "deny-1", Decision: approval.DecisionDenied}, pending.CreatedAt().Add(2*time.Minute)); !errors.Is(err, approval.ErrConflict) {
		t.Fatalf("second decision = %v, want conflict", err)
	}
}

func TestApprovalRefusesBroadenedScopeAndLateDecision(t *testing.T) {
	pending := validApproval(t)
	owner := ownerActor(t)
	fakeClock, err := clock.NewFake(pending.CreatedAt())
	if err != nil {
		t.Fatalf("new fake clock: %v", err)
	}
	if _, err := pending.Decide(owner, approval.DecisionCommand{
		IdempotencyKey: "approve-broad", Decision: approval.DecisionApproved,
		GrantedScope: approval.Scope{CapabilityDigest: pending.ProposedScope().CapabilityDigest, MaximumUses: pending.ProposedScope().MaximumUses + 1, ExpiresAt: pending.ExpiresAt()},
	}, fakeClock.Now().Add(time.Minute)); !errors.Is(err, approval.ErrScopeBroadening) {
		t.Fatalf("broadened scope = %v, want scope refusal", err)
	}
	if err := fakeClock.Advance(5 * time.Minute); err != nil {
		t.Fatalf("advance fake clock: %v", err)
	}
	expired, err := pending.Decide(owner, approval.DecisionCommand{IdempotencyKey: "late", Decision: approval.DecisionDenied}, fakeClock.Now())
	if !errors.Is(err, approval.ErrExpired) || expired.State() != approval.StateExpired {
		t.Fatalf("late decision = %#v, %v", expired, err)
	}
}

func TestTenantAdminMayDenyAnotherOwnerApprovalInsideTheSameTenant(t *testing.T) {
	pending := validApproval(t)
	admin := adminActor(t)
	denied, err := pending.Decide(admin, approval.DecisionCommand{IdempotencyKey: "deny-1", Decision: approval.DecisionDenied}, pending.CreatedAt().Add(time.Minute))
	if err != nil || denied.State() != approval.StateDenied {
		t.Fatalf("tenant-admin denial = %#v, %v", denied, err)
	}
	if _, err := pending.Inspect(actor(t, "AAAABBBBCCCCDDDD", "3333444455556666", true), pending.CreatedAt()); !errors.Is(err, approval.ErrNotFoundOrDenied) {
		t.Fatalf("cross-tenant admin inspect = %v, want safe refusal", err)
	}
}

func TestApprovalReplaysExactRecordedDecisionAfterExpiryWithoutReopeningIt(t *testing.T) {
	pending := validApproval(t)
	owner := ownerActor(t)
	command := approval.DecisionCommand{
		IdempotencyKey: "approve-1", Decision: approval.DecisionApproved,
		GrantedScope: approval.Scope{CapabilityDigest: pending.ProposedScope().CapabilityDigest, MaximumUses: 1, ExpiresAt: pending.ExpiresAt().Add(-time.Minute)},
	}
	approved, err := pending.Decide(owner, command, pending.CreatedAt().Add(time.Minute))
	if err != nil {
		t.Fatalf("first decision: %v", err)
	}
	replayed, err := approved.Decide(owner, command, pending.ExpiresAt().Add(time.Minute))
	if err != nil || replayed != approved || replayed.State() != approval.StateApproved {
		t.Fatalf("expired exact replay = %#v, %v", replayed, err)
	}
}

func TestApprovalCancellationAndInvalidationAreTerminalWithoutToolExecution(t *testing.T) {
	pending := validApproval(t)
	cancelled, err := pending.Cancel(pending.CreatedAt().Add(time.Minute))
	if err != nil || cancelled.State() != approval.StateCancelled || cancelled.Decision() != nil {
		t.Fatalf("cancel = %#v, %v", cancelled, err)
	}
	if _, err := cancelled.Decide(ownerActor(t), approval.DecisionCommand{IdempotencyKey: "late", Decision: approval.DecisionDenied}, pending.CreatedAt().Add(2*time.Minute)); !errors.Is(err, approval.ErrConflict) {
		t.Fatalf("cancelled decision = %v, want conflict", err)
	}
	invalidated, err := pending.Invalidate(pending.CreatedAt().Add(time.Minute))
	if err != nil || invalidated.State() != approval.StateInvalidated {
		t.Fatalf("invalidate = %#v, %v", invalidated, err)
	}
	if repeated, err := cancelled.Cancel(pending.ExpiresAt().Add(time.Minute)); err != nil || repeated != cancelled {
		t.Fatalf("repeat cancel = %#v, %v", repeated, err)
	}
	if repeated, err := invalidated.Invalidate(pending.ExpiresAt().Add(time.Minute)); err != nil || repeated != invalidated {
		t.Fatalf("repeat invalidation = %#v, %v", repeated, err)
	}
}

func TestApprovalInspectionExpiresWithFakeClockAndExposesSafeContext(t *testing.T) {
	pending := validApproval(t)
	owner := ownerActor(t)
	fakeClock, err := clock.NewFake(pending.CreatedAt())
	if err != nil {
		t.Fatalf("new fake clock: %v", err)
	}
	if err := fakeClock.Advance(5 * time.Minute); err != nil {
		t.Fatalf("advance fake clock: %v", err)
	}
	expired, err := pending.Inspect(owner, fakeClock.Now())
	if err != nil || expired.State() != approval.StateExpired {
		t.Fatalf("expired inspection = %#v, %v", expired, err)
	}
	if expired.Summary().String() != "restart workspace-service" || expired.PolicyRevisionDigest() != "sha256:2222222222222222222222222222222222222222222222222222222222222222" || expired.SessionID().String() != "sess_1234567890ABCDEF" || expired.TurnID().String() != "turn_1234567890ABCDEF" || expired.ToolCallID().String() != "tcall_1234567890ABCDEF" || expired.Owner() != owner {
		t.Fatalf("safe approval context was not available: %#v", expired)
	}
}

func validApproval(t *testing.T) approval.Approval {
	t.Helper()
	value, err := approval.New(validProposal(t))
	if err != nil {
		t.Fatalf("new approval: %v", err)
	}
	return value
}

func TestApprovalRejectsArbitrarySummaryPayload(t *testing.T) {
	proposal := validProposal(t)
	proposal.Summary = approval.Summary{Verb: approval.SummaryVerb("Authorization: Bearer secret"), Target: approval.SummaryTarget("untrusted")}
	if _, err := approval.New(proposal); err == nil {
		t.Fatal("arbitrary raw summary payload was accepted")
	}
}

func TestApprovalRefusesSecretLikeIdentityOrIdempotencyBeforeRetention(t *testing.T) {
	for _, token := range []string{
		"Authorization: Bearer secret",
		"authorization-bearer-topsecret",
		"Authorization.Bearer.topsecret",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvd25lciJ9.signature",
		"sk_live_1234567890ABCDEF",
	} {
		t.Run(token, func(t *testing.T) {
			proposal := validProposal(t)
			proposal.Owner.PrincipalID = approval.PrincipalID(token)
			if _, err := approval.New(proposal); err == nil {
				t.Fatal("secret-like principal identity was accepted")
			}
		})
	}

	pending := validApproval(t)
	owner := ownerActor(t)
	secretKey := "Authorization: Bearer secret"
	decided, err := pending.Decide(owner, approval.DecisionCommand{IdempotencyKey: secretKey, Decision: approval.DecisionDenied}, pending.CreatedAt().Add(time.Minute))
	if err != nil || decided.State() != approval.StateDenied {
		t.Fatalf("secret-like idempotency key was not safely accepted: %#v, %v", decided, err)
	}
	if decision := decided.Decision(); decision == nil || strings.Contains(fmt.Sprintf("%#v", decision), secretKey) || strings.Contains(fmt.Sprintf("%#v", decided), secretKey) {
		t.Fatalf("secret-like idempotency key was retained or re-exposed: decision=%#v approval=%#v", decision, decided)
	}
	replayed, err := decided.Decide(owner, approval.DecisionCommand{IdempotencyKey: secretKey, Decision: approval.DecisionDenied}, decided.ExpiresAt().Add(time.Minute))
	if err != nil || replayed != decided {
		t.Fatalf("secret-key replay changed terminal decision: %#v, %v", replayed, err)
	}
}

func validProposal(t *testing.T) approval.Proposal {
	t.Helper()
	sessionID, err := approval.ParseSessionID("sess_1234567890ABCDEF")
	if err != nil {
		t.Fatal(err)
	}
	turnID, err := approval.ParseTurnID("turn_1234567890ABCDEF")
	if err != nil {
		t.Fatal(err)
	}
	approvalID, err := approval.ParseID("appr_1234567890ABCDEF")
	if err != nil {
		t.Fatal(err)
	}
	toolCallID, err := approval.ParseToolCallID("tcall_1234567890ABCDEF")
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	return approval.Proposal{
		ID:                   approvalID,
		Owner:                ownerActor(t),
		SessionID:            sessionID,
		TurnID:               turnID,
		ToolCallID:           toolCallID,
		ActionDigest:         "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		PolicyRevisionDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		Summary:              approval.Summary{Verb: approval.SummaryRestart, Target: approval.SummaryWorkspaceService},
		ProposedScope:        approval.Scope{CapabilityDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333", MaximumUses: 2, ExpiresAt: createdAt.Add(4 * time.Minute)},
		CreatedAt:            createdAt,
		ExpiresAt:            createdAt.Add(5 * time.Minute),
	}
}

func ownerActor(t *testing.T) approval.Actor {
	t.Helper()
	return actor(t, "1234567890ABCDEF", "1234567890ABCDEF", false)
}

func adminActor(t *testing.T) approval.Actor {
	t.Helper()
	return actor(t, "1234567890ABCDEF", "FEDCBA0987654321", true)
}

func otherActor(t *testing.T) approval.Actor {
	t.Helper()
	return actor(t, "1234567890ABCDEF", "AAAABBBBCCCCDDDD", false)
}

func actor(t *testing.T, tenantPayload, principalPayload string, admin bool) approval.Actor {
	t.Helper()
	tenant, err := approval.ParseTenantID("ten_" + tenantPayload)
	if err != nil {
		t.Fatalf("parse tenant ID: %v", err)
	}
	principal, err := approval.ParsePrincipalID("prn_" + principalPayload)
	if err != nil {
		t.Fatalf("parse principal ID: %v", err)
	}
	return approval.Actor{TenantID: tenant, PrincipalID: principal, Admin: admin}
}
