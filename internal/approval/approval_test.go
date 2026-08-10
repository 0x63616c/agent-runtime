package approval_test

import (
	"errors"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/approval"
	"github.com/0x63616c/agent-runtime/internal/clock"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestApprovalOwnerOrTenantAdminMayInspectAndDecideExactlyOnce(t *testing.T) {
	pending := validApproval(t)
	if pending.ID().String() != "appr_1234567890ABCDEF" || pending.ActionDigest() != "sha256:1111111111111111111111111111111111111111111111111111111111111111" {
		t.Fatalf("immutable approval identity/action projection = %q %q", pending.ID(), pending.ActionDigest())
	}
	owner := approval.Actor{TenantID: "tenant-a", PrincipalID: "owner"}
	admin := approval.Actor{TenantID: "tenant-a", PrincipalID: "admin", Admin: true}
	other := approval.Actor{TenantID: "tenant-a", PrincipalID: "other"}
	if _, err := pending.Inspect(owner); err != nil {
		t.Fatalf("owner inspect: %v", err)
	}
	if _, err := pending.Inspect(admin); err != nil {
		t.Fatalf("tenant admin inspect: %v", err)
	}
	if _, err := pending.Inspect(other); !errors.Is(err, approval.ErrNotFoundOrDenied) {
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
	owner := approval.Actor{TenantID: "tenant-a", PrincipalID: "owner"}
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
	admin := approval.Actor{TenantID: "tenant-a", PrincipalID: "admin", Admin: true}
	denied, err := pending.Decide(admin, approval.DecisionCommand{IdempotencyKey: "deny-1", Decision: approval.DecisionDenied}, pending.CreatedAt().Add(time.Minute))
	if err != nil || denied.State() != approval.StateDenied {
		t.Fatalf("tenant-admin denial = %#v, %v", denied, err)
	}
	if _, err := pending.Inspect(approval.Actor{TenantID: "tenant-b", PrincipalID: "admin", Admin: true}); !errors.Is(err, approval.ErrNotFoundOrDenied) {
		t.Fatalf("cross-tenant admin inspect = %v, want safe refusal", err)
	}
}

func TestApprovalReplaysExactRecordedDecisionAfterExpiryWithoutReopeningIt(t *testing.T) {
	pending := validApproval(t)
	owner := approval.Actor{TenantID: "tenant-a", PrincipalID: "owner"}
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
	if _, err := cancelled.Decide(approval.Actor{TenantID: "tenant-a", PrincipalID: "owner"}, approval.DecisionCommand{IdempotencyKey: "late", Decision: approval.DecisionDenied}, pending.CreatedAt().Add(2*time.Minute)); !errors.Is(err, approval.ErrConflict) {
		t.Fatalf("cancelled decision = %v, want conflict", err)
	}
	invalidated, err := pending.Invalidate(pending.CreatedAt().Add(time.Minute))
	if err != nil || invalidated.State() != approval.StateInvalidated {
		t.Fatalf("invalidate = %#v, %v", invalidated, err)
	}
}

func validApproval(t *testing.T) approval.Approval {
	t.Helper()
	sessionID, err := agentruntime.ParseSessionID("sess_1234567890ABCDEF")
	if err != nil {
		t.Fatal(err)
	}
	turnID, err := agentruntime.ParseTurnID("turn_1234567890ABCDEF")
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
	value, err := approval.New(approval.Proposal{
		ID:                   approvalID,
		Owner:                approval.Actor{TenantID: "tenant-a", PrincipalID: "owner"},
		SessionID:            sessionID,
		TurnID:               turnID,
		ToolCallID:           toolCallID,
		ActionDigest:         "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		PolicyRevisionDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		Summary:              "Restart the isolated workspace service.",
		ProposedScope:        approval.Scope{CapabilityDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333", MaximumUses: 2, ExpiresAt: createdAt.Add(4 * time.Minute)},
		CreatedAt:            createdAt,
		ExpiresAt:            createdAt.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("new approval: %v", err)
	}
	return value
}
