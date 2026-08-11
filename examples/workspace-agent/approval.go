// Package workspaceagent is the public-contract Workspace Agent application.
// Its approval inbox consumes only the SDK; sandbox execution remains visibly
// unavailable until a protected Workspace profile has retained M4 evidence.
package workspaceagent

import (
	"context"
	"errors"
	"fmt"
	"html"
	"strings"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

// ApprovalClient is the narrow public SDK capability used by the approval UI.
type ApprovalClient interface {
	ListApprovals(context.Context) (agentruntime.ApprovalPage, error)
	InspectApproval(context.Context, agentruntime.ApprovalID) (agentruntime.Approval, error)
	DecideApproval(context.Context, agentruntime.DecideApprovalRequest) (agentruntime.Approval, error)
	CancelTurn(context.Context, agentruntime.CancelTurnRequest) (agentruntime.Turn, error)
}

// Inbox presents safe approval state and never renders model arguments,
// capability data, or sandbox descriptors.
type Inbox struct{ client ApprovalClient }

// NewInbox constructs the Workspace Agent public approval surface.
func NewInbox(client ApprovalClient) (*Inbox, error) {
	if client == nil {
		return nil, errors.New("create Workspace Agent approval inbox: client is required")
	}
	return &Inbox{client: client}, nil
}

// List returns the caller-owned bounded approval inbox.
func (inbox *Inbox) List(ctx context.Context) (agentruntime.ApprovalPage, error) {
	return inbox.client.ListApprovals(ctx)
}

// Decide records one owner approval or denial with the caller-supplied durable idempotency key.
func (inbox *Inbox) Decide(ctx context.Context, approvalID agentruntime.ApprovalID, decision agentruntime.ApprovalState, key string) (agentruntime.Approval, error) {
	if decision != agentruntime.ApprovalApproved && decision != agentruntime.ApprovalDenied {
		return agentruntime.Approval{}, errors.New("decide Workspace Agent approval: invalid decision")
	}
	return inbox.client.DecideApproval(ctx, agentruntime.DecideApprovalRequest{ApprovalID: approvalID, Decision: decision, IdempotencyKey: key})
}

// Cancel refuses further progress for the exact Turn backing a pending approval.
func (inbox *Inbox) Cancel(ctx context.Context, approval agentruntime.Approval, key string) (agentruntime.Turn, error) {
	return inbox.client.CancelTurn(ctx, agentruntime.CancelTurnRequest{SessionID: approval.SessionID, TurnID: approval.TurnID, IdempotencyKey: key})
}

// Terminal renders a bounded safe approval row for the Workspace Agent TUI.
func Terminal(approval agentruntime.Approval) string {
	action := "elevated action"
	if approval.Action != nil {
		action = approval.Action.Verb + " " + approval.Action.Target
	}
	uses := uint32(0)
	if approval.Scope != nil {
		uses = approval.Scope.MaximumUses
	}
	return fmt.Sprintf("%s  %s  %s  uses=%d  expires=%s", approval.ID, action, approval.State, uses, approval.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"))
}

// HTML renders one escaped approval row for the Workspace Agent browser UI.
func HTML(approval agentruntime.Approval) string {
	return "<li>" + html.EscapeString(strings.TrimSpace(Terminal(approval))) + "</li>"
}

// SandboxStatus is the truthful Workspace execution status. No UI path treats
// this text as a successful Firecracker workspace.
func SandboxStatus() string {
	return "Workspace sandbox execution is unavailable until the protected Firecracker profile and Linux/KVM evidence are enrolled."
}
