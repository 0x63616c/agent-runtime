// Package toolpolicy evaluates one already-normalized tool intent against one
// immutable operator-authored policy projection. It cannot grant or execute a tool.
package toolpolicy

import (
	"strings"
	"time"

	"github.com/0x63616c/agent-runtime/internal/approval"
)

const (
	maximumIdentityBytes  = 128
	maximumToolNameBytes  = 128
	maximumScopeUses      = 32
	maximumApprovalWindow = 24 * time.Hour
)

// Outcome is the complete result vocabulary for this proposal-only policy seam.
type Outcome string

const (
	// OutcomeDenied refuses a Tool intent without supplying execution authority.
	OutcomeDenied Outcome = "denied"
	// OutcomeRequiresApproval carries one immutable pending Approval request.
	OutcomeRequiresApproval Outcome = "requires_approval"
)

// Intent is the normalized correlation and digest projection of one model Tool call.
// It deliberately contains no raw arguments, provider request, or executable adapter.
type Intent struct {
	Owner                approval.Actor
	SessionID            approval.SessionID
	TurnID               approval.TurnID
	ToolCallID           approval.ToolCallID
	ToolName             string
	ActionDigest         string
	PolicyRevisionDigest string
}

// Projection is an already-authorized, immutable operator policy result for one
// tenant/tool/action/policy-revision tuple. This package neither parses a policy
// language nor decides how the normalized action would be executed.
type Projection struct {
	TenantID             string
	ToolName             string
	ActionDigest         string
	PolicyRevisionDigest string
	Summary              approval.Summary
	ProposedScope        approval.Scope
	ExpiresAt            time.Time
}

// Disposition is either a refusal or a pending Approval. It never carries a grant
// or an execution capability.
type Disposition struct {
	outcome  Outcome
	approval approval.Approval
}

// Outcome returns the policy disposition.
func (value Disposition) Outcome() Outcome { return value.outcome }

// Approval returns the pending immutable Approval only when approval is required.
func (value Disposition) Approval() (approval.Approval, bool) {
	if value.outcome != OutcomeRequiresApproval {
		return approval.Approval{}, false
	}
	return value.approval, true
}

// Evaluate matches an immutable policy projection exactly and either refuses the
// intent or builds a pending Approval. Every refusal happens before Approval
// construction; denial is deliberately non-diagnostic so this seam exposes no
// policy enumeration detail.
func Evaluate(intent Intent, projection Projection, approvalID approval.ID, now time.Time) Disposition {
	if !validNow(now) || !validIntent(intent) || !validProjection(projection, now) || !matches(intent, projection) || !validApprovalID(approvalID) {
		return denied()
	}

	request, err := approval.New(approval.Proposal{
		ID:                   approvalID,
		Owner:                intent.Owner,
		SessionID:            intent.SessionID,
		TurnID:               intent.TurnID,
		ToolCallID:           intent.ToolCallID,
		ActionDigest:         intent.ActionDigest,
		PolicyRevisionDigest: intent.PolicyRevisionDigest,
		Summary:              projection.Summary,
		ProposedScope:        projection.ProposedScope,
		CreatedAt:            now,
		ExpiresAt:            projection.ExpiresAt,
	})
	if err != nil {
		return denied()
	}
	return Disposition{outcome: OutcomeRequiresApproval, approval: request}
}

func denied() Disposition { return Disposition{outcome: OutcomeDenied} }

func matches(intent Intent, projection Projection) bool {
	return intent.Owner.TenantID.String() == projection.TenantID &&
		intent.ToolName == projection.ToolName &&
		intent.ActionDigest == projection.ActionDigest &&
		intent.PolicyRevisionDigest == projection.PolicyRevisionDigest
}

func validNow(now time.Time) bool { return validUTC(now) }

func validIntent(intent Intent) bool {
	if !validActor(intent.Owner) || !validToolName(intent.ToolName) || !validDigest(intent.ActionDigest) || !validDigest(intent.PolicyRevisionDigest) {
		return false
	}
	if _, err := approval.ParseSessionID(intent.SessionID.String()); err != nil {
		return false
	}
	if _, err := approval.ParseTurnID(intent.TurnID.String()); err != nil {
		return false
	}
	if _, err := approval.ParseToolCallID(intent.ToolCallID.String()); err != nil {
		return false
	}
	return true
}

func validProjection(projection Projection, now time.Time) bool {
	return boundedIdentity(projection.TenantID) &&
		validToolName(projection.ToolName) &&
		validDigest(projection.ActionDigest) &&
		validDigest(projection.PolicyRevisionDigest) &&
		validSummary(projection.Summary) &&
		validScope(projection.ProposedScope) &&
		validUTC(projection.ExpiresAt) &&
		projection.ExpiresAt.After(now) &&
		!projection.ExpiresAt.After(now.Add(maximumApprovalWindow)) &&
		projection.ProposedScope.ExpiresAt.After(now) &&
		!projection.ProposedScope.ExpiresAt.After(projection.ExpiresAt)
}

func validApprovalID(value approval.ID) bool {
	_, err := approval.ParseID(value.String())
	return err == nil
}

func validActor(actor approval.Actor) bool {
	_, tenantErr := approval.ParseTenantID(actor.TenantID.String())
	_, principalErr := approval.ParsePrincipalID(actor.PrincipalID.String())
	return tenantErr == nil && principalErr == nil
}

func validScope(scope approval.Scope) bool {
	return validDigest(scope.CapabilityDigest) && scope.MaximumUses > 0 && scope.MaximumUses <= maximumScopeUses && validUTC(scope.ExpiresAt)
}

func validSummary(summary approval.Summary) bool {
	return (summary.Verb == approval.SummaryExecute || summary.Verb == approval.SummaryRestart || summary.Verb == approval.SummaryWrite || summary.Verb == approval.SummaryDelete) &&
		(summary.Target == approval.SummaryWorkspaceService || summary.Target == approval.SummarySandboxProcess || summary.Target == approval.SummaryArtifact || summary.Target == approval.SummaryNetworkRequest)
}

func validToolName(value string) bool {
	if len(value) == 0 || len(value) > maximumToolNameBytes {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") || value != strings.ToLower(value) {
		return false
	}
	for _, character := range strings.TrimPrefix(value, "sha256:") {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func boundedIdentity(value string) bool {
	return len(value) > 0 && len(value) <= maximumIdentityBytes && !strings.ContainsAny(value, "\x00\r\n")
}

func validUTC(value time.Time) bool { return !value.IsZero() && value.Location() == time.UTC }
