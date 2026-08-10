// Package approval owns the pure, persistence-free human-approval state machine.
package approval

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/cockroachdb/errors"
)

const (
	maxIdentityBytes      = 128
	maxSummaryBytes       = 512
	maxScopeUses          = 32
	maximumApprovalWindow = 24 * time.Hour
)

var (
	// ErrNotFoundOrDenied is intentionally non-enumerating for unauthorized callers.
	ErrNotFoundOrDenied = errors.New("approval not found or denied")
	// ErrConflict reports a duplicate or terminal decision that cannot advance an Approval.
	ErrConflict = errors.New("approval decision conflict")
	// ErrExpired reports a decision received at or after the immutable Approval expiry.
	ErrExpired = errors.New("approval expired")
	// ErrScopeBroadening reports an approved grant that exceeds the immutable proposal.
	ErrScopeBroadening = errors.New("approval decision broadens proposed scope")
)

// ID is a stable internal Approval identity. It stays internal until the public contract is approved.
type ID string

// ToolCallID is an internal stable correlation reference for one model Tool intent.
type ToolCallID string

// String returns the canonical internal Approval identity.
func (id ID) String() string { return string(id) }

// String returns the canonical internal Tool-call identity.
func (id ToolCallID) String() string { return string(id) }

// ParseID validates one canonical internal Approval identity.
func ParseID(value string) (ID, error) {
	if !validID(value, "appr_") {
		return "", errors.New("parse approval ID: invalid identifier")
	}
	return ID(value), nil
}

// ParseToolCallID validates one canonical internal Tool-call identity.
func ParseToolCallID(value string) (ToolCallID, error) {
	if !validID(value, "tcall_") {
		return "", errors.New("parse tool call ID: invalid identifier")
	}
	return ToolCallID(value), nil
}

func validID(value, prefix string) bool {
	payload := strings.TrimPrefix(value, prefix)
	if len(payload) != 16 || prefix+payload != value {
		return false
	}
	for _, character := range payload {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

// Actor is the exact tenant/principal decision boundary. Admin is tenant-scoped only.
type Actor struct {
	TenantID    string
	PrincipalID string
	Admin       bool
}

func (actor Actor) valid() bool {
	return boundedIdentity(actor.TenantID) && boundedIdentity(actor.PrincipalID)
}

// Scope carries only an immutable capability description digest and two bounded narrowing controls.
// It deliberately contains neither a raw tool argument nor secret capability material.
type Scope struct {
	CapabilityDigest string
	MaximumUses      uint32
	ExpiresAt        time.Time
}

func (scope Scope) valid() bool {
	return validDigest(scope.CapabilityDigest) && scope.MaximumUses > 0 && scope.MaximumUses <= maxScopeUses && validUTC(scope.ExpiresAt)
}

func (scope Scope) narrowerThan(proposed Scope) bool {
	return scope.valid() && scope.CapabilityDigest == proposed.CapabilityDigest && scope.MaximumUses <= proposed.MaximumUses && !scope.ExpiresAt.After(proposed.ExpiresAt)
}

// Decision records the sole human decision available to an Approval.
type Decision string

const (
	DecisionApproved Decision = "approved"
	DecisionDenied   Decision = "denied"
)

// State is the durable-shaped state vocabulary; this package makes no durability claim.
type State string

const (
	StatePending     State = "pending"
	StateApproved    State = "approved"
	StateDenied      State = "denied"
	StateExpired     State = "expired"
	StateCancelled   State = "cancelled"
	StateInvalidated State = "invalidated"
)

// Proposal is an immutable, redacted request to approve one already-recorded Tool intent.
type Proposal struct {
	ID                   ID
	Owner                Actor
	SessionID            agentruntime.SessionID
	TurnID               agentruntime.TurnID
	ToolCallID           ToolCallID
	ActionDigest         string
	PolicyRevisionDigest string
	Summary              string
	ProposedScope        Scope
	CreatedAt            time.Time
	ExpiresAt            time.Time
}

// DecisionCommand is one idempotent decision request. A denial carries no capability scope.
type DecisionCommand struct {
	IdempotencyKey string
	Decision       Decision
	GrantedScope   Scope
}

type decisionRecord struct {
	actor          Actor
	idempotencyKey string
	decision       Decision
	grantedScope   Scope
	decidedAt      time.Time
}

// Approval is an immutable value snapshot. It has no execution callback or tool adapter.
type Approval struct {
	proposal    Proposal
	state       State
	decision    decisionRecord
	hasDecision bool
	terminalAt  time.Time
}

// New validates and creates one pending immutable Approval request.
func New(proposal Proposal) (Approval, error) {
	if err := validateProposal(proposal); err != nil {
		return Approval{}, err
	}
	return Approval{proposal: proposal, state: StatePending}, nil
}

// Inspect returns the same immutable snapshot only to its owner or a tenant admin.
func (value Approval) Inspect(actor Actor) (Approval, error) {
	if !value.authorized(actor) {
		return Approval{}, ErrNotFoundOrDenied
	}
	return value, nil
}

// Decide advances a pending Approval once. An exact repeated command returns the existing immutable result.
func (value Approval) Decide(actor Actor, command DecisionCommand, now time.Time) (Approval, error) {
	if !value.authorized(actor) {
		return Approval{}, ErrNotFoundOrDenied
	}
	if err := validateDecisionCommand(command); err != nil {
		return Approval{}, err
	}
	if err := value.validateNow(now); err != nil {
		return Approval{}, err
	}
	if value.state != StatePending {
		if value.matches(actor, command) {
			return value, nil
		}
		return Approval{}, ErrConflict
	}
	if !now.Before(value.proposal.ExpiresAt) {
		return value.expire(now), ErrExpired
	}
	if command.Decision == DecisionApproved {
		if !command.GrantedScope.narrowerThan(value.proposal.ProposedScope) || command.GrantedScope.ExpiresAt.After(value.proposal.ExpiresAt) || !command.GrantedScope.ExpiresAt.After(now) {
			return Approval{}, ErrScopeBroadening
		}
	} else if command.GrantedScope != (Scope{}) {
		return Approval{}, errors.New("deny approval decision: granted scope must be absent")
	}
	value.hasDecision = true
	value.decision = decisionRecord{actor: actor, idempotencyKey: command.IdempotencyKey, decision: command.Decision, grantedScope: command.GrantedScope, decidedAt: now}
	value.terminalAt = now
	if command.Decision == DecisionApproved {
		value.state = StateApproved
	} else {
		value.state = StateDenied
	}
	return value, nil
}

// Cancel marks a pending Approval terminal when its governing Turn is cancelled.
func (value Approval) Cancel(now time.Time) (Approval, error) {
	return value.endPending(StateCancelled, now)
}

// Invalidate marks a pending Approval terminal when its policy or governing Turn becomes invalid.
func (value Approval) Invalidate(now time.Time) (Approval, error) {
	return value.endPending(StateInvalidated, now)
}

// State returns the immutable current state.
func (value Approval) State() State { return value.state }

// ID returns the immutable Approval identifier.
func (value Approval) ID() ID { return value.proposal.ID }

// ActionDigest returns the immutable digest of the normalized requested action.
func (value Approval) ActionDigest() string { return value.proposal.ActionDigest }

// CreatedAt returns the immutable proposal creation time.
func (value Approval) CreatedAt() time.Time { return value.proposal.CreatedAt }

// ExpiresAt returns the immutable proposal expiry time.
func (value Approval) ExpiresAt() time.Time { return value.proposal.ExpiresAt }

// ProposedScope returns the immutable bounded proposed scope.
func (value Approval) ProposedScope() Scope { return value.proposal.ProposedScope }

// Decision returns a copied decision record when a human decision was recorded.
func (value Approval) Decision() *DecisionCommand {
	if !value.hasDecision {
		return nil
	}
	return &DecisionCommand{IdempotencyKey: value.decision.idempotencyKey, Decision: value.decision.decision, GrantedScope: value.decision.grantedScope}
}

func (value Approval) authorized(actor Actor) bool {
	return actor.valid() && actor.TenantID == value.proposal.Owner.TenantID && (actor.PrincipalID == value.proposal.Owner.PrincipalID || actor.Admin)
}

func (value Approval) validateNow(now time.Time) error {
	if !validUTC(now) || now.Before(value.proposal.CreatedAt) {
		return errors.New("approval decision time is invalid")
	}
	return nil
}

func (value Approval) expire(now time.Time) Approval {
	if value.state == StatePending {
		value.state = StateExpired
		value.terminalAt = now
	}
	return value
}

func (value Approval) endPending(next State, now time.Time) (Approval, error) {
	if err := value.validateNow(now); err != nil {
		return Approval{}, err
	}
	if !now.Before(value.proposal.ExpiresAt) {
		return value.expire(now), ErrExpired
	}
	if value.state != StatePending {
		return Approval{}, ErrConflict
	}
	value.state, value.terminalAt = next, now
	return value, nil
}

func (value Approval) matches(actor Actor, command DecisionCommand) bool {
	return value.hasDecision && value.decision.actor == actor && value.decision.idempotencyKey == command.IdempotencyKey && value.decision.decision == command.Decision && value.decision.grantedScope == command.GrantedScope
}

func validateProposal(proposal Proposal) error {
	if !validID(string(proposal.ID), "appr_") || !proposal.Owner.valid() || !validID(string(proposal.ToolCallID), "tcall_") || !validDigest(proposal.ActionDigest) || !validDigest(proposal.PolicyRevisionDigest) || !validSummary(proposal.Summary) || !proposal.ProposedScope.valid() || !validUTC(proposal.CreatedAt) || !validUTC(proposal.ExpiresAt) || !proposal.ExpiresAt.After(proposal.CreatedAt) || proposal.ExpiresAt.After(proposal.CreatedAt.Add(maximumApprovalWindow)) || proposal.ProposedScope.ExpiresAt.Before(proposal.CreatedAt) || proposal.ProposedScope.ExpiresAt.After(proposal.ExpiresAt) {
		return errors.New("approval proposal is invalid")
	}
	if _, err := agentruntime.ParseSessionID(proposal.SessionID.String()); err != nil {
		return errors.Wrap(err, "approval proposal session ID")
	}
	if _, err := agentruntime.ParseTurnID(proposal.TurnID.String()); err != nil {
		return errors.Wrap(err, "approval proposal turn ID")
	}
	return nil
}

func validateDecisionCommand(command DecisionCommand) error {
	if !boundedIdentity(command.IdempotencyKey) || (command.Decision != DecisionApproved && command.Decision != DecisionDenied) {
		return errors.New("approval decision command is invalid")
	}
	return nil
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

func validSummary(value string) bool {
	if len(value) == 0 || len(value) > maxSummaryBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func boundedIdentity(value string) bool {
	return len(value) > 0 && len(value) <= maxIdentityBytes && !strings.ContainsAny(value, "\x00\r\n")
}

func validUTC(value time.Time) bool { return !value.IsZero() && value.Location() == time.UTC }
