package codexsubscription

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// CredentialContextRef is an opaque, operator-configured reference to the
// credential context owned by a pinned Codex process. It is intentionally not
// a filesystem path, token, account name, or URL. The runtime must not use it
// to read, copy, refresh, or otherwise inspect credentials.
type CredentialContextRef string

// LifecycleState is the safe externally observable state of one opaque
// credential context. It contains no credential or account data.
type LifecycleState string

const (
	LifecycleUnavailable  LifecycleState = "unavailable"
	LifecycleLoginPending LifecycleState = "login_pending"
	LifecycleReady        LifecycleState = "ready"
	LifecycleExpired      LifecycleState = "expired"
	LifecycleRejected     LifecycleState = "rejected"
	LifecycleAmbiguous    LifecycleState = "ambiguous"
	LifecycleRevoked      LifecycleState = "revoked"
)

// Status is a redacted snapshot suitable for model-role diagnostics. Reference
// identifies the context but never its storage location or authenticated user.
type Status struct {
	Reference CredentialContextRef
	State     LifecycleState
	UpdatedAt time.Time
}

// Lifecycle coordinates offline credential-lifecycle fixtures. It is not an
// OAuth implementation and has no method that accepts, returns, or persists a
// credential. A production integration must delegate login and refresh to the
// pinned official Codex process after MOD-001 support is independently proven.
//
// Its refresh owner fence models the one-writer constraint: a second model
// worker cannot settle or replace a refresh until the current owner releases
// it. The state is process-local by design; durable deployment coordination is
// a future production composition concern, not evidence of a supported path.
type Lifecycle struct {
	mu       sync.Mutex
	contexts map[CredentialContextRef]contextState
}

type contextState struct {
	status       Status
	refreshOwner string
}

// NewLifecycle creates an empty fixture lifecycle coordinator.
func NewLifecycle() *Lifecycle {
	return &Lifecycle{contexts: make(map[CredentialContextRef]contextState)}
}

// Register declares an operator-reviewed opaque context. Registering an
// existing context preserves its lifecycle and cannot reset a revoked context.
func (lifecycle *Lifecycle) Register(reference CredentialContextRef, now time.Time) (Status, error) {
	if err := validateReference(reference); err != nil {
		return Status{}, err
	}
	if lifecycle == nil {
		return Status{}, errors.New("register Codex credential context: lifecycle is required")
	}
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if state, exists := lifecycle.contexts[reference]; exists {
		return state.status, nil
	}
	status := Status{Reference: reference, State: LifecycleUnavailable, UpdatedAt: now.UTC()}
	lifecycle.contexts[reference] = contextState{status: status}
	return status, nil
}

// BeginLogin records that a user-initiated official Codex login is pending.
// The runtime never receives the browser URL, device code, or credential.
func (lifecycle *Lifecycle) BeginLogin(reference CredentialContextRef, now time.Time) (Status, error) {
	return lifecycle.transition(reference, now, LifecycleLoginPending, LifecycleUnavailable, LifecycleExpired, LifecycleRejected, LifecycleAmbiguous)
}

// CancelLogin returns a pending login to unavailable. Cancellation cannot
// revive a ready, revoked, or otherwise terminal context.
func (lifecycle *Lifecycle) CancelLogin(reference CredentialContextRef, now time.Time) (Status, error) {
	return lifecycle.transition(reference, now, LifecycleUnavailable, LifecycleLoginPending)
}

// CompleteLogin accepts only an outcome already classified by the official
// Codex process. It deliberately has no success credential parameter.
func (lifecycle *Lifecycle) CompleteLogin(reference CredentialContextRef, outcome LifecycleState, now time.Time) (Status, error) {
	if outcome != LifecycleReady && outcome != LifecycleRejected && outcome != LifecycleAmbiguous {
		return Status{}, errors.New("complete Codex credential login: outcome is not declared")
	}
	return lifecycle.transition(reference, now, outcome, LifecycleLoginPending)
}

// AcquireRefresh fences a refresh attempt to one explicit model-role owner.
// It returns a redacted status; callers must delegate actual refresh to Codex.
func (lifecycle *Lifecycle) AcquireRefresh(reference CredentialContextRef, owner string, now time.Time) (Status, error) {
	if err := validateReference(reference); err != nil {
		return Status{}, err
	}
	if !validOwner(owner) {
		return Status{}, errors.New("acquire Codex credential refresh: owner is required")
	}
	if lifecycle == nil {
		return Status{}, errors.New("acquire Codex credential refresh: lifecycle is required")
	}
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	state, exists := lifecycle.contexts[reference]
	if !exists {
		return Status{}, errors.New("acquire Codex credential refresh: context is not registered")
	}
	if state.status.State != LifecycleReady && state.status.State != LifecycleExpired {
		return Status{}, fmt.Errorf("acquire Codex credential refresh: context is %s", state.status.State)
	}
	if state.refreshOwner != "" && state.refreshOwner != owner {
		return Status{}, errors.New("acquire Codex credential refresh: another model owner holds the refresh fence")
	}
	state.refreshOwner = owner
	state.status.UpdatedAt = now.UTC()
	lifecycle.contexts[reference] = state
	return state.status, nil
}

// SettleRefresh records a secret-free outcome for the current refresh owner
// and releases its fence. Rejected or ambiguous outcomes stay visible rather
// than being silently retried as successful credentials.
func (lifecycle *Lifecycle) SettleRefresh(reference CredentialContextRef, owner string, outcome LifecycleState, now time.Time) (Status, error) {
	if outcome != LifecycleReady && outcome != LifecycleExpired && outcome != LifecycleRejected && outcome != LifecycleAmbiguous {
		return Status{}, errors.New("settle Codex credential refresh: outcome is not declared")
	}
	if err := validateReference(reference); err != nil {
		return Status{}, err
	}
	if !validOwner(owner) {
		return Status{}, errors.New("settle Codex credential refresh: owner is required")
	}
	if lifecycle == nil {
		return Status{}, errors.New("settle Codex credential refresh: lifecycle is required")
	}
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	state, exists := lifecycle.contexts[reference]
	if !exists || state.refreshOwner != owner {
		return Status{}, errors.New("settle Codex credential refresh: owner does not hold the refresh fence")
	}
	state.refreshOwner = ""
	state.status.State = outcome
	state.status.UpdatedAt = now.UTC()
	lifecycle.contexts[reference] = state
	return state.status, nil
}

// Revoke records a local logout/revocation observation and fences any active
// refresh. It does not claim remote token revocation.
func (lifecycle *Lifecycle) Revoke(reference CredentialContextRef, now time.Time) (Status, error) {
	return lifecycle.transition(reference, now, LifecycleRevoked, LifecycleUnavailable, LifecycleLoginPending, LifecycleReady, LifecycleExpired, LifecycleRejected, LifecycleAmbiguous)
}

// Status returns a registered context's redacted lifecycle projection.
func (lifecycle *Lifecycle) Status(reference CredentialContextRef) (Status, error) {
	if err := validateReference(reference); err != nil {
		return Status{}, err
	}
	if lifecycle == nil {
		return Status{}, errors.New("read Codex credential status: lifecycle is required")
	}
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	state, exists := lifecycle.contexts[reference]
	if !exists {
		return Status{}, errors.New("read Codex credential status: context is not registered")
	}
	return state.status, nil
}

func (lifecycle *Lifecycle) transition(reference CredentialContextRef, now time.Time, destination LifecycleState, sources ...LifecycleState) (Status, error) {
	if err := validateReference(reference); err != nil {
		return Status{}, err
	}
	if lifecycle == nil {
		return Status{}, errors.New("transition Codex credential lifecycle: lifecycle is required")
	}
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	state, exists := lifecycle.contexts[reference]
	if !exists {
		return Status{}, errors.New("transition Codex credential lifecycle: context is not registered")
	}
	if state.refreshOwner != "" {
		return Status{}, errors.New("transition Codex credential lifecycle: refresh is fenced by a model owner")
	}
	if !containsState(sources, state.status.State) {
		return Status{}, fmt.Errorf("transition Codex credential lifecycle: cannot move %s to %s", state.status.State, destination)
	}
	state.status.State = destination
	state.status.UpdatedAt = now.UTC()
	lifecycle.contexts[reference] = state
	return state.status, nil
}

func validateReference(reference CredentialContextRef) error {
	value := string(reference)
	if len(value) < 3 || len(value) > 128 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "/\\\n\r\t:@") {
		return errors.New("validate Codex credential context reference: reference must be an opaque identifier")
	}
	for _, character := range value {
		if !isOpaqueReferenceCharacter(character) {
			return errors.New("validate Codex credential context reference: reference must be an opaque identifier")
		}
	}
	return nil
}

func isOpaqueReferenceCharacter(character rune) bool {
	return (character >= 'a' && character <= 'z') ||
		(character >= 'A' && character <= 'Z') ||
		(character >= '0' && character <= '9') ||
		character == '-' || character == '_' || character == '.'
}

func validOwner(value string) bool {
	return len(value) > 0 && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "/\\\n\r\t:@")
}

func containsState(states []LifecycleState, want LifecycleState) bool {
	for _, state := range states {
		if state == want {
			return true
		}
	}
	return false
}
