// Package kernel owns deterministic Agent, Session, Input, Turn, and Product-event transitions.
package kernel

import (
	"context"
	"sync"

	"github.com/cockroachdb/errors"
)

// Scope is an authenticated ownership boundary; its value is never exposed as an object ID.
type Scope string

// ParseScope validates a bounded composition-root ownership scope.
func ParseScope(value string) (Scope, error) {
	if len(value) == 0 || len(value) > 128 {
		return "", errors.New("parse runtime scope: invalid length")
	}
	for _, character := range value {
		if !scopeCharacter(character) {
			return "", errors.New("parse runtime scope: invalid character")
		}
	}
	return Scope(value), nil
}

func scopeCharacter(character rune) bool {
	return (character >= 'a' && character <= 'z') ||
		(character >= 'A' && character <= 'Z') ||
		(character >= '0' && character <= '9') ||
		character == '-' || character == '_'
}

// Repository atomically commits one tenant aggregate transition.
//
// Adapters must execute change against an isolated copy and commit only when it
// returns nil and ctx remains active. This keeps state-machine decisions in the
// kernel while allowing PostgreSQL to become the durable authority.
type Repository interface {
	Transact(context.Context, Scope, func(*TenantState) error) error
	View(context.Context, Scope, func(*TenantState) error) error
}

// MemoryRepository is a deterministic Repository for kernel and composition tests.
type MemoryRepository struct {
	mu     sync.Mutex
	states map[Scope]*TenantState
}

// NewMemoryRepository creates an empty isolated in-memory Repository.
func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{states: make(map[Scope]*TenantState)}
}

// Transact applies and atomically commits one transition unless the context is cancelled.
func (repository *MemoryRepository) Transact(ctx context.Context, scope Scope, change func(*TenantState) error) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if change == nil {
		return errors.New("transact runtime state: change is required")
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	state := repository.states[scope]
	if state == nil {
		state = newTenantState()
	}
	candidate := state.clone()
	if err := change(candidate); err != nil {
		return err
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	repository.states[scope] = candidate
	return nil
}

// View reads an isolated snapshot without permitting mutation of stored state.
func (repository *MemoryRepository) View(ctx context.Context, scope Scope, inspect func(*TenantState) error) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if inspect == nil {
		return errors.New("view runtime state: inspection is required")
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	state := repository.states[scope]
	if state == nil {
		state = newTenantState()
	}
	return inspect(state.clone())
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("runtime context is required")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
