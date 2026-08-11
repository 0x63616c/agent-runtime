package runtimepostgres

import (
	"context"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
)

// LifecycleAction is one operator-only state lifecycle operation.
type LifecycleAction string

const (
	// LifecycleEraseTenant permanently removes one tenant's PostgreSQL state metadata.
	LifecycleEraseTenant LifecycleAction = "erase_tenant"
)

// LifecycleRequest binds an operator authorization reference to one bounded action.
type LifecycleRequest struct {
	Action          LifecycleAction
	Tenant          runtimecontent.TenantID
	AuthorizationID string
}

// LifecycleAuthorizer verifies an operator-owned authorization outside the runtime public API.
type LifecycleAuthorizer interface {
	AuthorizeLifecycle(context.Context, LifecycleRequest) error
}

// EraseTenant removes one tenant's state snapshot and catalog row after an
// operator authorizer accepts the exact request. Content objects and physical
// PostgreSQL backup/PITR remain separate declared operator actions.
func (store *RuntimeStateStore) EraseTenant(ctx context.Context, authorizer LifecycleAuthorizer, request LifecycleRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil || store.pool == nil || authorizer == nil || request.Action != LifecycleEraseTenant || request.Tenant == "" || !validLifecycleAuthorizationID(request.AuthorizationID) {
		return runtimestate.ErrNotFoundOrDenied
	}
	if err := authorizer.AuthorizeLifecycle(ctx, request); err != nil {
		return runtimestate.ErrNotFoundOrDenied
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return runtimestate.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, string(request.Tenant)); err != nil {
		return runtimestate.ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `DELETE FROM runtime.runtime_state_snapshots WHERE tenant_id = $1`, string(request.Tenant)); err != nil {
		return runtimestate.ErrUnavailable
	}
	result, err := tx.Exec(ctx, `DELETE FROM runtime.tenants WHERE tenant_id = $1`, string(request.Tenant))
	if err != nil {
		return runtimestate.ErrUnavailable
	}
	if result.RowsAffected() != 1 {
		return runtimestate.ErrNotFoundOrDenied
	}
	if err := tx.Commit(ctx); err != nil {
		return runtimestate.ErrUnavailable
	}
	return nil
}

func validLifecycleAuthorizationID(value string) bool {
	return len(value) >= 16 && len(value) <= 128 && !strings.ContainsAny(value, "\x00\r\n")
}
