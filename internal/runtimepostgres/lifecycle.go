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

// CoordinatedErasureReceipt records content progress before metadata erasure.
type CoordinatedErasureReceipt struct {
	Tenant  runtimecontent.TenantID
	Content runtimecontent.ErasureReceipt
}

// EraseTenantAndContent removes exact state-referenced immutable content, then
// removes the PostgreSQL metadata in the same tenant-locked transaction. A
// content failure leaves metadata intact so the explicit request can be retried.
func (store *RuntimeStateStore) EraseTenantAndContent(ctx context.Context, authorizer LifecycleAuthorizer, request LifecycleRequest, content *runtimecontent.TenantErasureController) (CoordinatedErasureReceipt, error) {
	if err := ctx.Err(); err != nil {
		return CoordinatedErasureReceipt{}, err
	}
	if store == nil || store.pool == nil || authorizer == nil || content == nil || request.Action != LifecycleEraseTenant || request.Tenant == "" || !validLifecycleAuthorizationID(request.AuthorizationID) {
		return CoordinatedErasureReceipt{}, runtimestate.ErrNotFoundOrDenied
	}
	if err := authorizer.AuthorizeLifecycle(ctx, request); err != nil {
		return CoordinatedErasureReceipt{}, runtimestate.ErrNotFoundOrDenied
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return CoordinatedErasureReceipt{}, runtimestate.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, string(request.Tenant)); err != nil {
		return CoordinatedErasureReceipt{}, runtimestate.ErrUnavailable
	}
	state, err := store.load(ctx, tx, request.Tenant)
	if err != nil {
		return CoordinatedErasureReceipt{}, err
	}
	if len(state.Revisions)+len(state.Inputs)+len(state.Artifacts)+len(state.Conversations) == 0 {
		return CoordinatedErasureReceipt{}, runtimestate.ErrNotFoundOrDenied
	}
	references := stateReferences(state)
	receipt, err := content.Erase(ctx, runtimecontent.ErasureRequest{Tenant: request.Tenant, AuthorizationID: request.AuthorizationID, References: references})
	result := CoordinatedErasureReceipt{Tenant: request.Tenant, Content: receipt}
	if err != nil {
		return result, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM runtime.runtime_state_snapshots WHERE tenant_id = $1`, string(request.Tenant)); err != nil {
		return result, runtimestate.ErrUnavailable
	}
	deleted, err := tx.Exec(ctx, `DELETE FROM runtime.tenants WHERE tenant_id = $1`, string(request.Tenant))
	if err != nil {
		return result, runtimestate.ErrUnavailable
	}
	if deleted.RowsAffected() != 1 {
		return result, runtimestate.ErrNotFoundOrDenied
	}
	if err := tx.Commit(ctx); err != nil {
		return result, runtimestate.ErrUnavailable
	}
	return result, nil
}

func stateReferences(state runtimestate.RuntimeState) []runtimecontent.Reference {
	seen := map[string]struct{}{}
	result := []runtimecontent.Reference{}
	appendReference := func(reference runtimecontent.Reference) {
		key := reference.Digest + "\x00" + reference.MediaType
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			result = append(result, reference)
		}
	}
	for _, record := range state.Revisions {
		appendReference(record.Specification)
	}
	for _, record := range state.Inputs {
		appendReference(record.Content)
	}
	for _, record := range state.Artifacts {
		appendReference(record.Reference)
	}
	for _, record := range state.Conversations {
		appendReference(record.Reference)
	}
	return result
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
