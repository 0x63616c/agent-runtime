package runtimepostgres

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

// LifecycleAction is one operator-only state lifecycle operation.
type LifecycleAction string

const (
	// LifecycleEraseTenant permanently removes one tenant's PostgreSQL state metadata.
	LifecycleEraseTenant LifecycleAction = "erase_tenant"
	// LifecycleCollectExpired removes only retention-expired content metadata and
	// exact unreferenced immutable objects for one tenant.
	LifecycleCollectExpired LifecycleAction = "collect_expired"
)

// LifecycleRequest binds an operator authorization reference to one bounded action.
type LifecycleRequest struct {
	Action          LifecycleAction
	Tenant          runtimecontent.TenantID
	AuthorizationID string
	EvaluatedAt     time.Time
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

// RetentionCollectionReceipt reports a bounded, operator-only physical
// collection result. It never includes object keys or content bytes.
type RetentionCollectionReceipt struct {
	Tenant          runtimecontent.TenantID
	RemovedMetadata uint64
	Content         runtimecontent.ErasureReceipt
	CollectionAt    time.Time
}

// CollectExpiredAndContent physically removes retention-expired immutable
// content metadata and only those exact objects which are no longer referenced
// by surviving metadata. It holds the tenant advisory lock throughout the
// content/metadata boundary: a content failure leaves metadata intact for a
// retry, and no bucket listing is used as deletion authority.
func (store *RuntimeStateStore) CollectExpiredAndContent(ctx context.Context, authorizer LifecycleAuthorizer, request LifecycleRequest, content *runtimecontent.TenantErasureController) (RetentionCollectionReceipt, error) {
	if err := ctx.Err(); err != nil {
		return RetentionCollectionReceipt{}, err
	}
	if store == nil || store.pool == nil || authorizer == nil || content == nil || request.Action != LifecycleCollectExpired || request.Tenant == "" || request.EvaluatedAt.IsZero() || !validLifecycleAuthorizationID(request.AuthorizationID) {
		return RetentionCollectionReceipt{}, runtimestate.ErrNotFoundOrDenied
	}
	if err := authorizer.AuthorizeLifecycle(ctx, request); err != nil {
		return RetentionCollectionReceipt{}, runtimestate.ErrNotFoundOrDenied
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return RetentionCollectionReceipt{}, runtimestate.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := bindTenant(ctx, tx, request.Tenant); err != nil {
		return RetentionCollectionReceipt{}, runtimestate.ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, string(request.Tenant)); err != nil {
		return RetentionCollectionReceipt{}, runtimestate.ErrUnavailable
	}
	state, err := store.load(ctx, tx, request.Tenant)
	if err != nil {
		return RetentionCollectionReceipt{}, err
	}
	compacted, candidates, removed := compactExpiredContentMetadata(state, request.EvaluatedAt.UTC())
	result := RetentionCollectionReceipt{Tenant: request.Tenant, RemovedMetadata: removed, CollectionAt: request.EvaluatedAt.UTC()}
	if removed == 0 {
		return result, nil
	}
	remaining := referenceSet(stateReferences(compacted))
	toDelete := unreferenced(candidates, remaining)
	if len(toDelete) > 0 {
		receipt, err := content.Erase(ctx, runtimecontent.ErasureRequest{Tenant: request.Tenant, AuthorizationID: request.AuthorizationID, References: toDelete})
		result.Content = receipt
		if err != nil {
			return result, err
		}
	}
	encoded, err := json.Marshal(compacted)
	if err != nil {
		return result, runtimestate.ErrIntegrity
	}
	if _, err := tx.Exec(ctx, `UPDATE runtime.runtime_state_snapshots SET generation = generation + 1, state = $2::jsonb, updated_at = now() WHERE tenant_id = $1`, string(request.Tenant), encoded); err != nil {
		return result, runtimestate.ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `UPDATE runtime.tenant_retention_jobs
		SET last_collection_at = $2, last_authorization_id = $3, next_collection_at = $2 + interval '24 hours'
		WHERE tenant_id = $1`, string(request.Tenant), request.EvaluatedAt.UTC(), request.AuthorizationID); err != nil {
		return result, runtimestate.ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return result, runtimestate.ErrUnavailable
	}
	return result, nil
}

func compactExpiredContentMetadata(state runtimestate.RuntimeState, at time.Time) (runtimestate.RuntimeState, []runtimecontent.Reference, uint64) {
	compacted := state.Clone()
	candidates := []runtimecontent.Reference{}
	removed := uint64(0)
	keepReference := func(until time.Time, reference runtimecontent.Reference) bool {
		if until.After(at) {
			return true
		}
		candidates = append(candidates, reference)
		removed++
		return false
	}
	compacted.Inputs = filterInputs(compacted.Inputs, keepReference)
	compacted.Artifacts = filterArtifacts(compacted.Artifacts, keepReference)
	compacted.Conversations = filterConversations(compacted.Conversations, keepReference)
	// Agent revisions remain pinned while any Session names them. Their
	// specification body is therefore never collected behind a live Session.
	pinned := map[string]struct{}{}
	for _, session := range compacted.Sessions {
		pinned[string(session.RevisionID)] = struct{}{}
	}
	revisions := compacted.Revisions[:0]
	for _, record := range compacted.Revisions {
		if record.RetainUntil.After(at) || hasRevision(pinned, record.RevisionID) {
			revisions = append(revisions, record)
			continue
		}
		candidates = append(candidates, record.Specification)
		removed++
	}
	compacted.Revisions = revisions
	return compacted, candidates, removed
}

func filterInputs(records []runtimestate.InputRecord, keep func(time.Time, runtimecontent.Reference) bool) []runtimestate.InputRecord {
	result := records[:0]
	for _, record := range records {
		if keep(record.RetentionUntil, record.Content) {
			result = append(result, record)
		}
	}
	return result
}

func filterArtifacts(records []runtimestate.ArtifactRecord, keep func(time.Time, runtimecontent.Reference) bool) []runtimestate.ArtifactRecord {
	result := records[:0]
	for _, record := range records {
		if keep(record.RetainUntil, record.Reference) {
			result = append(result, record)
		}
	}
	return result
}

func filterConversations(records []runtimestate.ConversationRecord, keep func(time.Time, runtimecontent.Reference) bool) []runtimestate.ConversationRecord {
	result := records[:0]
	for _, record := range records {
		if keep(record.RetainUntil, record.Reference) {
			result = append(result, record)
		}
	}
	return result
}

func hasRevision(pinned map[string]struct{}, revisionID agentruntime.AgentRevisionID) bool {
	_, exists := pinned[string(revisionID)]
	return exists
}

func referenceSet(references []runtimecontent.Reference) map[string]struct{} {
	result := map[string]struct{}{}
	for _, reference := range references {
		result[reference.Digest+"\x00"+reference.MediaType] = struct{}{}
	}
	return result
}

func unreferenced(candidates []runtimecontent.Reference, remaining map[string]struct{}) []runtimecontent.Reference {
	seen, result := map[string]struct{}{}, []runtimecontent.Reference{}
	for _, reference := range candidates {
		key := reference.Digest + "\x00" + reference.MediaType
		if _, exists := remaining[key]; exists {
			continue
		}
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			result = append(result, reference)
		}
	}
	return result
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
	if err := bindTenant(ctx, tx, request.Tenant); err != nil {
		return CoordinatedErasureReceipt{}, runtimestate.ErrUnavailable
	}
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
	if err := bindTenant(ctx, tx, request.Tenant); err != nil {
		return runtimestate.ErrUnavailable
	}
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
