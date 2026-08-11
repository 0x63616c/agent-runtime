package runtimepostgres

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/jackc/pgx/v5"
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

// CollectExpiredAndContent durably removes retention-expired immutable content
// metadata and records exact object-deletion intent before external deletion.
// A lost external acknowledgement leaves the intent available for an explicit
// retry; no bucket listing is used as deletion authority.
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
	if removed > 0 {
		remaining := referenceSet(stateReferences(compacted))
		toDelete := unreferenced(candidates, remaining)
		if len(toDelete) > 0 {
			if err := store.recordPendingContentDeletions(ctx, tx, request.Tenant, request.AuthorizationID, toDelete); err != nil {
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
	}
	updated, err := tx.Exec(ctx, `UPDATE runtime.tenant_retention_jobs
		SET last_collection_at = $2, last_authorization_id = $3, next_collection_at = $4
		WHERE tenant_id = $1`, string(request.Tenant), request.EvaluatedAt.UTC(), request.AuthorizationID, request.EvaluatedAt.UTC().Add(24*time.Hour))
	if err != nil || updated.RowsAffected() != 1 {
		return result, runtimestate.ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return result, runtimestate.ErrUnavailable
	}
	receipt, err := store.reconcilePendingContentDeletions(ctx, request.Tenant, request.AuthorizationID, content)
	result.Content = receipt
	if err != nil {
		return result, err
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

// EraseTenantAndContent removes PostgreSQL metadata and records exact immutable
// content-deletion intent in one tenant-locked transaction. It then reconciles
// those intent records with the external content authority; a failed or unknown
// deletion acknowledgement remains durable for the same explicit retry.
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
	references := stateReferences(state)
	result := CoordinatedErasureReceipt{Tenant: request.Tenant}
	if len(references) > 0 {
		if err := store.recordPendingContentDeletions(ctx, tx, request.Tenant, request.AuthorizationID, references); err != nil {
			return result, err
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM runtime.runtime_state_snapshots WHERE tenant_id = $1`, string(request.Tenant)); err != nil {
		return result, runtimestate.ErrUnavailable
	}
	// V5 retention scheduling is tenant-owned metadata. Remove it in the same
	// bound transaction before deleting the catalog row; leaving it would make
	// the foreign-key restriction turn an authorized erase into an unavailable
	// outcome after content had already been erased.
	if _, err := tx.Exec(ctx, `DELETE FROM runtime.tenant_retention_jobs WHERE tenant_id = $1`, string(request.Tenant)); err != nil {
		return result, runtimestate.ErrUnavailable
	}
	deleted, err := tx.Exec(ctx, `DELETE FROM runtime.tenants WHERE tenant_id = $1`, string(request.Tenant))
	if err != nil {
		return result, runtimestate.ErrUnavailable
	}
	if deleted.RowsAffected() != 1 && len(references) == 0 {
		pending, err := store.pendingContentDeletions(ctx, tx, request.Tenant)
		if err != nil {
			return result, err
		}
		if len(pending) == 0 {
			return result, runtimestate.ErrNotFoundOrDenied
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return result, runtimestate.ErrUnavailable
	}
	receipt, err := store.reconcilePendingContentDeletions(ctx, request.Tenant, request.AuthorizationID, content)
	result.Content = receipt
	if err != nil {
		return result, err
	}
	return result, nil
}

type pendingContentDeletion struct {
	Reference       runtimecontent.Reference
	AuthorizationID string
}

type stateRows interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func (store *RuntimeStateStore) recordPendingContentDeletions(ctx context.Context, tx pgx.Tx, tenant runtimecontent.TenantID, authorizationID string, references []runtimecontent.Reference) error {
	for _, reference := range references {
		if _, err := tx.Exec(ctx, `INSERT INTO runtime.pending_content_deletions
			(tenant_id, digest, media_type, size_bytes, authorization_id, requested_at)
			VALUES ($1, $2, $3, $4, $5, now())
			ON CONFLICT (tenant_id, digest, media_type) DO NOTHING`, string(tenant), reference.Digest, reference.MediaType, reference.SizeBytes, authorizationID); err != nil {
			return runtimestate.ErrUnavailable
		}
	}
	return nil
}

func (store *RuntimeStateStore) pendingContentDeletions(ctx context.Context, query stateRows, tenant runtimecontent.TenantID) ([]pendingContentDeletion, error) {
	rows, err := query.Query(ctx, `SELECT digest, media_type, size_bytes, authorization_id
		FROM runtime.pending_content_deletions
		WHERE tenant_id = $1
		ORDER BY authorization_id, digest, media_type`, string(tenant))
	if err != nil {
		return nil, runtimestate.ErrUnavailable
	}
	defer rows.Close()
	result := []pendingContentDeletion{}
	for rows.Next() {
		var deletion pendingContentDeletion
		if err := rows.Scan(&deletion.Reference.Digest, &deletion.Reference.MediaType, &deletion.Reference.SizeBytes, &deletion.AuthorizationID); err != nil {
			return nil, runtimestate.ErrUnavailable
		}
		result = append(result, deletion)
	}
	if rows.Err() != nil {
		return nil, runtimestate.ErrUnavailable
	}
	return result, nil
}

func (store *RuntimeStateStore) reconcilePendingContentDeletions(ctx context.Context, tenant runtimecontent.TenantID, authorizationID string, content *runtimecontent.TenantErasureController) (runtimecontent.ErasureReceipt, error) {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return runtimecontent.ErasureReceipt{}, runtimestate.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := bindTenant(ctx, tx, tenant); err != nil {
		return runtimecontent.ErasureReceipt{}, runtimestate.ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, string(tenant)); err != nil {
		return runtimecontent.ErasureReceipt{}, runtimestate.ErrUnavailable
	}
	pending, err := store.pendingContentDeletions(ctx, tx, tenant)
	if err != nil {
		return runtimecontent.ErasureReceipt{}, err
	}
	if len(pending) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE runtime.pending_content_deletions
			SET authorization_id = $2, requested_at = now()
			WHERE tenant_id = $1`, string(tenant), authorizationID); err != nil {
			return runtimecontent.ErasureReceipt{}, runtimestate.ErrUnavailable
		}
	}
	result := runtimecontent.ErasureReceipt{Tenant: tenant, Deleted: make([]runtimecontent.Reference, 0, len(pending))}
	for _, deletion := range pending {
		receipt, err := content.Erase(ctx, runtimecontent.ErasureRequest{Tenant: tenant, AuthorizationID: authorizationID, References: []runtimecontent.Reference{deletion.Reference}})
		result.Deleted = append(result.Deleted, receipt.Deleted...)
		if receipt.Failed != nil {
			failed := *receipt.Failed
			result.Failed = &failed
		}
		if err != nil {
			return result, err
		}
	}
	if len(pending) > 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM runtime.pending_content_deletions WHERE tenant_id = $1`, string(tenant)); err != nil {
			return result, runtimestate.ErrUnavailable
		}
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
	if _, err := tx.Exec(ctx, `DELETE FROM runtime.tenant_retention_jobs WHERE tenant_id = $1`, string(request.Tenant)); err != nil {
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
