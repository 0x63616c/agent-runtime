package sandboxcontrol

import (
	"context"
	"encoding/json"
	"math"

	"github.com/0x63616c/agent-runtime/sandbox"
	"github.com/cockroachdb/errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const maxResourceProjectionBytes = 64 << 10

// PostgresResourceReadModel persists sandbox and process metadata together
// with the operation lifecycle transition that observed it. It is deliberately
// separate from PostgresLedger: callers must opt into these projection-aware
// methods rather than allowing a bare operation target to become a resource
// response.
//
// It currently has no public transport wiring. Output replay remains a
// separate prerequisite because host output receipts retain only metadata, not
// redacted bytes.
type PostgresResourceReadModel struct {
	ledger *PostgresLedger
}

// NewPostgresResourceReadModel binds a preconfigured pool. The operator must
// have applied the sandbox-control migrations before it is used.
func NewPostgresResourceReadModel(pool *pgxpool.Pool) (*PostgresResourceReadModel, error) {
	ledger, err := NewPostgresLedger(pool)
	if err != nil {
		return nil, err
	}
	return &PostgresResourceReadModel{ledger: ledger}, nil
}

// AcceptSandbox durably accepts a sandbox operation and its initial complete
// metadata in one transaction. The operation target is bound to the resource
// ID, so a caller cannot attach metadata to a guessed resource.
func (model *PostgresResourceReadModel) AcceptSandbox(ctx context.Context, operation Operation, value sandbox.SandboxInfo) (Operation, bool, error) {
	body, err := marshalResourceProjection(ctx, operation.Principal, string(value.ID), value)
	if err != nil {
		return Operation{}, false, err
	}
	return model.acceptProjection(ctx, operation, "sandbox", string(value.ID), body)
}

// AcceptProcess durably accepts a process operation and its initial complete
// metadata in one transaction.
func (model *PostgresResourceReadModel) AcceptProcess(ctx context.Context, operation Operation, value sandbox.ProcessInfo) (Operation, bool, error) {
	body, err := marshalResourceProjection(ctx, operation.Principal, string(value.ID), value)
	if err != nil {
		return Operation{}, false, err
	}
	return model.acceptProjection(ctx, operation, "process", string(value.ID), body)
}

// TransitionSandbox changes one sandbox operation and replaces its complete
// metadata projection atomically.
func (model *PostgresResourceReadModel) TransitionSandbox(ctx context.Context, principal, operationID string, version uint64, next State, value sandbox.SandboxInfo) (Operation, error) {
	body, err := marshalResourceProjection(ctx, principal, string(value.ID), value)
	if err != nil {
		return Operation{}, err
	}
	return model.transitionProjection(ctx, principal, operationID, version, next, "sandbox", string(value.ID), body)
}

// TransitionProcess changes one process operation and replaces its complete
// metadata projection atomically.
func (model *PostgresResourceReadModel) TransitionProcess(ctx context.Context, principal, operationID string, version uint64, next State, value sandbox.ProcessInfo) (Operation, error) {
	body, err := marshalResourceProjection(ctx, principal, string(value.ID), value)
	if err != nil {
		return Operation{}, err
	}
	return model.transitionProjection(ctx, principal, operationID, version, next, "process", string(value.ID), body)
}

func (model *PostgresResourceReadModel) acceptProjection(ctx context.Context, operation Operation, kind, resourceID string, body []byte) (Operation, bool, error) {
	operation = normalizeOperationForPersistence(operation)
	if err := validateOperation(operation); err != nil {
		return Operation{}, false, err
	}
	if operation.TargetKind != kind || operation.TargetID != resourceID || !matchesAdmittedResourceProjection(operation.ResourceProjectionBinding, ResourceProjectionKind(kind), resourceID, body) {
		return Operation{}, false, ErrConflict
	}
	var accepted Operation
	var replay bool
	err := model.ledger.transaction(ctx, "accept sandbox resource projection", func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			INSERT INTO runtime.sandbox_operations (
				principal, tenant, operation_id, kind, target_kind, target_id,
				input_digest, canonical_digest, effective_spec_digest, capability_digest,
				dispatch_body, resource_projection_kind, resource_projection_id,
				resource_projection_admitted_snapshot_digest, resource_projection_transition,
				state, version, accepted_at, retention_expires_at,
				cleanup_required, retained_output_bytes, assignment_fencing_token
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, 1, $17, $18, $19, $20, 0)
			ON CONFLICT DO NOTHING
			RETURNING `+selectOperationColumns,
			operation.Principal, operation.Tenant, operation.ID, operation.Kind, operation.TargetKind, operation.TargetID,
			operationInputDigest(operation), operation.CanonicalDigest, operation.EffectiveSpecDigest, operation.CapabilityDigest,
			operation.DispatchBody, resourceProjectionKindValue(operation), resourceProjectionIDValue(operation),
			resourceProjectionDigestValue(operation), resourceProjectionTransitionValue(operation),
			StateAccepted, operation.AcceptedAt.UTC(), operation.RetentionExpiresAt.UTC(), operation.CleanupRequired, retainedOutputLimit(operation))
		inserted, err := scanOperation(row)
		switch {
		case err == nil:
			if err := upsertResourceProjection(ctx, tx, inserted, kind, resourceID, body); err != nil {
				return err
			}
			accepted = inserted
			return insertOutbox(ctx, tx, inserted, OutboxAccepted)
		case !errors.Is(err, pgx.ErrNoRows):
			return errors.Wrap(err, "insert sandbox operation")
		}

		prior, err := lockedOperation(ctx, tx, operation.Principal, operation.ID)
		if err != nil {
			return err
		}
		if prior.State == StateTombstoned {
			return ErrOperationIDExpired
		}
		if operationInputDigest(prior) != operationInputDigest(operation) || prior.TargetKind != kind || prior.TargetID != resourceID || !sameResourceProjectionBinding(prior.ResourceProjectionBinding, operation.ResourceProjectionBinding) {
			return ErrConflict
		}
		// Version one is the initial acceptance snapshot and must match exactly.
		// Later retries reconnect to a newer lifecycle projection, which is
		// deliberately allowed: reissuing an already accepted operation must not
		// overwrite state observed after its initial admission.
		matches, err := resourceProjectionMatches(ctx, tx, operation.Principal, kind, resourceID, body)
		if err != nil || (prior.Version == 1 && !matches) {
			if err != nil {
				return err
			}
			return ErrConflict
		}
		accepted, replay = prior, true
		return nil
	})
	if err != nil {
		return Operation{}, false, err
	}
	return accepted, replay, nil
}

func (model *PostgresResourceReadModel) transitionProjection(ctx context.Context, principal, operationID string, version uint64, next State, kind, resourceID string, body []byte) (Operation, error) {
	if !validBounded(principal, maxPrincipalBytes) || !validBounded(operationID, maxOperationIDBytes) || version == 0 || version > math.MaxInt64 {
		return Operation{}, ErrInvalidTransition
	}
	var updated Operation
	err := model.ledger.transaction(ctx, "transition sandbox resource projection", func(tx pgx.Tx) error {
		current, err := lockedOperation(ctx, tx, principal, operationID)
		if err != nil {
			return err
		}
		if current.Version != version || !permits(current.State, next) {
			return ErrInvalidTransition
		}
		if current.TargetKind != kind || current.TargetID != resourceID || current.ResourceProjectionBinding == nil || current.ResourceProjectionBinding.Transition != ResourceProjectionReplaceSnapshot {
			return ErrConflict
		}
		current.State, current.Version = next, current.Version+1
		if err := updateOperation(ctx, tx, current); err != nil {
			return err
		}
		if err := upsertResourceProjection(ctx, tx, current, kind, resourceID, body); err != nil {
			return err
		}
		updated = current
		return insertOutbox(ctx, tx, current, OutboxStateChanged)
	})
	return updated, err
}

func matchesAdmittedResourceProjection(binding *ResourceProjectionBinding, kind ResourceProjectionKind, resourceID string, body []byte) bool {
	return binding != nil && binding.Kind == kind && binding.ResourceID == resourceID && binding.AdmittedSnapshotDigest == projectionSnapshotDigest(body) && binding.Transition == ResourceProjectionReplaceSnapshot
}

func (model *PostgresResourceReadModel) GetSandbox(ctx context.Context, principal string, id sandbox.SandboxID) (sandbox.SandboxInfo, error) {
	if err := validateProjectionInput(ctx, principal, string(id)); err != nil {
		return sandbox.SandboxInfo{}, err
	}
	body, err := readResourceProjection(ctx, model.ledger.pool, principal, "sandbox", string(id))
	if err != nil {
		return sandbox.SandboxInfo{}, err
	}
	var value sandbox.SandboxInfo
	if err := json.Unmarshal(body, &value); err != nil || value.ID != id {
		return sandbox.SandboxInfo{}, errors.New("read sandbox resource projection: invalid persisted sandbox metadata")
	}
	return copySandboxInfo(value), nil
}

func (model *PostgresResourceReadModel) GetProcess(ctx context.Context, principal string, id sandbox.ProcessID) (sandbox.ProcessInfo, error) {
	if err := validateProjectionInput(ctx, principal, string(id)); err != nil {
		return sandbox.ProcessInfo{}, err
	}
	body, err := readResourceProjection(ctx, model.ledger.pool, principal, "process", string(id))
	if err != nil {
		return sandbox.ProcessInfo{}, err
	}
	var value sandbox.ProcessInfo
	if err := json.Unmarshal(body, &value); err != nil || value.ID != id {
		return sandbox.ProcessInfo{}, errors.New("read sandbox resource projection: invalid persisted process metadata")
	}
	return copyProcessInfo(value), nil
}

func marshalResourceProjection(ctx context.Context, principal, resourceID string, value any) ([]byte, error) {
	if err := validateProjectionInput(ctx, principal, resourceID); err != nil {
		return nil, err
	}
	body, err := json.Marshal(value)
	if err != nil || len(body) < 2 || len(body) > maxResourceProjectionBytes {
		return nil, errors.New("persist sandbox resource projection: metadata is invalid or exceeds 64 KiB")
	}
	return body, nil
}

type projectionQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readResourceProjection(ctx context.Context, query projectionQuery, principal, kind, resourceID string) ([]byte, error) {
	var body []byte
	err := query.QueryRow(ctx, `SELECT body FROM runtime.sandbox_resource_projections WHERE principal=$1 AND resource_kind=$2 AND resource_id=$3`, principal, kind, resourceID).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFoundOrDenied
	}
	if err != nil {
		return nil, errors.Wrap(err, "read sandbox resource projection")
	}
	return body, nil
}

func resourceProjectionMatches(ctx context.Context, query projectionQuery, principal, kind, resourceID string, body []byte) (bool, error) {
	var matches bool
	err := query.QueryRow(ctx, `SELECT body = $4::jsonb FROM runtime.sandbox_resource_projections WHERE principal=$1 AND resource_kind=$2 AND resource_id=$3`, principal, kind, resourceID, body).Scan(&matches)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFoundOrDenied
	}
	if err != nil {
		return false, errors.Wrap(err, "compare sandbox resource projection")
	}
	return matches, nil
}

func upsertResourceProjection(ctx context.Context, tx pgx.Tx, operation Operation, kind, resourceID string, body []byte) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO runtime.sandbox_resource_projections
			(principal, resource_kind, resource_id, operation_id, operation_version, body)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb)
		ON CONFLICT (principal, resource_kind, resource_id) DO UPDATE
		SET operation_id=EXCLUDED.operation_id, operation_version=EXCLUDED.operation_version,
			body=EXCLUDED.body`,
		operation.Principal, kind, resourceID, operation.ID, int64(operation.Version), body)
	return errors.Wrap(err, "persist sandbox resource projection")
}
