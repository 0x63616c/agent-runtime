package sandboxcontrol

import (
	"context"
	"math"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const serializableAttempts = 3

// PostgresLedger is the production DurableStore. Its constructor never creates
// or migrates infrastructure; an audited operator must apply the declared
// schema before the control role starts.
type PostgresLedger struct {
	pool *pgxpool.Pool
}

// NewPostgresLedger binds an already configured PostgreSQL pool.
func NewPostgresLedger(pool *pgxpool.Pool) (*PostgresLedger, error) {
	if pool == nil {
		return nil, errors.New("construct PostgreSQL sandbox ledger: pool is required")
	}
	return &PostgresLedger{pool: pool}, nil
}

// Accept records an immutable operation and its publication fact in one
// serializable transaction, or reconnects to the prior identical record.
func (ledger *PostgresLedger) Accept(ctx context.Context, operation Operation) (Operation, bool, error) {
	if err := validateOperation(operation); err != nil {
		return Operation{}, false, err
	}
	var accepted Operation
	var replay bool
	err := ledger.transaction(ctx, "accept sandbox operation", func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			INSERT INTO runtime.sandbox_operations (
				principal, operation_id, kind, target_kind, target_id,
				input_digest, canonical_digest, effective_spec_digest, capability_digest,
				state, version, accepted_at, retention_expires_at, cleanup_required,
				assignment_fencing_token
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 1, $11, $12, $13, 0)
			ON CONFLICT DO NOTHING
			RETURNING principal, operation_id, kind, target_kind, target_id,
				input_digest, canonical_digest, effective_spec_digest, capability_digest,
				state, version, accepted_at, retention_expires_at, cleanup_required,
				assignment_host_id, assignment_fencing_token, assignment_lease_expires_at`,
			operation.Principal, operation.ID, operation.Kind, operation.TargetKind,
			operation.TargetID, operationInputDigest(operation), operation.CanonicalDigest, operation.EffectiveSpecDigest,
			operation.CapabilityDigest, StateAccepted, operation.AcceptedAt.UTC(),
			operation.RetentionExpiresAt.UTC(), operation.CleanupRequired)
		inserted, err := scanOperation(row)
		switch {
		case err == nil:
			accepted = inserted
			return insertOutbox(ctx, tx, inserted, OutboxAccepted)
		case !errors.Is(err, pgx.ErrNoRows):
			return errors.Wrap(err, "insert sandbox operation")
		}

		prior, err := scanOperation(tx.QueryRow(ctx, selectOperationSQL+` FOR UPDATE`, operation.Principal, operation.ID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFoundOrDenied
		}
		if err != nil {
			return errors.Wrap(err, "read prior sandbox operation")
		}
		if prior.State == StateTombstoned {
			return ErrOperationIDExpired
		}
		if operationInputDigest(prior) != operationInputDigest(operation) {
			return ErrConflict
		}
		accepted = prior
		replay = true
		return nil
	})
	if err != nil {
		return Operation{}, false, err
	}
	return accepted, replay, nil
}

// Get returns one authorized durable operation without revealing records under
// another Principal.
func (ledger *PostgresLedger) Get(ctx context.Context, principal, id string) (Operation, error) {
	if !validBounded(principal, maxPrincipalBytes) || !validBounded(id, maxOperationIDBytes) {
		return Operation{}, ErrNotFoundOrDenied
	}
	operation, err := scanOperation(ledger.pool.QueryRow(ctx, selectOperationSQL, principal, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Operation{}, ErrNotFoundOrDenied
	}
	if err != nil {
		return Operation{}, errors.Wrap(err, "get sandbox operation")
	}
	return operation, nil
}

// Transition records one optimistic-concurrency-checked lifecycle transition.
func (ledger *PostgresLedger) Transition(ctx context.Context, principal, id string, version uint64, next State) (Operation, error) {
	if !validBounded(principal, maxPrincipalBytes) || !validBounded(id, maxOperationIDBytes) || version == 0 || version > math.MaxInt64 {
		return Operation{}, ErrInvalidTransition
	}
	var updated Operation
	err := ledger.transaction(ctx, "transition sandbox operation", func(tx pgx.Tx) error {
		current, err := lockedOperation(ctx, tx, principal, id)
		if err != nil {
			return err
		}
		if current.Version != version || !permits(current.State, next) {
			return ErrInvalidTransition
		}
		current.State = next
		current.Version++
		if err := updateOperation(ctx, tx, current); err != nil {
			return err
		}
		updated = current
		return insertOutbox(ctx, tx, current, OutboxStateChanged)
	})
	return updated, err
}

// Assign records a fresh finite host lease and monotonically advances fencing
// authority before dispatch publication.
func (ledger *PostgresLedger) Assign(ctx context.Context, principal, id, hostID string, leaseExpiresAt time.Time) (Operation, error) {
	if !validBounded(principal, maxPrincipalBytes) || !validBounded(id, maxOperationIDBytes) || !validBounded(hostID, maxHostIDBytes) || leaseExpiresAt.IsZero() {
		return Operation{}, errors.New("assign sandbox operation: principal, id, host and lease expiry are required")
	}
	var updated Operation
	err := ledger.transaction(ctx, "assign sandbox operation", func(tx pgx.Tx) error {
		current, err := lockedOperation(ctx, tx, principal, id)
		if err != nil {
			return err
		}
		if current.State != StateAccepted && current.State != StateDispatched && current.State != StateStarted && current.State != StateUncertain && current.State != StateCleanupPending {
			return ErrInvalidTransition
		}
		if current.Assignment.FencingToken == math.MaxInt64 {
			return errors.New("assign sandbox operation: fencing token exhausted")
		}
		current.Assignment = Assignment{HostID: hostID, FencingToken: current.Assignment.FencingToken + 1, LeaseExpiresAt: leaseExpiresAt.UTC()}
		current.State = StateDispatched
		current.Version++
		if err := updateOperation(ctx, tx, current); err != nil {
			return err
		}
		updated = current
		return insertOutbox(ctx, tx, current, OutboxDispatched)
	})
	return updated, err
}

// RecordHostResult accepts only a result observed within the current host's
// finite fencing lease.
func (ledger *PostgresLedger) RecordHostResult(ctx context.Context, principal, id string, result HostResult) (Operation, error) {
	if !validBounded(principal, maxPrincipalBytes) || !validBounded(id, maxOperationIDBytes) || result.ObservedAt.IsZero() {
		return Operation{}, ErrStaleFence
	}
	var updated Operation
	err := ledger.transaction(ctx, "record sandbox host result", func(tx pgx.Tx) error {
		current, err := lockedOperation(ctx, tx, principal, id)
		if err != nil {
			return err
		}
		if !validBounded(result.HostID, maxHostIDBytes) || result.HostID != current.Assignment.HostID || result.FencingToken != current.Assignment.FencingToken || !result.ObservedAt.Before(current.Assignment.LeaseExpiresAt) {
			return ErrStaleFence
		}
		if !permits(current.State, result.State) {
			return ErrInvalidTransition
		}
		current.State = result.State
		current.Version++
		if err := updateOperation(ctx, tx, current); err != nil {
			return err
		}
		updated = current
		return insertOutbox(ctx, tx, current, OutboxStateChanged)
	})
	return updated, err
}

// RecoverExpiredAssignments atomically fences expired host authority and
// exposes the operation as uncertain for bounded reconciliation.
func (ledger *PostgresLedger) RecoverExpiredAssignments(ctx context.Context, now time.Time, limit int) ([]Operation, error) {
	if err := validateLedgerPage(now, limit); err != nil {
		return nil, errors.Wrap(err, "recover expired sandbox assignments")
	}
	var recovered []Operation
	err := ledger.transaction(ctx, "recover expired sandbox assignments", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, selectRecoverableSQL, now.UTC(), limit)
		if err != nil {
			return errors.Wrap(err, "select expired sandbox assignments")
		}
		operations, err := collectOperations(rows)
		if err != nil {
			return err
		}
		for _, current := range operations {
			if current.Assignment.FencingToken == math.MaxInt64 {
				return errors.New("recover expired sandbox assignments: fencing token exhausted")
			}
			current.Assignment = Assignment{FencingToken: current.Assignment.FencingToken + 1}
			current.State = StateUncertain
			current.Version++
			if err := updateOperation(ctx, tx, current); err != nil {
				return err
			}
			if err := insertOutbox(ctx, tx, current, OutboxLeaseExpired); err != nil {
				return err
			}
			recovered = append(recovered, current)
		}
		return nil
	})
	return recovered, err
}

// ClaimExpiredCleanup fences outstanding authority and records durable cleanup
// ownership before the reaper performs destructive work.
func (ledger *PostgresLedger) ClaimExpiredCleanup(ctx context.Context, now time.Time, limit int) ([]Operation, error) {
	if err := validateLedgerPage(now, limit); err != nil {
		return nil, errors.Wrap(err, "claim expired sandbox cleanup")
	}
	var claimed []Operation
	err := ledger.transaction(ctx, "claim expired sandbox cleanup", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, selectCleanupClaimableSQL, now.UTC(), limit)
		if err != nil {
			return errors.Wrap(err, "select expired sandbox cleanup")
		}
		operations, err := collectOperations(rows)
		if err != nil {
			return err
		}
		for _, current := range operations {
			if current.Assignment.FencingToken == math.MaxInt64 {
				return errors.New("claim expired sandbox cleanup: fencing token exhausted")
			}
			current.Assignment = Assignment{FencingToken: current.Assignment.FencingToken + 1}
			current.State = StateCleanupPending
			current.Version++
			if err := updateOperation(ctx, tx, current); err != nil {
				return err
			}
			if err := insertOutbox(ctx, tx, current, OutboxStateChanged); err != nil {
				return err
			}
			claimed = append(claimed, current)
		}
		return nil
	})
	return claimed, err
}

// Reap tombstones only expired terminal records for which cleanup is either
// unnecessary or durably confirmed.
func (ledger *PostgresLedger) Reap(ctx context.Context, now time.Time, limit int) ([]Operation, error) {
	if err := validateLedgerPage(now, limit); err != nil {
		return nil, errors.Wrap(err, "reap sandbox operations")
	}
	var reaped []Operation
	err := ledger.transaction(ctx, "reap sandbox operations", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, selectReapableSQL, now.UTC(), limit)
		if err != nil {
			return errors.Wrap(err, "select reapable sandbox operations")
		}
		operations, err := collectOperations(rows)
		if err != nil {
			return err
		}
		for _, current := range operations {
			current.State = StateTombstoned
			current.Assignment = Assignment{FencingToken: current.Assignment.FencingToken}
			current.Version++
			if err := updateOperation(ctx, tx, current); err != nil {
				return err
			}
			if err := insertOutbox(ctx, tx, current, OutboxTombstoned); err != nil {
				return err
			}
			reaped = append(reaped, current)
		}
		return nil
	})
	return reaped, err
}

// ReadOutbox returns bounded ordered publication inputs strictly after afterID.
func (ledger *PostgresLedger) ReadOutbox(ctx context.Context, afterID uint64, limit int) ([]OutboxRecord, error) {
	if afterID > math.MaxInt64 || limit <= 0 || limit > maxLedgerPage {
		return nil, errors.New("read sandbox control outbox: cursor and limit are invalid")
	}
	rows, err := ledger.pool.Query(ctx, `
		SELECT outbox_id, principal, operation_id, operation_version, event, state
		FROM runtime.sandbox_operation_outbox
		WHERE outbox_id > $1
		ORDER BY outbox_id
		LIMIT $2`, int64(afterID), limit)
	if err != nil {
		return nil, errors.Wrap(err, "read sandbox control outbox")
	}
	defer rows.Close()
	records := make([]OutboxRecord, 0, limit)
	for rows.Next() {
		var record OutboxRecord
		var id, version int64
		if err := rows.Scan(&id, &record.Principal, &record.OperationID, &version, &record.Event, &record.State); err != nil {
			return nil, errors.Wrap(err, "scan sandbox control outbox")
		}
		if id <= 0 || version <= 0 {
			return nil, errors.New("scan sandbox control outbox: invalid persisted sequence")
		}
		record.ID = uint64(id)
		record.OperationVersion = uint64(version)
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "iterate sandbox control outbox")
	}
	return records, nil
}

// ReadOperationOutbox returns one authorized Operation's ordered state facts
// strictly after its durable version cursor.
func (ledger *PostgresLedger) ReadOperationOutbox(ctx context.Context, principal, id string, afterVersion uint64, limit int) ([]OutboxRecord, error) {
	if !validBounded(principal, maxPrincipalBytes) || !validBounded(id, maxOperationIDBytes) || afterVersion > math.MaxInt64 || limit <= 0 || limit > maxLedgerPage {
		return nil, errors.New("read sandbox operation outbox: identity, cursor or limit is invalid")
	}
	if _, err := ledger.Get(ctx, principal, id); err != nil {
		return nil, err
	}
	rows, err := ledger.pool.Query(ctx, `
		SELECT outbox_id, principal, operation_id, operation_version, event, state
		FROM runtime.sandbox_operation_outbox
		WHERE principal = $1 AND operation_id = $2 AND operation_version > $3
		ORDER BY operation_version
		LIMIT $4`, principal, id, int64(afterVersion), limit)
	if err != nil {
		return nil, errors.Wrap(err, "read sandbox operation outbox")
	}
	return collectOutbox(rows, limit)
}

func (ledger *PostgresLedger) transaction(ctx context.Context, action string, apply func(pgx.Tx) error) error {
	for attempt := 0; attempt < serializableAttempts; attempt++ {
		tx, err := ledger.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
		if err != nil {
			return errors.Wrap(err, action)
		}
		if err = apply(tx); err != nil {
			_ = tx.Rollback(ctx)
			if retryablePostgres(err) && attempt < serializableAttempts-1 {
				continue
			}
			return errors.Wrap(err, action)
		}
		err = tx.Commit(ctx)
		if err == nil {
			return nil
		}
		_ = tx.Rollback(ctx)
		if !retryablePostgres(err) || attempt == serializableAttempts-1 {
			return errors.Wrap(err, action)
		}
	}
	return errors.New(action + ": transaction retry exhausted")
}

func retryablePostgres(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && (postgresError.Code == "40001" || postgresError.Code == "40P01")
}

const selectOperationColumns = `principal, operation_id, kind, target_kind, target_id,
	input_digest, canonical_digest, effective_spec_digest, capability_digest,
	state, version, accepted_at, retention_expires_at, cleanup_required,
	assignment_host_id, assignment_fencing_token, assignment_lease_expires_at`

const selectOperationSQL = `SELECT ` + selectOperationColumns + `
	FROM runtime.sandbox_operations WHERE principal = $1 AND operation_id = $2`

const selectRecoverableSQL = `SELECT ` + selectOperationColumns + `
	FROM runtime.sandbox_operations
	WHERE assignment_host_id IS NOT NULL
		AND assignment_lease_expires_at <= $1
		AND state IN ('dispatched', 'started')
	ORDER BY principal, operation_id
	FOR UPDATE SKIP LOCKED
	LIMIT $2`

const selectReapableSQL = `SELECT ` + selectOperationColumns + `
	FROM runtime.sandbox_operations
	WHERE retention_expires_at <= $1
		AND state IN ('succeeded', 'failed', 'cancelled', 'uncertain', 'cleanup-confirmed', 'expired')
		AND (cleanup_required = FALSE OR state = 'cleanup-confirmed')
	ORDER BY principal, operation_id
	FOR UPDATE SKIP LOCKED
	LIMIT $2`

const selectCleanupClaimableSQL = `SELECT ` + selectOperationColumns + `
	FROM runtime.sandbox_operations
	WHERE retention_expires_at <= $1
		AND cleanup_required = TRUE
		AND state NOT IN ('cleanup-pending', 'cleanup-confirmed', 'tombstoned')
	ORDER BY principal, operation_id
	FOR UPDATE SKIP LOCKED
	LIMIT $2`

type rowScanner interface {
	Scan(...any) error
}

func scanOperation(row rowScanner) (Operation, error) {
	var operation Operation
	var version, fence int64
	var hostID *string
	var leaseExpiresAt *time.Time
	err := row.Scan(
		&operation.Principal, &operation.ID, &operation.Kind, &operation.TargetKind,
		&operation.TargetID, &operation.InputDigest, &operation.CanonicalDigest, &operation.EffectiveSpecDigest,
		&operation.CapabilityDigest, &operation.State, &version,
		&operation.AcceptedAt, &operation.RetentionExpiresAt,
		&operation.CleanupRequired, &hostID, &fence, &leaseExpiresAt,
	)
	if err != nil {
		return Operation{}, err
	}
	if version <= 0 || fence < 0 {
		return Operation{}, errors.New("scan sandbox operation: invalid persisted version or fence")
	}
	operation.Version = uint64(version)
	operation.AcceptedAt = operation.AcceptedAt.UTC()
	operation.RetentionExpiresAt = operation.RetentionExpiresAt.UTC()
	operation.Assignment.FencingToken = uint64(fence)
	if hostID != nil {
		operation.Assignment.HostID = *hostID
	}
	if leaseExpiresAt != nil {
		operation.Assignment.LeaseExpiresAt = leaseExpiresAt.UTC()
	}
	return operation, nil
}

func collectOutbox(rows pgx.Rows, limit int) ([]OutboxRecord, error) {
	defer rows.Close()
	records := make([]OutboxRecord, 0, limit)
	for rows.Next() {
		var record OutboxRecord
		var outboxID, version int64
		if err := rows.Scan(&outboxID, &record.Principal, &record.OperationID, &version, &record.Event, &record.State); err != nil {
			return nil, errors.Wrap(err, "scan sandbox operation outbox")
		}
		if outboxID <= 0 || version <= 0 {
			return nil, errors.New("scan sandbox operation outbox: invalid persisted sequence")
		}
		record.ID = uint64(outboxID)
		record.OperationVersion = uint64(version)
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "iterate sandbox operation outbox")
	}
	return records, nil
}

func collectOperations(rows pgx.Rows) ([]Operation, error) {
	defer rows.Close()
	var operations []Operation
	for rows.Next() {
		operation, err := scanOperation(rows)
		if err != nil {
			return nil, errors.Wrap(err, "scan sandbox operations")
		}
		operations = append(operations, operation)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "iterate sandbox operations")
	}
	return operations, nil
}

func lockedOperation(ctx context.Context, tx pgx.Tx, principal, id string) (Operation, error) {
	operation, err := scanOperation(tx.QueryRow(ctx, selectOperationSQL+` FOR UPDATE`, principal, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Operation{}, ErrNotFoundOrDenied
	}
	if err != nil {
		return Operation{}, errors.Wrap(err, "lock sandbox operation")
	}
	return operation, nil
}

func updateOperation(ctx context.Context, tx pgx.Tx, operation Operation) error {
	if operation.Version > math.MaxInt64 || operation.Assignment.FencingToken > math.MaxInt64 {
		return errors.New("update sandbox operation: persisted counter exhausted")
	}
	var hostID any
	var leaseExpiresAt any
	if operation.Assignment.HostID != "" {
		hostID = operation.Assignment.HostID
	}
	if !operation.Assignment.LeaseExpiresAt.IsZero() {
		leaseExpiresAt = operation.Assignment.LeaseExpiresAt.UTC()
	}
	command, err := tx.Exec(ctx, `
		UPDATE runtime.sandbox_operations
		SET state = $3, version = $4, assignment_host_id = $5,
			assignment_fencing_token = $6, assignment_lease_expires_at = $7
		WHERE principal = $1 AND operation_id = $2`,
		operation.Principal, operation.ID, operation.State, int64(operation.Version),
		hostID, int64(operation.Assignment.FencingToken), leaseExpiresAt)
	if err != nil {
		return errors.Wrap(err, "update sandbox operation")
	}
	if command.RowsAffected() != 1 {
		return errors.New("update sandbox operation: locked record disappeared")
	}
	return nil
}

func insertOutbox(ctx context.Context, tx pgx.Tx, operation Operation, event OutboxEvent) error {
	if operation.Version > math.MaxInt64 {
		return errors.New("write sandbox control outbox: operation version exhausted")
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO runtime.sandbox_operation_outbox
			(principal, operation_id, operation_version, event, state)
		VALUES ($1, $2, $3, $4, $5)`,
		operation.Principal, operation.ID, int64(operation.Version), event, operation.State)
	return errors.Wrap(err, "write sandbox control outbox")
}
