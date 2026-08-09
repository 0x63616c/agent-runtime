package runtimeadmission

import (
	"context"
	stderrors "errors"
	"strconv"
	"time"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/cockroachdb/errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const defaultEventRetention = 24 * time.Hour

// PostgresRepository is the normalized runtime-v3 durable SendInput authority.
type PostgresRepository struct {
	pool           *pgxpool.Pool
	eventRetention time.Duration
}

// NewPostgresRepository constructs the existing-session admission repository.
func NewPostgresRepository(pool *pgxpool.Pool) (*PostgresRepository, error) {
	if pool == nil {
		return nil, errors.New("create runtime admission PostgreSQL repository: pool is required")
	}
	return &PostgresRepository{pool: pool, eventRetention: defaultEventRetention}, nil
}

// Admit serializes distinct sends at the scoped session row and replays an exact idempotent result.
func (repository *PostgresRepository) Admit(ctx context.Context, owner Owner, prepared PreparedInput, ids IDSource) (result AdmissionResult, resultErr error) {
	tx, err := repository.pool.Begin(ctx)
	if err != nil {
		return AdmissionResult{}, errors.Wrap(ErrUnavailable, "begin input admission")
	}
	defer func() {
		if resultErr != nil {
			_ = tx.Rollback(context.Background())
		}
	}()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, idempotencyLockKey(owner, prepared.IdempotencyKey)); err != nil {
		return AdmissionResult{}, errors.Wrap(ErrUnavailable, "lock input idempotency key")
	}
	var priorSessionID string
	var priorID string
	var priorDigest string
	var priorAccepted time.Time
	err = tx.QueryRow(ctx, `SELECT session_id, input_id, request_digest, accepted_at FROM runtime.inputs WHERE tenant_id=$1 AND principal_id=$2 AND idempotency_key=$3`, owner.TenantID, owner.PrincipalID, prepared.IdempotencyKey).Scan(&priorSessionID, &priorID, &priorDigest, &priorAccepted)
	if err == nil {
		if priorSessionID != prepared.SessionID.String() || priorDigest != prepared.RequestDigest {
			return AdmissionResult{}, ErrConflict
		}
		storedSessionID, parseErr := agentruntime.ParseSessionID(priorSessionID)
		if parseErr != nil {
			return AdmissionResult{}, ErrIntegrity
		}
		sessionErr := tx.QueryRow(ctx, `SELECT 1 FROM runtime.sessions WHERE tenant_id=$1 AND principal_id=$2 AND session_id=$3 FOR UPDATE`, owner.TenantID, owner.PrincipalID, storedSessionID.String()).Scan(new(int))
		if stderrors.Is(sessionErr, pgx.ErrNoRows) {
			return AdmissionResult{}, ErrIntegrity
		}
		if sessionErr != nil {
			return AdmissionResult{}, errors.Wrap(ErrUnavailable, "authorize idempotent input session")
		}
		turn, queryErr := readTurn(ctx, tx, owner, storedSessionID, agentruntime.InputID(priorID))
		if queryErr != nil {
			return AdmissionResult{}, queryErr
		}
		if err := tx.Commit(ctx); err != nil {
			return AdmissionResult{}, errors.Wrap(ErrUnavailable, "commit idempotent input replay")
		}
		return AdmissionResult{InputID: agentruntime.InputID(priorID), AcceptedAt: priorAccepted.UTC(), Turn: turn}, nil
	}
	if !stderrors.Is(err, pgx.ErrNoRows) {
		return AdmissionResult{}, errors.Wrap(ErrUnavailable, "read input idempotency")
	}
	var version int64
	var state string
	err = tx.QueryRow(ctx, `SELECT version, state FROM runtime.sessions WHERE tenant_id=$1 AND principal_id=$2 AND session_id=$3 FOR UPDATE`, owner.TenantID, owner.PrincipalID, prepared.SessionID.String()).Scan(&version, &state)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return AdmissionResult{}, ErrNotFoundOrDenied
	}
	if err != nil {
		return AdmissionResult{}, errors.Wrap(ErrUnavailable, "lock runtime session")
	}
	if state != string(agentruntime.SessionOpen) {
		return AdmissionResult{}, ErrConflict
	}
	var nextPosition int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(position), 0) + 1 FROM runtime.turns WHERE tenant_id=$1 AND principal_id=$2 AND session_id=$3`, owner.TenantID, owner.PrincipalID, prepared.SessionID.String()).Scan(&nextPosition); err != nil {
		return AdmissionResult{}, errors.Wrap(ErrUnavailable, "allocate turn position")
	}
	var hasRunning bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM runtime.turns WHERE tenant_id=$1 AND principal_id=$2 AND session_id=$3 AND state='running')`, owner.TenantID, owner.PrincipalID, prepared.SessionID.String()).Scan(&hasRunning); err != nil {
		return AdmissionResult{}, errors.Wrap(ErrUnavailable, "inspect active turn")
	}
	turnID, err := newID[agentruntime.TurnID](ids, "turn_")
	if err != nil {
		return AdmissionResult{}, err
	}
	firstEventID, err := newID[agentruntime.EventID](ids, "evt_")
	if err != nil {
		return AdmissionResult{}, err
	}
	firstCursor, err := newID[agentruntime.Cursor](ids, "cur_")
	if err != nil {
		return AdmissionResult{}, err
	}
	secondEventID, err := newID[agentruntime.EventID](ids, "evt_")
	if err != nil {
		return AdmissionResult{}, err
	}
	secondCursor, err := newID[agentruntime.Cursor](ids, "cur_")
	if err != nil {
		return AdmissionResult{}, err
	}
	auditID, err := newID[string](ids, "aud_")
	if err != nil {
		return AdmissionResult{}, err
	}
	turnState := agentruntime.TurnQueued
	var startedAt *time.Time
	secondKind := string(agentruntime.EventTurnQueued)
	if !hasRunning {
		turnState = agentruntime.TurnRunning
		started := prepared.AcceptedAt.UTC()
		startedAt = &started
		secondKind = string(agentruntime.EventTurnStarted)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO runtime.inputs (tenant_id,principal_id,session_id,input_id,expected_version,idempotency_key,request_digest,content_digest,content_media_type,content_size_bytes,accepted_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, owner.TenantID, owner.PrincipalID, prepared.SessionID.String(), prepared.ID.String(), version, prepared.IdempotencyKey, prepared.RequestDigest, prepared.Content.Digest, prepared.Content.MediaType, prepared.Content.SizeBytes, prepared.AcceptedAt.UTC()); err != nil {
		return AdmissionResult{}, errors.Wrap(ErrUnavailable, "insert input reference")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO runtime.turns (tenant_id,principal_id,session_id,turn_id,input_id,position,state,started_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, owner.TenantID, owner.PrincipalID, prepared.SessionID.String(), turnID.String(), prepared.ID.String(), nextPosition, string(turnState), startedAt); err != nil {
		return AdmissionResult{}, errors.Wrap(ErrUnavailable, "insert turn")
	}
	expires := prepared.AcceptedAt.UTC().Add(repository.eventRetention)
	sequence, err := nextEventSequence(ctx, tx, owner, prepared.SessionID)
	if err != nil {
		return AdmissionResult{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO runtime.session_events (tenant_id,principal_id,session_id,sequence,cursor,event_id,event_kind,input_id,turn_id,occurred_at,retention_expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11), ($1,$2,$3,$4+1,$12,$13,$14,$8,$9,$10,$11)`, owner.TenantID, owner.PrincipalID, prepared.SessionID.String(), sequence, firstCursor.String(), firstEventID.String(), string(agentruntime.EventInputAccepted), prepared.ID.String(), turnID.String(), prepared.AcceptedAt.UTC(), expires, secondCursor.String(), secondEventID.String(), secondKind); err != nil {
		return AdmissionResult{}, errors.Wrap(ErrUnavailable, "insert ordered input events")
	}
	newVersion := version + 1
	if _, err := tx.Exec(ctx, `UPDATE runtime.sessions SET version=$1, updated_at=$2 WHERE tenant_id=$3 AND principal_id=$4 AND session_id=$5 AND version=$6`, newVersion, prepared.AcceptedAt.UTC(), owner.TenantID, owner.PrincipalID, prepared.SessionID.String(), version); err != nil {
		return AdmissionResult{}, errors.Wrap(ErrUnavailable, "advance session version")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO runtime.audit_records (tenant_id,audit_id,operation_id,fact_kind,actor_id,subject_kind,subject_id,occurred_at,retention_expires_at) VALUES ($1,$2,$3,'input.accepted',$4,'input',$5,$6,$7)`, owner.TenantID, auditID, prepared.ID.String(), owner.PrincipalID, prepared.ID.String(), prepared.AcceptedAt.UTC(), expires); err != nil {
		return AdmissionResult{}, errors.Wrap(ErrUnavailable, "insert input audit fact")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO runtime.runtime_outbox (tenant_id,aggregate_kind,aggregate_id,aggregate_version,event_kind,payload_digest,payload_size_bytes,committed_at,retention_expires_at) VALUES ($1,'session',$2,$3,'input.accepted',$4,0,$5,$6)`, owner.TenantID, prepared.SessionID.String(), newVersion, prepared.RequestDigest, prepared.AcceptedAt.UTC(), expires); err != nil {
		return AdmissionResult{}, errors.Wrap(ErrUnavailable, "insert input outbox fact")
	}
	if err := tx.Commit(ctx); err != nil {
		return AdmissionResult{}, errors.Wrap(ErrUnavailable, "commit input admission")
	}
	return AdmissionResult{InputID: prepared.ID, AcceptedAt: prepared.AcceptedAt.UTC(), Turn: agentruntime.Turn{ID: turnID, InputID: prepared.ID, Position: uint64(nextPosition), State: turnState, StartedAt: startedAt}}, nil
}

// AuthorizeInputRead returns an unexported locator only after exact owner/session/input lookup.
func (repository *PostgresRepository) AuthorizeInputRead(ctx context.Context, owner Owner, sessionID agentruntime.SessionID, inputID agentruntime.InputID) (authorizedInputLocator, error) {
	var reference ContentReference
	err := repository.pool.QueryRow(ctx, `SELECT content_digest, content_media_type, content_size_bytes FROM runtime.inputs WHERE tenant_id=$1 AND principal_id=$2 AND session_id=$3 AND input_id=$4`, owner.TenantID, owner.PrincipalID, sessionID.String(), inputID.String()).Scan(&reference.Digest, &reference.MediaType, &reference.SizeBytes)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return authorizedInputLocator{}, ErrNotFoundOrDenied
	}
	if err != nil {
		return authorizedInputLocator{}, errors.Wrap(ErrUnavailable, "authorize input content read")
	}
	return authorizedInputLocator{owner: owner, sessionID: sessionID, inputID: inputID, reference: reference}, nil
}

func readTurn(ctx context.Context, tx pgx.Tx, owner Owner, sessionID agentruntime.SessionID, inputID agentruntime.InputID) (agentruntime.Turn, error) {
	var turn agentruntime.Turn
	var state string
	var startedAt, completedAt *time.Time
	err := tx.QueryRow(ctx, `SELECT turn_id,position,state,started_at,completed_at FROM runtime.turns WHERE tenant_id=$1 AND principal_id=$2 AND session_id=$3 AND input_id=$4`, owner.TenantID, owner.PrincipalID, sessionID.String(), inputID.String()).Scan(&turn.ID, &turn.Position, &state, &startedAt, &completedAt)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return agentruntime.Turn{}, ErrIntegrity
	}
	if err != nil {
		return agentruntime.Turn{}, errors.Wrap(ErrUnavailable, "read idempotent turn")
	}
	turn.InputID = inputID
	turn.State = agentruntime.TurnState(state)
	turn.StartedAt = startedAt
	turn.CompletedAt = completedAt
	return turn, nil
}
func nextEventSequence(ctx context.Context, tx pgx.Tx, owner Owner, sessionID agentruntime.SessionID) (int64, error) {
	var sequence int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM runtime.session_events WHERE tenant_id=$1 AND principal_id=$2 AND session_id=$3`, owner.TenantID, owner.PrincipalID, sessionID.String()).Scan(&sequence); err != nil {
		return 0, errors.Wrap(ErrUnavailable, "allocate event sequence")
	}
	return sequence, nil
}

func idempotencyLockKey(owner Owner, key string) string {
	return "agent-runtime/input-idempotency/v1/" + strconv.Itoa(len(owner.TenantID)) + ":" + owner.TenantID + "/" + strconv.Itoa(len(owner.PrincipalID)) + ":" + owner.PrincipalID + "/" + strconv.Itoa(len(key)) + ":" + key
}
