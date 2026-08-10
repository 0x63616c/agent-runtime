package sandboxcontrol

import (
	"bytes"
	"context"
	"time"

	"github.com/0x63616c/agent-runtime/internal/firecrackerbootprobev2"
	"github.com/cockroachdb/errors"
	"github.com/jackc/pgx/v5"
)

// CreateBootProbeSession creates the distinct v2 lifecycle only after the
// durable current enrolled host assignment has been locked and compared.
func (ledger *PostgresLedger) CreateBootProbeSession(ctx context.Context, identity HostIdentity, binding firecrackerbootprobev2.Binding, hostInstanceSessionID string, initial firecrackerbootprobev2.Delivery, now time.Time) (firecrackerbootprobev2.Snapshot, bool, error) {
	state, err := firecrackerbootprobev2.NewState(binding, hostInstanceSessionID, initial, now)
	if err != nil {
		return firecrackerbootprobev2.Snapshot{}, false, errors.Wrap(err, "create v2 boot-probe state")
	}
	session, err := firecrackerbootprobev2.NewSession(state)
	if err != nil {
		return firecrackerbootprobev2.Snapshot{}, false, errors.Wrap(err, "create v2 boot-probe session")
	}
	wire, err := firecrackerbootprobev2.EncodeSession(session)
	if err != nil {
		return firecrackerbootprobev2.Snapshot{}, false, err
	}
	var snapshot firecrackerbootprobev2.Snapshot
	created := false
	err = ledger.transaction(ctx, "create PostgreSQL v2 boot-probe session", func(tx pgx.Tx) error {
		if err := ledger.validateBootProbeAuthority(ctx, tx, identity, session, now); err != nil {
			return err
		}
		var prior []byte
		var version int64
		err := tx.QueryRow(ctx, `SELECT version, session_body FROM runtime.firecracker_boot_probe_sessions WHERE host_instance_session_id=$1 FOR UPDATE`, hostInstanceSessionID).Scan(&version, &prior)
		if errors.Is(err, pgx.ErrNoRows) {
			if _, err := tx.Exec(ctx, `INSERT INTO runtime.firecracker_boot_probe_sessions (host_instance_session_id,host_id,host_generation,principal,operation_id,assignment_id,version,session_body,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,1,$7,$8,$8)`, hostInstanceSessionID, binding.HostID, int64(binding.HostGeneration), binding.Principal, binding.OperationID, binding.AssignmentID, wire, now.UTC()); err != nil {
				return err
			}
			snapshot = firecrackerbootprobev2.Snapshot{Version: 1, Session: session, Wire: append([]byte(nil), wire...)}
			created = true
			return nil
		}
		if err != nil {
			return errors.Wrap(err, "load v2 boot-probe session")
		}
		priorSession, err := firecrackerbootprobev2.DecodeSession(prior)
		if err != nil || !bytes.Equal(prior, wire) {
			return errors.New("create v2 boot-probe session: conflicting host-instance session")
		}
		snapshot = firecrackerbootprobev2.Snapshot{Version: uint64(version), Session: priorSession, Wire: append([]byte(nil), prior...)}
		return nil
	})
	return snapshot, created, err
}

// RenewBootProbeSession admits exactly one successor only while the original
// enrolled host, assignment, lease, and fence are still authoritative.
func (ledger *PostgresLedger) RenewBootProbeSession(ctx context.Context, identity HostIdentity, expected firecrackerbootprobev2.Snapshot, successor firecrackerbootprobev2.Delivery, now time.Time) (firecrackerbootprobev2.Snapshot, error) {
	next, err := expected.Session.AcceptAuthenticatedSuccessor(successor, now)
	if err != nil {
		return firecrackerbootprobev2.Snapshot{}, err
	}
	return ledger.casBootProbeSession(ctx, identity, expected, next, now)
}

// AuthorizeBootProbeLaunch persistently authorizes the one current v2 delivery.
func (ledger *PostgresLedger) AuthorizeBootProbeLaunch(ctx context.Context, identity HostIdentity, expected firecrackerbootprobev2.Snapshot, now time.Time) (firecrackerbootprobev2.Snapshot, error) {
	next, err := expected.Session.AuthorizeLaunch(now)
	if err != nil {
		return firecrackerbootprobev2.Snapshot{}, err
	}
	return ledger.casBootProbeSession(ctx, identity, expected, next, now)
}

// RecordBootProbeLaunchStarted is called only after the host-instance journal
// fsyncs the exact authorized delivery; stale or revoked authority is refused.
func (ledger *PostgresLedger) RecordBootProbeLaunchStarted(ctx context.Context, identity HostIdentity, expected firecrackerbootprobev2.Snapshot, now time.Time) (firecrackerbootprobev2.Snapshot, error) {
	next, err := expected.Session.RecordLaunchStarted(now)
	if err != nil {
		return firecrackerbootprobev2.Snapshot{}, err
	}
	return ledger.casBootProbeSession(ctx, identity, expected, next, now)
}

func (ledger *PostgresLedger) casBootProbeSession(ctx context.Context, identity HostIdentity, expected firecrackerbootprobev2.Snapshot, successor firecrackerbootprobev2.Session, now time.Time) (firecrackerbootprobev2.Snapshot, error) {
	expectedWire, err := firecrackerbootprobev2.EncodeSession(expected.Session)
	if err != nil || !bytes.Equal(expectedWire, expected.Wire) {
		return firecrackerbootprobev2.Snapshot{}, errors.New("compare v2 boot-probe session: stale snapshot")
	}
	nextWire, err := firecrackerbootprobev2.EncodeSession(successor)
	if err != nil {
		return firecrackerbootprobev2.Snapshot{}, err
	}
	var snapshot firecrackerbootprobev2.Snapshot
	err = ledger.transaction(ctx, "compare PostgreSQL v2 boot-probe session", func(tx pgx.Tx) error {
		if err := ledger.validateBootProbeAuthority(ctx, tx, identity, expected.Session, now); err != nil {
			return err
		}
		if err := ledger.validateBootProbeAuthority(ctx, tx, identity, successor, now); err != nil {
			return err
		}
		var version int64
		var actual []byte
		if err := tx.QueryRow(ctx, `SELECT version,session_body FROM runtime.firecracker_boot_probe_sessions WHERE host_instance_session_id=$1 FOR UPDATE`, expected.Session.Delivery.HostInstanceSessionID).Scan(&version, &actual); err != nil || uint64(version) != expected.Version || !bytes.Equal(actual, expected.Wire) {
			return errors.New("compare v2 boot-probe session: stale persisted session")
		}
		if _, err := tx.Exec(ctx, `UPDATE runtime.firecracker_boot_probe_sessions SET version=version+1,session_body=$2,updated_at=$3 WHERE host_instance_session_id=$1`, expected.Session.Delivery.HostInstanceSessionID, nextWire, now.UTC()); err != nil {
			return err
		}
		snapshot = firecrackerbootprobev2.Snapshot{Version: expected.Version + 1, Session: successor, Wire: append([]byte(nil), nextWire...)}
		return nil
	})
	return snapshot, err
}

func (ledger *PostgresLedger) validateBootProbeAuthority(ctx context.Context, tx pgx.Tx, identity HostIdentity, session firecrackerbootprobev2.Session, now time.Time) error {
	host, err := authenticatePostgresHost(ctx, tx, identity, now)
	if err != nil {
		return ErrHostDenied
	}
	b := session.Delivery.Binding
	if b.HostID != host.HostID || b.HostGeneration != host.Generation {
		return ErrHostDenied
	}
	op, err := lockedOperation(ctx, tx, b.Principal, b.OperationID)
	if err != nil {
		return err
	}
	if op.Tenant != b.Tenant || op.Assignment.HostID != host.HostID || op.Assignment.HostGeneration != host.Generation || op.Assignment.AssignmentID != b.AssignmentID || op.Assignment.LeaseEpoch != session.Delivery.Current.LeaseEpoch || op.Assignment.FencingToken != session.Delivery.Current.FencingToken || !now.Before(op.Assignment.LeaseExpiresAt) {
		return ErrStaleFence
	}
	return nil
}
