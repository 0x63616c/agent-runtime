package sandboxcontrol

import (
	"context"
	"crypto/ed25519"
	"math"
	"time"

	"github.com/0x63616c/agent-runtime/internal/firecrackerbootprobev2"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/cockroachdb/errors"
	"github.com/jackc/pgx/v5"
)

var errConcurrentHostEnrollment = errors.New("concurrent sandbox host enrollment winner")

// ProvisionHost records one operator-reconciled enrollment generation. The
// runtime host API never calls this method.
func (ledger *PostgresLedger) ProvisionHost(ctx context.Context, enrollment HostEnrollment, input AttestationInput, verifier AttestationVerifier) error {
	var err error
	enrollment, err = evaluateHostEnrollment(ctx, enrollment, input, verifier)
	if err != nil {
		return err
	}
	if !validHostEnrollment(enrollment) {
		return errors.New("provision PostgreSQL sandbox host: invalid bounded enrollment")
	}
	err = ledger.transaction(ctx, "provision PostgreSQL sandbox host", func(tx pgx.Tx) error {
		var maximumGeneration *int64
		if err := tx.QueryRow(ctx, `SELECT MAX(generation) FROM runtime.sandbox_host_enrollments WHERE host_id=$1`, enrollment.HostID).Scan(&maximumGeneration); err != nil {
			return errors.Wrap(err, "read sandbox host generation")
		}
		if maximumGeneration != nil && enrollment.Generation < uint64(*maximumGeneration) {
			return ErrHostDenied
		}
		current, err := scanHost(tx.QueryRow(ctx, selectHostGenerationSQL+` FOR UPDATE`, enrollment.HostID, int64(enrollment.Generation)))
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return errors.Wrap(err, "read sandbox host enrollment")
		}
		if err == nil {
			if !sameEnrollment(current, enrollment) {
				return ErrConflict
			}
			return nil
		}
		result, err := tx.Exec(ctx, `
			INSERT INTO runtime.sandbox_host_enrollments
				(host_id, tenant, pool, generation, protocol_version, certificate_digest,
				 signing_public_key, capability_digest, attestation_digest, attestation_profile, attestation_state, status, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,''),$10,$11,$12,$13)
			ON CONFLICT (host_id, generation) DO NOTHING`,
			enrollment.HostID, enrollment.Tenant, enrollment.Pool, int64(enrollment.Generation),
			enrollment.ProtocolVersion, enrollment.CertificateDigest, []byte(enrollment.SigningPublicKey),
			enrollment.CapabilityDigest, enrollment.AttestationDigest, enrollment.AttestationProfile, enrollment.AttestationState, enrollment.Status, enrollment.ExpiresAt.UTC())
		if err != nil {
			return errors.Wrap(err, "write sandbox host enrollment")
		}
		if result.RowsAffected() == 0 {
			return errConcurrentHostEnrollment
		}
		return nil
	})
	if errors.Is(err, errConcurrentHostEnrollment) {
		winner, readErr := scanHost(ledger.pool.QueryRow(ctx, selectHostGenerationSQL, enrollment.HostID, int64(enrollment.Generation)))
		if readErr != nil {
			return errors.Wrap(readErr, "read concurrent sandbox host enrollment winner")
		}
		if !validHostEnrollment(winner) || !sameEnrollment(winner, enrollment) {
			return ErrConflict
		}
		if winner.Status == HostAttestationFailed {
			return ErrHostAttestationFailed
		}
		return nil
	}
	if err != nil {
		return err
	}
	if enrollment.Status == HostAttestationFailed {
		return ErrHostAttestationFailed
	}
	return nil
}

// RevokeHost denies the current generation and fences all of its operations.
func (ledger *PostgresLedger) RevokeHost(ctx context.Context, hostID string, generation uint64, now time.Time) error {
	if !validBounded(hostID, maxHostIDBytes) || generation == 0 || now.IsZero() {
		return ErrHostDenied
	}
	return ledger.transaction(ctx, "revoke PostgreSQL sandbox host", func(tx pgx.Tx) error {
		host, err := scanHost(tx.QueryRow(ctx, selectHostGenerationSQL+` FOR UPDATE`, hostID, int64(generation)))
		if err != nil || host.Generation != generation {
			return ErrHostDenied
		}
		if _, err := tx.Exec(ctx, `UPDATE runtime.sandbox_host_enrollments SET status='revoked' WHERE host_id=$1 AND generation=$2`, hostID, int64(generation)); err != nil {
			return errors.Wrap(err, "mark sandbox host revoked")
		}
		_, err = fencePostgresHost(ctx, tx, hostID, generation, StateUncertain, now)
		return err
	})
}

// AuthenticateHost verifies durable enrollment against identity derived from
// the TLS peer certificate and records only a safe last-authenticated instant.
func (ledger *PostgresLedger) AuthenticateHost(ctx context.Context, identity HostIdentity, now time.Time) (HostEnrollment, error) {
	var authenticated HostEnrollment
	err := ledger.transaction(ctx, "authenticate PostgreSQL sandbox host", func(tx pgx.Tx) error {
		host, err := authenticatePostgresHost(ctx, tx, identity, now)
		authenticated = host
		return err
	})
	return authenticated, err
}

// PullHostAssignment atomically persists routing, signed envelope and outbox
// before returning. A current non-terminal delivery is returned verbatim so
// either a lost receipt or lost result can be recovered without re-execution.
func (ledger *PostgresLedger) PullHostAssignment(ctx context.Context, identity HostIdentity, now, leaseExpiresAt time.Time, seed DeliverySeed, signer EnvelopeSigner) (HostDispatch, error) {
	if !validDeliverySeed(seed, true) || signer == nil || !leaseExpiresAt.After(now) || leaseExpiresAt.Sub(now) > time.Hour {
		return HostDispatch{}, ErrHostProtocolViolation
	}
	var dispatch HostDispatch
	err := ledger.transaction(ctx, "pull PostgreSQL sandbox host assignment", func(tx pgx.Tx) error {
		host, err := authenticatePostgresHost(ctx, tx, identity, now)
		if err != nil {
			return err
		}
		var principal, operationID string
		err = tx.QueryRow(ctx, `
			SELECT d.principal, d.operation_id
			FROM runtime.sandbox_host_dispatches d
			JOIN runtime.sandbox_operations o USING (principal, operation_id)
			WHERE d.host_id=$1 AND d.host_generation=$2
			  AND o.state IN ('dispatched', 'started')
			  AND o.assignment_lease_expires_at > $3
			ORDER BY o.accepted_at, d.assignment_id LIMIT 1
			FOR UPDATE OF d, o`, identity.HostID, int64(identity.Generation), now.UTC()).Scan(&principal, &operationID)
		if err == nil {
			operation, err := lockedOperation(ctx, tx, principal, operationID)
			if err != nil {
				return err
			}
			fields, err := readPostgresDispatch(ctx, tx, principal, operationID)
			if err != nil {
				return err
			}
			dispatch = dispatchFrom(operation, fields)
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return errors.Wrap(err, "read lost-ack sandbox host dispatch")
		}
		err = tx.QueryRow(ctx, `
			SELECT principal, operation_id FROM runtime.sandbox_operations
			WHERE tenant=$1 AND capability_digest=$2 AND state='accepted'
			ORDER BY accepted_at, principal, operation_id
			FOR UPDATE SKIP LOCKED LIMIT 1`, host.Tenant, host.CapabilityDigest).Scan(&principal, &operationID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoHostAssignment
		}
		if err != nil {
			return errors.Wrap(err, "select eligible sandbox host operation")
		}
		operation, err := lockedOperation(ctx, tx, principal, operationID)
		if err != nil {
			return err
		}
		if operation.Assignment.FencingToken >= math.MaxInt64 {
			return errors.New("pull PostgreSQL sandbox host assignment: fence exhausted")
		}
		operation.Assignment = Assignment{HostID: host.HostID, HostGeneration: host.Generation, AssignmentID: seed.AssignmentID, LeaseEpoch: 1, FencingToken: operation.Assignment.FencingToken + 1, LeaseExpiresAt: leaseExpiresAt.UTC()}
		wire, err := signer(envelopeFor(operation, now, leaseExpiresAt, seed))
		if err != nil || len(wire) == 0 || len(wire) > 1<<20 {
			return errors.New("pull PostgreSQL sandbox host assignment: sign bounded envelope")
		}
		fields := hostAssignmentFields{AssignmentID: seed.AssignmentID, HostGeneration: host.Generation, LeaseEpoch: 1, EnvelopeID: seed.EnvelopeID, DeliveryID: seed.DeliveryID, EnvelopeDigest: sandboxhostprotocol.Digest(wire), EnvelopeBody: append([]byte(nil), wire...)}
		operation.State, operation.Version = StateDispatched, operation.Version+1
		if err := updateOperation(ctx, tx, operation); err != nil {
			return err
		}
		if err := writePostgresDispatch(ctx, tx, operation, fields); err != nil {
			return err
		}
		if err := insertOutbox(ctx, tx, operation, OutboxDispatched); err != nil {
			return err
		}
		dispatch = dispatchFrom(operation, fields)
		return nil
	})
	return dispatch, err
}

// AcknowledgeHostAssignment stores a stable receipt or classifies an identical
// retry as a duplicate without starting another effect.
func (ledger *PostgresLedger) AcknowledgeHostAssignment(ctx context.Context, identity HostIdentity, assignmentID string, fence uint64, receiptDigest string, now time.Time) (bool, error) {
	var duplicate bool
	err := ledger.transaction(ctx, "acknowledge PostgreSQL sandbox host assignment", func(tx pgx.Tx) error {
		if _, err := authenticatePostgresHost(ctx, tx, identity, now); err != nil {
			return err
		}
		operation, fields, err := postgresAssignment(ctx, tx, identity, assignmentID)
		if err != nil || operation.Assignment.FencingToken != fence || !now.Before(operation.Assignment.LeaseExpiresAt) || !validBounded(receiptDigest, maxDigestBytes) {
			return ErrStaleFence
		}
		if fields.ReceiptDigest != "" {
			if fields.ReceiptDigest != receiptDigest {
				return ErrHostProtocolViolation
			}
			duplicate = true
			return nil
		}
		_, err = tx.Exec(ctx, `UPDATE runtime.sandbox_host_dispatches SET receipt_digest=$2, acknowledged_at=$3 WHERE assignment_id=$1`, assignmentID, receiptDigest, now.UTC())
		return errors.Wrap(err, "persist sandbox host receipt")
	})
	return duplicate, err
}

// RenewHostAssignment advances epoch/fence and replaces the exact envelope.
func (ledger *PostgresLedger) RenewHostAssignment(ctx context.Context, identity HostIdentity, assignmentID string, fence uint64, now, leaseExpiresAt time.Time, seed DeliverySeed, signer EnvelopeSigner) (HostDispatch, error) {
	if !validDeliverySeed(seed, false) || signer == nil || !leaseExpiresAt.After(now) || leaseExpiresAt.Sub(now) > time.Hour {
		return HostDispatch{}, ErrStaleFence
	}
	var dispatch HostDispatch
	err := ledger.transaction(ctx, "renew PostgreSQL sandbox host assignment", func(tx pgx.Tx) error {
		if _, err := authenticatePostgresHost(ctx, tx, identity, now); err != nil {
			return err
		}
		operation, _, err := postgresAssignment(ctx, tx, identity, assignmentID)
		if err != nil || (operation.State != StateDispatched && operation.State != StateStarted) || !now.Before(operation.Assignment.LeaseExpiresAt) || operation.Assignment.FencingToken != fence || operation.Assignment.FencingToken >= math.MaxInt64 || operation.Assignment.LeaseEpoch >= math.MaxInt64 {
			return ErrStaleFence
		}
		operation.Assignment.FencingToken++
		operation.Assignment.LeaseEpoch++
		operation.Assignment.LeaseExpiresAt = leaseExpiresAt.UTC()
		operation.Version++
		seed.AssignmentID = assignmentID
		wire, err := signer(envelopeFor(operation, now, leaseExpiresAt, seed))
		if err != nil || len(wire) == 0 || len(wire) > 1<<20 {
			return errors.New("renew PostgreSQL sandbox host assignment: sign bounded envelope")
		}
		fields := hostAssignmentFields{AssignmentID: assignmentID, HostGeneration: identity.Generation, LeaseEpoch: operation.Assignment.LeaseEpoch, EnvelopeID: seed.EnvelopeID, DeliveryID: seed.DeliveryID, EnvelopeDigest: sandboxhostprotocol.Digest(wire), EnvelopeBody: append([]byte(nil), wire...)}
		if err := updateOperation(ctx, tx, operation); err != nil {
			return err
		}
		if err := writePostgresDispatch(ctx, tx, operation, fields); err != nil {
			return err
		}
		if err := insertOutbox(ctx, tx, operation, OutboxDispatched); err != nil {
			return err
		}
		dispatch = dispatchFrom(operation, fields)
		return nil
	})
	return dispatch, err
}

// RecordAuthenticatedHostOutput persists the next control-owned output
// sequence while the assignment row is locked. Exact retries are idempotent.
func (ledger *PostgresLedger) RecordAuthenticatedHostOutput(ctx context.Context, identity HostIdentity, output sandboxhostprotocol.Output, receivedAt time.Time) (bool, error) {
	var duplicate bool
	err := ledger.transaction(ctx, "record authenticated PostgreSQL sandbox host output", func(tx pgx.Tx) error {
		if _, err := authenticatePostgresHost(ctx, tx, identity, receivedAt); err != nil {
			return err
		}
		operation, _, err := postgresAssignment(ctx, tx, identity, output.AssignmentID)
		if err != nil || !validHostOutputImmutableBinding(identity, operation, output) {
			return ErrStaleFence
		}
		var prior hostOutputFields
		var priorSequence, priorSize int64
		err = tx.QueryRow(ctx, `SELECT output_id, assignment_id, stream, sequence, chunk_digest, size_bytes, observed_at
			FROM runtime.sandbox_host_outputs WHERE assignment_id=$1 AND stream=$2 AND sequence=$3`, output.AssignmentID, output.Stream, int64(output.Sequence)).Scan(&prior.OutputID, &prior.AssignmentID, &prior.Stream, &priorSequence, &prior.ChunkDigest, &priorSize, &prior.ObservedAt)
		if err == nil {
			prior.Sequence = uint64(priorSequence)
			prior.SizeBytes = uint32(priorSize)
			prior.ObservedAt = prior.ObservedAt.UTC()
			if prior != outputFields(output) {
				return ErrHostProtocolViolation
			}
			duplicate = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return errors.Wrap(err, "read sandbox host output sequence")
		}
		if !validHostOutputLiveBinding(operation, output, receivedAt) {
			return ErrStaleFence
		}
		var last int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(sequence),0) FROM runtime.sandbox_host_outputs WHERE assignment_id=$1 AND stream=$2`, output.AssignmentID, output.Stream).Scan(&last); err != nil {
			return errors.Wrap(err, "read sandbox host output watermark")
		}
		if output.Sequence != uint64(last)+1 {
			return ErrHostProtocolViolation
		}
		_, err = tx.Exec(ctx, `INSERT INTO runtime.sandbox_host_outputs
			(output_id, principal, operation_id, assignment_id, stream, sequence, chunk_digest, size_bytes, observed_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, output.OutputID, output.Principal, output.OperationID, output.AssignmentID, output.Stream, int64(output.Sequence), output.ChunkDigest, int64(output.SizeBytes), output.ObservedAt.UTC())
		return errors.Wrap(err, "persist sandbox host output sequence")
	})
	return duplicate, err
}

// RecordAuthenticatedHostResult performs durable assignment and digest checks.
func (ledger *PostgresLedger) RecordAuthenticatedHostResult(ctx context.Context, identity HostIdentity, result sandboxhostprotocol.Result, receivedAt time.Time) (Operation, error) {
	var updated Operation
	err := ledger.transaction(ctx, "record authenticated PostgreSQL sandbox host result", func(tx pgx.Tx) error {
		if _, err := authenticatePostgresHost(ctx, tx, identity, receivedAt); err != nil {
			return err
		}
		operation, fields, err := postgresAssignment(ctx, tx, identity, result.AssignmentID)
		if err != nil || !validHostResultImmutableBinding(identity, operation, result) {
			return ErrStaleFence
		}
		if fields.ReceiptDigest == "" {
			return ErrHostProtocolViolation
		}
		next := State(result.State)
		resultDigest, err := authenticatedResultDigest(result)
		if err != nil {
			return ErrHostProtocolViolation
		}
		if operation.State == next {
			if fields.ResultDigest == resultDigest {
				updated = operation
				return nil
			}
			return ErrHostProtocolViolation
		}
		if !validHostResultLiveBinding(operation, result, receivedAt) {
			return ErrStaleFence
		}
		if !permits(operation.State, next) {
			return ErrInvalidTransition
		}
		operation.State, operation.Version = next, operation.Version+1
		if err := updateOperation(ctx, tx, operation); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE runtime.sandbox_host_dispatches SET result_digest=$2 WHERE assignment_id=$1`, result.AssignmentID, resultDigest); err != nil {
			return errors.Wrap(err, "persist sandbox host result identity")
		}
		updated = operation
		return insertOutbox(ctx, tx, operation, OutboxStateChanged)
	})
	return updated, err
}

// QuarantineHost denies the host and fences all non-terminal assignments.
func (ledger *PostgresLedger) QuarantineHost(ctx context.Context, identity HostIdentity, reason string, now time.Time) ([]Operation, error) {
	if !validBounded(reason, 256) {
		return nil, ErrHostDenied
	}
	var fenced []Operation
	err := ledger.transaction(ctx, "quarantine PostgreSQL sandbox host", func(tx pgx.Tx) error {
		if _, err := authenticatePostgresHost(ctx, tx, identity, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE runtime.sandbox_host_enrollments SET status='quarantined', quarantine_reason=$3 WHERE host_id=$1 AND generation=$2`, identity.HostID, int64(identity.Generation), reason); err != nil {
			return errors.Wrap(err, "mark sandbox host quarantined")
		}
		var err error
		fenced, err = fencePostgresHost(ctx, tx, identity.HostID, identity.Generation, StateUncertain, now)
		return err
	})
	return fenced, err
}

// ConfirmHostCleanupAndRequeue records explicit cleanup evidence before a
// previously uncertain operation becomes eligible for reassignment.
func (ledger *PostgresLedger) ConfirmHostCleanupAndRequeue(ctx context.Context, principal, operationID string, version uint64, observedAt time.Time) (Operation, error) {
	var updated Operation
	err := ledger.transaction(ctx, "confirm PostgreSQL sandbox host cleanup", func(tx pgx.Tx) error {
		operation, err := lockedOperation(ctx, tx, principal, operationID)
		if err != nil {
			return err
		}
		if operation.State != StateUncertain || operation.Version != version || !operation.CleanupRequired || observedAt.IsZero() {
			return ErrInvalidTransition
		}
		if operation.Assignment.HostID != "" {
			if operation.Assignment.FencingToken >= math.MaxInt64 {
				return ErrInvalidTransition
			}
			operation.Assignment = Assignment{FencingToken: operation.Assignment.FencingToken + 1}
		}
		operation.State, operation.Version = StateAccepted, operation.Version+1
		if err := updateOperation(ctx, tx, operation); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM runtime.sandbox_host_dispatches WHERE principal=$1 AND operation_id=$2`, principal, operationID); err != nil {
			return errors.Wrap(err, "remove recovered sandbox host dispatch")
		}
		updated = operation
		return insertOutbox(ctx, tx, operation, OutboxStateChanged)
	})
	return updated, err
}

func authenticatePostgresHost(ctx context.Context, tx pgx.Tx, identity HostIdentity, now time.Time) (HostEnrollment, error) {
	host, err := scanHost(tx.QueryRow(ctx, selectHostGenerationSQL+` FOR UPDATE`, identity.HostID, int64(identity.Generation)))
	if err != nil || !validHostEnrollment(host) || host.Status != HostActive || host.Generation != identity.Generation || host.CertificateDigest != identity.CertificateDigest || host.ProtocolVersion != sandboxhostprotocol.Version || now.IsZero() || !now.Before(host.ExpiresAt) {
		return HostEnrollment{}, ErrHostDenied
	}
	if _, err := tx.Exec(ctx, `UPDATE runtime.sandbox_host_enrollments SET last_authenticated_at=$3 WHERE host_id=$1 AND generation=$2`, host.HostID, int64(host.Generation), now.UTC()); err != nil {
		return HostEnrollment{}, errors.Wrap(err, "record sandbox host authentication")
	}
	host.LastAuthenticatedAt = now.UTC()
	return host, nil
}

func postgresAssignment(ctx context.Context, tx pgx.Tx, identity HostIdentity, assignmentID string) (Operation, hostAssignmentFields, error) {
	var principal, operationID string
	err := tx.QueryRow(ctx, `SELECT principal, operation_id FROM runtime.sandbox_host_dispatches WHERE assignment_id=$1 AND host_id=$2 AND host_generation=$3 FOR UPDATE`, assignmentID, identity.HostID, int64(identity.Generation)).Scan(&principal, &operationID)
	if err != nil {
		return Operation{}, hostAssignmentFields{}, ErrStaleFence
	}
	operation, err := lockedOperation(ctx, tx, principal, operationID)
	if err != nil {
		return Operation{}, hostAssignmentFields{}, err
	}
	fields, err := readPostgresDispatch(ctx, tx, principal, operationID)
	return operation, fields, err
}

func readPostgresDispatch(ctx context.Context, tx pgx.Tx, principal, operationID string) (hostAssignmentFields, error) {
	var fields hostAssignmentFields
	var hostGeneration, leaseEpoch int64
	var receipt, result *string
	var acknowledged *time.Time
	err := tx.QueryRow(ctx, `SELECT assignment_id, host_generation, lease_epoch, envelope_id, delivery_id, envelope_digest, envelope_body, receipt_digest, result_digest, acknowledged_at FROM runtime.sandbox_host_dispatches WHERE principal=$1 AND operation_id=$2 FOR UPDATE`, principal, operationID).Scan(&fields.AssignmentID, &hostGeneration, &leaseEpoch, &fields.EnvelopeID, &fields.DeliveryID, &fields.EnvelopeDigest, &fields.EnvelopeBody, &receipt, &result, &acknowledged)
	if err != nil {
		return hostAssignmentFields{}, errors.Wrap(err, "read sandbox host dispatch")
	}
	fields.HostGeneration, fields.LeaseEpoch = uint64(hostGeneration), uint64(leaseEpoch)
	if receipt != nil {
		fields.ReceiptDigest = *receipt
	}
	if result != nil {
		fields.ResultDigest = *result
	}
	if acknowledged != nil {
		fields.AcknowledgedAt = acknowledged.UTC()
	}
	return fields, nil
}

func writePostgresDispatch(ctx context.Context, tx pgx.Tx, operation Operation, fields hostAssignmentFields) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO runtime.sandbox_host_dispatches
			(principal, operation_id, assignment_id, host_id, host_generation, lease_epoch,
			 envelope_id, delivery_id, envelope_digest, envelope_body)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (principal, operation_id) DO UPDATE SET
			assignment_id=EXCLUDED.assignment_id, host_id=EXCLUDED.host_id,
			host_generation=EXCLUDED.host_generation, lease_epoch=EXCLUDED.lease_epoch,
			envelope_id=EXCLUDED.envelope_id, delivery_id=EXCLUDED.delivery_id,
			envelope_digest=EXCLUDED.envelope_digest, envelope_body=EXCLUDED.envelope_body,
			receipt_digest=NULL, result_digest=NULL, acknowledged_at=NULL`,
		operation.Principal, operation.ID, fields.AssignmentID, operation.Assignment.HostID,
		int64(fields.HostGeneration), int64(fields.LeaseEpoch), fields.EnvelopeID,
		fields.DeliveryID, fields.EnvelopeDigest, fields.EnvelopeBody)
	return errors.Wrap(err, "write sandbox host dispatch")
}

func fencePostgresHost(ctx context.Context, tx pgx.Tx, hostID string, generation uint64, next State, now time.Time) ([]Operation, error) {
	// Revocation and quarantine must also durably converge every private v2
	// host-instance lifecycle to cleanup-pending in the same transaction.
	sessions, err := tx.Query(ctx, `SELECT host_instance_session_id, session_body FROM runtime.firecracker_boot_probe_sessions WHERE host_id=$1 AND host_generation=$2 FOR UPDATE`, hostID, int64(generation))
	if err != nil {
		return nil, errors.Wrap(err, "select v2 boot-probe sessions to fence")
	}
	type fencedSession struct {
		id   string
		wire []byte
	}
	var pending []fencedSession
	for sessions.Next() {
		var id string
		var wire []byte
		if err := sessions.Scan(&id, &wire); err != nil {
			sessions.Close()
			return nil, err
		}
		pending = append(pending, fencedSession{id: id, wire: wire})
	}
	if err := sessions.Err(); err != nil {
		sessions.Close()
		return nil, err
	}
	sessions.Close()
	for _, pendingSession := range pending {
		session, err := firecrackerbootprobev2.DecodeSession(pendingSession.wire)
		if err != nil {
			sessions.Close()
			return nil, errors.Wrap(err, "decode fenced v2 boot-probe session")
		}
		if session.Lifecycle.Phase == firecrackerbootprobev2.LifecycleCleanupConfirmed || session.Lifecycle.Phase == firecrackerbootprobev2.LifecycleCleanupPending {
			continue
		}
		clean, err := session.BeginCleanup()
		if err != nil {
			sessions.Close()
			return nil, err
		}
		cleanWire, err := firecrackerbootprobev2.EncodeSession(clean)
		if err != nil {
			sessions.Close()
			return nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE runtime.firecracker_boot_probe_sessions SET version=version+1,session_body=$2,updated_at=$3 WHERE host_instance_session_id=$1`, pendingSession.id, cleanWire, now.UTC()); err != nil {
			sessions.Close()
			return nil, err
		}
	}
	rows, err := tx.Query(ctx, selectOperationSQLByHost+` FOR UPDATE`, hostID, int64(generation))
	if err != nil {
		return nil, errors.Wrap(err, "select sandbox host operations to fence")
	}
	operations, err := collectOperations(rows)
	if err != nil {
		return nil, err
	}
	for index := range operations {
		operation := operations[index]
		if isTerminalState(operation.State) {
			continue
		}
		operation.Assignment = Assignment{FencingToken: operation.Assignment.FencingToken + 1}
		operation.State, operation.Version = next, operation.Version+1
		if err := updateOperation(ctx, tx, operation); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM runtime.sandbox_host_dispatches WHERE principal=$1 AND operation_id=$2`, operation.Principal, operation.ID); err != nil {
			return nil, errors.Wrap(err, "delete fenced sandbox host dispatch")
		}
		if err := insertOutbox(ctx, tx, operation, OutboxStateChanged); err != nil {
			return nil, err
		}
		operations[index] = operation
	}
	return operations, nil
}

type hostRowScanner interface{ Scan(...any) error }

func scanHost(row hostRowScanner) (HostEnrollment, error) {
	var host HostEnrollment
	var generation int64
	var publicKey []byte
	var attestation, quarantine *string
	var lastAuthenticated *time.Time
	err := row.Scan(&host.HostID, &host.Tenant, &host.Pool, &generation, &host.ProtocolVersion,
		&host.CertificateDigest, &publicKey, &host.CapabilityDigest, &attestation, &host.AttestationProfile, &host.AttestationState,
		&host.Status, &host.ExpiresAt, &lastAuthenticated, &quarantine)
	if err != nil {
		return HostEnrollment{}, err
	}
	host.Generation = uint64(generation)
	host.SigningPublicKey = append(ed25519.PublicKey(nil), publicKey...)
	host.ExpiresAt = host.ExpiresAt.UTC()
	if attestation != nil {
		host.AttestationDigest = *attestation
	}
	if lastAuthenticated != nil {
		host.LastAuthenticatedAt = lastAuthenticated.UTC()
	}
	if quarantine != nil {
		host.QuarantineReason = *quarantine
	}
	return host, nil
}

const selectHostGenerationSQL = `SELECT host_id, tenant, pool, generation, protocol_version,
	certificate_digest, signing_public_key, capability_digest, attestation_digest, attestation_profile, attestation_state,
	status, expires_at, last_authenticated_at, quarantine_reason
	FROM runtime.sandbox_host_enrollments WHERE host_id=$1 AND generation=$2`

const selectOperationSQLByHost = `SELECT ` + selectOperationColumns + `
	FROM runtime.sandbox_operations WHERE assignment_host_id=$1 AND assignment_host_generation=$2`

var _ HostControlStore = (*PostgresLedger)(nil)
