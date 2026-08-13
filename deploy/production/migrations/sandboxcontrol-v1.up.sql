-- Sandbox control schema is applied only by the audited infrastructure
-- operator. The sandbox-control binary has no schema-creation authority.
CREATE SCHEMA IF NOT EXISTS runtime;

CREATE TABLE runtime.sandbox_operations (
    principal TEXT NOT NULL CHECK (octet_length(principal) BETWEEN 1 AND 512),
    operation_id TEXT NOT NULL CHECK (octet_length(operation_id) BETWEEN 1 AND 128),
    canonical_digest TEXT NOT NULL CHECK (octet_length(canonical_digest) BETWEEN 1 AND 128),
    effective_spec_digest TEXT NOT NULL CHECK (octet_length(effective_spec_digest) BETWEEN 1 AND 128),
    state TEXT NOT NULL CHECK (state IN (
        'accepted', 'dispatched', 'started', 'succeeded', 'failed',
        'cancelled', 'uncertain', 'cleanup-pending', 'cleanup-confirmed',
        'expired', 'tombstoned'
    )),
    version BIGINT NOT NULL CHECK (version > 0),
    accepted_at TIMESTAMPTZ NOT NULL,
    retention_expires_at TIMESTAMPTZ NOT NULL,
    cleanup_required BOOLEAN NOT NULL,
    assignment_host_id TEXT CHECK (assignment_host_id IS NULL OR octet_length(assignment_host_id) BETWEEN 1 AND 128),
    assignment_fencing_token BIGINT NOT NULL CHECK (assignment_fencing_token >= 0),
    assignment_lease_expires_at TIMESTAMPTZ,
    PRIMARY KEY (principal, operation_id),
    CHECK (retention_expires_at > accepted_at),
    CHECK ((assignment_host_id IS NULL) = (assignment_lease_expires_at IS NULL))
);

CREATE INDEX sandbox_operations_expired_assignment_idx
    ON runtime.sandbox_operations (assignment_lease_expires_at, principal, operation_id)
    WHERE assignment_host_id IS NOT NULL AND state IN ('dispatched', 'started');

CREATE INDEX sandbox_operations_retention_idx
    ON runtime.sandbox_operations (retention_expires_at, principal, operation_id)
    WHERE state <> 'tombstoned';

CREATE TABLE runtime.sandbox_operation_outbox (
    outbox_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    principal TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    operation_version BIGINT NOT NULL CHECK (operation_version > 0),
    event TEXT NOT NULL CHECK (event IN (
        'accepted', 'dispatched', 'state-changed', 'lease-expired', 'tombstoned'
    )),
    state TEXT NOT NULL,
    UNIQUE (principal, operation_id, operation_version),
    FOREIGN KEY (principal, operation_id)
        REFERENCES runtime.sandbox_operations (principal, operation_id)
        ON DELETE RESTRICT
);

CREATE INDEX sandbox_operation_outbox_sequence_idx
    ON runtime.sandbox_operation_outbox (outbox_id);
