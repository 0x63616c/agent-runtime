-- Durable enrolled-host identity, private assignment generations and exact
-- signed delivery/receipt journals. Private keys and certificate bodies never
-- enter this schema.
ALTER TABLE runtime.sandbox_operations
    ADD COLUMN assignment_host_generation BIGINT NOT NULL DEFAULT 0 CHECK (assignment_host_generation >= 0),
    ADD COLUMN assignment_id TEXT CHECK (assignment_id IS NULL OR octet_length(assignment_id) BETWEEN 1 AND 128),
    ADD COLUMN assignment_lease_epoch BIGINT NOT NULL DEFAULT 0 CHECK (assignment_lease_epoch >= 0);

CREATE UNIQUE INDEX sandbox_operations_assignment_id_idx
    ON runtime.sandbox_operations (assignment_id)
    WHERE assignment_id IS NOT NULL;

CREATE INDEX sandbox_operations_host_assignment_idx
    ON runtime.sandbox_operations (assignment_host_id, assignment_host_generation, assignment_lease_epoch)
    WHERE assignment_host_id IS NOT NULL;

CREATE INDEX sandbox_operations_host_eligible_idx
    ON runtime.sandbox_operations (tenant, accepted_at, principal, operation_id)
    WHERE state = 'accepted';

CREATE TABLE runtime.sandbox_host_enrollments (
    host_id TEXT NOT NULL CHECK (octet_length(host_id) BETWEEN 1 AND 128),
    tenant TEXT NOT NULL CHECK (octet_length(tenant) BETWEEN 1 AND 256),
    pool TEXT NOT NULL CHECK (octet_length(pool) BETWEEN 1 AND 128),
    generation BIGINT NOT NULL CHECK (generation > 0),
    protocol_version TEXT NOT NULL CHECK (octet_length(protocol_version) BETWEEN 1 AND 64),
    certificate_digest TEXT NOT NULL CHECK (octet_length(certificate_digest) BETWEEN 1 AND 128),
    signing_public_key BYTEA NOT NULL CHECK (octet_length(signing_public_key) = 32),
    capability_digest TEXT NOT NULL CHECK (octet_length(capability_digest) BETWEEN 1 AND 128),
    attestation_digest TEXT CHECK (attestation_digest IS NULL OR octet_length(attestation_digest) BETWEEN 1 AND 128),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'quarantined')),
    expires_at TIMESTAMPTZ NOT NULL,
    last_authenticated_at TIMESTAMPTZ,
    quarantine_reason TEXT CHECK (quarantine_reason IS NULL OR octet_length(quarantine_reason) BETWEEN 1 AND 256),
    PRIMARY KEY (host_id, generation)
);

CREATE TABLE runtime.sandbox_host_dispatches (
    principal TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    assignment_id TEXT NOT NULL UNIQUE CHECK (octet_length(assignment_id) BETWEEN 1 AND 128),
    host_id TEXT NOT NULL,
    host_generation BIGINT NOT NULL CHECK (host_generation > 0),
    lease_epoch BIGINT NOT NULL CHECK (lease_epoch > 0),
    envelope_id TEXT NOT NULL CHECK (octet_length(envelope_id) BETWEEN 1 AND 128),
    delivery_id TEXT NOT NULL CHECK (octet_length(delivery_id) BETWEEN 1 AND 128),
    envelope_digest TEXT NOT NULL CHECK (octet_length(envelope_digest) BETWEEN 1 AND 128),
    envelope_body BYTEA NOT NULL CHECK (octet_length(envelope_body) BETWEEN 1 AND 1048576),
    receipt_digest TEXT CHECK (receipt_digest IS NULL OR octet_length(receipt_digest) BETWEEN 1 AND 128),
    result_digest TEXT CHECK (result_digest IS NULL OR octet_length(result_digest) BETWEEN 1 AND 128),
    acknowledged_at TIMESTAMPTZ,
    PRIMARY KEY (principal, operation_id),
    FOREIGN KEY (principal, operation_id) REFERENCES runtime.sandbox_operations (principal, operation_id) ON DELETE RESTRICT,
    FOREIGN KEY (host_id, host_generation) REFERENCES runtime.sandbox_host_enrollments (host_id, generation) ON DELETE RESTRICT,
    CHECK ((receipt_digest IS NULL) = (acknowledged_at IS NULL))
);

CREATE INDEX sandbox_host_dispatches_host_idx
    ON runtime.sandbox_host_dispatches (host_id, host_generation, lease_epoch);

CREATE TABLE runtime.sandbox_host_outputs (
    output_id TEXT NOT NULL UNIQUE CHECK (octet_length(output_id) BETWEEN 1 AND 128),
    principal TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    assignment_id TEXT NOT NULL,
    stream TEXT NOT NULL CHECK (stream IN ('stdout', 'stderr')),
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    chunk_digest TEXT NOT NULL CHECK (octet_length(chunk_digest) BETWEEN 1 AND 128),
    size_bytes BIGINT NOT NULL CHECK (size_bytes BETWEEN 1 AND 262144),
    observed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (assignment_id, stream, sequence),
    FOREIGN KEY (principal, operation_id) REFERENCES runtime.sandbox_operations (principal, operation_id) ON DELETE RESTRICT
);
