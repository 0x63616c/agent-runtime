-- Runtime metadata, cursor, audit, and outbox authority. Immutable content is
-- held by the declared blob authority and enters these records only as a
-- digest, media type, and bounded byte count.
BEGIN;

SELECT pg_advisory_xact_lock(hashtextextended('agent-runtime/runtime-v2', 0));

CREATE TABLE IF NOT EXISTS runtime.schema_migrations (
    migration_version BIGINT PRIMARY KEY,
    schema_fingerprint TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL,
    CHECK (migration_version > 0),
    CHECK (octet_length(schema_fingerprint) BETWEEN 1 AND 128)
);

CREATE TABLE IF NOT EXISTS runtime.tenants (
    tenant_id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    retention_expires_at TIMESTAMPTZ,
    CHECK (octet_length(tenant_id) BETWEEN 1 AND 128)
);

CREATE TABLE IF NOT EXISTS runtime.agent_revisions (
    tenant_id TEXT NOT NULL REFERENCES runtime.tenants (tenant_id),
    agent_id TEXT NOT NULL,
    revision_id TEXT NOT NULL,
    revision BIGINT NOT NULL,
    name TEXT NOT NULL,
    model_profile TEXT NOT NULL,
    specification_digest TEXT NOT NULL,
    specification_size_bytes BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    retention_expires_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, revision_id),
    UNIQUE (tenant_id, agent_id, revision),
    UNIQUE (tenant_id, agent_id, revision_id),
    CHECK (octet_length(agent_id) BETWEEN 1 AND 128),
    CHECK (octet_length(revision_id) BETWEEN 1 AND 128),
    CHECK (revision > 0),
    CHECK (octet_length(name) BETWEEN 1 AND 128),
    CHECK (octet_length(model_profile) BETWEEN 1 AND 128),
    CONSTRAINT agent_revisions_specification_digest_format CHECK (specification_digest ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (specification_size_bytes BETWEEN 0 AND 262144)
);

CREATE TABLE IF NOT EXISTS runtime.sessions (
    tenant_id TEXT NOT NULL REFERENCES runtime.tenants (tenant_id),
    principal_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    agent_revision_id TEXT NOT NULL,
    state TEXT NOT NULL,
    version BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    retention_expires_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, principal_id, session_id),
    CONSTRAINT sessions_agent_revision_integrity FOREIGN KEY (tenant_id, agent_id, agent_revision_id) REFERENCES runtime.agent_revisions (tenant_id, agent_id, revision_id),
    CHECK (octet_length(principal_id) BETWEEN 1 AND 128),
    CHECK (octet_length(session_id) BETWEEN 1 AND 128),
    CHECK (octet_length(agent_id) BETWEEN 1 AND 128),
    CHECK (state IN ('open', 'closing', 'completed', 'cancelled', 'failed')),
    CHECK (version > 0)
);

CREATE TABLE IF NOT EXISTS runtime.inputs (
    tenant_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    input_id TEXT NOT NULL,
    expected_version BIGINT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    content_media_type TEXT NOT NULL,
    content_size_bytes BIGINT NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL,
    retention_expires_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, principal_id, session_id, input_id),
    CONSTRAINT inputs_session_integrity FOREIGN KEY (tenant_id, principal_id, session_id) REFERENCES runtime.sessions (tenant_id, principal_id, session_id),
    UNIQUE (tenant_id, principal_id, idempotency_key),
    CHECK (octet_length(input_id) BETWEEN 1 AND 128),
    CHECK (expected_version > 0),
    CHECK (octet_length(idempotency_key) BETWEEN 1 AND 128),
    CONSTRAINT inputs_request_digest_format CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT inputs_content_digest_format CHECK (content_digest ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (octet_length(content_media_type) BETWEEN 1 AND 255),
    CHECK (content_size_bytes BETWEEN 0 AND 262144)
);

CREATE TABLE IF NOT EXISTS runtime.turns (
    tenant_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    turn_id TEXT NOT NULL,
    input_id TEXT NOT NULL,
    position BIGINT NOT NULL,
    state TEXT NOT NULL,
    failure_code TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    retention_expires_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, principal_id, session_id, turn_id),
    CONSTRAINT turns_input_integrity FOREIGN KEY (tenant_id, principal_id, session_id, input_id) REFERENCES runtime.inputs (tenant_id, principal_id, session_id, input_id),
    UNIQUE (tenant_id, principal_id, session_id, position),
    UNIQUE (tenant_id, principal_id, session_id, input_id, turn_id),
    CHECK (octet_length(turn_id) BETWEEN 1 AND 128),
    CHECK (position > 0),
    CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
    CHECK (failure_code IS NULL OR octet_length(failure_code) BETWEEN 1 AND 64)
);

CREATE TABLE IF NOT EXISTS runtime.session_events (
    tenant_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    sequence BIGINT NOT NULL,
    cursor TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    input_id TEXT,
    turn_id TEXT,
    occurred_at TIMESTAMPTZ NOT NULL,
    retention_expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, principal_id, session_id, sequence),
    CONSTRAINT session_events_session_integrity FOREIGN KEY (tenant_id, principal_id, session_id) REFERENCES runtime.sessions (tenant_id, principal_id, session_id),
    CONSTRAINT session_events_turn_integrity FOREIGN KEY (tenant_id, principal_id, session_id, input_id, turn_id) REFERENCES runtime.turns (tenant_id, principal_id, session_id, input_id, turn_id),
    UNIQUE (tenant_id, principal_id, session_id, cursor),
    UNIQUE (tenant_id, principal_id, session_id, event_id),
    CHECK (sequence > 0),
    CHECK (octet_length(cursor) BETWEEN 1 AND 128),
    CHECK (octet_length(event_id) BETWEEN 1 AND 128),
    CHECK (octet_length(event_kind) BETWEEN 1 AND 128),
    CHECK (input_id IS NULL OR octet_length(input_id) BETWEEN 1 AND 128),
    CHECK (turn_id IS NULL OR octet_length(turn_id) BETWEEN 1 AND 128),
    CONSTRAINT session_events_link_pair CHECK ((input_id IS NULL) = (turn_id IS NULL))
);

CREATE TABLE IF NOT EXISTS runtime.audit_records (
    tenant_id TEXT NOT NULL REFERENCES runtime.tenants (tenant_id),
    audit_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    fact_kind TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    subject_kind TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    retention_expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, audit_id),
    UNIQUE (tenant_id, operation_id),
    CHECK (octet_length(audit_id) BETWEEN 1 AND 128),
    CHECK (octet_length(operation_id) BETWEEN 1 AND 128),
    CHECK (octet_length(fact_kind) BETWEEN 1 AND 128),
    CHECK (octet_length(actor_id) BETWEEN 1 AND 128),
    CHECK (octet_length(subject_kind) BETWEEN 1 AND 128),
    CHECK (octet_length(subject_id) BETWEEN 1 AND 128)
);

CREATE TABLE IF NOT EXISTS runtime.runtime_outbox (
    outbox_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES runtime.tenants (tenant_id),
    aggregate_kind TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    aggregate_version BIGINT NOT NULL,
    event_kind TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    payload_size_bytes BIGINT NOT NULL,
    committed_at TIMESTAMPTZ NOT NULL,
    published_at TIMESTAMPTZ,
    reconciled_at TIMESTAMPTZ,
    retention_expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, aggregate_kind, aggregate_id, aggregate_version, event_kind),
    CHECK (octet_length(aggregate_kind) BETWEEN 1 AND 128),
    CHECK (octet_length(aggregate_id) BETWEEN 1 AND 128),
    CHECK (aggregate_version > 0),
    CHECK (octet_length(event_kind) BETWEEN 1 AND 128),
    CONSTRAINT runtime_outbox_payload_digest_format CHECK (payload_digest ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (payload_size_bytes BETWEEN 0 AND 65536)
);

CREATE INDEX IF NOT EXISTS session_events_retention_index
    ON runtime.session_events (retention_expires_at, tenant_id, principal_id, session_id, sequence);
CREATE INDEX IF NOT EXISTS runtime_outbox_delivery_index
    ON runtime.runtime_outbox (published_at, outbox_id);

INSERT INTO runtime.schema_migrations (migration_version, schema_fingerprint, applied_at)
VALUES (2, 'runtime-v2-authority-schema-20260809', now())
ON CONFLICT (migration_version) DO NOTHING;

DO $$
DECLARE
    expected_fingerprint TEXT := 'runtime-v2-authority-schema-20260809';
    stored_fingerprint TEXT;
BEGIN
    SELECT schema_fingerprint INTO stored_fingerprint
    FROM runtime.schema_migrations
    WHERE migration_version = 2;
    IF stored_fingerprint IS DISTINCT FROM expected_fingerprint THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'runtime v2 migration fingerprint mismatch';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM (VALUES
            ('tenants', 'tenant_id'), ('tenants', 'created_at'),
            ('agent_revisions', 'tenant_id'), ('agent_revisions', 'agent_id'), ('agent_revisions', 'revision_id'), ('agent_revisions', 'specification_digest'),
            ('sessions', 'tenant_id'), ('sessions', 'principal_id'), ('sessions', 'session_id'), ('sessions', 'agent_id'), ('sessions', 'agent_revision_id'),
            ('inputs', 'tenant_id'), ('inputs', 'principal_id'), ('inputs', 'session_id'), ('inputs', 'input_id'), ('inputs', 'request_digest'), ('inputs', 'content_digest'),
            ('turns', 'tenant_id'), ('turns', 'principal_id'), ('turns', 'session_id'), ('turns', 'turn_id'), ('turns', 'input_id'),
            ('session_events', 'tenant_id'), ('session_events', 'principal_id'), ('session_events', 'session_id'), ('session_events', 'sequence'), ('session_events', 'cursor'), ('session_events', 'input_id'), ('session_events', 'turn_id'),
            ('audit_records', 'tenant_id'), ('audit_records', 'audit_id'), ('audit_records', 'operation_id'),
            ('runtime_outbox', 'outbox_id'), ('runtime_outbox', 'tenant_id'), ('runtime_outbox', 'payload_digest')
        ) AS expected(table_name, column_name)
        LEFT JOIN information_schema.columns actual
          ON actual.table_schema = 'runtime' AND actual.table_name = expected.table_name AND actual.column_name = expected.column_name
        WHERE actual.column_name IS NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'runtime v2 migration physical schema is incomplete';
    END IF;
    IF (SELECT count(*) FROM pg_constraint WHERE connamespace = 'runtime'::regnamespace AND conname = ANY (ARRAY[
        'agent_revisions_specification_digest_format', 'sessions_agent_revision_integrity', 'inputs_session_integrity', 'inputs_request_digest_format', 'inputs_content_digest_format',
        'turns_input_integrity', 'session_events_session_integrity', 'session_events_turn_integrity', 'session_events_link_pair',
        'runtime_outbox_payload_digest_format'
    ])) <> 10 THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'runtime v2 migration constraints are incomplete';
    END IF;
END $$;

COMMIT;
