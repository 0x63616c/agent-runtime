-- Runtime v4 adds the plans-only lifecycle records. Immutable bytes remain in runtimecontent;
-- existing input content_media_type metadata is retained without copying content.
BEGIN;
SELECT pg_advisory_xact_lock(hashtextextended('agent-runtime/runtime-v4', 0));
DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM runtime.schema_migrations WHERE migration_version = 3) THEN RAISE EXCEPTION 'runtime v4 requires runtime v3 authority'; END IF; END $$;

CREATE TABLE IF NOT EXISTS runtime.invocations (
 tenant_id TEXT NOT NULL, principal_id TEXT NOT NULL, session_id TEXT NOT NULL, turn_id TEXT NOT NULL,
 invocation_id TEXT NOT NULL, operation_id TEXT NOT NULL, ordinal BIGINT NOT NULL, invocation_fence BIGINT NOT NULL,
 state TEXT NOT NULL, result_digest TEXT, result_media_type TEXT, result_size_bytes BIGINT, failure_code TEXT,
 created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL, retention_expires_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY (tenant_id, principal_id, session_id, turn_id, invocation_id), UNIQUE (tenant_id, operation_id),
 CHECK (ordinal > 0), CHECK (invocation_fence > 0), CHECK (state IN ('intent','succeeded','failed','uncertain','cancelled'))
);
CREATE TABLE IF NOT EXISTS runtime.mutation_receipts (
 tenant_id TEXT NOT NULL, principal_id TEXT NOT NULL DEFAULT '', authority TEXT NOT NULL, idempotency_key TEXT NOT NULL,
 command_kind TEXT NOT NULL, request_digest TEXT NOT NULL, operation_id TEXT NOT NULL, accepted_at TIMESTAMPTZ NOT NULL, retention_expires_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY (tenant_id, principal_id, authority, idempotency_key), CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$')
);
CREATE TABLE IF NOT EXISTS runtime.outbox_leases (
 tenant_id TEXT NOT NULL, outbox_id TEXT NOT NULL, version BIGINT NOT NULL, claimer TEXT, claim_until TIMESTAMPTZ, published_at TIMESTAMPTZ,
 PRIMARY KEY (tenant_id, outbox_id), CHECK (version > 0)
);
-- A versioned, metadata-only transition document is the storage CAS boundary.
-- Its JSONB value is exclusively the closed RuntimeState record graph: digests,
-- typed IDs, retention, cursors, audit facts and outbox lease routes.  Immutable
-- Agent/Input bytes remain in the separate runtimecontent authority.
CREATE TABLE IF NOT EXISTS runtime.runtime_state_snapshots (
 tenant_id TEXT PRIMARY KEY REFERENCES runtime.tenants (tenant_id), generation BIGINT NOT NULL,
 state JSONB NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL,
 CHECK (generation >= 0),
 CHECK (jsonb_typeof(state) = 'object')
);
CREATE INDEX IF NOT EXISTS runtime_state_snapshots_updated_index ON runtime.runtime_state_snapshots (updated_at, tenant_id);
INSERT INTO runtime.schema_migrations (migration_version, schema_fingerprint, applied_at) VALUES (4, 'runtime-v4/plans-only-v1', now()) ON CONFLICT (migration_version) DO NOTHING;
COMMIT;
