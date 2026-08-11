-- Runtime v5 moves the active state authority onto native tenant hash
-- partitions and makes the application table inaccessible without an explicit
-- transaction-local tenant setting. The migration is intentionally operated by
-- a database administrator; runtime processes receive only the narrow group
-- role below.
BEGIN;
SELECT pg_advisory_xact_lock(hashtextextended('agent-runtime/runtime-v5', 0));
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM runtime.schema_migrations WHERE migration_version = 4) THEN
    RAISE EXCEPTION 'runtime v5 requires runtime v4 authority';
  END IF;
END $$;

-- These are capability groups, never login roles. A deployment grants the
-- application login only runtime_state_app. The migration executor is made a
-- member so a disposable authority can prove the same boundary with SET ROLE.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'runtime_state_app') THEN
    CREATE ROLE runtime_state_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'runtime_state_operator') THEN
    CREATE ROLE runtime_state_operator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
END $$;
GRANT runtime_state_app, runtime_state_operator TO CURRENT_USER;
REVOKE ALL ON SCHEMA runtime FROM PUBLIC;
GRANT USAGE ON SCHEMA runtime TO runtime_state_app, runtime_state_operator;

-- The app needs the tenant catalog only to create/delete the matching state
-- partition. It has no grant on the legacy denormalized lifecycle tables.
ALTER TABLE runtime.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE runtime.tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY runtime_tenant_catalog_isolation ON runtime.tenants
  USING (current_user = 'runtime_state_operator' OR tenant_id = current_setting('runtime.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('runtime.tenant_id', true));
GRANT SELECT, INSERT, DELETE ON runtime.tenants TO runtime_state_app;

-- PostgreSQL cannot convert a plain table to a partitioned table in place.
-- Copy under the v5 migration lock, then replace the physical authority in the
-- same transaction so no partial tenant namespace is exposed.
LOCK TABLE runtime.runtime_state_snapshots IN ACCESS EXCLUSIVE MODE;
ALTER TABLE runtime.runtime_state_snapshots RENAME TO runtime_state_snapshots_v4;
CREATE TABLE runtime.runtime_state_snapshots (
  tenant_id TEXT PRIMARY KEY REFERENCES runtime.tenants (tenant_id),
  generation BIGINT NOT NULL,
  state JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  CHECK (generation >= 0),
  CHECK (jsonb_typeof(state) = 'object')
) PARTITION BY HASH (tenant_id);
CREATE TABLE runtime.runtime_state_snapshots_p0 PARTITION OF runtime.runtime_state_snapshots FOR VALUES WITH (MODULUS 4, REMAINDER 0);
CREATE TABLE runtime.runtime_state_snapshots_p1 PARTITION OF runtime.runtime_state_snapshots FOR VALUES WITH (MODULUS 4, REMAINDER 1);
CREATE TABLE runtime.runtime_state_snapshots_p2 PARTITION OF runtime.runtime_state_snapshots FOR VALUES WITH (MODULUS 4, REMAINDER 2);
CREATE TABLE runtime.runtime_state_snapshots_p3 PARTITION OF runtime.runtime_state_snapshots FOR VALUES WITH (MODULUS 4, REMAINDER 3);
INSERT INTO runtime.runtime_state_snapshots (tenant_id, generation, state, updated_at)
  SELECT tenant_id, generation, state, updated_at FROM runtime.runtime_state_snapshots_v4;
DROP TABLE runtime.runtime_state_snapshots_v4;
CREATE INDEX runtime_state_snapshots_updated_index ON runtime.runtime_state_snapshots (updated_at, tenant_id);

-- Only a transaction that binds the canonical tenant can see or change that
-- tenant's partition. There is deliberately no PUBLIC grant to the child
-- partitions, which prevents a direct-partition query bypassing this policy.
ALTER TABLE runtime.runtime_state_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE runtime.runtime_state_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY runtime_state_tenant_isolation ON runtime.runtime_state_snapshots
  USING (current_user = 'runtime_state_operator' OR tenant_id = current_setting('runtime.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('runtime.tenant_id', true));
GRANT SELECT, INSERT, UPDATE, DELETE ON runtime.runtime_state_snapshots TO runtime_state_app;
CREATE VIEW runtime.runtime_state_tenant_partitions
  WITH (security_barrier = true)
  AS SELECT tenant_id FROM runtime.runtime_state_snapshots;
GRANT SELECT ON runtime.runtime_state_tenant_partitions TO runtime_state_operator;

-- Retention is bounded, tenant-scoped scheduling metadata. The runtime worker
-- cannot enqueue cross-tenant work because the same RLS policy applies.
CREATE TABLE runtime.tenant_retention_jobs (
  tenant_id TEXT PRIMARY KEY REFERENCES runtime.tenants (tenant_id),
  next_collection_at TIMESTAMPTZ NOT NULL,
  last_collection_at TIMESTAMPTZ,
  last_authorization_id TEXT,
  CHECK (last_authorization_id IS NULL OR octet_length(last_authorization_id) BETWEEN 16 AND 128)
) PARTITION BY HASH (tenant_id);
CREATE TABLE runtime.tenant_retention_jobs_p0 PARTITION OF runtime.tenant_retention_jobs FOR VALUES WITH (MODULUS 4, REMAINDER 0);
CREATE TABLE runtime.tenant_retention_jobs_p1 PARTITION OF runtime.tenant_retention_jobs FOR VALUES WITH (MODULUS 4, REMAINDER 1);
CREATE TABLE runtime.tenant_retention_jobs_p2 PARTITION OF runtime.tenant_retention_jobs FOR VALUES WITH (MODULUS 4, REMAINDER 2);
CREATE TABLE runtime.tenant_retention_jobs_p3 PARTITION OF runtime.tenant_retention_jobs FOR VALUES WITH (MODULUS 4, REMAINDER 3);
CREATE INDEX tenant_retention_jobs_due_index ON runtime.tenant_retention_jobs (next_collection_at, tenant_id);
INSERT INTO runtime.tenant_retention_jobs (tenant_id, next_collection_at)
  SELECT tenant_id, now() + interval '24 hours' FROM runtime.runtime_state_snapshots;
ALTER TABLE runtime.tenant_retention_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE runtime.tenant_retention_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_retention_job_isolation ON runtime.tenant_retention_jobs
  USING (current_user = 'runtime_state_operator' OR tenant_id = current_setting('runtime.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('runtime.tenant_id', true));
GRANT SELECT, INSERT, UPDATE, DELETE ON runtime.tenant_retention_jobs TO runtime_state_app;

-- External immutable-object deletion is a cross-store boundary. Metadata
-- compaction/erasure commits one exact, tenant-bound deletion intent first;
-- only a later acknowledgement removes this record. It intentionally has no
-- tenant foreign key because tenant metadata may be erased before an external
-- deletion can be observed and reconciled.
CREATE TABLE runtime.pending_content_deletions (
  tenant_id TEXT NOT NULL,
  digest TEXT NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
  media_type TEXT NOT NULL CHECK (octet_length(media_type) BETWEEN 1 AND 256),
  size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
  authorization_id TEXT NOT NULL CHECK (octet_length(authorization_id) BETWEEN 16 AND 128),
  requested_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, digest, media_type)
) PARTITION BY HASH (tenant_id);
CREATE TABLE runtime.pending_content_deletions_p0 PARTITION OF runtime.pending_content_deletions FOR VALUES WITH (MODULUS 4, REMAINDER 0);
CREATE TABLE runtime.pending_content_deletions_p1 PARTITION OF runtime.pending_content_deletions FOR VALUES WITH (MODULUS 4, REMAINDER 1);
CREATE TABLE runtime.pending_content_deletions_p2 PARTITION OF runtime.pending_content_deletions FOR VALUES WITH (MODULUS 4, REMAINDER 2);
CREATE TABLE runtime.pending_content_deletions_p3 PARTITION OF runtime.pending_content_deletions FOR VALUES WITH (MODULUS 4, REMAINDER 3);
ALTER TABLE runtime.pending_content_deletions ENABLE ROW LEVEL SECURITY;
ALTER TABLE runtime.pending_content_deletions FORCE ROW LEVEL SECURITY;
CREATE POLICY pending_content_deletion_isolation ON runtime.pending_content_deletions
  USING (current_user = 'runtime_state_operator' OR tenant_id = current_setting('runtime.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('runtime.tenant_id', true));
GRANT SELECT, INSERT, DELETE ON runtime.pending_content_deletions TO runtime_state_app;

INSERT INTO runtime.schema_migrations (migration_version, schema_fingerprint, applied_at)
  VALUES (5, 'runtime-v5/tenant-partitions-rls-v1', now())
  ON CONFLICT (migration_version) DO NOTHING;
COMMIT;
