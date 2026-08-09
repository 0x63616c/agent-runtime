//go:build integration

package runtimepostgres_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRuntimeMigrationsEnforceBoundedTenantScopedMetadataAndOutboxFacts(t *testing.T) {
	dsn := os.Getenv("AR_RUNTIME_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("AR_RUNTIME_POSTGRES_DSN is required for the integration suite")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping PostgreSQL: %v", err)
	}
	applyRuntimeMigrations(t, ctx, pool)
	applyRuntimeMigrations(t, ctx, pool)
	if _, err := pool.Exec(ctx, `
		TRUNCATE runtime.runtime_outbox, runtime.audit_records, runtime.session_events,
			runtime.turns, runtime.inputs, runtime.sessions, runtime.agent_revisions,
			runtime.tenants RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate runtime authority tables: %v", err)
	}

	now := time.Date(2026, 8, 9, 14, 0, 0, 0, time.UTC)
	_, err = pool.Exec(ctx, `
		INSERT INTO runtime.tenants (tenant_id, created_at)
		VALUES ('tenant_a', $1)`, now)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO runtime.agent_revisions (
			tenant_id, agent_id, revision_id, revision, name, model_profile,
			specification_digest, specification_size_bytes, created_at
		) VALUES ('tenant_a', 'agt_0000000000000001', 'arv_0000000000000001', 1,
			'assistant', 'balanced', 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 128, $1)`, now)
	if err != nil {
		t.Fatalf("insert agent revision: %v", err)
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO runtime.sessions (
			tenant_id, principal_id, session_id, agent_id, agent_revision_id,
			state, version, created_at, updated_at
		) VALUES ('tenant_a', 'principal_a', 'ses_0000000000000001',
			'agt_0000000000000001', 'arv_0000000000000001', 'open', 1, $1, $1)`, now)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO runtime.inputs (
			tenant_id, principal_id, session_id, input_id, expected_version,
			idempotency_key, request_digest, content_digest, content_media_type,
			content_size_bytes, accepted_at
		) VALUES ('tenant_a', 'principal_a', 'ses_0000000000000001',
			'inp_0000000000000001', 1, 'send-1', 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
			'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', 'application/vnd.agent-runtime.input+json', 64, $1)`, now)
	if err != nil {
		t.Fatalf("insert input metadata: %v", err)
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO runtime.turns (
			tenant_id, principal_id, session_id, turn_id, input_id, position, state
		) VALUES ('tenant_a', 'principal_a', 'ses_0000000000000001',
			'trn_0000000000000001', 'inp_0000000000000001', 1, 'running')`)
	if err != nil {
		t.Fatalf("insert turn: %v", err)
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO runtime.session_events (
			tenant_id, principal_id, session_id, sequence, cursor, event_id,
			event_kind, input_id, turn_id, occurred_at, retention_expires_at
		) VALUES ('tenant_a', 'principal_a', 'ses_0000000000000001', 1,
			'cur_0000000000000001', 'evt_0000000000000001', 'input.accepted',
			'inp_0000000000000001', 'trn_0000000000000001', $1, $2)`, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("insert ordered product event: %v", err)
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO runtime.audit_records (
			tenant_id, audit_id, operation_id, fact_kind, actor_id, subject_kind,
			subject_id, occurred_at, retention_expires_at
		) VALUES ('tenant_a', 'aud_0000000000000001', 'operation-1', 'authorized',
			'principal_a', 'session', 'ses_0000000000000001', $1, $2)`, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("insert audit fact: %v", err)
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO runtime.runtime_outbox (
			tenant_id, aggregate_kind, aggregate_id, aggregate_version, event_kind,
			payload_digest, payload_size_bytes, committed_at, retention_expires_at
		) VALUES ('tenant_a', 'session', 'ses_0000000000000001', 1,
			'session.event.published', 'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', 64, $1, $2)`, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("insert durable outbox fact: %v", err)
	}

	_, err = pool.Exec(ctx, `
		INSERT INTO runtime.session_events (
			tenant_id, principal_id, session_id, sequence, cursor, event_id,
			event_kind, occurred_at, retention_expires_at
		) VALUES ('tenant_a', 'principal_a', 'ses_0000000000000001', 1,
			'cur_0000000000000002', 'evt_0000000000000002', 'turn.started', $1, $2)`, now, now.Add(24*time.Hour))
	assertPostgresCode(t, err, "23505")
	_, err = pool.Exec(ctx, `
		INSERT INTO runtime.audit_records (
			tenant_id, audit_id, operation_id, fact_kind, actor_id, subject_kind,
			subject_id, occurred_at, retention_expires_at
		) VALUES ('tenant_a', 'aud_0000000000000002', 'operation-1', 'authorized',
			'principal_a', 'session', 'ses_0000000000000001', $1, $2)`, now, now.Add(24*time.Hour))
	assertPostgresCode(t, err, "23505")
	_, err = pool.Exec(ctx, `
		INSERT INTO runtime.inputs (
			tenant_id, principal_id, session_id, input_id, expected_version,
			idempotency_key, request_digest, content_digest, content_media_type,
			content_size_bytes, accepted_at
		) VALUES ('tenant_a', 'principal_a', 'ses_0000000000000001',
			'inp_0000000000000002', 1, 'send-2', 'sha256:2222222222222222222222222222222222222222222222222222222222222222',
			'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', 'application/vnd.agent-runtime.input+json', 262145, $1)`, now)
	assertPostgresCode(t, err, "23514")

	rows, err := pool.Query(ctx, `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema = 'runtime'
		  AND table_name IN ('agent_revisions', 'inputs', 'session_events', 'runtime_outbox')`)
	if err != nil {
		t.Fatalf("read runtime metadata columns: %v", err)
	}
	defer rows.Close()
	columns := make([]string, 0)
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			t.Fatalf("scan runtime metadata column: %v", err)
		}
		columns = append(columns, column)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate runtime metadata columns: %v", err)
	}
	sort.Strings(columns)
	for _, prohibited := range []string{"raw_prompt", "prompt_text", "content_text", "event_payload"} {
		if index := sort.SearchStrings(columns, prohibited); index < len(columns) && columns[index] == prohibited {
			t.Fatalf("runtime metadata must not contain raw content column %q", prohibited)
		}
	}
}

func TestRuntimeV2MigrationRefusesRollbackWithoutDestroyingDurableData(t *testing.T) {
	pool := openRuntimePool(t)
	ctx := context.Background()
	resetRuntimeV2(t, ctx, pool)
	applyRuntimeMigrations(t, ctx, pool)
	if _, err := pool.Exec(ctx, `INSERT INTO runtime.tenants (tenant_id, created_at) VALUES ('tenant_rollback', now())`); err != nil {
		t.Fatalf("insert durable runtime row: %v", err)
	}
	err := applyMigration(t, ctx, pool, "runtime-v2.down.sql")
	assertPostgresCode(t, err, "P0001")
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime.tenants WHERE tenant_id = 'tenant_rollback'`).Scan(&count); err != nil {
		t.Fatalf("read durable row after refused rollback: %v", err)
	}
	if count != 1 {
		t.Fatalf("durable rows after refused rollback = %d, want 1", count)
	}
}

func TestRuntimeV2MigrationRejectsPartialSchemaAndWrongMigrationFingerprint(t *testing.T) {
	pool := openRuntimePool(t)
	ctx := context.Background()
	resetRuntimeV2(t, ctx, pool)
	applyMigration(t, ctx, pool, "runtime-v1.up.sql")
	if _, err := pool.Exec(ctx, `CREATE TABLE runtime.tenants (tenant_id TEXT PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL)`); err != nil {
		t.Fatalf("create deliberately partial tenant table: %v", err)
	}
	err := applyMigration(t, ctx, pool, "runtime-v2.up.sql")
	assertPostgresCode(t, err, "P0001")

	resetRuntimeV2(t, ctx, pool)
	applyMigration(t, ctx, pool, "runtime-v1.up.sql")
	if _, err := pool.Exec(ctx, `
		CREATE TABLE runtime.schema_migrations (
			migration_version BIGINT PRIMARY KEY,
			schema_fingerprint TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL
		);
		INSERT INTO runtime.schema_migrations (migration_version, schema_fingerprint, applied_at)
		VALUES (2, 'wrong-fingerprint', now())`); err != nil {
		t.Fatalf("seed deliberately wrong migration fingerprint: %v", err)
	}
	err = applyMigration(t, ctx, pool, "runtime-v2.up.sql")
	assertPostgresCode(t, err, "P0001")

	resetRuntimeV2(t, ctx, pool)
	applyMigration(t, ctx, pool, "runtime-v1.up.sql")
	if _, err := pool.Exec(ctx, `CREATE TABLE runtime.tenants (tenant_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, retention_expires_at TIMESTAMPTZ)`); err != nil {
		t.Fatalf("create deliberately wrong-type tenant table: %v", err)
	}
	err = applyMigration(t, ctx, pool, "runtime-v2.up.sql")
	assertPostgresCode(t, err, "P0001")

	resetRuntimeV2(t, ctx, pool)
	applyRuntimeMigrations(t, ctx, pool)
	if _, err := pool.Exec(ctx, `ALTER TABLE runtime.tenants ADD CONSTRAINT spoofed_tenant_check CHECK (tenant_id <> '')`); err != nil {
		t.Fatalf("add spoofed check constraint: %v", err)
	}
	err = applyMigration(t, ctx, pool, "runtime-v2.up.sql")
	assertPostgresCode(t, err, "P0001")

	resetRuntimeV2(t, ctx, pool)
	applyRuntimeMigrations(t, ctx, pool)
	if _, err := pool.Exec(ctx, `CREATE INDEX spoofed_tenant_index ON runtime.tenants (tenant_id)`); err != nil {
		t.Fatalf("add spoofed duplicate index: %v", err)
	}
	err = applyMigration(t, ctx, pool, "runtime-v2.up.sql")
	assertPostgresCode(t, err, "P0001")
}

func TestRuntimeV2SchemaRejectsForgedRelationshipsAndMalformedDigestReferences(t *testing.T) {
	pool := openRuntimePool(t)
	ctx := context.Background()
	resetRuntimeV2(t, ctx, pool)
	applyRuntimeMigrations(t, ctx, pool)
	now := time.Date(2026, 8, 9, 15, 0, 0, 0, time.UTC)
	insertRuntimeTenant(t, ctx, pool, "tenant_relationship", now)
	_, err := pool.Exec(ctx, `
		INSERT INTO runtime.agent_revisions (tenant_id, agent_id, revision_id, revision, name, model_profile, specification_digest, specification_size_bytes, created_at)
		VALUES ('tenant_relationship', 'agt_0000000000000000', 'arv_0000000000000000', 1, 'assistant', 'balanced', 'raw-prompt', 128, $1)`, now)
	assertPostgresCode(t, err, "23514")
	insertRuntimeRevision(t, ctx, pool, "tenant_relationship", "agt_0000000000000001", "arv_0000000000000001", now)
	_, err = pool.Exec(ctx, `
		INSERT INTO runtime.sessions (
			tenant_id, principal_id, session_id, agent_id, agent_revision_id,
			state, version, created_at, updated_at
		) VALUES ('tenant_relationship', 'principal_a', 'ses_0000000000000001',
			'agt_forged000000001', 'arv_0000000000000001', 'open', 1, $1, $1)`, now)
	assertPostgresCode(t, err, "23503")
	insertRuntimeSession(t, ctx, pool, "tenant_relationship", "principal_a", "ses_0000000000000001", now)
	insertRuntimeInput(t, ctx, pool, "tenant_relationship", "principal_a", "ses_0000000000000001", "inp_0000000000000001", "send-1", validDigest("1"), now)
	insertRuntimeInput(t, ctx, pool, "tenant_relationship", "principal_a", "ses_0000000000000001", "inp_0000000000000002", "send-2", validDigest("2"), now)
	insertRuntimeTurn(t, ctx, pool, "tenant_relationship", "principal_a", "ses_0000000000000001", "trn_0000000000000001", "inp_0000000000000001", 1)
	insertRuntimeTurn(t, ctx, pool, "tenant_relationship", "principal_a", "ses_0000000000000001", "trn_0000000000000002", "inp_0000000000000002", 2)
	_, err = pool.Exec(ctx, `
		INSERT INTO runtime.session_events (
			tenant_id, principal_id, session_id, sequence, cursor, event_id,
			event_kind, input_id, turn_id, occurred_at, retention_expires_at
		) VALUES ('tenant_relationship', 'principal_a', 'ses_0000000000000001', 1,
			'cur_0000000000000001', 'evt_0000000000000001', 'turn.started',
			'inp_0000000000000001', 'trn_0000000000000002', $1, $2)`, now, now.Add(time.Hour))
	assertPostgresCode(t, err, "23503")
	_, err = pool.Exec(ctx, `
		INSERT INTO runtime.inputs (
			tenant_id, principal_id, session_id, input_id, expected_version,
			idempotency_key, request_digest, content_digest, content_media_type,
			content_size_bytes, accepted_at
		) VALUES ('tenant_relationship', 'principal_a', 'ses_0000000000000001',
			'inp_0000000000000003', 1, 'send-3', 'not-a-digest',
			'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', 'application/vnd.agent-runtime.input+json', 64, $1)`, now)
	assertPostgresCode(t, err, "23514")
	_, err = pool.Exec(ctx, `
		INSERT INTO runtime.inputs (
			tenant_id, principal_id, session_id, input_id, expected_version,
			idempotency_key, request_digest, content_digest, content_media_type,
			content_size_bytes, accepted_at
		) VALUES ('tenant_relationship', 'principal_a', 'ses_0000000000000001',
			'inp_0000000000000004', 1, 'send-4', 'sha256:4444444444444444444444444444444444444444444444444444444444444444',
			'raw-token', 'application/vnd.agent-runtime.input+json', 64, $1)`, now)
	assertPostgresCode(t, err, "23514")
	_, err = pool.Exec(ctx, `
		INSERT INTO runtime.runtime_outbox (
			tenant_id, aggregate_kind, aggregate_id, aggregate_version, event_kind,
			payload_digest, payload_size_bytes, committed_at, retention_expires_at
		) VALUES ('tenant_relationship', 'session', 'ses_0000000000000001', 1,
			'session.event.published', 'raw-token', 64, $1, $2)`, now, now.Add(time.Hour))
	assertPostgresCode(t, err, "23514")
}

func applyRuntimeMigrations(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	for _, filename := range []string{"runtime-v1.up.sql", "runtime-v2.up.sql"} {
		if err := applyMigration(t, ctx, pool, filename); err != nil {
			t.Fatalf("apply %s: %v", filename, err)
		}
	}
}

func applyMigration(t *testing.T, ctx context.Context, pool *pgxpool.Pool, filename string) error {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "production", "migrations", filename))
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	_, err = pool.Exec(ctx, string(contents))
	return err
}

func openRuntimePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AR_RUNTIME_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("AR_RUNTIME_POSTGRES_DSN is required for the integration suite")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(context.Background()); err != nil {
		t.Fatalf("ping PostgreSQL: %v", err)
	}
	return pool
}

func resetRuntimeV2(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		DROP TABLE IF EXISTS runtime.runtime_outbox, runtime.audit_records, runtime.session_events,
			runtime.turns, runtime.inputs, runtime.sessions, runtime.agent_revisions,
			runtime.tenants, runtime.schema_migrations CASCADE`); err != nil {
		t.Fatalf("reset runtime v2 tables: %v", err)
	}
}

func insertRuntimeTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenant string, now time.Time) {
	t.Helper()
	if _, err := pool.Exec(ctx, `INSERT INTO runtime.tenants (tenant_id, created_at) VALUES ($1, $2)`, tenant, now); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
}

func insertRuntimeRevision(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenant, agent, revision string, now time.Time) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		INSERT INTO runtime.agent_revisions (tenant_id, agent_id, revision_id, revision, name, model_profile, specification_digest, specification_size_bytes, created_at)
		VALUES ($1, $2, $3, 1, 'assistant', 'balanced', $4, 128, $5)`, tenant, agent, revision, validDigest("a"), now); err != nil {
		t.Fatalf("insert agent revision: %v", err)
	}
}

func insertRuntimeSession(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenant, principal, session string, now time.Time) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		INSERT INTO runtime.sessions (tenant_id, principal_id, session_id, agent_id, agent_revision_id, state, version, created_at, updated_at)
		VALUES ($1, $2, $3, 'agt_0000000000000001', 'arv_0000000000000001', 'open', 1, $4, $4)`, tenant, principal, session, now); err != nil {
		t.Fatalf("insert session: %v", err)
	}
}

func insertRuntimeInput(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenant, principal, session, input, key, digest string, now time.Time) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		INSERT INTO runtime.inputs (tenant_id, principal_id, session_id, input_id, expected_version, idempotency_key, request_digest, content_digest, content_media_type, content_size_bytes, accepted_at)
		VALUES ($1, $2, $3, $4, 1, $5, $6, $7, 'application/vnd.agent-runtime.input+json', 64, $8)`, tenant, principal, session, input, key, digest, validDigest("b"), now); err != nil {
		t.Fatalf("insert input: %v", err)
	}
}

func insertRuntimeTurn(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenant, principal, session, turn, input string, position int) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		INSERT INTO runtime.turns (tenant_id, principal_id, session_id, turn_id, input_id, position, state)
		VALUES ($1, $2, $3, $4, $5, $6, 'running')`, tenant, principal, session, turn, input, position); err != nil {
		t.Fatalf("insert turn: %v", err)
	}
}

func validDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }

func assertPostgresCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("write error = nil, want PostgreSQL code %s", code)
	}
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != code {
		t.Fatalf("write error = %v, want PostgreSQL code %s", err, code)
	}
}
