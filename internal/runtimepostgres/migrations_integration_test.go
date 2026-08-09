//go:build integration

package runtimepostgres_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
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
			'assistant', 'balanced', 'sha256:agent', 128, $1)`, now)
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
			'inp_0000000000000001', 1, 'send-1', 'sha256:request',
			'sha256:content', 'application/vnd.agent-runtime.input+json', 64, $1)`, now)
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
			'session.event.published', 'sha256:outbox', 64, $1, $2)`, now, now.Add(24*time.Hour))
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
			'inp_0000000000000002', 1, 'send-2', 'sha256:request-2',
			'sha256:content-2', 'application/vnd.agent-runtime.input+json', 262145, $1)`, now)
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

func applyRuntimeMigrations(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	for _, filename := range []string{"runtime-v1.up.sql", "runtime-v2.up.sql"} {
		contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "production", "migrations", filename))
		if err != nil {
			t.Fatalf("read %s: %v", filename, err)
		}
		if _, err := pool.Exec(ctx, string(contents)); err != nil {
			t.Fatalf("apply %s: %v", filename, err)
		}
	}
}

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
