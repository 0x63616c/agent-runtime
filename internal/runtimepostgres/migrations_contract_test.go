package runtimepostgres_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeV2MigrationDeclaresBoundedMetadataAuthorityWithoutRawContentColumns(t *testing.T) {
	t.Parallel()

	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "production", "migrations", "runtime-v2.up.sql"))
	if err != nil {
		t.Fatalf("read runtime v2 migration: %v", err)
	}
	statement := string(contents)
	for _, required := range []string{
		"SELECT pg_advisory_xact_lock",
		"CREATE TABLE IF NOT EXISTS runtime.schema_migrations",
		"md5:3e2be286da9ec6335297a050e0cb59a4",
		"CREATE TABLE IF NOT EXISTS runtime.tenants",
		"CREATE TABLE IF NOT EXISTS runtime.agent_revisions",
		"CREATE TABLE IF NOT EXISTS runtime.sessions",
		"CREATE TABLE IF NOT EXISTS runtime.inputs",
		"CREATE TABLE IF NOT EXISTS runtime.turns",
		"CREATE TABLE IF NOT EXISTS runtime.session_events",
		"CREATE TABLE IF NOT EXISTS runtime.audit_records",
		"CREATE TABLE IF NOT EXISTS runtime.runtime_outbox",
		"content_digest",
		"content_size_bytes",
		"expected_version",
		"PRIMARY KEY (tenant_id, principal_id, session_id, sequence)",
		"UNIQUE (tenant_id, operation_id)",
		"sessions_agent_revision_integrity",
		"session_events_turn_integrity",
		"^sha256:[0-9a-f]{64}$",
	} {
		if !strings.Contains(statement, required) {
			t.Errorf("runtime v2 migration is missing %q", required)
		}
	}
	for _, prohibited := range []string{"raw_prompt", "prompt_text", "content_text", "event_payload"} {
		if strings.Contains(statement, prohibited) {
			t.Errorf("runtime v2 migration must not persist raw content column %q", prohibited)
		}
	}
}

func TestRuntimeV2RollbackArtifactExplicitlyRefusesDestructiveRollback(t *testing.T) {
	t.Parallel()

	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "production", "migrations", "runtime-v2.down.sql"))
	if err != nil {
		t.Fatalf("read runtime v2 rollback migration: %v", err)
	}
	statement := string(contents)
	for _, required := range []string{"SELECT pg_advisory_xact_lock", "runtime v2 migration is forward-only", "restore a tested PostgreSQL backup"} {
		if !strings.Contains(statement, required) {
			t.Errorf("runtime v2 rollback migration is missing %q", required)
		}
	}
	for _, prohibited := range []string{"DROP TABLE", "TRUNCATE", "DELETE FROM"} {
		if strings.Contains(statement, prohibited) {
			t.Errorf("runtime v2 rollback migration must not execute destructive statement %q", prohibited)
		}
	}
}

func TestRuntimeV3MigrationRaisesInputReferenceBoundWithoutRawContent(t *testing.T) {
	t.Parallel()

	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "production", "migrations", "runtime-v3.up.sql"))
	if err != nil {
		t.Fatalf("read runtime v3 migration: %v", err)
	}
	statement := string(contents)
	for _, required := range []string{
		"hashtextextended('agent-runtime/runtime-v3', 0)",
		"inputs_content_size_bytes_v3_bound",
		"2101248",
		"migration_version, schema_fingerprint",
		"runtime v3 migration fingerprint mismatch",
	} {
		if !strings.Contains(statement, required) {
			t.Errorf("runtime v3 migration is missing %q", required)
		}
	}
	for _, prohibited := range []string{"raw_prompt", "prompt_text", "content_text", "event_payload"} {
		if strings.Contains(statement, prohibited) {
			t.Errorf("runtime v3 migration must not persist raw content column %q", prohibited)
		}
	}
}

func TestRuntimeV4MigrationDeclaresPlansOnlyLifecycleMetadata(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "production", "migrations", "runtime-v4.up.sql"))
	if err != nil {
		t.Fatalf("read runtime v4 migration: %v", err)
	}
	statement := string(contents)
	for _, required := range []string{"runtime-v4", "runtime.invocations", "runtime.mutation_receipts", "runtime.outbox_leases", "invocation_fence", "request_digest", "content_media_type"} {
		if !strings.Contains(statement, required) {
			t.Errorf("runtime v4 migration missing %q", required)
		}
	}
	for _, prohibited := range []string{"raw_prompt", "prompt_text", "content_text", "event_payload"} {
		if strings.Contains(statement, prohibited) {
			t.Errorf("runtime v4 migration must not persist raw content %q", prohibited)
		}
	}
}

func TestRuntimeV5MigrationDeclaresNativeTenantPartitionsAndLeastPrivilegeBoundary(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "production", "migrations", "runtime-v5.up.sql"))
	if err != nil {
		t.Fatalf("read runtime v5 migration: %v", err)
	}
	statement := string(contents)
	for _, required := range []string{
		"runtime-v5", "PARTITION BY HASH (tenant_id)", "runtime_state_snapshots_p0",
		"runtime_state_app", "runtime_state_operator", "ENABLE ROW LEVEL SECURITY",
		"FORCE ROW LEVEL SECURITY", "current_setting('runtime.tenant_id', true)",
		"tenant_retention_jobs", "runtime_tenant_catalog_isolation", "REVOKE ALL ON SCHEMA runtime FROM PUBLIC",
	} {
		if !strings.Contains(statement, required) {
			t.Errorf("runtime v5 migration missing %q", required)
		}
	}
}
