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
		"runtime-v2-authority-schema-20260809",
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
