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
