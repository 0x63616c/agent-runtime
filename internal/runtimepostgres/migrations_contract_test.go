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
		"CREATE TABLE runtime.tenants",
		"CREATE TABLE runtime.agent_revisions",
		"CREATE TABLE runtime.sessions",
		"CREATE TABLE runtime.inputs",
		"CREATE TABLE runtime.turns",
		"CREATE TABLE runtime.session_events",
		"CREATE TABLE runtime.audit_records",
		"CREATE TABLE runtime.runtime_outbox",
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
