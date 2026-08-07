package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRunChecksOnlyTheConfiguredRoleCredentials(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "orchestration.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"role":"orchestration","namespace":"agent-runtime","listen_address":"127.0.0.1:8081","dependencies":[{"name":"state","endpoint":"postgres://state:5432/runtime","secret_environment":"STATE_DATABASE_DSN"},{"name":"telemetry","endpoint":"http://telemetry:4318"},{"name":"temporal","endpoint":"temporal:7233","secret_environment":"TEMPORAL_AUTH_TOKEN"}]}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	lookup := func(name string) (string, bool) {
		value, found := map[string]string{"STATE_DATABASE_DSN": "state", "TEMPORAL_AUTH_TOKEN": "temporal"}[name]
		return value, found
	}
	if err := run(context.Background(), []string{"serve", "--config", path, "--role", "orchestration", "--check"}, lookup); err != nil {
		t.Fatalf("run check: %v", err)
	}
	if err := run(context.Background(), []string{"serve", "--config", path, "--role", "model", "--check"}, lookup); err == nil {
		t.Fatal("expected mismatched role rejection")
	}
}

func TestRunAcceptsExplicitNonSecretConfigurationEnvironment(t *testing.T) {
	t.Parallel()
	configuration := `{"version":1,"role":"api","namespace":"agent-runtime","listen_address":"127.0.0.1:8080","dependencies":[{"name":"state","endpoint":"http://state:8080"},{"name":"telemetry","endpoint":"http://telemetry:4318"}]}`
	lookup := func(name string) (string, bool) {
		if name == "RUNTIME_ROLE_CONFIG" {
			return configuration, true
		}
		return "", false
	}
	if err := run(context.Background(), []string{"serve", "--config-env", "RUNTIME_ROLE_CONFIG", "--role", "api", "--check"}, lookup); err != nil {
		t.Fatalf("run config environment check: %v", err)
	}
	if err := run(context.Background(), []string{"--config-env", "RUNTIME_ROLE_CONFIG", "--config", "other.json", "--role", "api", "--check"}, lookup); err == nil {
		t.Fatal("expected mutually exclusive config source rejection")
	}
}
