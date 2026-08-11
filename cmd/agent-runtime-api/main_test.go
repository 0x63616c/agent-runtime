package main

import (
	"testing"
)

const environmentConfig = `{"version":1,"listen_address":"127.0.0.1:8088","storage":{"mode":"memory-unsafe"},"model_profiles":["balanced"],"max_request_bytes":4194304,"principals":[{"tenant":"local","principal":"admin","admin":true,"bearer_token_environment":"ADMIN_TOKEN"}]}`

func TestLoadConfigAcceptsDeclaredEnvironmentConfigurationAndCheck(t *testing.T) {
	t.Parallel()
	config, check, err := loadConfig([]string{"--config-env", "RUNTIME_API_CONFIG", "--check"}, func(name string) (string, bool) {
		if name == "RUNTIME_API_CONFIG" {
			return environmentConfig, true
		}
		return "", false
	})
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	_ = config // Config is intentionally opaque; successful strict parsing is the contract here.
	if !check {
		t.Fatal("loadConfig() check = false, want true")
	}
}

func TestLoadConfigFailsClosedForMissingOrMalformedEnvironmentConfiguration(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		lookup func(string) (string, bool)
	}{
		{name: "missing", lookup: func(string) (string, bool) { return "", false }},
		{name: "malformed", lookup: func(string) (string, bool) { return `{"version":1}`, true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := loadConfig([]string{"--config-env", "RUNTIME_API_CONFIG", "--check"}, test.lookup); err == nil {
				t.Fatal("loadConfig() error = nil")
			}
		})
	}
}
