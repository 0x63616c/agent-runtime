package main

import "testing"

func TestParseConfigurationAcceptsOneStrictEnvironmentDocument(t *testing.T) {
	t.Setenv("RUNTIME_API_CONFIG", `{"version":1,"listen_address":"0.0.0.0:8088","public_listen":true,"storage":{"mode":"memory-unsafe"},"model_profiles":["balanced"],"max_request_bytes":4194304,"principals":[{"tenant":"production","principal":"admin","admin":true,"bearer_token_environment":"RUNTIME_API_ADMIN_TOKEN"}]}`)
	if _, err := parseConfiguration("", "RUNTIME_API_CONFIG", 0); err != nil {
		t.Fatalf("parse configuration environment: %v", err)
	}
}

func TestParseConfigurationRejectsAmbiguousOrMissingSources(t *testing.T) {
	if _, err := parseConfiguration("/tmp/runtime-api.json", "RUNTIME_API_CONFIG", 0); err == nil {
		t.Fatal("parse configuration with two sources succeeded")
	}
	if _, err := parseConfiguration("", "RUNTIME_API_CONFIG", 0); err == nil {
		t.Fatal("parse missing configuration environment succeeded")
	}
}
