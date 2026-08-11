package runtimeoperations

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestLoadConfigFailsClosedWithoutProtectedAuthorityAndAcceptsCompleteBoundedInput(t *testing.T) {
	values := map[string]string{
		"RUNTIME_OPERATIONS_RUNNER_CONTRACT":               RunnerContract,
		"AR_RUNTIME_OPERATIONS_DATABASE_DSN":               "postgres://operator@db.example.invalid/runtime_source?sslmode=require",
		"AR_RUNTIME_OPERATIONS_PITR_RESTORE_DSN":           "postgres://operator@db.example.invalid/runtime_restore?sslmode=require",
		"AR_RUNTIME_OPERATIONS_AUDIT_SINK_URL":             "https://audit.example.invalid/v1/facts",
		"AR_RUNTIME_OPERATIONS_AUDIT_RETENTION_URL":        "https://audit.example.invalid/v1/retention",
		"AR_RUNTIME_OPERATIONS_RETENTION_TENANT":           "protected-retention-tenant",
		"AR_RUNTIME_OPERATIONS_RETENTION_AUTHORIZATION_ID": "retention-authorization-0001",
		"AR_RUNTIME_OPERATIONS_PITR_TENANT":                "protected-pitr-tenant",
		"AR_RUNTIME_OPERATIONS_PITR_AUTHORIZATION_ID":      "pitr-authorization-00000001",
		"AR_RUNTIME_OPERATIONS_PITR_RECOVERY_POINT":        "2026-08-11T12:00:00Z",
		"AR_RUNTIME_OPERATIONS_PITR_EXPECTED_GENERATION":   "7",
		"GITHUB_SHA": "abcdef0123456789",
	}
	get := func(key string) string { return values[key] }
	config, err := LoadConfig(get)
	if err != nil {
		t.Fatalf("load complete protected config: %v", err)
	}
	if config.PITRExpectedGeneration != 7 || config.SourceRevision == "" {
		t.Fatalf("config = %#v", config)
	}
	values["RUNTIME_OPERATIONS_RUNNER_CONTRACT"] = ""
	if _, err := LoadConfig(get); err == nil {
		t.Fatal("missing runner contract loaded")
	}
	values["RUNTIME_OPERATIONS_RUNNER_CONTRACT"] = RunnerContract
	values["AR_RUNTIME_OPERATIONS_PITR_RESTORE_DSN"] = values["AR_RUNTIME_OPERATIONS_DATABASE_DSN"]
	if _, err := LoadConfig(get); err == nil {
		t.Fatal("same source and PITR database loaded")
	}
}

func TestEvidenceRoundTripIsStrictAndNeverOverwritesAnExistingArtifact(t *testing.T) {
	evidence := Evidence{
		SchemaVersion: SchemaVersion, ProofLevel: "protected_authorized_operational_drill", Result: "passed", OccurredAt: time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC).Format(time.RFC3339), SourceRevision: "abcdef0123456789",
		Database:    DatabaseEvidence{AppRoleMember: true, OperatorRoleMember: true, RetentionScheduled: true, RetentionExecuted: true, PartitionCount: 4},
		AuditSink:   AuditSinkEvidence{OutageStatus: 503, RecoveryStatus: 202, RetentionSeconds: 86400},
		PITR:        PITREvidence{ArchiveModeOn: true, SourcePrimary: true, IsolatedTarget: true, RecoveredGeneration: 7, RecoveryPoint: "2026-08-11T12:00:00Z"},
		Limitations: []string{"one bounded drill"},
	}
	path := filepath.Join(t.TempDir(), "operational.json")
	if err := WriteEvidence(path, evidence); err != nil {
		t.Fatalf("write evidence: %v", err)
	}
	loaded, err := ReadEvidence(path)
	if err != nil || !reflect.DeepEqual(loaded, evidence) {
		t.Fatalf("read evidence = %#v, %v", loaded, err)
	}
	if err := WriteEvidence(path, evidence); err == nil {
		t.Fatal("overwrote protected artifact")
	}
	invalid := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(invalid, []byte(`{"schema_version":"agent-runtime.operations-evidence/v1","unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadEvidence(invalid); err == nil {
		t.Fatal("unknown report field was accepted")
	}
}
