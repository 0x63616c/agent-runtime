package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/firecracker"
)

func TestRunRefusesBeforeFixtureReadWithoutTheProtectedRunnerContract(t *testing.T) {
	t.Setenv("FIRECRACKER_RUNNER_CONTRACT", "")
	record := report{Preflight: firecracker.KVMPreflight{GOOS: "linux", GOARCH: "amd64", KVMCharacterDevice: true, KVMReadWrite: true, CgroupV2: true}}
	err := run(recordRunnerConfig{fixtureLockPath: filepath.Join(t.TempDir(), "not-read.lock")}, &record)
	if err == nil || record.Result != firecracker.EvidenceBlocked || record.Reason != "protected self-hosted KVM runner contract is absent" {
		t.Fatalf("run() = (%v, %#v), want contract refusal before fixture read", err, record)
	}
}

func TestRunRefusesMissingProtectedInputsAfterTheRunnerPreflight(t *testing.T) {
	t.Setenv("FIRECRACKER_RUNNER_CONTRACT", runnerContract)
	record := report{Preflight: firecracker.KVMPreflight{GOOS: "linux", GOARCH: "amd64", KVMCharacterDevice: true, KVMReadWrite: true, CgroupV2: true}}
	err := run(recordRunnerConfig{fixtureLockPath: filepath.Join(t.TempDir(), "not-read.lock")}, &record)
	if err == nil || record.Result != firecracker.EvidenceBlocked || record.Reason != "reviewed fixture lock, VM identity, unprivileged Jailer identity, cgroup authority, external limit owner, and bounded timeout are required" {
		t.Fatalf("run() = (%v, %#v), want exact input refusal", err, record)
	}
}

func TestWriteReportRetainsOnlyTheBoundedRedactedRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	record := report{SchemaVersion: "firecracker.smoke-evidence/v2", ProofLevel: firecracker.ProofLevelLinuxKVME2E, Result: firecracker.EvidenceBlocked, Reason: "fixture lock unavailable"}
	if err := writeReport(path, record); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "{\n  \"schema_version\": \"firecracker.smoke-evidence/v2\",\n  \"proof_level\": \"linux_kvm_e2e\",\n  \"result\": \"blocked\",\n  \"preflight\": {\n    \"goos\": \"\",\n    \"goarch\": \"\",\n    \"kvm_character_device\": false,\n    \"kvm_read_write\": false,\n    \"cgroup_v2\": false\n  },\n  \"cleanup\": {\n    \"proved\": false\n  },\n  \"reason\": \"fixture lock unavailable\"\n}\n" {
		t.Fatalf("report = %q, err = %v, want bounded canonical report", contents, err)
	}
}
