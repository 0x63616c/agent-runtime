package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/firecracker"
)

func TestSmokeObservationFailureReasonRetainsOnlyTheFailedProofBoundary(t *testing.T) {
	prefix := "protected smoke harness did not retain a complete boot/control/cleanup observation"
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{name: "stage", err: errors.New("prepare jailed rootfs: arbitrary host path /private/secret"), want: prefix + ": Jailer fixture staging failed"},
		{name: "api readiness", err: errors.New("launch jailer: await Firecracker API socket: arbitrary Jailer diagnostic"), want: prefix + ": Firecracker API socket was not observed"},
		{name: "launch", err: errors.New("launch jailer: arbitrary Jailer diagnostic"), want: prefix + ": Jailer or Firecracker launch failed"},
		{name: "jailer permission", err: fmt.Errorf("launch jailer: start Jailer: %w", fs.ErrPermission), want: prefix + ": Jailer executable was denied by the host"},
		{name: "jailer permission text", err: errors.New("launch jailer: start Jailer: fork/exec: permission denied"), want: prefix + ": Jailer executable was denied by the host"},
		{name: "jailer missing", err: errors.New("launch jailer: start Jailer: fork/exec: no such file or directory"), want: prefix + ": Jailer executable was unavailable to the host"},
		{name: "serial", err: errors.New("await guest serial marker: context deadline exceeded"), want: prefix + ": guest serial boot marker was not observed"},
		{name: "control", err: errors.New("guest control channel: arbitrary guest wire"), want: prefix + ": private guest control handshake failed"},
		{name: "cleanup", err: errors.New("cleanup protected Firecracker resources: arbitrary cleanup output"), want: prefix + ": Jailer cleanup proof failed"},
		{name: "unknown", err: errors.New("arbitrary internal failure"), want: prefix + ": an unclassified bounded smoke lifecycle edge failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := smokeObservationFailureReason(test.err); got != test.want {
				t.Fatalf("smokeObservationFailureReason() = %q, want %q", got, test.want)
			}
		})
	}
}

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

func TestRunRefusesDirectExecutionOutsideTheRootOwnedAuthority(t *testing.T) {
	record := report{Preflight: firecracker.KVMPreflight{GOOS: "linux", GOARCH: "amd64", KVMCharacterDevice: true, KVMReadWrite: true, CgroupV2: true}}
	err := run(recordRunnerConfig{fixtureLockPath: filepath.Join(t.TempDir(), "not-read.lock"), executionMode: directExecutionMode}, &record)
	if err == nil || record.Result != firecracker.EvidenceBlocked || record.Reason != "direct Firecracker config path does not match the reviewed authority" || record.ExecutionMode != directExecutionMode {
		t.Fatalf("run() = (%v, %#v), want direct authority refusal before fixture read", err, record)
	}
}

func TestRunRefusesDirectExecutionConfigOutsideTheReviewedAuthority(t *testing.T) {
	t.Setenv("FIRECRACKER_DIRECT_KVM_PREFLIGHT", "passed")
	record := report{Preflight: firecracker.KVMPreflight{GOOS: "linux", GOARCH: "amd64", KVMCharacterDevice: true, KVMReadWrite: true, CgroupV2: true}}
	err := run(recordRunnerConfig{fixtureLockPath: filepath.Join(t.TempDir(), "not-read.lock"), executionMode: directExecutionMode, directConfigPath: filepath.Join(t.TempDir(), "config.json")}, &record)
	if err == nil || record.Reason != "direct Firecracker config path does not match the reviewed authority" {
		t.Fatalf("run() = (%v, %#v), want authority-path refusal", err, record)
	}
}

func TestDirectEvidenceReportIsConfinedToTheOperatorEvidenceRoot(t *testing.T) {
	if validDirectEvidenceReportPath("evidence/report.json") || validDirectEvidenceReportPath("/tmp/report.json") || validDirectEvidenceReportPath("/var/lib/agent-runtime/firecracker-evidence/run/report.txt") || !validDirectEvidenceReportPath("/var/lib/agent-runtime/firecracker-evidence/home-server/run.json") {
		t.Fatal("validDirectEvidenceReportPath() did not confine direct evidence")
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
