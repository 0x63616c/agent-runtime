package main

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestReviewedRunnerContractIsCompleteAndSecretFree(t *testing.T) {
	loaded, err := readContract(filepath.Join("..", "..", "deploy", "firecracker", "runner-contract.json"))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Bootstrap.ConfigPath != "/etc/agent-runtime/firecracker-kvm-runner.json" || loaded.Fixtures.LockPath != "tools/firecracker/fixtures.lock" {
		t.Fatalf("contract = %#v, want reviewed bootstrap and fixture lock paths", loaded)
	}
}

func TestValidateWorkflowRefusesLocalOrUnlabelledExecution(t *testing.T) {
	loaded, err := readContract(filepath.Join("..", "..", "deploy", "firecracker", "runner-contract.json"))
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{
		"FIRECRACKER_RUNNER_CONTRACT":    "protected-linux-kvm-v1",
		"GITHUB_ACTIONS":                 "true",
		"GITHUB_REF_PROTECTED":           "true",
		"GITHUB_WORKFLOW":                "firecracker-kvm",
		"RUNNER_ENVIRONMENT":             "self-hosted",
		"RUNNER_OS":                      "Linux",
		"RUNNER_ARCH":                    "X64",
		"FIRECRACKER_GITHUB_ENVIRONMENT": "firecracker-kvm",
		"FIRECRACKER_RUNNER_LABELS":      "self-hosted,linux,x64,kvm,firecracker-protected",
	}
	getenv := func(name string) string { return values[name] }
	if err := validateWorkflow(loaded, getenv, "linux", "amd64"); err != nil {
		t.Fatalf("validateWorkflow() error = %v", err)
	}
	values["FIRECRACKER_RUNNER_LABELS"] = "self-hosted,linux,x64,kvm"
	if err := validateWorkflow(loaded, getenv, "linux", "amd64"); err == nil {
		t.Fatal("validateWorkflow() succeeded without the protected runner label")
	}
	if err := validateWorkflow(loaded, getenv, runtime.GOOS, runtime.GOARCH); err == nil && (runtime.GOOS != "linux" || runtime.GOARCH != "amd64") {
		t.Fatal("validateWorkflow() accepted a non-linux/amd64 local platform")
	}
}

func TestBootstrapValuesAreStrictlyBounded(t *testing.T) {
	if validRelativePath("/agent-runtime") || validRelativePath("../agent-runtime") || validRelativePath("agent-runtime//child") || !validRelativePath("agent-runtime/firecracker") {
		t.Fatal("validRelativePath() did not reject unsafe cgroup parent paths")
	}
	if validName("owner\nsecret") || !validName("firecracker-kvm") {
		t.Fatal("validName() did not enforce bounded non-secret identifiers")
	}
}
