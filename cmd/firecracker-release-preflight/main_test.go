package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/firecracker"
)

const testRevision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestValidateReleaseTargetRequiresExactCommitReleaseAssets(t *testing.T) {
	target := projectReleasePrefix + "commit-" + testRevision + "/"
	lock := firecracker.FixtureLock{Sources: []firecracker.LockedSource{
		{ID: "kernel", URL: target + "kernel-vmlinux", Reference: "commit:" + testRevision},
		{ID: "rootfs", URL: target + "rootfs-bundle.tar.gz", Reference: "commit:" + testRevision},
		{ID: "guest-agent", URL: target + "guest-agent-bundle.tar.gz", Reference: "commit:" + testRevision},
	}}
	if err := validateReleaseTarget(lock, testRevision); err != nil {
		t.Fatalf("validateReleaseTarget() error = %v", err)
	}
	lock.Sources[1].URL = target + "other-rootfs.tar.gz"
	if err := validateReleaseTarget(lock, testRevision); err == nil {
		t.Fatal("validateReleaseTarget() accepted a non-contract release asset")
	}
}

func TestReadManifestRejectsTrailingData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inputs.json")
	contents := `{"schema_version":"agent-runtime.firecracker.fixture-inputs/v1","source_revision":"` + testRevision + `","source_tree":{"sha256":"sha256:abc","size_bytes":1}} {}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readManifest(path); err == nil {
		t.Fatal("readManifest() accepted trailing JSON")
	}
}

func TestCleanRevisionRejectsDirtyCheckout(t *testing.T) {
	calls := 0
	_, err := cleanRevision(func(_ string, _ ...string) ([]byte, error) {
		calls++
		if calls == 1 {
			return []byte(testRevision + "\n"), nil
		}
		return nil, assertError{}
	})
	if err == nil {
		t.Fatal("cleanRevision() accepted a dirty checkout")
	}
}

type assertError struct{}

func (assertError) Error() string { return "expected command refusal" }
