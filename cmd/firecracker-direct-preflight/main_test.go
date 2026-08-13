package main

import (
	"os"
	"testing"
)

func TestDirectConfigRejectsUnsafeEvidenceAndAuthorityValues(t *testing.T) {
	if validEvidenceDirectory(directEvidenceRoot) || validEvidenceDirectory("/tmp/evidence") || !validEvidenceDirectory(directEvidenceRoot+"/home-server") {
		t.Fatal("validEvidenceDirectory() did not confine direct evidence")
	}
	if validName("direct/run") || validRelativePath("../other") || !validRelativePath("agent-runtime/firecracker") {
		t.Fatal("direct configuration validation accepted unsafe values")
	}

}

func TestDirectPreflightRequiresLinuxAMD64BeforeReadingConfig(t *testing.T) {
	err := run("not-read", "not-read", func(string) (os.FileInfo, error) { t.Fatal("stat called"); return nil, nil }, "darwin", "arm64")
	if err == nil || err.Error() != "direct Firecracker execution requires linux/amd64" {
		t.Fatalf("run() error = %v", err)
	}
}
