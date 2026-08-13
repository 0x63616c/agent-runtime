package firecrackerfixtures

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestContainerRootFSRecipeRejectsNonImmutableBuilderReferenceBeforeDocker(t *testing.T) {
	script := filepath.Join("build-rootfs-container.sh")
	command := exec.Command("sh", script, "alpine:latest", "agent", "rootfs.ext4", "1048576", "00000000-0000-0000-0000-000000000001", "attestation.json")
	command.Env = append(command.Environ(), "SOURCE_DATE_EPOCH=1704067200")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("container recipe accepted a floating builder image")
	}
	if got := string(output); !strings.Contains(got, "exact image reference") {
		t.Fatalf("floating builder rejection = %q", got)
	}
}

func TestContainerRootFSRecipeRequiresFixedEpochBeforeDocker(t *testing.T) {
	script := filepath.Join("build-rootfs-container.sh")
	image := "registry.example.invalid/rootfs@sha256:" + strings.Repeat("a", 64)
	command := exec.Command("sh", script, image, "agent", "rootfs.ext4", "1048576", "00000000-0000-0000-0000-000000000001", "attestation.json")
	command.Env = append(command.Environ(), "SOURCE_DATE_EPOCH=not-fixed")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("container recipe accepted a non-fixed epoch")
	}
	if got := string(output); !strings.Contains(got, "SOURCE_DATE_EPOCH must be a fixed integer") {
		t.Fatalf("epoch rejection = %q", got)
	}
}

func TestContainerRootFSRecipeIsNetworklessAndPullFree(t *testing.T) {
	contents, err := os.ReadFile("build-rootfs-container.sh")
	if err != nil {
		t.Fatalf("read container recipe: %v", err)
	}
	for _, required := range []string{"--pull=never", "--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges", "--platform linux/amd64"} {
		if !strings.Contains(string(contents), required) {
			t.Errorf("container recipe is missing %q", required)
		}
	}
}
