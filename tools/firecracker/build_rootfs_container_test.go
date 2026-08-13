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
	manifest := writeRootFSBuilderManifest(t, "registry.example.invalid/rootfs@sha256:"+strings.Repeat("a", 64))
	command := exec.Command("sh", script, manifest, "alpine:latest", "agent", "rootfs.ext4", "1048576", "00000000-0000-0000-0000-000000000001", "attestation.json")
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
	manifest := writeRootFSBuilderManifest(t, image)
	command := exec.Command("sh", script, manifest, image, "agent", "rootfs.ext4", "1048576", "00000000-0000-0000-0000-000000000001", "attestation.json")
	command.Env = append(command.Environ(), "SOURCE_DATE_EPOCH=not-fixed")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("container recipe accepted a non-fixed epoch")
	}
	if got := string(output); !strings.Contains(got, "SOURCE_DATE_EPOCH must be a fixed integer") {
		t.Fatalf("epoch rejection = %q", got)
	}
}

func TestContainerRootFSRecipeRejectsAnUnreviewedDigestBeforeDocker(t *testing.T) {
	script := filepath.Join("build-rootfs-container.sh")
	manifest := writeRootFSBuilderManifest(t, "registry.example.invalid/rootfs@sha256:"+strings.Repeat("a", 64))
	image := "registry.example.invalid/rootfs@sha256:" + strings.Repeat("b", 64)
	command := exec.Command("sh", script, manifest, image, "agent", "rootfs.ext4", "1048576", "00000000-0000-0000-0000-000000000001", "attestation.json")
	command.Env = append(command.Environ(), "SOURCE_DATE_EPOCH=1704067200")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("container recipe accepted an unreviewed builder digest")
	}
	if got := string(output); !strings.Contains(got, "must equal the reviewed") {
		t.Fatalf("unreviewed builder rejection = %q", got)
	}
}

func writeRootFSBuilderManifest(t *testing.T, image string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rootfs-builder.json")
	contents := `{"schema_version":"agent-runtime.firecracker.rootfs-builder/v1","image":"` + image + `","platform":{"os":"linux","architecture":"amd64"},"required_commands":["awk","grep","install","mke2fs","mkdir","mktemp","readelf","rm","sha256sum","tr","truncate","wc"],"e2fsprogs_version":"1.47.2","binutils_version":"2.44"}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write builder manifest: %v", err)
	}
	return path
}

func TestContainerRootFSRecipeIsNetworklessAndPullFree(t *testing.T) {
	contents, err := os.ReadFile("build-rootfs-container.sh")
	if err != nil {
		t.Fatalf("read container recipe: %v", err)
	}
	for _, required := range []string{"--pull=never", "--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges", "--platform linux/amd64", "mke2fs -V", "readelf --version"} {
		if !strings.Contains(string(contents), required) {
			t.Errorf("container recipe is missing %q", required)
		}
	}
}
