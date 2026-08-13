package firecrackerfixtures

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
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
	contents, err := json.Marshal(rootFSBuilderManifest(t, image))
	if err != nil {
		t.Fatalf("marshal builder manifest: %v", err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write builder manifest: %v", err)
	}
	return path
}

func rootFSBuilderManifest(t *testing.T, image string) map[string]any {
	t.Helper()
	return map[string]any{
		"schema_version":     "agent-runtime.firecracker.rootfs-builder/v1",
		"image":              image,
		"platform":           map[string]string{"os": "linux", "architecture": "amd64"},
		"required_commands":  []string{"awk", "grep", "install", "mke2fs", "mkdir", "mktemp", "readelf", "rm", "sha256sum", "tr", "truncate", "wc"},
		"e2fsprogs_version":  "1.47.2",
		"binutils_version":   "2.44",
		"source_revision":    gitHead(t),
		"dockerfile_sha256":  fileSHA256(t, filepath.Join("rootfs-builder", "Dockerfile")),
		"inputs_lock_sha256": fileSHA256(t, filepath.Join("rootfs-builder", "inputs.lock.json")),
	}
}

func gitHead(t *testing.T) string {
	t.Helper()
	output, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatalf("read checkout revision: %v", err)
	}
	return strings.TrimSpace(string(output))
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	digest := sha256.Sum256(contents)
	return "sha256:" + hex.EncodeToString(digest[:])
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

func TestRootFSBuilderSourceVerifierRejectsDockerfileOutsideSourceLock(t *testing.T) {
	temporary := t.TempDir()
	for _, name := range []string{"verify-source.sh", "Dockerfile", "inputs.lock.json"} {
		contents, err := os.ReadFile(filepath.Join("rootfs-builder", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		mode := os.FileMode(0o600)
		if name == "verify-source.sh" {
			mode = 0o700
		}
		if err := os.WriteFile(filepath.Join(temporary, name), contents, mode); err != nil {
			t.Fatalf("copy %s: %v", name, err)
		}
	}

	if output, err := exec.Command("sh", filepath.Join(temporary, "verify-source.sh")).CombinedOutput(); err != nil {
		t.Fatalf("copied source verifier rejected reviewed source: %v\n%s", err, output)
	}
	if err := os.WriteFile(filepath.Join(temporary, "Dockerfile"), []byte("FROM alpine:latest\n"), 0o600); err != nil {
		t.Fatalf("tamper Dockerfile: %v", err)
	}
	output, err := exec.Command("sh", filepath.Join(temporary, "verify-source.sh")).CombinedOutput()
	if err == nil || !strings.Contains(string(output), "Dockerfile differs from the reviewed inputs contract") {
		t.Fatalf("tampered Dockerfile result = %v, %q", err, output)
	}
}

func TestRootFSBuilderManifestBindsCurrentReviewedSource(t *testing.T) {
	image := "registry.example.invalid/rootfs@sha256:" + strings.Repeat("a", 64)
	manifestPath := writeRootFSBuilderManifest(t, image)
	if output, err := exec.Command("sh", "validate-rootfs-builder.sh", manifestPath, image).CombinedOutput(); err != nil {
		t.Fatalf("reviewed manifest rejected: %v\n%s", err, output)
	}

	for _, test := range []struct {
		name    string
		field   string
		value   string
		message string
	}{
		{"revision", "source_revision", strings.Repeat("b", 40), "source_revision must bind the current checkout"},
		{"dockerfile", "dockerfile_sha256", "sha256:" + strings.Repeat("b", 64), "dockerfile_sha256 must bind the reviewed Dockerfile"},
		{"source lock", "inputs_lock_sha256", "sha256:" + strings.Repeat("b", 64), "inputs_lock_sha256 must bind the reviewed source lock"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manifest := rootFSBuilderManifest(t, image)
			manifest[test.field] = test.value
			contents, err := json.Marshal(manifest)
			if err != nil {
				t.Fatalf("marshal tampered manifest: %v", err)
			}
			if err := os.WriteFile(manifestPath, contents, 0o600); err != nil {
				t.Fatalf("write tampered manifest: %v", err)
			}
			output, err := exec.Command("sh", "validate-rootfs-builder.sh", manifestPath, image).CombinedOutput()
			if err == nil || !strings.Contains(string(output), test.message) {
				t.Fatalf("stale %s manifest result = %v, %q", test.name, err, output)
			}
		})
	}
}

func TestRootFSBuilderBuildContractIsVerifiedBeforeDockerAndPullFree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test requires a POSIX shell")
	}
	fakeBin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "docker.log")
	fakeDocker := filepath.Join(fakeBin, "docker")
	if err := os.WriteFile(fakeDocker, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$FAKE_DOCKER_LOG\"\n"), 0o700); err != nil {
		t.Fatalf("write fake Docker: %v", err)
	}
	command := exec.Command("sh", "build-rootfs-builder.sh", "registry.example.invalid/rootfs:local")
	command.Env = append(command.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH"), "FAKE_DOCKER_LOG="+logPath)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build contract invocation failed: %v\n%s", err, output)
	}
	contents, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read fake Docker log: %v", err)
	}
	got := strings.Fields(string(contents))
	baseImage := "docker.io/library/alpine@sha256:7c8cb692ae09657cbc4a3f3cbd0e8d5a2690ba38386aaaf252dbb060bf5eb2e6"
	want := []string{"image", "inspect", baseImage, "build", "--pull=false", "--platform", "linux/amd64", "--file", filepath.Join(mustAbs(t, "rootfs-builder"), "Dockerfile"), "--tag", "registry.example.invalid/rootfs:local", mustAbs(t, "rootfs-builder")}
	if !slices.Equal(got, want) {
		t.Fatalf("Docker contract = %#v, want %#v", got, want)
	}
}

func mustAbs(t *testing.T, path string) string {
	t.Helper()
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("absolute %s: %v", path, err)
	}
	return abs
}
