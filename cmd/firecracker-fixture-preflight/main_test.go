package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/firecracker"
	"github.com/0x63616c/agent-runtime/sandbox"
)

// This is deliberately an assembly-shaped test fixture, rather than a copy of
// the checked-in lock.  It exercises the command's local-only boundary with
// deterministic synthetic bytes, including the commit-scoped project release
// URLs that a real assembled candidate must use.  It does not download,
// publish, build a rootfs, or require Linux/KVM.
func TestRunPreflightsSyntheticCandidateWithCommitBoundReleaseSources(t *testing.T) {
	lockPath, files, lock := syntheticCandidate(t)

	if err := run(lockPath, files); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	const revision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, source := range lock.Sources {
		if source.ID == "firecracker-release" {
			continue
		}
		wantPrefix := "https://github.com/0x63616c/agent-runtime/releases/download/commit-" + revision + "/"
		if !strings.HasPrefix(source.URL, wantPrefix) {
			t.Fatalf("source %q URL = %q, want project release prefix %q", source.ID, source.URL, wantPrefix)
		}
	}
}

func TestRunRejectsSyntheticCandidateWhoseProjectReleaseBindingChanges(t *testing.T) {
	lockPath, files, lock := syntheticCandidate(t)
	for index := range lock.Sources {
		if lock.Sources[index].ID == "kernel" {
			lock.Sources[index].URL = "https://github.com/0x63616c/other/releases/download/commit-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/kernel-vmlinux"
		}
	}
	writeSyntheticLock(t, lockPath, lock)

	err := run(lockPath, files)
	if err == nil || !strings.Contains(err.Error(), "parse candidate lock") {
		t.Fatalf("run() error = %v, want rejected project release binding", err)
	}
}

func syntheticCandidate(t *testing.T) (string, map[string]string, firecracker.FixtureLock) {
	t.Helper()
	const revision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const version = "v1.16.1"
	directory := t.TempDir()

	write := func(name string, contents []byte) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return path
	}

	archive := tarGzip(t, map[string][]byte{
		"release-v1.16.1-x86_64/firecracker-v1.16.1-x86_64": []byte("synthetic-firecracker"),
		"release-v1.16.1-x86_64/jailer-v1.16.1-x86_64":      []byte("synthetic-jailer"),
	})
	kernel := []byte("synthetic-kernel")
	guestAgent := []byte("synthetic-static-guest-agent")
	rootFS := []byte("synthetic-rootfs")
	rootInputs := []byte(`{"recipe":"synthetic-rootfs"}`)
	rootSBOM := []byte(`{"spdxVersion":"SPDX-2.3"}`)
	agentInputs := []byte(`{"recipe":"synthetic-guest-agent"}`)
	agentSBOM := []byte(`{"spdxVersion":"SPDX-2.3"}`)

	rootBuild := firecracker.BuildProvenance{
		RecipePath: "tools/firecracker/build-rootfs.sh", SourceRevision: revision, Toolchain: "synthetic-go",
		InputsMember: "rootfs-inputs.json", InputsDigest: syntheticDigest(rootInputs), InputsSizeBytes: uint64(len(rootInputs)),
		SBOMMember: "rootfs-sbom.spdx.json", SBOMDigest: syntheticDigest(rootSBOM), SBOMSizeBytes: uint64(len(rootSBOM)),
		GuestAgentDigest: syntheticDigest(guestAgent), AttestationMember: "rootfs-attestation.json",
	}
	agentBuild := firecracker.BuildProvenance{
		RecipePath: "tools/firecracker/build-guest-agent.sh", SourceRevision: revision, Toolchain: "synthetic-go",
		InputsMember: "guest-agent-inputs.json", InputsDigest: syntheticDigest(agentInputs), InputsSizeBytes: uint64(len(agentInputs)),
		SBOMMember: "guest-agent-sbom.spdx.json", SBOMDigest: syntheticDigest(agentSBOM), SBOMSizeBytes: uint64(len(agentSBOM)), Static: true,
	}

	lock := firecracker.FixtureLock{
		Version: "firecracker.fixtures/v2", FixtureVersion: "synthetic-v1",
		Sources: []firecracker.LockedSource{
			{ID: "firecracker-release", Kind: firecracker.FixtureSourceReleaseArchive, URL: "https://github.com/firecracker-microvm/firecracker/releases/download/" + version + "/firecracker-" + version + "-x86_64.tgz", Reference: "release:" + version, Format: firecracker.FixtureSourceTarGzip, Digest: syntheticDigest(archive), SizeBytes: uint64(len(archive)), License: "Apache-2.0"},
			{ID: "kernel", Kind: firecracker.FixtureSourceProjectReleaseAsset, URL: "https://github.com/0x63616c/agent-runtime/releases/download/commit-" + revision + "/kernel-vmlinux", Reference: "commit:" + revision, Format: firecracker.FixtureSourceFile, Digest: syntheticDigest(kernel), SizeBytes: uint64(len(kernel)), License: "GPL-2.0-only"},
		},
		Artifacts: []firecracker.LockedArtifact{
			{Name: firecracker.FixtureFirecracker, SourceID: "firecracker-release", Member: "release-v1.16.1-x86_64/firecracker-v1.16.1-x86_64", Digest: syntheticDigest([]byte("synthetic-firecracker")), SizeBytes: uint64(len("synthetic-firecracker")), License: "Apache-2.0", Platform: syntheticPlatform()},
			{Name: firecracker.FixtureJailer, SourceID: "firecracker-release", Member: "release-v1.16.1-x86_64/jailer-v1.16.1-x86_64", Digest: syntheticDigest([]byte("synthetic-jailer")), SizeBytes: uint64(len("synthetic-jailer")), License: "Apache-2.0", Platform: syntheticPlatform()},
			{Name: firecracker.FixtureKernel, SourceID: "kernel", Digest: syntheticDigest(kernel), SizeBytes: uint64(len(kernel)), License: "GPL-2.0-only", Platform: syntheticPlatform()},
		},
	}

	attestation, err := json.Marshal(firecracker.RootFSAttestation{SchemaVersion: "agent-runtime.firecracker.rootfs-attestation/v1", RootFSDigest: syntheticDigest(rootFS), RootFSSize: uint64(len(rootFS)), InitPath: "/sbin/init", InitDigest: syntheticDigest(guestAgent), InitSize: uint64(len(guestAgent)), Platform: syntheticPlatform(), Static: true})
	if err != nil {
		t.Fatalf("marshal rootfs attestation: %v", err)
	}
	rootBundle := tarGzip(t, map[string][]byte{"rootfs.ext4": rootFS, "rootfs-attestation.json": attestation, rootBuild.InputsMember: rootInputs, rootBuild.SBOMMember: rootSBOM})
	agentBundle := tarGzip(t, map[string][]byte{"guest-agent": guestAgent, agentBuild.InputsMember: agentInputs, agentBuild.SBOMMember: agentSBOM})
	base := "https://github.com/0x63616c/agent-runtime/releases/download/commit-" + revision + "/"
	lock.Sources = append(lock.Sources,
		firecracker.LockedSource{ID: "rootfs", Kind: firecracker.FixtureSourceProjectBuild, URL: base + "rootfs-bundle.tar.gz", Reference: "commit:" + revision, Format: firecracker.FixtureSourceTarGzip, Digest: syntheticDigest(rootBundle), SizeBytes: uint64(len(rootBundle)), License: "LicenseRef-agent-runtime-rootfs-sbom"},
		firecracker.LockedSource{ID: "guest-agent", Kind: firecracker.FixtureSourceProjectBuild, URL: base + "guest-agent-bundle.tar.gz", Reference: "commit:" + revision, Format: firecracker.FixtureSourceTarGzip, Digest: syntheticDigest(agentBundle), SizeBytes: uint64(len(agentBundle)), License: "MIT"},
	)
	lock.Artifacts = append(lock.Artifacts,
		firecracker.LockedArtifact{Name: firecracker.FixtureRootFS, SourceID: "rootfs", Member: "rootfs.ext4", Digest: syntheticDigest(rootFS), SizeBytes: uint64(len(rootFS)), License: "LicenseRef-agent-runtime-rootfs-sbom", Platform: syntheticPlatform(), Build: &rootBuild},
		firecracker.LockedArtifact{Name: firecracker.FixtureGuestAgent, SourceID: "guest-agent", Member: "guest-agent", Digest: syntheticDigest(guestAgent), SizeBytes: uint64(len(guestAgent)), License: "MIT", Platform: syntheticPlatform(), Build: &agentBuild},
	)
	lockPath := filepath.Join(directory, "fixtures.lock.candidate.json")
	writeSyntheticLock(t, lockPath, lock)
	return lockPath, map[string]string{"firecracker-release": write("firecracker.tgz", archive), "kernel": write("kernel-vmlinux", kernel), "rootfs": write("rootfs-bundle.tar.gz", rootBundle), "guest-agent": write("guest-agent-bundle.tar.gz", agentBundle)}, lock
}

func writeSyntheticLock(t *testing.T, path string, lock firecracker.FixtureLock) {
	t.Helper()
	contents, err := json.Marshal(lock)
	if err != nil {
		t.Fatalf("marshal candidate lock: %v", err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write candidate lock: %v", err)
	}
}

func syntheticPlatform() firecracker.FixturePlatform {
	return firecracker.FixturePlatform{OS: "linux", Architecture: "amd64"}
}

func syntheticDigest(contents []byte) sandbox.Digest {
	digest := sha256.Sum256(contents)
	return sandbox.Digest("sha256:" + hex.EncodeToString(digest[:]))
}

func tarGzip(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, name := range []string{"release-v1.16.1-x86_64/firecracker-v1.16.1-x86_64", "release-v1.16.1-x86_64/jailer-v1.16.1-x86_64", "rootfs.ext4", "rootfs-attestation.json", "rootfs-inputs.json", "rootfs-sbom.spdx.json", "guest-agent", "guest-agent-inputs.json", "guest-agent-sbom.spdx.json"} {
		contents, ok := members[name]
		if !ok {
			continue
		}
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(contents))}); err != nil {
			t.Fatalf("write tar header %s: %v", name, err)
		}
		if _, err := tarWriter.Write(contents); err != nil {
			t.Fatalf("write tar contents %s: %v", name, err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buffer.Bytes()
}
