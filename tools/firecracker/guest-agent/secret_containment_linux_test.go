//go:build linux

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/firecracker"
)

func TestGuestCgroupTreeReapVerifierRequiresExactMembershipAndAnEmptyTree(t *testing.T) {
	root := &recordingGuestCgroupRoot{files: map[string][]byte{"cgroup.procs": []byte("42\n")}}
	verifier, err := newGuestCgroupTreeReapVerifierWithRoot("/agent-runtime/secrets/process-001", root, func(pid int) ([]byte, error) {
		if pid != 42 {
			t.Fatalf("process cgroup pid = %d", pid)
		}
		return []byte("0::/agent-runtime/secrets/process-001\n"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyProcessContained(context.Background(), 42); err != nil {
		t.Fatalf("VerifyProcessContained() error = %v", err)
	}
	if err := verifier.VerifyTreeReaped(context.Background(), 42, 7); err == nil {
		t.Fatal("VerifyTreeReaped() accepted live cgroup member")
	}
	root.files["cgroup.procs"] = nil
	if err := verifier.VerifyTreeReaped(context.Background(), 42, 7); err != nil {
		t.Fatalf("VerifyTreeReaped() error = %v", err)
	}
	if err := verifier.Close(); err != nil || !root.closed {
		t.Fatalf("Close() = %v closed=%t", err, root.closed)
	}
}

func TestGuestCgroupTreeReapVerifierRefusesMembershipSubstitutionAndBadPaths(t *testing.T) {
	if _, err := newGuestCgroupTreeReapVerifierWithRoot("/agent-runtime/../escape", &recordingGuestCgroupRoot{}, func(int) ([]byte, error) { return nil, nil }); err == nil {
		t.Fatal("newGuestCgroupTreeReapVerifierWithRoot accepted an escaped cgroup path")
	}
	root := &recordingGuestCgroupRoot{files: map[string][]byte{"cgroup.procs": []byte("42\n")}}
	verifier, err := newGuestCgroupTreeReapVerifierWithRoot("/agent-runtime/secrets/process-001", root, func(int) ([]byte, error) {
		return []byte("0::/other\n"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyProcessContained(context.Background(), 42); err == nil {
		t.Fatal("VerifyProcessContained() accepted a cgroup-substituted process")
	}
	if err := verifier.VerifyTreeReaped(context.Background(), 42, -1); err == nil {
		t.Fatal("VerifyTreeReaped() accepted missing pidfd identity")
	}
}

func TestGuestSecretCgroupManifestWiringRefusesUnprotectedOrSubstitutedConfiguration(t *testing.T) {
	manifest := firecracker.SecretContainmentManifest{
		Version:                   "firecracker.jailer-secret-containment/v1",
		VMID:                      "sandbox-001",
		GuestCgroupPath:           "/agent-runtime/secrets/sandbox-001",
		SecretAreaPath:            "/run/agent-runtime/secrets/sandbox-001",
		SecretAreaFilesystem:      "tmpfs",
		SecretAreaMountOptions:    []string{"mode=0700", "nodev", "noexec", "nosuid"},
		ProcMountPath:             "/proc",
		ProcFilesystem:            "proc",
		ProcMountOptions:          []string{"hidepid=2", "nodev", "noexec", "nosuid", "subset=pid"},
		MountNamespaceRequired:    true,
		SnapshotExclusionRequired: true,
		CgroupV2LifecycleRequired: true,
	}
	directory, err := guestSecretCgroupDirectoryFromManifest(manifest, "sandbox-001")
	if err != nil || directory != "/sys/fs/cgroup/agent-runtime/secrets/sandbox-001" {
		t.Fatalf("guestSecretCgroupDirectoryFromManifest() = %q, %v", directory, err)
	}
	manifest.SnapshotExclusionRequired = false
	if _, err := guestSecretCgroupDirectoryFromManifest(manifest, "sandbox-001"); err == nil {
		t.Fatal("guestSecretCgroupDirectoryFromManifest accepted an unguarded snapshot area")
	}
}

type recordingGuestCgroupRoot struct {
	files  map[string][]byte
	closed bool
	err    error
}

func (root *recordingGuestCgroupRoot) ReadFile(name string) ([]byte, error) {
	if root.err != nil {
		return nil, root.err
	}
	value, ok := root.files[name]
	if !ok {
		return nil, errors.New("missing cgroup file")
	}
	return append([]byte(nil), value...), nil
}

func (root *recordingGuestCgroupRoot) Close() error {
	root.closed = true
	return root.err
}
