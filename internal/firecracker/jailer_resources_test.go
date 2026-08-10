package firecracker

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/0x63616c/agent-runtime/sandbox"
)

func TestLinuxJailerResourceStagerCopiesVerifiedKernelAndPrivateRootFSIntoTheExactFreshJailerRoot(t *testing.T) {
	plan, fixtures, rootFSCopyPath, contents := stagedResourceInputs(t)

	stage, err := testLinuxJailerResourceStager().Stage(context.Background(), plan, fixtures, rootFSCopyPath)
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	if !validJailedResourceStage(stage, plan, fixtures, rootFSCopyPath) {
		t.Fatalf("Stage() = %#v, want exact fixture-bound jailed stage", stage)
	}
	if got, want := stage.JailRoot, filepath.Join(planChrootBase(plan), "firecracker", plan.VMID(), "root"); got != want {
		t.Fatalf("Stage().JailRoot = %q, want %q", got, want)
	}
	for destination, want := range map[string]string{
		filepath.Join(stage.JailRoot, "kernel", "vmlinux"):     contents[FixtureKernel],
		filepath.Join(stage.JailRoot, "drives", "rootfs.ext4"): contents[FixtureRootFS],
	} {
		got, readErr := os.ReadFile(destination)
		if readErr != nil {
			t.Fatalf("read staged %s: %v", destination, readErr)
		}
		if string(got) != want {
			t.Fatalf("staged %s = %q, want %q", destination, got, want)
		}
	}
	if _, statErr := os.Lstat(filepath.Join(stage.JailRoot, "firecracker")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("staged Firecracker executable = %v, want Jailer-owned copy to remain absent", statErr)
	}
}

func TestLinuxJailerResourceStagerBindsPlanIdentityToPrivateJailedResources(t *testing.T) {
	plan, fixtures, rootFSCopyPath, _ := stagedResourceInputs(t)

	stage, err := testLinuxJailerResourceStager().Stage(context.Background(), plan, fixtures, rootFSCopyPath)
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	if stage.OwnerUID != plan.UID() || stage.OwnerGID != plan.GID() {
		t.Fatalf("Stage() owner = (%d, %d), want plan identity (%d, %d)", stage.OwnerUID, stage.OwnerGID, plan.UID(), plan.GID())
	}
	for path, mode := range map[string]os.FileMode{
		filepath.Join(stage.JailRoot, "kernel"):                0o700,
		filepath.Join(stage.JailRoot, "drives"):                0o700,
		filepath.Join(stage.JailRoot, "run"):                   0o700,
		filepath.Join(stage.JailRoot, "kernel", "vmlinux"):     0o400,
		filepath.Join(stage.JailRoot, "drives", "rootfs.ext4"): 0o600,
	} {
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatalf("stat staged %s: %v", path, statErr)
		}
		if got := info.Mode().Perm(); got != mode {
			t.Fatalf("staged %s mode = %04o, want %04o", path, got, mode)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != plan.UID() || stat.Gid != plan.GID() {
			t.Fatalf("staged %s owner = %#v, want plan identity (%d, %d)", path, info.Sys(), plan.UID(), plan.GID())
		}
	}
}

func TestLinuxJailerResourceStagerRestoresExactPrivateModesAfterOwnershipChanges(t *testing.T) {
	plan, fixtures, rootFSCopyPath, _ := stagedResourceInputs(t)
	stager := testLinuxJailerResourceStager()
	stager.changeOwner = func(path string, _, _ int) error {
		if filepath.Base(path) == "vmlinux" || filepath.Base(path) == "rootfs.ext4" {
			return os.Chmod(path, 0)
		}
		return nil
	}

	stage, err := stager.Stage(context.Background(), plan, fixtures, rootFSCopyPath)
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	for path, mode := range map[string]os.FileMode{
		filepath.Join(stage.JailRoot, "kernel"):                0o700,
		filepath.Join(stage.JailRoot, "drives"):                0o700,
		filepath.Join(stage.JailRoot, "run"):                   0o700,
		filepath.Join(stage.JailRoot, "kernel", "vmlinux"):     0o400,
		filepath.Join(stage.JailRoot, "drives", "rootfs.ext4"): 0o600,
	} {
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatalf("stat staged %s: %v", path, statErr)
		}
		if got := info.Mode().Perm(); got != mode {
			t.Fatalf("staged %s mode = %04o, want post-umask mode %04o", path, got, mode)
		}
	}
}

func TestLinuxJailerResourceStagerTransfersGuestDirectoryOwnershipOnlyAfterFinalizingFiles(t *testing.T) {
	plan, fixtures, rootFSCopyPath, _ := stagedResourceInputs(t)
	var ownershipOrder []string
	stager := testLinuxJailerResourceStager()
	stager.changeOwner = func(path string, _, _ int) error {
		ownershipOrder = append(ownershipOrder, filepath.Base(path))
		return nil
	}

	if _, err := stager.Stage(context.Background(), plan, fixtures, rootFSCopyPath); err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	if got, want := ownershipOrder, []string{"vmlinux", "rootfs.ext4", "kernel", "drives", "run"}; !sameStrings(got, want) {
		t.Fatalf("ownership order = %v, want finalized files before guest-writable directories %v", got, want)
	}
}

func TestLinuxJailerResourceStagerRequiresARootOwnedJailerBaseBeforeCreatingANamespace(t *testing.T) {
	plan, fixtures, rootFSCopyPath, _ := stagedResourceInputs(t)
	if os.Geteuid() == 0 {
		if err := os.Chown(planChrootBase(plan), 10001, 10001); err != nil {
			t.Fatalf("make Jailer base non-root-owned: %v", err)
		}
	}

	if _, err := (LinuxJailerResourceStager{}).Stage(context.Background(), plan, fixtures, rootFSCopyPath); !errors.Is(err, ErrSmokeUnavailable) {
		t.Fatalf("Stage() error = %v, want root-owned Jailer base refusal", err)
	}
	if _, statErr := os.Lstat(filepath.Join(planChrootBase(plan), "firecracker", plan.VMID())); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("Jailer namespace after untrusted-base refusal = %v, want none", statErr)
	}
}

func TestLinuxJailerResourceStagerRefusesPreexistingJailerVMNamespace(t *testing.T) {
	plan, fixtures, rootFSCopyPath, _ := stagedResourceInputs(t)
	vmDirectory := filepath.Join(planChrootBase(plan), "firecracker", plan.VMID())
	if err := os.MkdirAll(vmDirectory, 0o700); err != nil {
		t.Fatalf("make pre-existing Jailer VM directory: %v", err)
	}

	if _, err := testLinuxJailerResourceStager().Stage(context.Background(), plan, fixtures, rootFSCopyPath); !errors.Is(err, ErrSmokeUnavailable) {
		t.Fatalf("Stage() error = %v, want pre-existing namespace refusal", err)
	}
}

func TestLinuxJailerResourceStagerRefusesAGroupOrWorldWritableJailerBase(t *testing.T) {
	plan, _, _, _ := stagedResourceInputs(t)
	if err := os.Chmod(planChrootBase(plan), 0o777); err != nil {
		t.Fatalf("make Jailer base writable: %v", err)
	}

	if err := trustedJailerDirectory(planChrootBase(plan)); err == nil {
		t.Fatal("trustedJailerDirectory() error = nil, want writable Jailer base refusal")
	}
}

func TestLinuxJailerResourceStagerRefusesAGroupOrWorldWritableJailerExecutableDirectory(t *testing.T) {
	plan, _, _, _ := stagedResourceInputs(t)
	executableDirectory := filepath.Join(planChrootBase(plan), "firecracker")
	if err := os.Mkdir(executableDirectory, 0o777); err != nil {
		t.Fatalf("make Jailer executable directory: %v", err)
	}
	if err := os.Chmod(executableDirectory, 0o777); err != nil {
		t.Fatalf("make Jailer executable directory writable: %v", err)
	}

	if err := trustedJailerDirectory(executableDirectory); err == nil {
		t.Fatal("trustedJailerDirectory() error = nil, want writable executable-directory refusal")
	}
}

func TestLinuxJailerResourceStagerRefusesASymlinkFixtureBeforeCreatingAJailerNamespace(t *testing.T) {
	plan, fixtures, rootFSCopyPath, _ := stagedResourceInputs(t)
	kernel, ok := fixtures.Artifact(FixtureKernel)
	if !ok {
		t.Fatal("FixtureSet has no kernel")
	}
	if err := os.Remove(kernel.Path); err != nil {
		t.Fatalf("remove kernel fixture: %v", err)
	}
	if err := os.Symlink(plan.Firecracker().Path, kernel.Path); err != nil {
		t.Fatalf("make kernel fixture symlink: %v", err)
	}

	if _, err := testLinuxJailerResourceStager().Stage(context.Background(), plan, fixtures, rootFSCopyPath); !errors.Is(err, ErrArtifactIntegrity) {
		t.Fatalf("Stage() error = %v, want symlink integrity refusal", err)
	}
	if _, statErr := os.Lstat(filepath.Join(planChrootBase(plan), "firecracker", plan.VMID())); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("Jailer namespace after symlink refusal = %v, want none", statErr)
	}
}

func TestLinuxJailerResourceStagerRefusesARootFSCopyThatIsNotPrivateAndDigestBound(t *testing.T) {
	plan, fixtures, _, _ := stagedResourceInputs(t)
	rootFS, ok := fixtures.Artifact(FixtureRootFS)
	if !ok {
		t.Fatal("FixtureSet has no rootfs")
	}

	if _, err := testLinuxJailerResourceStager().Stage(context.Background(), plan, fixtures, rootFS.Path); !errors.Is(err, ErrSmokeUnavailable) {
		t.Fatalf("Stage() error = %v, want private-rootfs refusal", err)
	}
}

func TestLinuxJailerResourceStagerRefusesAPrivateRootFSCopyLargerThanTheDeclaredRootDiskLimit(t *testing.T) {
	plan, fixtures, rootFSCopyPath, contents := stagedResourceInputs(t)
	plan.resources.RootDiskBytes = uint64(len(contents[FixtureRootFS]) - 1)

	if _, err := testLinuxJailerResourceStager().Stage(context.Background(), plan, fixtures, rootFSCopyPath); !errors.Is(err, ErrArtifactIntegrity) {
		t.Fatalf("Stage() error = %v, want rootfs-size integrity refusal", err)
	}
}

func TestLinuxJailerResourceStagerPreservesAPreexistingJailerExecutableDirectoryAfterAStageFailure(t *testing.T) {
	plan, fixtures, rootFSCopyPath, _ := stagedResourceInputs(t)
	executableDirectory := filepath.Join(planChrootBase(plan), "firecracker")
	if err := os.Mkdir(executableDirectory, 0o700); err != nil {
		t.Fatalf("make pre-existing Jailer executable directory: %v", err)
	}
	stager := LinuxJailerResourceStager{trustDirectory: func(string) error { return nil }, copyArtifact: func(context.Context, PinnedArtifact, string, os.FileMode) error {
		return errors.New("injected copy failure")
	}}

	if _, err := stager.Stage(context.Background(), plan, fixtures, rootFSCopyPath); err == nil {
		t.Fatal("Stage() error = nil, want staged-copy failure")
	}
	if info, statErr := os.Stat(executableDirectory); statErr != nil || !info.IsDir() {
		t.Fatalf("pre-existing Jailer executable directory after failure = (%#v, %v), want preserved directory", info, statErr)
	}
}

func TestLinuxJailerResourceStagerPreservesCancellationAndCleansTheFreshNamespace(t *testing.T) {
	plan, fixtures, rootFSCopyPath, _ := stagedResourceInputs(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stager := LinuxJailerResourceStager{trustDirectory: func(string) error { return nil }, copyArtifact: func(copyCtx context.Context, _ PinnedArtifact, _ string, _ os.FileMode) error {
		_, err := copyDigestWithContext(copyCtx, io.Discard, cancelAfterOneRead{cancel: cancel})
		return err
	}}

	if _, err := stager.Stage(ctx, plan, fixtures, rootFSCopyPath); !errors.Is(err, context.Canceled) {
		t.Fatalf("Stage() error = %v, want preserved cancellation", err)
	}
	if _, statErr := os.Lstat(filepath.Join(planChrootBase(plan), "firecracker", plan.VMID())); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("fresh Jailer namespace after cancellation = %v, want cleanup", statErr)
	}
}

func TestLinuxJailerResourceStagerReturnsAnUnreconciledNamespaceCleanupFailure(t *testing.T) {
	plan, fixtures, rootFSCopyPath, _ := stagedResourceInputs(t)
	cleanupFailure := errors.New("injected namespace cleanup failure")
	stager := LinuxJailerResourceStager{
		trustDirectory: func(string) error { return nil },
		copyArtifact: func(context.Context, PinnedArtifact, string, os.FileMode) error {
			return errors.New("injected copy failure")
		},
		removeNamespace: func(string, string, bool) error { return cleanupFailure },
	}

	if _, err := stager.Stage(context.Background(), plan, fixtures, rootFSCopyPath); !errors.Is(err, cleanupFailure) {
		t.Fatalf("Stage() error = %v, want retained namespace cleanup failure", err)
	}
}

func stagedResourceInputs(t *testing.T) (Plan, FixtureSet, string, map[FixtureName]string) {
	t.Helper()
	root := t.TempDir()
	fixtureDirectory := filepath.Join(root, "fixtures")
	chrootBase := filepath.Join(root, "jailer")
	if err := os.MkdirAll(fixtureDirectory, 0o700); err != nil {
		t.Fatalf("make fixture directory: %v", err)
	}
	if err := os.Mkdir(chrootBase, 0o700); err != nil {
		t.Fatalf("make Jailer base: %v", err)
	}
	contents := map[FixtureName]string{
		FixtureFirecracker: "verified-firecracker",
		FixtureJailer:      "verified-jailer",
		FixtureKernel:      "verified-kernel",
		FixtureRootFS:      "verified-rootfs",
		FixtureGuestAgent:  "verified-guest-agent",
	}
	artifacts := make(map[FixtureName]PinnedArtifact, len(contents))
	for name, content := range contents {
		path := filepath.Join(fixtureDirectory, string(name))
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s fixture: %v", name, err)
		}
		artifacts[name] = PinnedArtifact{Path: path, Digest: sandbox.Digest(digest([]byte(content)))}
	}
	rootFSCopyPath := filepath.Join(root, "private-rootfs.ext4")
	if err := os.WriteFile(rootFSCopyPath, []byte(contents[FixtureRootFS]), 0o600); err != nil {
		t.Fatalf("write private rootfs copy: %v", err)
	}
	profile := validProfile()
	profile.Firecracker = artifacts[FixtureFirecracker]
	profile.Jailer = artifacts[FixtureJailer]
	profile.Kernel = artifacts[FixtureKernel]
	profile.RootFS = artifacts[FixtureRootFS]
	profile.GuestAgent = artifacts[FixtureGuestAgent]
	profile.UID, profile.GID = testUnprivilegedIdentity()
	plan := mustCompile(t, profile)
	for index, argument := range plan.jailerArguments {
		if argument == "--chroot-base-dir" {
			plan.jailerArguments[index+1] = chrootBase
			break
		}
	}
	return plan, FixtureSet{directory: fixtureDirectory, fixtureVersion: "fixture-v1", artifacts: artifacts, verified: true}, rootFSCopyPath, contents
}

func planChrootBase(plan Plan) string {
	return jailerArgumentValue(plan.JailerArguments(), "--chroot-base-dir")
}

func testLinuxJailerResourceStager() LinuxJailerResourceStager {
	return LinuxJailerResourceStager{trustDirectory: func(string) error { return nil }}
}

func testUnprivilegedIdentity() (uint32, uint32) {
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		return 10001, 10001
	}
	return uint32(os.Geteuid()), uint32(os.Getegid())
}

type cancelAfterOneRead struct {
	cancel func()
	read   bool
}

func (reader cancelAfterOneRead) Read(destination []byte) (int, error) {
	if reader.read {
		return 0, io.EOF
	}
	reader.cancel()
	copy(destination, "fixture")
	return len("fixture"), nil
}
