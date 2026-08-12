package firecracker

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/0x63616c/agent-runtime/sandbox"
	"golang.org/x/sys/unix"
)

// LinuxJailerResourceStager creates one fresh, fixture-bound Jailer namespace without starting a process.
type LinuxJailerResourceStager struct {
	copyArtifact    func(context.Context, PinnedArtifact, string, os.FileMode) error
	changeOwner     func(string, int, int) error
	changeMode      func(string, os.FileMode) error
	trustDirectory  func(string) error
	removeNamespace func(string, string, bool) error
}

// Stage verifies immutable fixture inputs, copies only the jailed kernel and private rootfs, and returns their exact Jailer mapping.
func (stager LinuxJailerResourceStager) Stage(ctx context.Context, plan Plan, fixtures FixtureSet, rootFSCopyPath string) (stage JailedResourceStage, err error) {
	if err := contextError(ctx); err != nil {
		return JailedResourceStage{}, err
	}
	if !validCompiledPlan(plan) || !fixturesMatchPlan(fixtures, plan) || !safeAbsolutePath(rootFSCopyPath) || rootFSCopyPath == plan.RootFS().Path {
		return JailedResourceStage{}, fmt.Errorf("%w: complete verified fixtures and a distinct private rootfs copy are required", ErrSmokeUnavailable)
	}
	for _, artifact := range []PinnedArtifact{plan.Firecracker(), plan.Jailer(), plan.Kernel(), plan.RootFS(), plan.GuestAgent()} {
		if err := verifyRegularArtifact(ctx, artifact); err != nil {
			return JailedResourceStage{}, err
		}
	}
	if err := verifyPrivateRootFSCopy(ctx, rootFSCopyPath, plan.RootFS(), plan.Resources().RootDiskBytes); err != nil {
		return JailedResourceStage{}, err
	}
	trustDirectory := stager.trustDirectory
	if trustDirectory == nil {
		trustDirectory = trustedJailerDirectory
	}
	root, vmDirectory, executableDirectory, createdExecutableDirectory, err := createFreshJailerRoot(plan, trustDirectory)
	if err != nil {
		return JailedResourceStage{}, err
	}
	removeNamespace := stager.removeNamespace
	if removeNamespace == nil {
		removeNamespace = removeFreshJailerNamespace
	}
	cleanup := true
	defer func() {
		if !cleanup {
			return
		}
		if cleanupErr := removeNamespace(vmDirectory, executableDirectory, createdExecutableDirectory); cleanupErr != nil {
			stage = JailedResourceStage{}
			err = errors.Join(err, fmt.Errorf("clean fresh Jailer namespace: %w", cleanupErr))
		}
	}()
	changeOwner := stager.changeOwner
	if changeOwner == nil {
		changeOwner = os.Chown
	}
	changeMode := stager.changeMode
	if changeMode == nil {
		changeMode = os.Chmod
	}
	for _, directory := range []string{
		filepath.Join(root, "kernel"),
		filepath.Join(root, "drives"),
		filepath.Join(root, "run"),
	} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			return JailedResourceStage{}, fmt.Errorf("%w: create jailed resource directory: %v", ErrSmokeUnavailable, err)
		}
	}
	copyArtifact := stager.copyArtifact
	if copyArtifact == nil {
		copyArtifact = copyVerifiedArtifact
	}
	stage = JailedResourceStage{
		FixtureVersion: fixtures.FixtureVersion(),
		JailRoot:       root,
		OwnerUID:       plan.UID(),
		OwnerGID:       plan.GID(),
		Jailer:         plan.Jailer(),
		Firecracker:    JailedFixtureBinding{Source: plan.Firecracker(), JailedPath: "/" + filepath.Base(plan.Firecracker().Path)},
		Kernel:         JailedFixtureBinding{Source: plan.Kernel(), JailedPath: "/kernel/vmlinux"},
		RootFS:         JailedFixtureBinding{Source: PinnedArtifact{Path: rootFSCopyPath, Digest: plan.RootFS().Digest}, JailedPath: "/drives/rootfs.ext4"},
		GuestAgent:     plan.GuestAgent(),
		GuestInitPath:  "/sbin/init",
		APISocketPath:  jailedAPISocketPath(plan.JailerArguments()),
		VSockUDSPath:   "/run/firecracker.vsock",
	}
	if err := copyArtifact(ctx, plan.Kernel(), filepath.Join(root, "kernel", "vmlinux"), 0o400); err != nil {
		return JailedResourceStage{}, err
	}
	if err := changeOwner(filepath.Join(root, "kernel", "vmlinux"), int(plan.UID()), int(plan.GID())); err != nil {
		return JailedResourceStage{}, fmt.Errorf("%w: assign jailed kernel ownership: %v", ErrSmokeUnavailable, err)
	}
	if err := changeMode(filepath.Join(root, "kernel", "vmlinux"), 0o400); err != nil {
		return JailedResourceStage{}, fmt.Errorf("%w: enforce jailed kernel mode: %v", ErrSmokeUnavailable, err)
	}
	if err := copyArtifact(ctx, stage.RootFS.Source, filepath.Join(root, "drives", "rootfs.ext4"), 0o600); err != nil {
		return JailedResourceStage{}, err
	}
	if err := changeOwner(filepath.Join(root, "drives", "rootfs.ext4"), int(plan.UID()), int(plan.GID())); err != nil {
		return JailedResourceStage{}, fmt.Errorf("%w: assign jailed rootfs ownership: %v", ErrSmokeUnavailable, err)
	}
	if err := changeMode(filepath.Join(root, "drives", "rootfs.ext4"), 0o600); err != nil {
		return JailedResourceStage{}, fmt.Errorf("%w: enforce jailed rootfs mode: %v", ErrSmokeUnavailable, err)
	}
	for _, directory := range []string{
		filepath.Join(root, "kernel"),
		filepath.Join(root, "drives"),
		filepath.Join(root, "run"),
	} {
		if err := changeOwner(directory, int(plan.UID()), int(plan.GID())); err != nil {
			return JailedResourceStage{}, fmt.Errorf("%w: assign finalized jailed resource directory ownership: %v", ErrSmokeUnavailable, err)
		}
		if err := changeMode(directory, 0o700); err != nil {
			return JailedResourceStage{}, fmt.Errorf("%w: enforce finalized jailed resource directory mode: %v", ErrSmokeUnavailable, err)
		}
	}
	stage.BindingDigest = stage.bindingDigest()
	if !validJailedResourceStage(stage, plan, fixtures, rootFSCopyPath) {
		return JailedResourceStage{}, fmt.Errorf("%w: staged Jailer resources do not retain exact fixture provenance", ErrSmokeUnavailable)
	}
	cleanup = false
	return stage, nil
}

// Discard removes only the fresh per-VM namespace returned by Stage before a Jailer process owns it.
func (stager LinuxJailerResourceStager) Discard(ctx context.Context, plan Plan, stage JailedResourceStage) (CleanupProof, error) {
	if err := contextError(ctx); err != nil {
		return CleanupProof{Reason: "staged namespace cleanup context is unavailable"}, err
	}
	vmDirectory := filepath.Dir(stage.JailRoot)
	if !validCompiledPlan(plan) || stage.BindingDigest != stage.bindingDigest() || stage.JailRoot != expectedJailRoot(plan) || stage.OwnerUID != plan.UID() || stage.OwnerGID != plan.GID() || stage.Jailer != plan.Jailer() || stage.Firecracker.Source != plan.Firecracker() || stage.Firecracker.JailedPath != "/"+filepath.Base(plan.Firecracker().Path) || filepath.Base(stage.JailRoot) != "root" || !validVMID(filepath.Base(vmDirectory)) || !safeAbsolutePath(vmDirectory) {
		return CleanupProof{Reason: "staged namespace is not exact"}, fmt.Errorf("%w: exact staged Jailer namespace is required", ErrSmokeUnavailable)
	}
	trustDirectory := stager.trustDirectory
	if trustDirectory == nil {
		trustDirectory = trustedJailerDirectory
	}
	if err := trustDirectory(stage.JailRoot); err != nil {
		return CleanupProof{Reason: "staged namespace is not trusted"}, fmt.Errorf("%w: trusted staged Jailer namespace: %v", ErrSmokeUnavailable, err)
	}
	removeNamespace := stager.removeNamespace
	if removeNamespace == nil {
		removeNamespace = removeFreshJailerNamespace
	}
	if err := removeNamespace(vmDirectory, "", false); err != nil {
		return CleanupProof{Reason: "staged Jailer namespace cleanup did not complete"}, fmt.Errorf("remove staged Jailer namespace: %w", err)
	}
	return CleanupProof{Proved: true, Removed: []string{vmDirectory}}, nil
}

func removeFreshJailerNamespace(vmDirectory, executableDirectory string, createdExecutableDirectory bool) error {
	removeVMErr := os.RemoveAll(vmDirectory)
	var removeExecutableErr error
	if createdExecutableDirectory {
		removeExecutableErr = os.Remove(executableDirectory)
	}
	return errors.Join(removeVMErr, removeExecutableErr)
}

func createFreshJailerRoot(plan Plan, trustDirectory func(string) error) (root, vmDirectory, executableDirectory string, createdExecutableDirectory bool, err error) {
	base := jailerArgumentValue(plan.JailerArguments(), "--chroot-base-dir")
	if !safeAbsolutePath(base) || trustDirectory == nil {
		return "", "", "", false, fmt.Errorf("%w: a non-symlink Jailer base directory is required", ErrSmokeUnavailable)
	}
	if trustErr := trustDirectory(base); trustErr != nil {
		return "", "", "", false, fmt.Errorf("%w: trusted Jailer base directory: %v", ErrSmokeUnavailable, trustErr)
	}
	executableName := filepath.Base(plan.Firecracker().Path)
	if executableName == "." || executableName == string(filepath.Separator) {
		return "", "", "", false, fmt.Errorf("%w: a Jailer executable name is required", ErrSmokeUnavailable)
	}
	executableDirectory = filepath.Join(base, executableName)
	if info, statErr := os.Lstat(executableDirectory); statErr == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", "", "", false, fmt.Errorf("%w: Jailer executable directory is unsafe", ErrSmokeUnavailable)
		}
		if trustErr := trustDirectory(executableDirectory); trustErr != nil {
			return "", "", "", false, fmt.Errorf("%w: trusted Jailer executable directory: %v", ErrSmokeUnavailable, trustErr)
		}
	} else if errors.Is(statErr, os.ErrNotExist) {
		if mkdirErr := os.Mkdir(executableDirectory, 0o700); mkdirErr != nil {
			return "", "", "", false, fmt.Errorf("%w: create Jailer executable directory: %v", ErrSmokeUnavailable, mkdirErr)
		}
		createdExecutableDirectory = true
	} else {
		return "", "", "", false, fmt.Errorf("%w: inspect Jailer executable directory: %v", ErrSmokeUnavailable, statErr)
	}
	vmDirectory = filepath.Join(executableDirectory, plan.VMID())
	if mkdirErr := os.Mkdir(vmDirectory, 0o700); mkdirErr != nil {
		var cleanupErr error
		if createdExecutableDirectory {
			cleanupErr = os.Remove(executableDirectory)
		}
		return "", "", "", false, fmt.Errorf("%w: a fresh Jailer VM namespace is required: %w", ErrSmokeUnavailable, errors.Join(mkdirErr, cleanupErr))
	}
	root = filepath.Join(vmDirectory, "root")
	if mkdirErr := os.Mkdir(root, 0o700); mkdirErr != nil {
		cleanupErr := os.Remove(vmDirectory)
		if createdExecutableDirectory {
			cleanupErr = errors.Join(cleanupErr, os.Remove(executableDirectory))
		}
		return "", "", "", false, fmt.Errorf("%w: create Jailer root: %w", ErrSmokeUnavailable, errors.Join(mkdirErr, cleanupErr))
	}
	return root, vmDirectory, executableDirectory, createdExecutableDirectory, nil
}

func trustedJailerDirectory(path string) error {
	if !safeAbsolutePath(path) {
		return errors.New("absolute Jailer directory is required")
	}
	ancestors := []string{}
	for current := path; ; current = filepath.Dir(current) {
		ancestors = append(ancestors, current)
		if current == string(filepath.Separator) {
			break
		}
	}
	for index := len(ancestors) - 1; index >= 0; index-- {
		info, err := os.Lstat(ancestors[index])
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return errors.New("root-owned non-symlink directory without group or world write is required")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return errors.New("root-owned directory is required")
		}
	}
	return nil
}

func verifyPrivateRootFSCopy(ctx context.Context, rootFSCopyPath string, rootFS PinnedArtifact, maximumBytes uint64) error {
	copyInfo, err := os.Stat(rootFSCopyPath)
	if err != nil || !copyInfo.Mode().IsRegular() || copyInfo.Size() < 0 || uint64(copyInfo.Size()) > maximumBytes {
		return fmt.Errorf("%w: private rootfs copy is not a regular file", ErrArtifactIntegrity)
	}
	sourceInfo, err := os.Stat(rootFS.Path)
	if err != nil || os.SameFile(copyInfo, sourceInfo) {
		return fmt.Errorf("%w: rootfs copy must be distinct from the verified fixture", ErrSmokeUnavailable)
	}
	return verifyRegularArtifact(ctx, PinnedArtifact{Path: rootFSCopyPath, Digest: rootFS.Digest})
}

func verifyRegularArtifact(ctx context.Context, artifact PinnedArtifact) (err error) {
	file, err := openRegularNoFollow(artifact.Path)
	if err != nil {
		return fmt.Errorf("%w: open pinned artifact: %v", ErrArtifactIntegrity, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close pinned artifact: %w", closeErr)
		}
	}()
	actual, err := digestOpenFile(ctx, file)
	if err != nil {
		return fmt.Errorf("verify pinned artifact digest: %w", err)
	}
	if actual != artifact.Digest {
		return fmt.Errorf("%w: pinned artifact digest differs", ErrArtifactIntegrity)
	}
	return nil
}

func copyVerifiedArtifact(ctx context.Context, artifact PinnedArtifact, destination string, mode os.FileMode) (err error) {
	if err := contextError(ctx); err != nil {
		return err
	}
	source, err := openRegularNoFollow(artifact.Path)
	if err != nil {
		return fmt.Errorf("%w: open pinned artifact for Jailer stage: %v", ErrArtifactIntegrity, err)
	}
	defer func() {
		if closeErr := source.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close pinned artifact for Jailer stage: %w", closeErr)
		}
	}()
	destinationFile, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("%w: create Jailer staged artifact: %v", ErrSmokeUnavailable, err)
	}
	actual, copyErr := copyDigestWithContext(ctx, destinationFile, source)
	closeErr := destinationFile.Close()
	if copyErr != nil {
		_ = os.Remove(destination)
		return fmt.Errorf("copy pinned artifact into Jailer namespace: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(destination)
		return fmt.Errorf("close staged Jailer artifact: %w", closeErr)
	}
	if actual != artifact.Digest {
		_ = os.Remove(destination)
		return fmt.Errorf("%w: verify staged Jailer artifact", ErrArtifactIntegrity)
	}
	return nil
}

func openRegularNoFollow(path string) (*os.File, error) {
	if !safeAbsolutePath(path) {
		return nil, errors.New("absolute artifact path is required")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("wrap artifact descriptor")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("regular artifact file is required")
	}
	return file, nil
}

func digestOpenFile(ctx context.Context, file *os.File) (sandbox.Digest, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	return copyDigestWithContext(ctx, io.Discard, file)
}

func copyDigestWithContext(ctx context.Context, destination io.Writer, source io.Reader) (sandbox.Digest, error) {
	hash := sha256.New()
	buffer := make([]byte, 32<<10)
	for {
		if err := contextError(ctx); err != nil {
			return "", err
		}
		count, readErr := source.Read(buffer)
		if count > 0 {
			if _, writeErr := destination.Write(buffer[:count]); writeErr != nil {
				return "", writeErr
			}
			if _, hashErr := hash.Write(buffer[:count]); hashErr != nil {
				return "", hashErr
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return "", readErr
		}
	}
	if err := contextError(ctx); err != nil {
		return "", err
	}
	return sandbox.Digest(fmt.Sprintf("sha256:%x", hash.Sum(nil))), nil
}
