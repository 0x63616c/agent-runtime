//go:build linux

package firecracker

import (
	"context"
	"errors"
	"fmt"
	"path"
	"runtime"
	"strings"
	"sync"

	"github.com/0x63616c/agent-runtime/internal/sandboxresource"
	"golang.org/x/sys/unix"
)

// LinuxShareExport is one operator-configured directory held open by the
// sharing daemon. Callers receive only its stable SourceIdentity, never Path.
type LinuxShareExport struct {
	Path   string
	Source sandboxresource.SourceIdentity
}

// LinuxJailedSharingDaemon mounts only descriptor-pinned operator exports into
// one already-created Jailer mount namespace. It is not a capability profile;
// LinuxJailerHost keeps this data plane unavailable until protected evidence.
type LinuxJailedSharingDaemon struct {
	mu          sync.Mutex
	exports     map[string]linuxShareExport
	namespaceFD int
	guestRootFD int
	attached    map[string]JailedShareRequest
	detached    map[string]JailedShareRequest
}

type linuxShareExport struct {
	identity sandboxresource.SourceIdentity
	fd       int
}

// NewLinuxJailedSharingDaemon opens every trusted export and target namespace
// once. The retained descriptors close path-replacement windows between lease
// observation and the eventual bind mount.
func NewLinuxJailedSharingDaemon(exports []LinuxShareExport, namespacePath, guestRootPath string) (*LinuxJailedSharingDaemon, error) {
	if len(exports) == 0 || !safeAbsolutePath(namespacePath) || !safeAbsolutePath(guestRootPath) {
		return nil, fmt.Errorf("create Linux jailed sharing daemon: %w", ErrCapabilityUnavailable)
	}
	daemon := &LinuxJailedSharingDaemon{exports: make(map[string]linuxShareExport, len(exports)), namespaceFD: -1, guestRootFD: -1, attached: make(map[string]JailedShareRequest), detached: make(map[string]JailedShareRequest)}
	closeAll := func() {
		for _, export := range daemon.exports {
			_ = unix.Close(export.fd)
		}
		if daemon.namespaceFD >= 0 {
			_ = unix.Close(daemon.namespaceFD)
		}
		if daemon.guestRootFD >= 0 {
			_ = unix.Close(daemon.guestRootFD)
		}
	}
	for _, configured := range exports {
		if !validLinuxShareExport(configured) {
			closeAll()
			return nil, fmt.Errorf("create Linux jailed sharing daemon: %w", ErrCapabilityUnavailable)
		}
		if _, exists := daemon.exports[configured.Source.ExportID]; exists {
			closeAll()
			return nil, fmt.Errorf("create Linux jailed sharing daemon: %w", ErrCapabilityUnavailable)
		}
		fd, identity, err := openLinuxShareDirectory(configured)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("create Linux jailed sharing daemon: %w", ErrCapabilityUnavailable)
		}
		daemon.exports[identity.ExportID] = linuxShareExport{identity: identity, fd: fd}
	}
	// Linux namespace handles are exposed as procfs magic links. The path is a
	// composition-root value, never supplied by a mount command; opening it
	// follows only that kernel handle so Setns receives the exact retained FD.
	namespaceFD, err := unix.Open(namespacePath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		closeAll()
		return nil, fmt.Errorf("create Linux jailed sharing daemon: %w", ErrCapabilityUnavailable)
	}
	daemon.namespaceFD = namespaceFD
	guestRootFD, err := unix.Open(guestRootPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		closeAll()
		return nil, fmt.Errorf("create Linux jailed sharing daemon: %w", ErrCapabilityUnavailable)
	}
	daemon.guestRootFD = guestRootFD
	return daemon, nil
}

// Close releases only daemon-held descriptors after the reaper has detached
// every exact share. It refuses a live attach so cleanup cannot lose authority.
func (daemon *LinuxJailedSharingDaemon) Close() error {
	if daemon == nil {
		return nil
	}
	daemon.mu.Lock()
	defer daemon.mu.Unlock()
	if len(daemon.attached) != 0 {
		return fmt.Errorf("close Linux jailed sharing daemon: %w", ErrCapabilityUnavailable)
	}
	var closeErr error
	for _, export := range daemon.exports {
		closeErr = errors.Join(closeErr, unix.Close(export.fd))
	}
	daemon.exports = nil
	if daemon.namespaceFD >= 0 {
		closeErr = errors.Join(closeErr, unix.Close(daemon.namespaceFD))
		daemon.namespaceFD = -1
	}
	if daemon.guestRootFD >= 0 {
		closeErr = errors.Join(closeErr, unix.Close(daemon.guestRootFD))
		daemon.guestRootFD = -1
	}
	return closeErr
}

// ObserveMountSource re-stats the pinned descriptor instead of reopening an
// export path, so a replacement cannot become a later mount source.
func (daemon *LinuxJailedSharingDaemon) ObserveMountSource(ctx context.Context, exportID string) (sandboxresource.SourceIdentity, error) {
	if err := contextError(ctx); err != nil {
		return sandboxresource.SourceIdentity{}, err
	}
	if daemon == nil || exportID == "" {
		return sandboxresource.SourceIdentity{}, fmt.Errorf("observe Linux jailed share source: %w", ErrCapabilityUnavailable)
	}
	daemon.mu.Lock()
	defer daemon.mu.Unlock()
	export, exists := daemon.exports[exportID]
	if !exists || export.fd < 0 {
		return sandboxresource.SourceIdentity{}, fmt.Errorf("observe Linux jailed share source: %w", ErrCapabilityUnavailable)
	}
	if identity, err := statLinuxShareDirectory(export.fd, export.identity); err != nil || identity != export.identity {
		return sandboxresource.SourceIdentity{}, fmt.Errorf("observe Linux jailed share source: %w", ErrCapabilityUnavailable)
	}
	return export.identity, nil
}

// Attach resolves both source and target through retained descriptors, then
// performs a bind mount only while this OS thread is in the Jailer namespace.
func (daemon *LinuxJailedSharingDaemon) Attach(ctx context.Context, request JailedShareRequest) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if daemon == nil || !validJailedShareRequest(request) {
		return fmt.Errorf("attach Linux jailed share: %w", ErrCapabilityUnavailable)
	}
	daemon.mu.Lock()
	defer daemon.mu.Unlock()
	key := linuxShareKey(request)
	if prior, exists := daemon.detached[key]; exists {
		if prior == request {
			return fmt.Errorf("attach Linux jailed share: %w", ErrCapabilityUnavailable)
		}
		return fmt.Errorf("attach Linux jailed share: %w", ErrCapabilityUnavailable)
	}
	if prior, exists := daemon.attached[key]; exists {
		if prior == request {
			return nil
		}
		return fmt.Errorf("attach Linux jailed share: %w", ErrCapabilityUnavailable)
	}
	export, exists := daemon.exports[request.Source.ExportID]
	if !exists || export.identity != request.Source {
		return fmt.Errorf("attach Linux jailed share: %w", ErrCapabilityUnavailable)
	}
	if identity, err := statLinuxShareDirectory(export.fd, export.identity); err != nil || identity != request.Source {
		return fmt.Errorf("attach Linux jailed share: %w", ErrCapabilityUnavailable)
	}
	targetFD, err := daemon.openTarget(request.Target)
	if err != nil {
		return fmt.Errorf("attach Linux jailed share: %w", ErrCapabilityUnavailable)
	}
	defer unix.Close(targetFD)
	if err := mountLinuxShare(ctx, daemon.namespaceFD, export.fd, targetFD, request.Mode); err != nil {
		return err
	}
	daemon.attached[key] = request
	return nil
}

// Detach removes only the exact target selected by a previously validated
// request. Repeating the same reaper action is safe; a different tuple cannot
// detach it.
func (daemon *LinuxJailedSharingDaemon) Detach(ctx context.Context, request JailedShareRequest) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if daemon == nil || !validJailedShareRequest(request) {
		return fmt.Errorf("detach Linux jailed share: %w", ErrCapabilityUnavailable)
	}
	daemon.mu.Lock()
	defer daemon.mu.Unlock()
	key := linuxShareKey(request)
	if prior, exists := daemon.detached[key]; exists {
		if prior == request {
			return nil
		}
		return fmt.Errorf("detach Linux jailed share: %w", ErrCapabilityUnavailable)
	}
	prior, exists := daemon.attached[key]
	if !exists || prior != request {
		return fmt.Errorf("detach Linux jailed share: %w", ErrCapabilityUnavailable)
	}
	for priorKey, prior := range daemon.attached {
		if prior.Target == request.Target && priorKey != key {
			return fmt.Errorf("detach Linux jailed share: %w", ErrCapabilityUnavailable)
		}
	}
	targetFD, err := daemon.openTarget(request.Target)
	if err != nil {
		return fmt.Errorf("detach Linux jailed share: %w", ErrCapabilityUnavailable)
	}
	defer unix.Close(targetFD)
	if err := unmountLinuxShare(ctx, daemon.namespaceFD, targetFD); err != nil {
		return err
	}
	delete(daemon.attached, key)
	daemon.detached[key] = request
	return nil
}

func (daemon *LinuxJailedSharingDaemon) openTarget(target string) (int, error) {
	relative, ok := jailedShareTarget(target)
	if !ok || daemon.guestRootFD < 0 {
		return -1, errors.New("safe jailed target is required")
	}
	return unix.Openat2(daemon.guestRootFD, relative, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
}

func validLinuxShareExport(export LinuxShareExport) bool {
	return safeAbsolutePath(export.Path) && validJailedSourceIdentity(export.Source)
}

func validJailedShareRequest(request JailedShareRequest) bool {
	_, target := jailedShareTarget(request.Target)
	return request.SandboxID != "" && request.MountID != "" && request.Generation > 0 && validJailedSourceIdentity(request.Source) && target && (request.Mode == sandboxresource.ReadOnly || request.Mode == sandboxresource.ReadWrite) && (request.View == "live" || request.View == "frozen")
}

func validJailedSourceIdentity(identity sandboxresource.SourceIdentity) bool {
	return identity.ExportID != "" && identity.Device != 0 && identity.Inode != 0 && identity.Generation != 0
}

func jailedShareTarget(target string) (string, bool) {
	if target == "" || !strings.HasPrefix(target, "/") || target == "/" || strings.ContainsRune(target, '\x00') {
		return "", false
	}
	clean := path.Clean(target)
	if clean != target || !strings.HasPrefix(clean, "/") || clean == "/" {
		return "", false
	}
	return strings.TrimPrefix(clean, "/"), true
}

func linuxShareKey(request JailedShareRequest) string {
	return request.SandboxID + "\x00" + request.MountID + "\x00" + request.Source.ExportID + "\x00" + request.Target + "\x00" + request.View + "\x00" + string(request.Mode) + "\x00" + fmt.Sprintf("%d\x00%d\x00%d\x00%d", request.Generation, request.Source.Device, request.Source.Inode, request.Source.Generation)
}

func openLinuxShareDirectory(configured LinuxShareExport) (int, sandboxresource.SourceIdentity, error) {
	fd, err := unix.Open(configured.Path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, sandboxresource.SourceIdentity{}, err
	}
	identity, err := statLinuxShareDirectory(fd, configured.Source)
	if err != nil || identity != configured.Source {
		_ = unix.Close(fd)
		return -1, sandboxresource.SourceIdentity{}, errors.New("pinned regular directory identity is required")
	}
	return fd, identity, nil
}

func statLinuxShareDirectory(fd int, expected sandboxresource.SourceIdentity) (sandboxresource.SourceIdentity, error) {
	var stat unix.Stat_t
	if fd < 0 || unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return sandboxresource.SourceIdentity{}, errors.New("directory source is required")
	}
	return sandboxresource.SourceIdentity{ExportID: expected.ExportID, Device: uint64(stat.Dev), Inode: stat.Ino, Generation: expected.Generation}, nil
}

func mountLinuxShare(ctx context.Context, namespaceFD, sourceFD, targetFD int, mode sandboxresource.AttachmentMode) error {
	if namespaceFD < 0 || sourceFD < 0 || targetFD < 0 {
		return fmt.Errorf("mount Linux jailed share: %w", ErrCapabilityUnavailable)
	}
	return withLinuxMountNamespace(namespaceFD, func() error {
		if err := contextError(ctx); err != nil {
			return err
		}
		source, target := linuxDescriptorPath(sourceFD), linuxDescriptorPath(targetFD)
		if err := unix.Mount(source, target, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("mount Linux jailed share: %w", err)
		}
		flags := uintptr(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
		if mode == sandboxresource.ReadOnly {
			flags |= unix.MS_RDONLY
		}
		if err := unix.Mount("", target, "", flags, ""); err != nil {
			_ = unix.Unmount(target, unix.MNT_DETACH)
			return fmt.Errorf("seal Linux jailed share: %w", err)
		}
		return nil
	})
}

func unmountLinuxShare(ctx context.Context, namespaceFD, targetFD int) error {
	if namespaceFD < 0 || targetFD < 0 {
		return fmt.Errorf("unmount Linux jailed share: %w", ErrCapabilityUnavailable)
	}
	return withLinuxMountNamespace(namespaceFD, func() error {
		if err := contextError(ctx); err != nil {
			return err
		}
		err := unix.Unmount(linuxDescriptorPath(targetFD), unix.MNT_DETACH)
		if err == nil || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("unmount Linux jailed share: %w", err)
	})
}

func withLinuxMountNamespace(namespaceFD int, action func() error) (err error) {
	if namespaceFD < 0 || action == nil {
		return fmt.Errorf("enter Linux jailed mount namespace: %w", ErrCapabilityUnavailable)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	currentFD, openErr := unix.Open("/proc/self/ns/mnt", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if openErr != nil {
		return fmt.Errorf("open current Linux mount namespace: %w", openErr)
	}
	defer unix.Close(currentFD)
	if err := unix.Setns(namespaceFD, unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("enter Linux jailed mount namespace: %w", err)
	}
	defer func() {
		restoreErr := unix.Setns(currentFD, unix.CLONE_NEWNS)
		if restoreErr != nil {
			err = errors.Join(err, fmt.Errorf("restore Linux mount namespace: %w", restoreErr))
		}
	}()
	return action()
}

func linuxDescriptorPath(fd int) string { return "/proc/self/fd/" + fmt.Sprintf("%d", fd) }

var _ MountSourceObserver = (*LinuxJailedSharingDaemon)(nil)
var _ JailedSharingDaemon = (*LinuxJailedSharingDaemon)(nil)
