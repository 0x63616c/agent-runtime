//go:build linux

package firecracker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/sandboxresource"
	"golang.org/x/sys/unix"
)

func TestLinuxJailedSharingDaemonPinsDescriptorAcrossExportReplacement(t *testing.T) {
	root := t.TempDir()
	exportPath := filepath.Join(root, "export")
	guestRoot := filepath.Join(root, "guest")
	if err := os.Mkdir(exportPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(guestRoot, "workspace", "source"), 0o700); err != nil {
		t.Fatal(err)
	}
	source := linuxTestSource(t, exportPath, "export_01", 1)
	daemon, err := NewLinuxJailedSharingDaemon([]LinuxShareExport{{Path: exportPath, Source: source}}, "/proc/self/ns/mnt", guestRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := daemon.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	stalePath := filepath.Join(root, "export-stale")
	if err := os.Rename(exportPath, stalePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(exportPath, 0o700); err != nil {
		t.Fatal(err)
	}
	observed, err := daemon.ObserveMountSource(context.Background(), source.ExportID)
	if err != nil || observed != source {
		t.Fatalf("ObserveMountSource() = %#v, %v; want original descriptor identity %#v", observed, err, source)
	}
	if descriptor, err := daemon.openTarget("/workspace/source"); err != nil {
		t.Fatalf("openTarget(valid) = %v", err)
	} else if err := unix.Close(descriptor); err != nil {
		t.Fatal(err)
	}
	if _, err := daemon.openTarget("/workspace/../escape"); err == nil {
		t.Fatal("openTarget() accepted traversal")
	}
	if err := os.Symlink("/tmp", filepath.Join(guestRoot, "workspace", "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := daemon.openTarget("/workspace/link"); err == nil {
		t.Fatal("openTarget() accepted a symlink target")
	}
}

func TestLinuxJailedSharingDaemonRefusesSpecialOrSymlinkExport(t *testing.T) {
	root := t.TempDir()
	guestRoot := filepath.Join(root, "guest")
	if err := os.Mkdir(guestRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	fifoPath := filepath.Join(root, "export-fifo")
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}
	fifoSource := linuxTestSource(t, fifoPath, "export_fifo", 1)
	if daemon, err := NewLinuxJailedSharingDaemon([]LinuxShareExport{{Path: fifoPath, Source: fifoSource}}, "/proc/self/ns/mnt", guestRoot); daemon != nil || !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("NewLinuxJailedSharingDaemon(fifo) = (%#v, %v)", daemon, err)
	}
	directory := filepath.Join(root, "export-directory")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(root, "export-symlink")
	if err := os.Symlink(directory, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if daemon, err := NewLinuxJailedSharingDaemon([]LinuxShareExport{{Path: symlinkPath, Source: linuxTestSource(t, directory, "export_symlink", 1)}}, "/proc/self/ns/mnt", guestRoot); daemon != nil || !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("NewLinuxJailedSharingDaemon(symlink) = (%#v, %v)", daemon, err)
	}
}

func TestLinuxJailedSharingDaemonReaperRefusesWrongRequestAndRepeatsExactDetach(t *testing.T) {
	request := JailedShareRequest{SandboxID: "sandbox_01", MountID: "mount_01", Generation: 1, Source: sandboxresource.SourceIdentity{ExportID: "export_01", Device: 1, Inode: 2, Generation: 3}, Target: "/workspace/source", Mode: sandboxresource.ReadOnly, View: "frozen"}
	daemon := &LinuxJailedSharingDaemon{attached: map[string]JailedShareRequest{linuxShareKey(request): request}, detached: make(map[string]JailedShareRequest)}
	wrong := request
	wrong.Target = "/workspace/other"
	if err := daemon.Detach(context.Background(), wrong); !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("Detach(wrong request) = %v, want unavailable", err)
	}
	delete(daemon.attached, linuxShareKey(request))
	daemon.detached[linuxShareKey(request)] = request
	if err := daemon.Detach(context.Background(), request); err != nil {
		t.Fatalf("Detach(exact completed request) = %v", err)
	}
}

func linuxTestSource(t *testing.T, path, exportID string, generation uint64) sandboxresource.SourceIdentity {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat type = %T, want Linux Stat_t", info.Sys())
	}
	return sandboxresource.SourceIdentity{ExportID: exportID, Device: uint64(stat.Dev), Inode: stat.Ino, Generation: generation}
}
