//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/sandboxauthority"
)

const guestCgroupV2Root = "/sys/fs/cgroup"

// guestNoSnapshotSecretArea is the guest-side lifecycle boundary for a
// command secret. A protected profile must hold snapshot exclusion before a
// memfd is populated and release it only after that memfd is closed. The
// static fixture deliberately supplies no implementation, so it remains
// unable to accept a secret dispatch.
type guestNoSnapshotSecretArea interface {
	BeginNonSnapshotSecret(context.Context, sandboxauthority.SecretRequest) error
	EndNonSnapshotSecret(context.Context, sandboxauthority.SecretRequest) error
}

// guestProcessContainmentVerifier adds the pre-start membership proof that a
// pidfd alone cannot provide. The runner requires this stronger shape before
// binding a secret descriptor to a process.
type guestProcessContainmentVerifier interface {
	guestTreeReapVerifier
	VerifyProcessContained(context.Context, int) error
}

type guestCgroupRoot interface {
	ReadFile(string) ([]byte, error)
	Close() error
}

// guestCgroupTreeReapVerifier binds secret recipients to one exact cgroup v2
// subtree. It checks membership before descriptor binding and accepts tree
// reaping only when that subtree's cgroup.procs file is empty. This is a
// Linux contract implementation, not proof that a Jailer created or isolated
// the subtree; profile availability remains separately Linux/KVM-gated.
type guestCgroupTreeReapVerifier struct {
	expectedPath  string
	root          guestCgroupRoot
	processCgroup func(int) ([]byte, error)
}

func newGuestCgroupTreeReapVerifier(cgroupDirectory string) (*guestCgroupTreeReapVerifier, error) {
	if !validGuestSecretCgroupDirectory(cgroupDirectory) {
		return nil, fmt.Errorf("create guest secret cgroup verifier: exact cgroup v2 subtree is required")
	}
	root, err := os.OpenRoot(cgroupDirectory)
	if err != nil {
		return nil, fmt.Errorf("create guest secret cgroup verifier: open protected subtree: %w", err)
	}
	verifier, err := newGuestCgroupTreeReapVerifierWithRoot(strings.TrimPrefix(cgroupDirectory, guestCgroupV2Root), root, func(pid int) ([]byte, error) {
		return os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	})
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	return verifier, nil
}

func newGuestCgroupTreeReapVerifierWithRoot(expectedPath string, root guestCgroupRoot, processCgroup func(int) ([]byte, error)) (*guestCgroupTreeReapVerifier, error) {
	if !validGuestSecretCgroupPath(expectedPath) || root == nil || processCgroup == nil {
		return nil, fmt.Errorf("create guest secret cgroup verifier: exact cgroup v2 subtree is required")
	}
	if _, err := root.ReadFile("cgroup.procs"); err != nil {
		return nil, fmt.Errorf("create guest secret cgroup verifier: inspect cgroup membership: %w", err)
	}
	return &guestCgroupTreeReapVerifier{expectedPath: expectedPath, root: root, processCgroup: processCgroup}, nil
}

// VerifyProcessContained proves the newly-started process is a member of the
// same cgroup whose later emptiness will authorize secret revocation.
func (verifier *guestCgroupTreeReapVerifier) VerifyProcessContained(ctx context.Context, pid int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if verifier == nil || verifier.root == nil || verifier.processCgroup == nil || pid <= 0 {
		return fmt.Errorf("verify guest secret process containment: exact cgroup proof is required")
	}
	encoded, err := verifier.processCgroup(pid)
	if err != nil || !hasGuestCgroupMembership(encoded, verifier.expectedPath) {
		return fmt.Errorf("verify guest secret process containment: recipient is outside the exact cgroup")
	}
	members, err := verifier.root.ReadFile("cgroup.procs")
	if err != nil || !hasGuestCgroupMember(members, pid) {
		return fmt.Errorf("verify guest secret process containment: recipient is absent from the exact cgroup")
	}
	return nil
}

// VerifyTreeReaped refuses a still-populated cgroup even after the caller has
// observed a ready pidfd for the leader. Descendants or sibling helpers keep
// cgroup.procs non-empty and therefore retain the secret area lease.
func (verifier *guestCgroupTreeReapVerifier) VerifyTreeReaped(ctx context.Context, pid, pidfd int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if verifier == nil || verifier.root == nil || pid <= 0 || pidfd < 0 {
		return fmt.Errorf("verify guest secret tree reap: exact cgroup proof is required")
	}
	members, err := verifier.root.ReadFile("cgroup.procs")
	if err != nil || len(strings.Fields(string(members))) != 0 {
		return fmt.Errorf("verify guest secret tree reap: cgroup still has live processes")
	}
	return nil
}

// Close releases the retained descriptor to the cgroup subtree. It must be
// called only after its associated secret runner has been reaped.
func (verifier *guestCgroupTreeReapVerifier) Close() error {
	if verifier == nil || verifier.root == nil {
		return nil
	}
	root := verifier.root
	verifier.root = nil
	return root.Close()
}

func validGuestSecretCgroupDirectory(directory string) bool {
	return strings.HasPrefix(directory, guestCgroupV2Root+"/") && path.Clean(directory) == directory && validGuestSecretCgroupPath(strings.TrimPrefix(directory, guestCgroupV2Root))
}

func validGuestSecretCgroupPath(value string) bool {
	if value == "/" || !strings.HasPrefix(value, "/") || path.Clean(value) != value {
		return false
	}
	for _, segment := range strings.Split(strings.TrimPrefix(value, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func hasGuestCgroupMembership(encoded []byte, expectedPath string) bool {
	for _, line := range strings.Split(string(encoded), "\n") {
		if line == "0::"+expectedPath {
			return true
		}
	}
	return false
}

func hasGuestCgroupMember(encoded []byte, pid int) bool {
	for _, value := range strings.Fields(string(encoded)) {
		candidate, err := strconv.Atoi(value)
		if err == nil && candidate == pid {
			return true
		}
	}
	return false
}
