//go:build !linux

package firecracker

import (
	"errors"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/sandboxresource"
)

func TestLinuxJailedSharingDaemonRefusesNonLinuxConstruction(t *testing.T) {
	if daemon, err := NewLinuxJailedSharingDaemon(nil, "/proc/self/ns/mnt", "/guest"); daemon != nil || !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("NewLinuxJailedSharingDaemon() = (%#v, %v)", daemon, err)
	}
}

func TestLinuxMountExecutionAuthorityRefusesAbsentLinuxDaemon(t *testing.T) {
	if authority, err := NewLinuxMountExecutionAuthority(nil, sandboxresource.MountLease{}, "", "", 0, nil, nil, nil); authority != nil || !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("NewLinuxMountExecutionAuthority() = (%#v, %v)", authority, err)
	}
}
