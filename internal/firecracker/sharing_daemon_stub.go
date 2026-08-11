//go:build !linux

package firecracker

import (
	"context"
	"fmt"

	"github.com/0x63616c/agent-runtime/internal/sandboxresource"
)

// LinuxShareExport is one operator-configured source identity. The non-Linux
// build keeps this shape so composition fails before any host I/O.
type LinuxShareExport struct {
	Path   string
	Source sandboxresource.SourceIdentity
}

// LinuxJailedSharingDaemon is deliberately unusable off Linux. Its presence
// cannot make a local adapter advertise a mount capability.
type LinuxJailedSharingDaemon struct{}

// NewLinuxJailedSharingDaemon refuses construction away from Linux.
func NewLinuxJailedSharingDaemon([]LinuxShareExport, string, string) (*LinuxJailedSharingDaemon, error) {
	return nil, fmt.Errorf("create Linux jailed sharing daemon: %w", ErrCapabilityUnavailable)
}

// Close is a no-op only because a non-Linux daemon is never constructed.
func (*LinuxJailedSharingDaemon) Close() error { return nil }

// ObserveMountSource refuses any non-Linux source observation.
func (*LinuxJailedSharingDaemon) ObserveMountSource(context.Context, string) (sandboxresource.SourceIdentity, error) {
	return sandboxresource.SourceIdentity{}, fmt.Errorf("observe Linux jailed share source: %w", ErrCapabilityUnavailable)
}

// Attach refuses any non-Linux mount operation.
func (*LinuxJailedSharingDaemon) Attach(context.Context, JailedShareRequest) error {
	return fmt.Errorf("attach Linux jailed share: %w", ErrCapabilityUnavailable)
}

// Detach refuses any non-Linux mount operation.
func (*LinuxJailedSharingDaemon) Detach(context.Context, JailedShareRequest) error {
	return fmt.Errorf("detach Linux jailed share: %w", ErrCapabilityUnavailable)
}

var _ MountSourceObserver = (*LinuxJailedSharingDaemon)(nil)
var _ JailedSharingDaemon = (*LinuxJailedSharingDaemon)(nil)
