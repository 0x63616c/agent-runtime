package firecracker

import (
	"context"
	"fmt"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
)

// HostProcessExecutor adapts the authenticated sandbox-host-process executor
// seam to one LinuxJailerHost. Envelope signature/trust verification and the
// durable started/uncertain journal remain owned by sandboxhostprocess; this
// adapter receives only a verified fenced Envelope.
type HostProcessExecutor struct{ Host *LinuxJailerHost }

// Execute hands an already-verified envelope to the sole Firecracker guest-dispatch gate.
func (executor HostProcessExecutor) Execute(ctx context.Context, envelope sandboxhostprotocol.Envelope) error {
	if executor.Host == nil {
		return fmt.Errorf("execute Firecracker host envelope: %w", ErrCapabilityUnavailable)
	}
	return executor.Host.ExecuteDispatch(ctx, envelope)
}
