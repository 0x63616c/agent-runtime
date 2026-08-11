package firecracker

import (
	"context"
	"errors"
	"fmt"
	"time"

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
	err := executor.Host.ExecuteDispatch(ctx, envelope)
	if ctx == nil || ctx.Err() == nil || errors.Is(err, ErrCapabilityUnavailable) {
		return err
	}
	// The deadline-derived execution context is already cancelled, so use only
	// a short independent cleanup context for the bounded cancellation frame.
	// If that exchange cannot complete, the durable host journal still records
	// an uncertain terminal state and LinuxJailerHost.Cleanup reaps the peer.
	cancelCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return errors.Join(err, executor.Host.CancelDispatch(cancelCtx, envelope))
}

// ExecuteAuthenticated preserves the exact control-signed canonical delivery
// that sandboxhostprocess already trust-verified before guest dispatch.
func (executor HostProcessExecutor) ExecuteAuthenticated(ctx context.Context, envelope sandboxhostprotocol.Envelope, authenticatedEnvelope []byte) error {
	if executor.Host == nil {
		return fmt.Errorf("execute authenticated Firecracker host envelope: %w", ErrCapabilityUnavailable)
	}
	err := executor.Host.ExecuteAuthenticatedDispatch(ctx, envelope, authenticatedEnvelope)
	if ctx == nil || ctx.Err() == nil || errors.Is(err, ErrCapabilityUnavailable) {
		return err
	}
	cancelCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return errors.Join(err, executor.Host.CancelDispatch(cancelCtx, envelope))
}
