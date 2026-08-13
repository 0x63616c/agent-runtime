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
type HostProcessExecutor struct {
	Host     *LinuxJailerHost
	Secrets  *SecretExecutionAuthority
	Egress   *ProxyAuthorityIssuer
	Transfer *TransferExecutionAuthority
	Restore  *SnapshotRestoreExecutionAuthority
	Mount    *MountExecutionAuthority
	// Ownership is the optional durable direct-KVM foundation-plan owner. It
	// never certifies availability or starts a Jailer; when composed it binds
	// verified create and exec deliveries before this adapter reaches a host.
	Ownership *DirectLaunchOwnership
}

// UnavailableHostProcessExecutor binds the public host-control runtime to the
// Firecracker authority adapter before an operator has supplied a reviewed
// Linux Jailer composition.  It is deliberately useful only as a fail-closed
// control/recovery owner: the empty host cannot launch, dispatch, or promote a
// capability profile.
func UnavailableHostProcessExecutor() HostProcessExecutor {
	return HostProcessExecutor{Host: &LinuxJailerHost{}}
}

// ExecuteAuthenticatedTransfer is the private control-to-host data-plane door.
// It accepts only the original authenticated envelope, returns no bytes, and
// remains profile-gated until protected guest evidence exists.
func (executor HostProcessExecutor) ExecuteAuthenticatedTransfer(ctx context.Context, envelope sandboxhostprotocol.Envelope, authenticatedEnvelope []byte, emit TransferReceiptEmitter) (TransferReceipt, error) {
	if executor.Host == nil || executor.Transfer == nil || emit == nil {
		return TransferReceipt{}, fmt.Errorf("execute authenticated Firecracker transfer: %w", ErrCapabilityUnavailable)
	}
	if err := sandboxhostprotocol.ValidateAuthenticatedEnvelopeWire(authenticatedEnvelope, envelope); err != nil {
		return TransferReceipt{}, fmt.Errorf("execute authenticated Firecracker transfer: exact canonical envelope is required: %w", ErrCapabilityUnavailable)
	}
	return executor.Host.DispatchAuthenticatedTransfer(ctx, envelope, authenticatedEnvelope, executor.Transfer, emit)
}

// ExecuteAuthenticatedSnapshotRestore is the corresponding private resource
// restore door. The store/sink remain fixed at construction and profile-gated.
func (executor HostProcessExecutor) ExecuteAuthenticatedSnapshotRestore(ctx context.Context, envelope sandboxhostprotocol.Envelope, authenticatedEnvelope []byte, emit TransferReceiptEmitter) (TransferReceipt, error) {
	if executor.Host == nil || executor.Restore == nil || emit == nil {
		return TransferReceipt{}, fmt.Errorf("execute authenticated Firecracker snapshot restore: exact canonical envelope is required: %w", ErrCapabilityUnavailable)
	}
	if err := sandboxhostprotocol.ValidateAuthenticatedEnvelopeWire(authenticatedEnvelope, envelope); err != nil {
		return TransferReceipt{}, fmt.Errorf("execute authenticated Firecracker snapshot restore: exact canonical envelope is required: %w", ErrCapabilityUnavailable)
	}
	return executor.Host.DispatchAuthenticatedSnapshotRestore(ctx, envelope, authenticatedEnvelope, executor.Restore, emit)
}

// ExecuteAuthenticatedMount is the private host-control door for one exact
// jailed sharing lease. LinuxJailerHost keeps it unavailable until the daemon
// profile has protected Linux/KVM evidence.
func (executor HostProcessExecutor) ExecuteAuthenticatedMount(ctx context.Context, envelope sandboxhostprotocol.Envelope, authenticatedEnvelope []byte, emit MountReceiptEmitter) (MountReceipt, error) {
	if executor.Host == nil || executor.Mount == nil || emit == nil {
		return MountReceipt{}, fmt.Errorf("execute authenticated Firecracker mount: exact canonical envelope is required: %w", ErrCapabilityUnavailable)
	}
	if err := sandboxhostprotocol.ValidateAuthenticatedEnvelopeWire(authenticatedEnvelope, envelope); err != nil {
		return MountReceipt{}, fmt.Errorf("execute authenticated Firecracker mount: exact canonical envelope is required: %w", ErrCapabilityUnavailable)
	}
	return executor.Host.DispatchAuthenticatedMount(ctx, envelope, authenticatedEnvelope, executor.Mount, emit)
}

// ReapAuthenticatedMount lets the durable host/reaper owner converge an exact
// prior mount command after cancellation, host loss, or a lost control ack.
// It deliberately does not require an available profile: cleanup must remain
// possible even when capability certification is withdrawn.
func (executor HostProcessExecutor) ReapAuthenticatedMount(ctx context.Context, envelope sandboxhostprotocol.Envelope) error {
	if executor.Host == nil || executor.Mount == nil {
		return fmt.Errorf("reap authenticated Firecracker mount: %w", ErrCapabilityUnavailable)
	}
	return executor.Mount.Reap(ctx, envelope)
}

// ReapAuthenticatedSnapshotRestore converges the fixed guest sink and exact
// snapshot lease after cancellation, a process crash, or terminal delivery.
// Like mount cleanup, it stays callable while profiles are unavailable: a
// withdrawn capability must never strand an already-started protected sink.
func (executor HostProcessExecutor) ReapAuthenticatedSnapshotRestore(ctx context.Context, envelope sandboxhostprotocol.Envelope) error {
	if executor.Host == nil || executor.Restore == nil {
		return fmt.Errorf("reap authenticated Firecracker snapshot restore: %w", ErrCapabilityUnavailable)
	}
	return executor.Restore.Reap(ctx, envelope)
}

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
		return fmt.Errorf("execute authenticated Firecracker host envelope: exact canonical envelope is required: %w", ErrCapabilityUnavailable)
	}
	if err := sandboxhostprotocol.ValidateAuthenticatedEnvelopeWire(authenticatedEnvelope, envelope); err != nil {
		return fmt.Errorf("execute authenticated Firecracker host envelope: exact canonical envelope is required: %w", ErrCapabilityUnavailable)
	}
	if executor.Ownership != nil {
		switch envelope.OperationKind {
		case "create-sandbox":
			if err := executor.Ownership.ClaimCreate(envelope, authenticatedEnvelope); err != nil {
				return err
			}
			return fmt.Errorf("execute authenticated Firecracker create: durable foundation ownership is not a certified launch: %w", ErrCapabilityUnavailable)
		case "exec-process":
			if err := executor.Ownership.BindExec(envelope, authenticatedEnvelope); err != nil {
				return err
			}
		}
	}
	err := executor.Host.ExecuteAuthenticatedDispatch(ctx, envelope, authenticatedEnvelope)
	if ctx == nil || ctx.Err() == nil || errors.Is(err, ErrCapabilityUnavailable) {
		return err
	}
	cancelCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return errors.Join(err, executor.Host.CancelDispatch(cancelCtx, envelope))
}

// ExecuteWithOutput forwards only stdout/stderr chunks to sandboxhostprocess,
// which signs, journals, and acknowledges them before terminal completion.
func (executor HostProcessExecutor) ExecuteWithOutput(ctx context.Context, envelope sandboxhostprotocol.Envelope, emit sandboxhostprotocol.GuestOutputEmitter) error {
	if executor.Host == nil || emit == nil {
		return fmt.Errorf("execute Firecracker guest output: %w", ErrCapabilityUnavailable)
	}
	return fmt.Errorf("execute Firecracker guest output: %w", ErrCapabilityUnavailable)
}

// ExecuteAuthenticatedWithOutput preserves exact control trust and forwards
// each stdout/stderr chunk before allowing the durable terminal path to run.
func (executor HostProcessExecutor) ExecuteAuthenticatedWithOutput(ctx context.Context, envelope sandboxhostprotocol.Envelope, authenticatedEnvelope []byte, emit sandboxhostprotocol.GuestOutputEmitter) error {
	if executor.Host == nil || emit == nil {
		return fmt.Errorf("execute authenticated Firecracker guest output: exact canonical envelope is required: %w", ErrCapabilityUnavailable)
	}
	if err := sandboxhostprotocol.ValidateAuthenticatedEnvelopeWire(authenticatedEnvelope, envelope); err != nil {
		return fmt.Errorf("execute authenticated Firecracker guest output: exact canonical envelope is required: %w", ErrCapabilityUnavailable)
	}
	if envelope.OperationKind == GuestSecretCommandOperationKind {
		if executor.Secrets == nil {
			return fmt.Errorf("execute authenticated Firecracker secret command: %w", ErrCapabilityUnavailable)
		}
		return executor.Host.DispatchAuthenticatedSecret(ctx, envelope, authenticatedEnvelope, executor.Secrets, emit)
	}
	if envelope.OperationKind == GuestProxyOperationKind {
		if executor.Egress == nil {
			return fmt.Errorf("execute authenticated Firecracker guest proxy: %w", ErrCapabilityUnavailable)
		}
		result, err := executor.Host.DispatchAuthenticatedProxy(ctx, envelope, authenticatedEnvelope, executor.Egress)
		if err != nil {
			if ctx == nil || ctx.Err() == nil || errors.Is(err, ErrCapabilityUnavailable) {
				return err
			}
			cancelCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			return errors.Join(err, executor.Host.CancelDispatch(cancelCtx, envelope))
		}
		for _, output := range result.Outputs {
			if output.Stream != "stdout" && output.Stream != "stderr" {
				continue
			}
			if err := emit(ctx, sandboxhostprotocol.GuestOutput{Stream: output.Stream, Sequence: output.Sequence, Data: append([]byte(nil), output.Data...)}); err != nil {
				return err
			}
		}
		if result.State == "SUCCEEDED" {
			return nil
		}
		return fmt.Errorf("authenticated Firecracker guest proxy result: %w", ErrCapabilityUnavailable)
	}
	result, err := executor.Host.DispatchAuthenticated(ctx, envelope, authenticatedEnvelope)
	if err != nil {
		return err
	}
	for _, output := range result.Outputs {
		if output.Stream != "stdout" && output.Stream != "stderr" {
			continue
		}
		if err := emit(ctx, sandboxhostprotocol.GuestOutput{Stream: output.Stream, Sequence: output.Sequence, Data: append([]byte(nil), output.Data...)}); err != nil {
			return err
		}
	}
	return fmt.Errorf("authenticated Firecracker guest dispatch: %w", ErrCapabilityUnavailable)
}

// ExecuteWithDataPlaneReceipt dispatches only a private reference-only data
// plane operation. The host-process owner signs and acknowledges the emitted
// receipt before it may stage a generic terminal result.
func (executor HostProcessExecutor) ExecuteWithDataPlaneReceipt(ctx context.Context, envelope sandboxhostprotocol.Envelope, emit func(context.Context, string, []byte) error) error {
	return executor.ExecuteAuthenticatedWithDataPlaneReceipt(ctx, envelope, nil, emit)
}

// ExecuteAuthenticatedWithDataPlaneReceipt preserves the exact signed control
// wire while selecting one fixed transfer, restore, or sharing authority.
func (executor HostProcessExecutor) ExecuteAuthenticatedWithDataPlaneReceipt(ctx context.Context, envelope sandboxhostprotocol.Envelope, authenticatedEnvelope []byte, emit func(context.Context, string, []byte) error) error {
	if executor.Host == nil || emit == nil || len(authenticatedEnvelope) == 0 {
		return fmt.Errorf("execute Firecracker data-plane receipt: exact canonical envelope is required: %w", ErrCapabilityUnavailable)
	}
	if err := sandboxhostprotocol.ValidateAuthenticatedEnvelopeWire(authenticatedEnvelope, envelope); err != nil {
		return fmt.Errorf("execute Firecracker data-plane receipt: exact canonical envelope is required: %w", ErrCapabilityUnavailable)
	}
	if guestTransferOperationKind(envelope.OperationKind) {
		if executor.Transfer == nil {
			return fmt.Errorf("execute Firecracker transfer receipt: %w", ErrCapabilityUnavailable)
		}
		_, err := executor.Host.DispatchAuthenticatedTransfer(ctx, envelope, authenticatedEnvelope, executor.Transfer, func(receiptCtx context.Context, wire []byte) error { return emit(receiptCtx, "transfer", wire) })
		return err
	}
	switch envelope.OperationKind {
	case GuestSnapshotRestoreOperationKind:
		if executor.Restore == nil {
			return fmt.Errorf("execute Firecracker snapshot restore receipt: %w", ErrCapabilityUnavailable)
		}
		_, err := executor.Host.DispatchAuthenticatedSnapshotRestore(ctx, envelope, authenticatedEnvelope, executor.Restore, func(receiptCtx context.Context, wire []byte) error { return emit(receiptCtx, "snapshot-restore", wire) })
		return err
	case GuestMountOperationKind:
		if executor.Mount == nil {
			return fmt.Errorf("execute Firecracker mount receipt: %w", ErrCapabilityUnavailable)
		}
		_, err := executor.Host.DispatchAuthenticatedMount(ctx, envelope, authenticatedEnvelope, executor.Mount, func(receiptCtx context.Context, wire []byte) error { return emit(receiptCtx, "mount", wire) })
		return err
	default:
		return fmt.Errorf("execute Firecracker data-plane receipt: %w", ErrCapabilityUnavailable)
	}
}

// ReapAuthenticated converges only the exact already-verified control command
// after a cancellation or a failed guest exchange.  It is intentionally
// conservative: an unavailable profile may refuse cleanup, but it can never
// receive an altered envelope, a different lease, or a different fence.
func (executor HostProcessExecutor) ReapAuthenticated(ctx context.Context, envelope sandboxhostprotocol.Envelope, authenticatedEnvelope []byte) error {
	if executor.Host == nil || sandboxhostprotocol.ValidateAuthenticatedEnvelopeWire(authenticatedEnvelope, envelope) != nil {
		return fmt.Errorf("reap authenticated Firecracker command: exact canonical envelope is required: %w", ErrCapabilityUnavailable)
	}
	if executor.Ownership != nil && envelope.OperationKind == "exec-process" {
		if err := executor.Ownership.BindExec(envelope, authenticatedEnvelope); err != nil {
			return err
		}
	}
	if guestTransferOperationKind(envelope.OperationKind) {
		if executor.Transfer == nil {
			return fmt.Errorf("reap authenticated Firecracker transfer: %w", ErrCapabilityUnavailable)
		}
		return executor.Transfer.Reap(envelope)
	}
	switch envelope.OperationKind {
	case GuestSecretCommandOperationKind:
		if executor.Secrets == nil {
			return fmt.Errorf("reap authenticated Firecracker secret command: %w", ErrCapabilityUnavailable)
		}
		return executor.Secrets.AbandonAfterLostContact(ctx, envelope.ProcessID)
	case GuestSnapshotRestoreOperationKind:
		return executor.ReapAuthenticatedSnapshotRestore(ctx, envelope)
	case GuestMountOperationKind:
		return executor.ReapAuthenticatedMount(ctx, envelope)
	default:
		return executor.Host.CancelDispatch(ctx, envelope)
	}
}
