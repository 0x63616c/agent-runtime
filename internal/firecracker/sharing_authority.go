package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostjournal"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/0x63616c/agent-runtime/internal/sandboxresource"
)

// GuestMountOperationKind identifies the private jailed-sharing command. It
// carries a mount lease identity only; host paths and share handles are absent.
const GuestMountOperationKind = "agent-runtime.guest-mount/v1"

const mountReceiptVersion = "agent-runtime.guest-mount-receipt/v1"

// GuestMountCommand binds a pre-acquired mount lease to the current host
// fence. It cannot select a source path, daemon endpoint, or guest target.
type GuestMountCommand struct {
	Version      string `json:"version"`
	MountID      string `json:"mount_id"`
	Generation   uint64 `json:"generation"`
	FencingToken uint64 `json:"fencing_token"`
}

// MountReceipt is a canonical private terminal observation for a successful
// attach. It deliberately contains no host path, socket, descriptor, or bytes.
type MountReceipt struct {
	Version      string    `json:"version"`
	EnvelopeID   string    `json:"envelope_id"`
	AssignmentID string    `json:"assignment_id"`
	OperationID  string    `json:"operation_id"`
	FencingToken uint64    `json:"fencing_token"`
	MountID      string    `json:"mount_id"`
	Generation   uint64    `json:"generation"`
	CompletedAt  time.Time `json:"completed_at"`
}

// MountReceiptEmitter transports only a previously fsynced receipt to control.
type MountReceiptEmitter func(context.Context, []byte) error

// MountSourceObserver reads descriptor-rooted source identity. Its
// implementation must never resolve a caller-selected host path.
type MountSourceObserver interface {
	ObserveMountSource(context.Context, string) (sandboxresource.SourceIdentity, error)
}

// JailedShareRequest contains the exact source identity and guest-visible
// target a daemon may attach. There is intentionally no host path field.
type JailedShareRequest struct {
	SandboxID  string
	MountID    string
	Generation uint64
	Source     sandboxresource.SourceIdentity
	Target     string
	Mode       sandboxresource.AttachmentMode
	View       string
}

// JailedSharingDaemon is the only future mount data-plane seam. Attach and
// Detach must be idempotent for one exact request so a host reaper can converge
// after crash, cancellation, or a lost control acknowledgement.
type JailedSharingDaemon interface {
	Attach(context.Context, JailedShareRequest) error
	Detach(context.Context, JailedShareRequest) error
}

// MountExecutionAuthority freezes a leased resource store, descriptor identity
// observer, daemon, journal, clock, and command tuple at composition time. It
// is not a generic sharing service and remains profile-gated by LinuxJailerHost.
type MountExecutionAuthority struct {
	store       *sandboxresource.Store
	lease       sandboxresource.MountLease
	processID   string
	operationID string
	fence       uint64
	clock       clock.Clock
	observer    MountSourceObserver
	daemon      JailedSharingDaemon
	journal     *sandboxhostjournal.Journal
}

// NewMountExecutionAuthority creates one exact jailed-sharing authority around
// an already-acquired lease. A command cannot replace any data-plane port.
func NewMountExecutionAuthority(store *sandboxresource.Store, lease sandboxresource.MountLease, processID, operationID string, fence uint64, sourceClock clock.Clock, observer MountSourceObserver, daemon JailedSharingDaemon, journal *sandboxhostjournal.Journal) (*MountExecutionAuthority, error) {
	if store == nil || lease.Owner == "" || lease.ID == "" || lease.SandboxID == "" || lease.Generation == 0 || lease.Source.ExportID == "" || lease.Source.Device == 0 || lease.Source.Inode == 0 || lease.Source.Generation == 0 || lease.Target == "" || processID == "" || operationID == "" || fence == 0 || sourceClock == nil || observer == nil || daemon == nil || journal == nil {
		return nil, fmt.Errorf("create guest mount authority: %w", ErrCapabilityUnavailable)
	}
	return &MountExecutionAuthority{store: store, lease: lease, processID: processID, operationID: operationID, fence: fence, clock: sourceClock, observer: observer, daemon: daemon, journal: journal}, nil
}

// DecodeGuestMountCommand accepts only one canonical lease/fence request.
func DecodeGuestMountCommand(payload []byte) (GuestMountCommand, error) {
	if len(payload) == 0 || len(payload) > maximumGuestDispatchBytes {
		return GuestMountCommand{}, fmt.Errorf("decode guest mount command: %w", ErrCapabilityUnavailable)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var command GuestMountCommand
	if err := decoder.Decode(&command); err != nil {
		return GuestMountCommand{}, fmt.Errorf("decode guest mount command: %w", ErrCapabilityUnavailable)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return GuestMountCommand{}, fmt.Errorf("decode guest mount command: %w", ErrCapabilityUnavailable)
	}
	canonical, err := json.Marshal(command)
	if err != nil || !bytes.Equal(canonical, payload) || command.Version != GuestMountOperationKind || command.MountID == "" || command.Generation == 0 || command.FencingToken == 0 {
		return GuestMountCommand{}, fmt.Errorf("decode guest mount command: %w", ErrCapabilityUnavailable)
	}
	return command, nil
}

// Execute observes the source identity immediately before attach, validates the
// still-live exact lease, then fsyncs a path-free receipt before control send.
// A replay observes no new daemon attach after a lost acknowledgement.
func (authority *MountExecutionAuthority) Execute(ctx context.Context, envelope sandboxhostprotocol.Envelope, emit MountReceiptEmitter) (MountReceipt, error) {
	if authority == nil || ctx == nil || emit == nil || !authority.journal.ExecutionStarted(envelope) {
		return MountReceipt{}, fmt.Errorf("execute guest mount authority: %w", ErrCapabilityUnavailable)
	}
	command, err := DecodeGuestMountCommand(envelope.Payload)
	if err != nil || !authority.exactCommand(command, envelope) {
		return MountReceipt{}, fmt.Errorf("execute guest mount authority: %w", ErrCapabilityUnavailable)
	}
	if entry, exists := authority.journal.Entry(envelope); exists && entry.TransferReceiptDigest != "" {
		receipt, err := decodeMountReceipt(entry.TransferReceiptWire)
		if err != nil || !exactMountReceipt(receipt, envelope, authority.lease) {
			return MountReceipt{}, fmt.Errorf("execute guest mount authority: %w", ErrCapabilityUnavailable)
		}
		if !entry.TransferReceiptAcknowledged {
			if err := emit(ctx, append([]byte(nil), entry.TransferReceiptWire...)); err != nil {
				return MountReceipt{}, err
			}
		}
		return receipt, nil
	}
	observed, err := authority.observer.ObserveMountSource(ctx, authority.lease.Source.ExportID)
	if err != nil || observed != authority.lease.Source {
		return MountReceipt{}, fmt.Errorf("execute guest mount authority: %w", ErrCapabilityUnavailable)
	}
	if err := authority.store.ValidateMountLease(ctx, authority.lease.Owner, authority.lease.ID, authority.lease.Generation, observed, authority.clock.Now().UTC()); err != nil {
		return MountReceipt{}, err
	}
	request := authority.request()
	if err := authority.daemon.Attach(ctx, request); err != nil {
		return MountReceipt{}, err
	}
	receipt := MountReceipt{Version: mountReceiptVersion, EnvelopeID: envelope.EnvelopeID, AssignmentID: envelope.AssignmentID, OperationID: envelope.OperationID, FencingToken: envelope.FencingToken, MountID: authority.lease.ID, Generation: authority.lease.Generation, CompletedAt: authority.clock.Now().UTC()}
	wire, err := encodeMountReceipt(receipt)
	if err != nil {
		return MountReceipt{}, err
	}
	if err := authority.journal.StageTypedTransferReceipt(envelope, "mount", wire); err != nil {
		return MountReceipt{}, err
	}
	if err := emit(ctx, append([]byte(nil), wire...)); err != nil {
		return receipt, err
	}
	return receipt, nil
}

// AcknowledgeReceipt makes only the exact fsynced mount observation terminal.
func (authority *MountExecutionAuthority) AcknowledgeReceipt(envelope sandboxhostprotocol.Envelope, receipt MountReceipt) error {
	if authority == nil || !exactMountReceipt(receipt, envelope, authority.lease) {
		return fmt.Errorf("acknowledge guest mount receipt: %w", ErrCapabilityUnavailable)
	}
	wire, err := encodeMountReceipt(receipt)
	if err != nil {
		return err
	}
	entry, exists := authority.journal.Entry(envelope)
	if !exists || entry.TransferReceiptDigest != sandboxhostprotocol.Digest(wire) {
		return fmt.Errorf("acknowledge guest mount receipt: %w", ErrCapabilityUnavailable)
	}
	return authority.journal.AcknowledgeTransferReceipt(entry.ReceiptKey, entry.TransferReceiptDigest)
}

// Reap detaches only the exact daemon share and then releases its exact lease.
// It is safe after uncertain started work: a daemon must make Detach idempotent,
// and a released lease cannot be rebound by a delayed envelope.
func (authority *MountExecutionAuthority) Reap(ctx context.Context, envelope sandboxhostprotocol.Envelope) error {
	if authority == nil || ctx == nil || envelope.OperationID != authority.operationID || envelope.ProcessID != authority.processID || envelope.SandboxID != authority.lease.SandboxID || envelope.FencingToken != authority.fence {
		return fmt.Errorf("reap guest mount authority: %w", ErrCapabilityUnavailable)
	}
	if err := authority.daemon.Detach(ctx, authority.request()); err != nil {
		return err
	}
	_, err := authority.store.ReleaseMount(ctx, authority.lease.Owner, authority.lease.ID, authority.lease.Generation, authority.clock.Now().UTC())
	if errors.Is(err, sandboxresource.ErrConflict) {
		return nil
	}
	return err
}

func (authority *MountExecutionAuthority) exactCommand(command GuestMountCommand, envelope sandboxhostprotocol.Envelope) bool {
	return envelope.OperationKind == GuestMountOperationKind && envelope.Principal == authority.lease.Owner && envelope.SandboxID == authority.lease.SandboxID && envelope.ProcessID == authority.processID && envelope.OperationID == authority.operationID && envelope.FencingToken == authority.fence && command.MountID == authority.lease.ID && command.Generation == authority.lease.Generation && command.FencingToken == authority.fence && authority.clock.Now().UTC().Before(envelope.ExpiresAt) && authority.clock.Now().UTC().Before(authority.lease.LeaseExpiresAt)
}

func (authority *MountExecutionAuthority) request() JailedShareRequest {
	return JailedShareRequest{SandboxID: authority.lease.SandboxID, MountID: authority.lease.ID, Generation: authority.lease.Generation, Source: authority.lease.Source, Target: authority.lease.Target, Mode: authority.lease.Mode, View: authority.lease.View}
}

func exactMountReceipt(receipt MountReceipt, envelope sandboxhostprotocol.Envelope, lease sandboxresource.MountLease) bool {
	return receipt.Version == mountReceiptVersion && receipt.EnvelopeID == envelope.EnvelopeID && receipt.AssignmentID == envelope.AssignmentID && receipt.OperationID == envelope.OperationID && receipt.FencingToken == envelope.FencingToken && receipt.MountID == lease.ID && receipt.Generation == lease.Generation && !receipt.CompletedAt.IsZero() && receipt.CompletedAt.Location() == time.UTC
}

func encodeMountReceipt(receipt MountReceipt) ([]byte, error) {
	if receipt.Version != mountReceiptVersion || receipt.EnvelopeID == "" || receipt.AssignmentID == "" || receipt.OperationID == "" || receipt.FencingToken == 0 || receipt.MountID == "" || receipt.Generation == 0 || receipt.CompletedAt.IsZero() || receipt.CompletedAt.Location() != time.UTC {
		return nil, fmt.Errorf("encode guest mount receipt: %w", ErrCapabilityUnavailable)
	}
	wire, err := json.Marshal(receipt)
	if err != nil || len(wire) == 0 || len(wire) > maximumGuestDispatchBytes {
		return nil, fmt.Errorf("encode guest mount receipt: %w", ErrCapabilityUnavailable)
	}
	return wire, nil
}

func decodeMountReceipt(wire []byte) (MountReceipt, error) {
	if len(wire) == 0 || len(wire) > maximumGuestDispatchBytes {
		return MountReceipt{}, ErrCapabilityUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var receipt MountReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return MountReceipt{}, ErrCapabilityUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return MountReceipt{}, ErrCapabilityUnavailable
	}
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(canonical, wire) {
		return MountReceipt{}, ErrCapabilityUnavailable
	}
	return receipt, nil
}
