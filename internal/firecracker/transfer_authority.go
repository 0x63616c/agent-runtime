package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostjournal"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/0x63616c/agent-runtime/internal/sandboxresource"
	"github.com/0x63616c/agent-runtime/internal/sandboxtransfer"
	"github.com/0x63616c/agent-runtime/sandbox"
)

// GuestTransferOperationKind identifies the private, reference-only workspace
// command. It is not a public sandbox API and never carries artifact bytes.
const GuestTransferOperationKind = "agent-runtime.guest-transfer/v1"

// GuestSnapshotRestoreOperationKind identifies the private leased restore
// command. It names only a snapshot identity; no snapshot bytes are encoded.
const GuestSnapshotRestoreOperationKind = "agent-runtime.guest-snapshot-restore/v1"

// GuestDataPlaneReceiptVersion is the shared canonical version for private
// transfer and restore terminal receipts.
const GuestDataPlaneReceiptVersion = "agent-runtime.guest-data-plane-receipt/v1"

// GuestTransferCommand is one canonical transfer direction bound to the same
// process, operation, fence, and expiry as its authenticated host envelope.
// Exactly one request is present. Neither request has a representation for
// bytes: copy-in/archive-in names an immutable source and copy-out returns a
// reference. Archive-in is deliberately a separate command arm so a regular
// file cannot silently acquire directory-materialization authority.
type GuestTransferCommand struct {
	Version   string                  `json:"version"`
	CopyIn    *sandbox.CopyInRequest  `json:"copy_in,omitempty"`
	ArchiveIn *sandbox.CopyInRequest  `json:"archive_in,omitempty"`
	CopyOut   *sandbox.CopyOutRequest `json:"copy_out,omitempty"`
}

// GuestSnapshotRestoreCommand binds an admitted store restore request to the
// host-control fencing token, preventing an old lease delivery from rebinding.
type GuestSnapshotRestoreCommand struct {
	Version      string                                 `json:"version"`
	FencingToken uint64                                 `json:"fencing_token"`
	Request      sandboxresource.SnapshotRestoreRequest `json:"request"`
}

// TransferReceipt is the canonical private terminal receipt. It binds an
// effect to an exact envelope and may contain only an immutable artifact
// reference; no file, archive, snapshot, or secret bytes may cross this seam.
type TransferReceipt struct {
	Version        string               `json:"version"`
	EnvelopeID     string               `json:"envelope_id"`
	AssignmentID   string               `json:"assignment_id"`
	OperationID    string               `json:"operation_id"`
	FencingToken   uint64               `json:"fencing_token"`
	Kind           string               `json:"kind"`
	Artifact       *sandbox.ArtifactRef `json:"artifact,omitempty"`
	ArchiveDigest  string               `json:"archive_digest,omitempty"`
	SnapshotID     string               `json:"snapshot_id,omitempty"`
	SnapshotDigest string               `json:"snapshot_digest,omitempty"`
	CompletedAt    time.Time            `json:"completed_at"`
}

// TransferReceiptEmitter delivers a previously-fsynced canonical receipt to
// the authenticated control owner. Its acknowledgement is deliberately
// separate, so a lost response never repeats the workspace effect.
type TransferReceiptEmitter func(context.Context, []byte) error

// TransferExecutionAuthority owns an exact descriptor-rooted workspace
// operation. It is deliberately independent of a Firecracker profile: host
// composition stays unavailable until protected guest-profile evidence exists.
type TransferExecutionAuthority struct {
	workspace *sandboxtransfer.GuestWorkspaceBinding
	source    sandboxtransfer.ArtifactSource
	sink      sandboxtransfer.ArtifactSink
	journal   *sandboxhostjournal.Journal
	clock     clock.Clock
}

// SnapshotRestoreExecutionAuthority binds the durable resource store to one
// leased, fenced command and a host-selected sink. It exposes no path, bytes,
// or generic host-sharing primitive.
type SnapshotRestoreExecutionAuthority struct {
	store   *sandboxresource.Store
	sink    sandboxresource.SnapshotRestoreSink
	reaper  SnapshotRestoreSinkReaper
	journal *sandboxhostjournal.Journal
	clock   clock.Clock
}

// SnapshotRestoreSinkReaper removes only the sink state belonging to one
// exact restore request. Implementations must be idempotent: it is invoked
// after cancellation and durable recovery, never as a broad host cleanup.
type SnapshotRestoreSinkReaper interface {
	ReapSnapshotRestore(context.Context, sandboxresource.SnapshotRestoreRequest) error
}

// NewSnapshotRestoreExecutionAuthority freezes one store/sink/journal/clock
// set at the composition root; a payload cannot replace any of those ports.
func NewSnapshotRestoreExecutionAuthority(store *sandboxresource.Store, sink sandboxresource.SnapshotRestoreSink, journal *sandboxhostjournal.Journal, sourceClock clock.Clock) (*SnapshotRestoreExecutionAuthority, error) {
	reaper, ok := sink.(SnapshotRestoreSinkReaper)
	if store == nil || sink == nil || !ok || reaper == nil || journal == nil || sourceClock == nil {
		return nil, fmt.Errorf("create guest snapshot restore authority: %w", ErrCapabilityUnavailable)
	}
	return &SnapshotRestoreExecutionAuthority{store: store, sink: sink, reaper: reaper, journal: journal, clock: sourceClock}, nil
}

// NewTransferExecutionAuthority freezes all host-selected data-plane ports.
// A caller cannot replace a source, sink, workspace, journal, or clock through
// an envelope payload.
func NewTransferExecutionAuthority(workspace *sandboxtransfer.GuestWorkspaceBinding, source sandboxtransfer.ArtifactSource, sink sandboxtransfer.ArtifactSink, journal *sandboxhostjournal.Journal, sourceClock clock.Clock) (*TransferExecutionAuthority, error) {
	if workspace == nil || source == nil || sink == nil || journal == nil || sourceClock == nil {
		return nil, fmt.Errorf("create guest transfer authority: %w", ErrCapabilityUnavailable)
	}
	return &TransferExecutionAuthority{workspace: workspace, source: source, sink: sink, journal: journal, clock: sourceClock}, nil
}

// DecodeGuestTransferCommand accepts one exact canonical reference-only
// command. Unknown fields, both directions, raw bytes, and invalid paths are
// refused before the data plane is touched.
func DecodeGuestTransferCommand(payload []byte) (GuestTransferCommand, error) {
	if len(payload) == 0 || len(payload) > maximumGuestDispatchBytes {
		return GuestTransferCommand{}, fmt.Errorf("decode guest transfer command: %w", ErrCapabilityUnavailable)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var command GuestTransferCommand
	if err := decoder.Decode(&command); err != nil {
		return GuestTransferCommand{}, fmt.Errorf("decode guest transfer command: %w", ErrCapabilityUnavailable)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return GuestTransferCommand{}, fmt.Errorf("decode guest transfer command: %w", ErrCapabilityUnavailable)
	}
	requestCount := 0
	if command.CopyIn != nil {
		requestCount++
	}
	if command.ArchiveIn != nil {
		requestCount++
	}
	if command.CopyOut != nil {
		requestCount++
	}
	canonical, err := json.Marshal(command)
	if err != nil || !bytes.Equal(canonical, payload) || command.Version != GuestTransferOperationKind || requestCount != 1 {
		return GuestTransferCommand{}, fmt.Errorf("decode guest transfer command: %w", ErrCapabilityUnavailable)
	}
	return command, nil
}

// DecodeGuestSnapshotRestoreCommand accepts only one canonical, reference-only
// leased request and rejects a raw payload or caller-selected destination.
func DecodeGuestSnapshotRestoreCommand(payload []byte) (GuestSnapshotRestoreCommand, error) {
	if len(payload) == 0 || len(payload) > maximumGuestDispatchBytes {
		return GuestSnapshotRestoreCommand{}, fmt.Errorf("decode guest snapshot restore command: %w", ErrCapabilityUnavailable)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var command GuestSnapshotRestoreCommand
	if err := decoder.Decode(&command); err != nil {
		return GuestSnapshotRestoreCommand{}, fmt.Errorf("decode guest snapshot restore command: %w", ErrCapabilityUnavailable)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return GuestSnapshotRestoreCommand{}, fmt.Errorf("decode guest snapshot restore command: %w", ErrCapabilityUnavailable)
	}
	canonical, err := json.Marshal(command)
	if err != nil || !bytes.Equal(canonical, payload) || command.Version != GuestSnapshotRestoreOperationKind || command.FencingToken == 0 || command.Request.Owner == "" || command.Request.ID == "" || command.Request.Holder == "" || command.Request.Generation == 0 {
		return GuestSnapshotRestoreCommand{}, fmt.Errorf("decode guest snapshot restore command: %w", ErrCapabilityUnavailable)
	}
	return command, nil
}

// Execute performs an exact effect only after sandboxhostprocess has fsynced
// its signed started intent. It fsyncs the immutable receipt before delivery;
// retries replay that receipt rather than duplicate copy-in or copy-out.
func (authority *TransferExecutionAuthority) Execute(ctx context.Context, envelope sandboxhostprotocol.Envelope, emit TransferReceiptEmitter) (TransferReceipt, error) {
	if authority == nil || ctx == nil || emit == nil || !authority.journal.ExecutionStarted(envelope) {
		return TransferReceipt{}, fmt.Errorf("execute guest transfer authority: %w", ErrCapabilityUnavailable)
	}
	command, err := DecodeGuestTransferCommand(envelope.Payload)
	if err != nil || envelope.OperationKind != GuestTransferOperationKind || envelope.ExpiresAt.IsZero() || !authority.clock.Now().UTC().Before(envelope.ExpiresAt) {
		return TransferReceipt{}, fmt.Errorf("execute guest transfer authority: %w", ErrCapabilityUnavailable)
	}
	if entry, exists := authority.journal.Entry(envelope); exists && entry.TransferReceiptDigest != "" {
		receipt, err := decodeTransferReceipt(entry.TransferReceiptWire)
		if err != nil || !exactTransferReceipt(receipt, envelope) {
			return TransferReceipt{}, fmt.Errorf("execute guest transfer authority: %w", ErrCapabilityUnavailable)
		}
		if !entry.TransferReceiptAcknowledged {
			if err := emit(ctx, append([]byte(nil), entry.TransferReceiptWire...)); err != nil {
				return TransferReceipt{}, err
			}
		}
		return receipt, nil
	}
	if err := exactTransferCommand(command, envelope); err != nil {
		return TransferReceipt{}, fmt.Errorf("execute guest transfer authority: %w", ErrCapabilityUnavailable)
	}
	receipt := TransferReceipt{Version: GuestDataPlaneReceiptVersion, EnvelopeID: envelope.EnvelopeID, AssignmentID: envelope.AssignmentID, OperationID: envelope.OperationID, FencingToken: envelope.FencingToken, CompletedAt: authority.clock.Now().UTC()}
	if command.CopyIn != nil {
		if err := authority.workspace.CopyIn(ctx, authority.source, *command.CopyIn); err != nil {
			return TransferReceipt{}, err
		}
		receipt.Kind = "copy-in"
	} else if command.ArchiveIn != nil {
		if err := authority.workspace.CopyArchiveIn(ctx, authority.source, *command.ArchiveIn); err != nil {
			return TransferReceipt{}, err
		}
		receipt.Kind, receipt.ArchiveDigest = "archive-in", string(command.ArchiveIn.Source.Digest)
	} else {
		artifact, err := authority.workspace.CopyOut(ctx, authority.sink, *command.CopyOut)
		if err != nil {
			return TransferReceipt{}, err
		}
		receipt.Kind, receipt.Artifact = "copy-out", &artifact
	}
	wire, err := encodeTransferReceipt(receipt)
	if err != nil {
		return TransferReceipt{}, err
	}
	if err := authority.journal.StageTypedTransferReceipt(envelope, "transfer", wire); err != nil {
		return TransferReceipt{}, err
	}
	if err := emit(ctx, append([]byte(nil), wire...)); err != nil {
		return receipt, err
	}
	return receipt, nil
}

// AcknowledgeReceipt permits the generic terminal result only after control
// has durably accepted this exact terminal data-plane observation.
func (authority *TransferExecutionAuthority) AcknowledgeReceipt(envelope sandboxhostprotocol.Envelope, receipt TransferReceipt) error {
	if authority == nil || !exactTransferReceipt(receipt, envelope) {
		return fmt.Errorf("acknowledge guest transfer receipt: %w", ErrCapabilityUnavailable)
	}
	wire, err := encodeTransferReceipt(receipt)
	if err != nil {
		return err
	}
	entry, exists := authority.journal.Entry(envelope)
	if !exists || entry.TransferReceiptDigest != sandboxhostprotocol.Digest(wire) {
		return fmt.Errorf("acknowledge guest transfer receipt: %w", ErrCapabilityUnavailable)
	}
	return authority.journal.AcknowledgeTransferReceipt(entry.ReceiptKey, entry.TransferReceiptDigest)
}

// Reap closes the descriptor-rooted workspace only after the exact receipt is
// acknowledged. A lost ack intentionally preserves the workspace for replay
// and reconciliation rather than releasing it under an uncertain effect.
func (authority *TransferExecutionAuthority) Reap(envelope sandboxhostprotocol.Envelope) error {
	if authority == nil {
		return fmt.Errorf("reap guest transfer authority: %w", ErrCapabilityUnavailable)
	}
	entry, exists := authority.journal.Entry(envelope)
	if !exists || entry.TransferReceiptDigest == "" || !entry.TransferReceiptAcknowledged || entry.ResultDigest == "" || !entry.ResultAcknowledged {
		return fmt.Errorf("reap guest transfer authority: %w", ErrCapabilityUnavailable)
	}
	return authority.workspace.Close()
}

// Execute restores exactly one store snapshot after durable started intent.
// It stages and replays the same reference-only terminal receipt on a lost
// acknowledgement, so the injected sink is never invoked twice for retries.
func (authority *SnapshotRestoreExecutionAuthority) Execute(ctx context.Context, envelope sandboxhostprotocol.Envelope, emit TransferReceiptEmitter) (TransferReceipt, error) {
	if authority == nil || ctx == nil || emit == nil || !authority.journal.ExecutionStarted(envelope) {
		return TransferReceipt{}, fmt.Errorf("execute guest snapshot restore authority: %w", ErrCapabilityUnavailable)
	}
	command, err := DecodeGuestSnapshotRestoreCommand(envelope.Payload)
	if err != nil || !authority.exactCommand(command, envelope) {
		return TransferReceipt{}, fmt.Errorf("execute guest snapshot restore authority: %w", ErrCapabilityUnavailable)
	}
	if entry, exists := authority.journal.Entry(envelope); exists && entry.TransferReceiptDigest != "" {
		receipt, err := decodeTransferReceipt(entry.TransferReceiptWire)
		if err != nil || !exactTransferReceipt(receipt, envelope) {
			return TransferReceipt{}, fmt.Errorf("execute guest snapshot restore authority: %w", ErrCapabilityUnavailable)
		}
		if !entry.TransferReceiptAcknowledged {
			if err := emit(ctx, append([]byte(nil), entry.TransferReceiptWire...)); err != nil {
				return TransferReceipt{}, err
			}
		}
		return receipt, nil
	}
	manifest, err := authority.store.RestoreSnapshot(ctx, command.Request, authority.sink, authority.clock.Now().UTC())
	if err != nil {
		return TransferReceipt{}, err
	}
	receipt := TransferReceipt{Version: GuestDataPlaneReceiptVersion, EnvelopeID: envelope.EnvelopeID, AssignmentID: envelope.AssignmentID, OperationID: envelope.OperationID, FencingToken: envelope.FencingToken, Kind: "snapshot-restore", SnapshotID: manifest.ID, SnapshotDigest: manifest.CiphertextDigest, CompletedAt: authority.clock.Now().UTC()}
	wire, err := encodeTransferReceipt(receipt)
	if err != nil {
		return TransferReceipt{}, err
	}
	if err := authority.journal.StageTypedTransferReceipt(envelope, "snapshot-restore", wire); err != nil {
		return TransferReceipt{}, err
	}
	if err := emit(ctx, append([]byte(nil), wire...)); err != nil {
		return receipt, err
	}
	return receipt, nil
}

// AcknowledgeReceipt records the exact terminal restore receipt before a
// generic terminal result can be staged by the host-process owner.
func (authority *SnapshotRestoreExecutionAuthority) AcknowledgeReceipt(envelope sandboxhostprotocol.Envelope, receipt TransferReceipt) error {
	if authority == nil || !exactTransferReceipt(receipt, envelope) {
		return fmt.Errorf("acknowledge guest snapshot restore receipt: %w", ErrCapabilityUnavailable)
	}
	wire, err := encodeTransferReceipt(receipt)
	if err != nil {
		return err
	}
	entry, exists := authority.journal.Entry(envelope)
	if !exists || entry.TransferReceiptDigest != sandboxhostprotocol.Digest(wire) {
		return fmt.Errorf("acknowledge guest snapshot restore receipt: %w", ErrCapabilityUnavailable)
	}
	return authority.journal.AcknowledgeTransferReceipt(entry.ReceiptKey, entry.TransferReceiptDigest)
}

// Reap converges an exact snapshot sink after cancellation, restart, or a
// completed terminal lifecycle. A durable but unacknowledged receipt is not
// reaped: it must remain replayable so a lost acknowledgement cannot turn a
// completed restore into ambiguous state.
func (authority *SnapshotRestoreExecutionAuthority) Reap(ctx context.Context, envelope sandboxhostprotocol.Envelope) error {
	if authority == nil || ctx == nil || authority.reaper == nil || !authority.journal.ExecutionStarted(envelope) {
		return fmt.Errorf("reap guest snapshot restore authority: %w", ErrCapabilityUnavailable)
	}
	command, err := DecodeGuestSnapshotRestoreCommand(envelope.Payload)
	if err != nil || !authority.exactCommand(command, envelope) {
		return fmt.Errorf("reap guest snapshot restore authority: %w", ErrCapabilityUnavailable)
	}
	if entry, exists := authority.journal.Entry(envelope); exists && entry.TransferReceiptDigest != "" && (!entry.TransferReceiptAcknowledged || entry.ResultDigest == "" || !entry.ResultAcknowledged) {
		return fmt.Errorf("reap guest snapshot restore authority: %w", ErrCapabilityUnavailable)
	}
	if err := authority.reaper.ReapSnapshotRestore(ctx, command.Request); err != nil {
		return err
	}
	if _, err := authority.store.ReleaseSnapshotLease(ctx, command.Request.Owner, command.Request.ID, command.Request.Generation); err != nil && !errors.Is(err, sandboxresource.ErrConflict) {
		return err
	}
	return nil
}

func (authority *SnapshotRestoreExecutionAuthority) exactCommand(command GuestSnapshotRestoreCommand, envelope sandboxhostprotocol.Envelope) bool {
	return envelope.OperationKind == GuestSnapshotRestoreOperationKind && command.FencingToken == envelope.FencingToken && command.Request.Owner == envelope.Principal && command.Request.SandboxID == envelope.SandboxID && command.Request.Holder == envelope.ProcessID && command.Request.Generation == envelope.LeaseEpoch && command.Request.EffectiveSpecDigest == envelope.EffectiveSpecDigest && command.Request.CapabilityDigest == envelope.CapabilityDigest && authority.clock.Now().UTC().Before(envelope.ExpiresAt)
}

func exactTransferCommand(command GuestTransferCommand, envelope sandboxhostprotocol.Envelope) error {
	if command.CopyIn != nil && command.CopyIn.SandboxID == sandbox.SandboxID(envelope.SandboxID) {
		return nil
	}
	if command.CopyOut != nil && command.CopyOut.SandboxID == sandbox.SandboxID(envelope.SandboxID) {
		return nil
	}
	if command.ArchiveIn != nil && command.ArchiveIn.SandboxID == sandbox.SandboxID(envelope.SandboxID) && command.ArchiveIn.Source.MediaType == sandboxtransfer.ArchiveMediaType {
		return nil
	}
	return ErrCapabilityUnavailable
}

func exactTransferReceipt(receipt TransferReceipt, envelope sandboxhostprotocol.Envelope) bool {
	if receipt.Version != GuestDataPlaneReceiptVersion || receipt.EnvelopeID != envelope.EnvelopeID || receipt.AssignmentID != envelope.AssignmentID || receipt.OperationID != envelope.OperationID || receipt.FencingToken != envelope.FencingToken || receipt.CompletedAt.IsZero() || receipt.CompletedAt.Location() != time.UTC {
		return false
	}
	if receipt.Kind == "copy-in" {
		return receipt.Artifact == nil && receipt.ArchiveDigest == "" && receipt.SnapshotID == "" && receipt.SnapshotDigest == ""
	}
	if receipt.Kind == "copy-out" {
		return receipt.Artifact != nil && receipt.Artifact.ID != "" && receipt.Artifact.MediaType != "" && receipt.Artifact.SizeBytes > 0 && len(receipt.Artifact.Digest) == 71 && receipt.ArchiveDigest == "" && receipt.SnapshotID == "" && receipt.SnapshotDigest == ""
	}
	if receipt.Kind == "archive-in" {
		return receipt.Artifact == nil && validReceiptDigest(receipt.ArchiveDigest) && receipt.SnapshotID == "" && receipt.SnapshotDigest == ""
	}
	return receipt.Kind == "snapshot-restore" && receipt.Artifact == nil && receipt.ArchiveDigest == "" && receipt.SnapshotID != "" && validReceiptDigest(receipt.SnapshotDigest)
}

func validReceiptDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[7:] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func encodeTransferReceipt(receipt TransferReceipt) ([]byte, error) {
	if !exactTransferReceipt(receipt, sandboxhostprotocol.Envelope{EnvelopeID: receipt.EnvelopeID, AssignmentID: receipt.AssignmentID, OperationID: receipt.OperationID, FencingToken: receipt.FencingToken}) {
		return nil, fmt.Errorf("encode guest transfer receipt: %w", ErrCapabilityUnavailable)
	}
	wire, err := json.Marshal(receipt)
	if err != nil || len(wire) == 0 || len(wire) > maximumGuestDispatchBytes {
		return nil, fmt.Errorf("encode guest transfer receipt: %w", ErrCapabilityUnavailable)
	}
	return wire, nil
}

func decodeTransferReceipt(wire []byte) (TransferReceipt, error) {
	if len(wire) == 0 || len(wire) > maximumGuestDispatchBytes {
		return TransferReceipt{}, ErrCapabilityUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var receipt TransferReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return TransferReceipt{}, ErrCapabilityUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return TransferReceipt{}, ErrCapabilityUnavailable
	}
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(canonical, wire) {
		return TransferReceipt{}, ErrCapabilityUnavailable
	}
	return receipt, nil
}
