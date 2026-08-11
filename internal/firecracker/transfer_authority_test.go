package firecracker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostjournal"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/0x63616c/agent-runtime/internal/sandboxresource"
	"github.com/0x63616c/agent-runtime/internal/sandboxtransfer"
	"github.com/0x63616c/agent-runtime/sandbox"
)

func TestTransferExecutionAuthorityFencesDurableReceiptAndLostAckReplay(t *testing.T) {
	now := time.Date(2026, 8, 10, 1, 2, 3, 0, time.UTC)
	sourceClock, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	binding, err := sandboxtransfer.BindGuestWorkspace("sandbox-001", root, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(t.TempDir(), "receipts.json")
	journal, err := sandboxhostjournal.Open(journalPath, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	data := []byte("immutable artifact")
	artifact := transferArtifact("artifact-001", "text/plain", data)
	source := &transferSource{data: data}
	sink := &transferSink{}
	authority, err := NewTransferExecutionAuthority(binding, source, sink, journal, sourceClock)
	if err != nil {
		t.Fatal(err)
	}
	envelope := transferEnvelope(t, now, sandbox.CopyInRequest{SandboxID: "sandbox-001", Source: artifact, Destination: "/workspace/input.txt", Options: sandbox.TransferOptions{Overwrite: sandbox.OverwriteFailIfExists, Durable: true}})
	if _, _, err := journal.Accept(envelope, sandboxhostprotocol.Digest([]byte("control-envelope"))); err != nil {
		t.Fatal(err)
	}
	if err := journal.StageStarted(envelope, []byte(`{"state":"started"}`)); err != nil {
		t.Fatal(err)
	}

	var firstWire []byte
	receipt, err := authority.Execute(context.Background(), envelope, func(_ context.Context, wire []byte) error {
		firstWire = append([]byte(nil), wire...)
		return errors.New("lost ack")
	})
	if err == nil || receipt.Kind != "copy-in" {
		t.Fatalf("Execute() = %#v, %v; want receipt and lost ack", receipt, err)
	}
	if source.opens != 1 || len(firstWire) == 0 {
		t.Fatalf("effect/source opens = %d, receipt bytes = %d", source.opens, len(firstWire))
	}
	if err := journal.StageResult(envelope, []byte(`{"state":"succeeded"}`)); err == nil {
		t.Fatal("StageResult() accepted terminal state before transfer receipt ack")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = sandboxhostjournal.Open(journalPath, 10)
	if err != nil {
		t.Fatal(err)
	}
	authority, err = NewTransferExecutionAuthority(binding, source, sink, journal, sourceClock)
	if err != nil {
		t.Fatal(err)
	}

	var replayWire []byte
	replayed, err := authority.Execute(context.Background(), envelope, func(_ context.Context, wire []byte) error { replayWire = append([]byte(nil), wire...); return nil })
	if err != nil || replayed != receipt || !bytes.Equal(replayWire, firstWire) || source.opens != 1 {
		t.Fatalf("replay = %#v, %v; opens=%d; want byte-identical no-effect replay", replayed, err, source.opens)
	}
	if err := authority.AcknowledgeReceipt(envelope, receipt); err != nil {
		t.Fatal(err)
	}
	if err := journal.StageResult(envelope, []byte(`{"state":"succeeded"}`)); err != nil {
		t.Fatal(err)
	}
	entry, _ := journal.Entry(envelope)
	if err := journal.AcknowledgeResult(entry.ReceiptKey, entry.ResultDigest); err != nil {
		t.Fatal(err)
	}
	if err := authority.Reap(envelope); err != nil {
		t.Fatal(err)
	}
}

func TestTransferExecutionAuthorityRefusesCrossSandboxBeforeEffect(t *testing.T) {
	now := time.Date(2026, 8, 10, 1, 2, 3, 0, time.UTC)
	sourceClock, _ := clock.NewFake(now)
	binding, err := sandboxtransfer.BindGuestWorkspace("sandbox-001", t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := sandboxhostjournal.Open(filepath.Join(t.TempDir(), "receipts.json"), 10)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	source, sink := &transferSource{data: []byte("x")}, &transferSink{}
	authority, err := NewTransferExecutionAuthority(binding, source, sink, journal, sourceClock)
	if err != nil {
		t.Fatal(err)
	}
	envelope := transferEnvelope(t, now, sandbox.CopyInRequest{SandboxID: "other", Source: transferArtifact("artifact-001", "text/plain", []byte("x")), Destination: "/workspace/x", Options: sandbox.TransferOptions{Overwrite: sandbox.OverwriteFailIfExists}})
	if _, _, err := journal.Accept(envelope, sandboxhostprotocol.Digest([]byte("control-envelope"))); err != nil {
		t.Fatal(err)
	}
	if err := journal.StageStarted(envelope, []byte(`{"state":"started"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Execute(context.Background(), envelope, func(context.Context, []byte) error { return nil }); !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("Execute() error = %v, want unavailable", err)
	}
	if source.opens != 0 {
		t.Fatalf("source opens = %d, want no effect", source.opens)
	}
}

func TestTransferExecutionAuthorityArchiveInReplaysReceiptWithoutSecondExtraction(t *testing.T) {
	now := time.Date(2026, 8, 10, 1, 2, 3, 0, time.UTC)
	sourceClock, _ := clock.NewFake(now)
	root := t.TempDir()
	binding, err := sandboxtransfer.BindGuestWorkspace("sandbox-001", root, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(t.TempDir(), "receipts.json")
	journal, err := sandboxhostjournal.Open(journalPath, 10)
	if err != nil {
		t.Fatal(err)
	}
	archive := transferArchive(t)
	request := sandbox.CopyInRequest{SandboxID: "sandbox-001", Source: transferArtifact("archive-001", sandboxtransfer.ArchiveMediaType, archive), Destination: "/workspace/restored", Options: sandbox.TransferOptions{Overwrite: sandbox.OverwriteFailIfExists, Durable: true}}
	source := &transferSource{data: archive}
	authority, err := NewTransferExecutionAuthority(binding, source, &transferSink{}, journal, sourceClock)
	if err != nil {
		t.Fatal(err)
	}
	envelope := transferArchiveEnvelope(t, now, request)
	if _, _, err := journal.Accept(envelope, sandboxhostprotocol.Digest([]byte("control-envelope"))); err != nil {
		t.Fatal(err)
	}
	if err := journal.StageStarted(envelope, []byte(`{"state":"started"}`)); err != nil {
		t.Fatal(err)
	}
	var firstWire []byte
	receipt, err := authority.Execute(context.Background(), envelope, func(_ context.Context, wire []byte) error {
		firstWire = append([]byte(nil), wire...)
		return errors.New("lost ack")
	})
	if err == nil || receipt.Kind != "archive-in" || receipt.ArchiveDigest != string(request.Source.Digest) || source.opens != 1 {
		t.Fatalf("Execute() = %#v, %v; opens=%d", receipt, err, source.opens)
	}
	got, err := os.ReadFile(filepath.Join(root, "restored", "results", "value.txt"))
	if err != nil || string(got) != "value" {
		t.Fatalf("archive materialization = %q, %v", got, err)
	}
	if err := authority.Reap(envelope); !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("Reap() before receipt ack = %v, want unavailable", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = sandboxhostjournal.Open(journalPath, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	authority, err = NewTransferExecutionAuthority(binding, source, &transferSink{}, journal, sourceClock)
	if err != nil {
		t.Fatal(err)
	}
	var replayWire []byte
	if replayed, err := authority.Execute(context.Background(), envelope, func(_ context.Context, wire []byte) error { replayWire = append([]byte(nil), wire...); return nil }); err != nil || replayed != receipt || !bytes.Equal(firstWire, replayWire) || source.opens != 1 {
		t.Fatalf("replay = %#v, %v; opens=%d", replayed, err, source.opens)
	}
	if err := authority.AcknowledgeReceipt(envelope, receipt); err != nil {
		t.Fatal(err)
	}
	if err := journal.StageResult(envelope, []byte(`{"state":"succeeded"}`)); err != nil {
		t.Fatal(err)
	}
	entry, _ := journal.Entry(envelope)
	if err := journal.AcknowledgeResult(entry.ReceiptKey, entry.ResultDigest); err != nil {
		t.Fatal(err)
	}
	if err := authority.Reap(envelope); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotRestoreAuthorityReplaysLostReceiptWithoutSecondSinkEffect(t *testing.T) {
	now := time.Date(2026, 8, 10, 1, 2, 3, 0, time.UTC)
	sourceClock, _ := clock.NewFake(now)
	store, err := sandboxresource.Open(t.TempDir(), sandboxresource.Config{MaximumVolumeBytes: 1024, MaximumVolumeInodes: 32, MaximumSnapshotBytes: 1024}, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	manifest := sandboxresource.SnapshotManifest{Owner: "tenant:alice", ID: "snap-001", SourceSandboxID: "sandbox-001", SourceEffectiveSpecDigest: "sha256:effective", CapabilityDigest: "sha256:capability", ImageDigest: "sha256:image", RequestID: "snapshot-op", Format: "ext4-overlay", Encryption: "aes-256-gcm", Integrity: "sha256", RetentionExpiresAt: now.Add(time.Hour)}
	created, err := store.CreateSnapshot(context.Background(), manifest, strings.NewReader("disk"), now)
	if err != nil {
		t.Fatal(err)
	}
	leased, err := store.AcquireSnapshotLease(context.Background(), created.Owner, created.ID, "process-001", now.Add(time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := sandboxhostjournal.Open(filepath.Join(t.TempDir(), "receipts.json"), 10)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	sink := &snapshotSink{}
	authority, err := NewSnapshotRestoreExecutionAuthority(store, sink, journal, sourceClock)
	if err != nil {
		t.Fatal(err)
	}
	envelope := snapshotRestoreEnvelope(t, now, created, leased)
	if _, _, err := journal.Accept(envelope, sandboxhostprotocol.Digest([]byte("control-envelope"))); err != nil {
		t.Fatal(err)
	}
	if err := journal.StageStarted(envelope, []byte(`{"state":"started"}`)); err != nil {
		t.Fatal(err)
	}
	receipt, err := authority.Execute(context.Background(), envelope, func(context.Context, []byte) error { return errors.New("lost ack") })
	if err == nil || receipt.Kind != "snapshot-restore" || sink.calls != 1 {
		t.Fatalf("Execute() = %#v, %v; sink calls=%d", receipt, err, sink.calls)
	}
	replayed, err := authority.Execute(context.Background(), envelope, func(context.Context, []byte) error { return nil })
	if err != nil || replayed != receipt || sink.calls != 1 {
		t.Fatalf("replay = %#v, %v; sink calls=%d", replayed, err, sink.calls)
	}
	if err := authority.Reap(context.Background(), envelope); !errors.Is(err, ErrCapabilityUnavailable) || sink.reaps != 0 {
		t.Fatalf("Reap() before lost receipt ack = %v; reaps=%d", err, sink.reaps)
	}
	if err := authority.AcknowledgeReceipt(envelope, receipt); err != nil {
		t.Fatal(err)
	}
	if err := journal.StageResult(envelope, []byte(`{"state":"succeeded"}`)); err != nil {
		t.Fatal(err)
	}
	entry, _ := journal.Entry(envelope)
	if err := journal.AcknowledgeResult(entry.ReceiptKey, entry.ResultDigest); err != nil {
		t.Fatal(err)
	}
	if err := authority.Reap(context.Background(), envelope); err != nil || sink.reaps != 1 {
		t.Fatalf("Reap() = %v; reaps=%d", err, sink.reaps)
	}
}

func TestSnapshotRestoreAuthorityReapsFailedSinkAndReleasesOnlyExactLease(t *testing.T) {
	now := time.Date(2026, 8, 10, 1, 2, 3, 0, time.UTC)
	sourceClock, _ := clock.NewFake(now)
	store, err := sandboxresource.Open(t.TempDir(), sandboxresource.Config{MaximumVolumeBytes: 1024, MaximumVolumeInodes: 32, MaximumSnapshotBytes: 1024}, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	manifest := sandboxresource.SnapshotManifest{Owner: "tenant:alice", ID: "snap-001", SourceSandboxID: "sandbox-001", SourceEffectiveSpecDigest: "sha256:effective", CapabilityDigest: "sha256:capability", ImageDigest: "sha256:image", RequestID: "snapshot-op", Format: "ext4-overlay", Encryption: "aes-256-gcm", Integrity: "sha256", RetentionExpiresAt: now.Add(time.Hour)}
	created, err := store.CreateSnapshot(context.Background(), manifest, strings.NewReader("disk"), now)
	if err != nil {
		t.Fatal(err)
	}
	leased, err := store.AcquireSnapshotLease(context.Background(), created.Owner, created.ID, "process-001", now.Add(time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := sandboxhostjournal.Open(filepath.Join(t.TempDir(), "receipts.json"), 10)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	sink := &snapshotSink{restoreErr: context.Canceled}
	authority, err := NewSnapshotRestoreExecutionAuthority(store, sink, journal, sourceClock)
	if err != nil {
		t.Fatal(err)
	}
	envelope := snapshotRestoreEnvelope(t, now, created, leased)
	if _, _, err := journal.Accept(envelope, sandboxhostprotocol.Digest([]byte("control-envelope"))); err != nil {
		t.Fatal(err)
	}
	if err := journal.StageStarted(envelope, []byte(`{"state":"started"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Execute(context.Background(), envelope, func(context.Context, []byte) error { return nil }); err == nil || sink.calls != 1 {
		t.Fatalf("Execute() error = %v; sink calls=%d", err, sink.calls)
	}
	if err := authority.Reap(context.Background(), envelope); err != nil || sink.reaps != 1 {
		t.Fatalf("Reap() = %v; reaps=%d", err, sink.reaps)
	}
	if _, err := store.AcquireSnapshotLease(context.Background(), created.Owner, created.ID, "process-002", now.Add(time.Minute), now); err != nil {
		t.Fatalf("AcquireSnapshotLease() after exact reap = %v", err)
	}
}

func transferEnvelope(t *testing.T, now time.Time, request sandbox.CopyInRequest) sandboxhostprotocol.Envelope {
	t.Helper()
	return transferEnvelopeCommand(t, now, GuestTransferCommand{Version: GuestTransferOperationKind, CopyIn: &request})
}

func snapshotRestoreEnvelope(t *testing.T, now time.Time, created, leased sandboxresource.SnapshotManifest) sandboxhostprotocol.Envelope {
	t.Helper()
	command := GuestSnapshotRestoreCommand{Version: GuestSnapshotRestoreOperationKind, FencingToken: 7, Request: sandboxresource.SnapshotRestoreRequest{Owner: created.Owner, ID: created.ID, Holder: "process-001", Generation: leased.Lease.Generation, SandboxID: created.SourceSandboxID, EffectiveSpecDigest: created.SourceEffectiveSpecDigest, CapabilityDigest: created.CapabilityDigest, ImageDigest: created.ImageDigest}}
	payload, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	return sandboxhostprotocol.Envelope{EnvelopeID: "envelope-restore", DeliveryID: "delivery-restore", HostID: "host-001", HostGeneration: 1, AssignmentID: "assignment-restore", LeaseEpoch: leased.Lease.Generation, FencingToken: 7, Tenant: "tenant", Principal: created.Owner, SandboxID: created.SourceSandboxID, ProcessID: "process-001", OperationID: "restore-op", OperationKind: GuestSnapshotRestoreOperationKind, EffectiveSpecDigest: created.SourceEffectiveSpecDigest, CapabilityDigest: created.CapabilityDigest, CanonicalRequestDigest: sandboxhostprotocol.Digest([]byte("restore-request")), Payload: payload, PayloadDigest: sandboxhostprotocol.Digest(payload), ExpiresAt: now.Add(time.Minute)}
}

func transferArchiveEnvelope(t *testing.T, now time.Time, request sandbox.CopyInRequest) sandboxhostprotocol.Envelope {
	t.Helper()
	return transferEnvelopeCommand(t, now, GuestTransferCommand{Version: GuestTransferOperationKind, ArchiveIn: &request})
}

func transferEnvelopeCommand(t *testing.T, now time.Time, command GuestTransferCommand) sandboxhostprotocol.Envelope {
	t.Helper()
	payload, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	return sandboxhostprotocol.Envelope{EnvelopeID: "envelope-001", DeliveryID: "delivery-001", HostID: "host-001", HostGeneration: 1, AssignmentID: "assignment-001", LeaseEpoch: 1, FencingToken: 7, Tenant: "tenant", Principal: "tenant:principal", SandboxID: "sandbox-001", ProcessID: "process-001", OperationID: "operation-001", OperationKind: GuestTransferOperationKind, CanonicalRequestDigest: sandboxhostprotocol.Digest([]byte("request")), Payload: payload, PayloadDigest: sandboxhostprotocol.Digest(payload), ExpiresAt: now.Add(time.Minute)}
}

func transferArchive(t *testing.T) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, header := range []*tar.Header{{Name: "results", Typeflag: tar.TypeDir}, {Name: "results/value.txt", Size: 5, Mode: 0o600, Typeflag: tar.TypeReg}} {
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := writer.Write([]byte("value")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func transferArtifact(id sandbox.ArtifactID, mediaType string, data []byte) sandbox.ArtifactRef {
	hash := sha256.Sum256(data)
	return sandbox.ArtifactRef{ID: id, MediaType: mediaType, SizeBytes: uint64(len(data)), Digest: sandbox.Digest("sha256:" + hex.EncodeToString(hash[:]))}
}

type transferSource struct {
	data  []byte
	opens int
}

func (source *transferSource) Open(_ context.Context, _ sandbox.ArtifactRef) (io.ReadCloser, error) {
	source.opens++
	return io.NopCloser(bytes.NewReader(source.data)), nil
}

type transferSink struct{}

func (transferSink) Put(_ context.Context, descriptor sandboxtransfer.ArtifactDescriptor, reader io.Reader) (sandbox.ArtifactRef, error) {
	_, err := io.ReadAll(reader)
	return descriptor.Reference, err
}

type snapshotSink struct {
	calls      int
	reaps      int
	restoreErr error
}

func (sink *snapshotSink) RestoreSnapshot(_ context.Context, _ sandboxresource.SnapshotManifest, reader io.Reader) error {
	sink.calls++
	_, err := io.ReadAll(reader)
	if err == nil && sink.restoreErr != nil {
		return sink.restoreErr
	}
	return err
}

func (sink *snapshotSink) ReapSnapshotRestore(_ context.Context, _ sandboxresource.SnapshotRestoreRequest) error {
	sink.reaps++
	return nil
}
