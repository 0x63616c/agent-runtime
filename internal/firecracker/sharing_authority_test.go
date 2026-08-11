package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostjournal"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/0x63616c/agent-runtime/internal/sandboxresource"
)

func TestMountExecutionAuthorityFencesSourceAndReapsLostAckShare(t *testing.T) {
	now := time.Date(2026, 8, 10, 3, 0, 0, 0, time.UTC)
	sourceClock, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	store, err := sandboxresource.Open(t.TempDir(), sandboxresource.Config{MaximumVolumeBytes: 1024, MaximumVolumeInodes: 32, MaximumSnapshotBytes: 1024}, bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.AcquireMount(context.Background(), sandboxresource.MountLease{ID: "mount-001", Owner: "tenant:alice", SandboxID: "sandbox-001", Source: sandboxresource.SourceIdentity{ExportID: "export-001", Device: 7, Inode: 11, Generation: 2}, Target: "/workspace/source", Mode: sandboxresource.ReadOnly, View: "frozen", LeaseExpiresAt: now.Add(time.Minute)}, now)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := sandboxhostjournal.Open(filepath.Join(t.TempDir(), "receipts.json"), 10)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	observer := &sharingObserver{identity: lease.Source}
	daemon := &sharingDaemon{}
	authority, err := NewMountExecutionAuthority(store, lease, "process-001", "mount-op-001", 7, sourceClock, observer, daemon, journal)
	if err != nil {
		t.Fatal(err)
	}
	envelope := mountAuthorityEnvelope(t, now, lease)
	if _, _, err := journal.Accept(envelope, sandboxhostprotocol.Digest([]byte("control-envelope"))); err != nil {
		t.Fatal(err)
	}
	if err := journal.StageStarted(envelope, []byte(`{"state":"started"}`)); err != nil {
		t.Fatal(err)
	}
	receipt, err := authority.Execute(context.Background(), envelope, func(context.Context, []byte) error { return errors.New("lost control ack") })
	if err == nil || receipt.MountID != lease.ID || daemon.attaches != 1 {
		t.Fatalf("Execute() = %#v, %v; attaches=%d", receipt, err, daemon.attaches)
	}
	if err := journal.StageResult(envelope, []byte(`{"state":"succeeded"}`)); err == nil {
		t.Fatal("StageResult accepted terminal before mount receipt acknowledgement")
	}
	replayed, err := authority.Execute(context.Background(), envelope, func(context.Context, []byte) error { return nil })
	if err != nil || replayed != receipt || daemon.attaches != 1 {
		t.Fatalf("replay = %#v, %v; attaches=%d", replayed, err, daemon.attaches)
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
	if err := authority.Reap(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	if daemon.detaches != 1 {
		t.Fatalf("detaches = %d, want 1", daemon.detaches)
	}
	if err := store.ValidateMountLease(context.Background(), lease.Owner, lease.ID, lease.Generation, lease.Source, now); !errors.Is(err, sandboxresource.ErrLeaseExpired) {
		t.Fatalf("lease after reaper = %v, want released", err)
	}
}

func TestMountExecutionAuthorityRefusesSourceReplacementBeforeDaemonAttach(t *testing.T) {
	now := time.Date(2026, 8, 10, 3, 0, 0, 0, time.UTC)
	sourceClock, _ := clock.NewFake(now)
	store, err := sandboxresource.Open(t.TempDir(), sandboxresource.Config{MaximumVolumeBytes: 1024, MaximumVolumeInodes: 32, MaximumSnapshotBytes: 1024}, bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.AcquireMount(context.Background(), sandboxresource.MountLease{ID: "mount-001", Owner: "tenant:alice", SandboxID: "sandbox-001", Source: sandboxresource.SourceIdentity{ExportID: "export-001", Device: 7, Inode: 11, Generation: 2}, Target: "/workspace/source", Mode: sandboxresource.ReadOnly, View: "frozen", LeaseExpiresAt: now.Add(time.Minute)}, now)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := sandboxhostjournal.Open(filepath.Join(t.TempDir(), "receipts.json"), 10)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	changed := lease.Source
	changed.Inode++
	daemon := &sharingDaemon{}
	authority, err := NewMountExecutionAuthority(store, lease, "process-001", "mount-op-001", 7, sourceClock, &sharingObserver{identity: changed}, daemon, journal)
	if err != nil {
		t.Fatal(err)
	}
	envelope := mountAuthorityEnvelope(t, now, lease)
	if _, _, err := journal.Accept(envelope, sandboxhostprotocol.Digest([]byte("control-envelope"))); err != nil {
		t.Fatal(err)
	}
	if err := journal.StageStarted(envelope, []byte(`{"state":"started"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Execute(context.Background(), envelope, func(context.Context, []byte) error { return nil }); !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("Execute() = %v, want unavailable", err)
	}
	if daemon.attaches != 0 {
		t.Fatalf("attaches = %d, want 0", daemon.attaches)
	}
}

func mountAuthorityEnvelope(t *testing.T, now time.Time, lease sandboxresource.MountLease) sandboxhostprotocol.Envelope {
	t.Helper()
	payload, err := json.Marshal(GuestMountCommand{Version: GuestMountOperationKind, MountID: lease.ID, Generation: lease.Generation, FencingToken: 7})
	if err != nil {
		t.Fatal(err)
	}
	return sandboxhostprotocol.Envelope{EnvelopeID: "mount-envelope-001", DeliveryID: "mount-delivery-001", HostID: "host-001", HostGeneration: 1, AssignmentID: "mount-assignment-001", LeaseEpoch: 1, FencingToken: 7, Tenant: "tenant", Principal: lease.Owner, SandboxID: lease.SandboxID, ProcessID: "process-001", OperationID: "mount-op-001", OperationKind: GuestMountOperationKind, CanonicalRequestDigest: sandboxhostprotocol.Digest([]byte("mount-request")), Payload: payload, PayloadDigest: sandboxhostprotocol.Digest(payload), ExpiresAt: now.Add(time.Minute)}
}

type sharingObserver struct {
	identity sandboxresource.SourceIdentity
}

func (observer *sharingObserver) ObserveMountSource(context.Context, string) (sandboxresource.SourceIdentity, error) {
	return observer.identity, nil
}

type sharingDaemon struct{ attaches, detaches int }

func (daemon *sharingDaemon) Attach(context.Context, JailedShareRequest) error {
	daemon.attaches++
	return nil
}
func (daemon *sharingDaemon) Detach(context.Context, JailedShareRequest) error {
	daemon.detaches++
	return nil
}
