package sandboxresource

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestStorePersistsGenerationFencedVolumeTombstoneAcrossRestart(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	store := openTestStore(t, directory)
	volume, err := store.CreateVolume(ctx, testVolume(now))
	if err != nil {
		t.Fatal(err)
	}
	attached, err := store.AttachVolume(ctx, volume.Owner, volume.ID, "sbx_01", ReadWrite, now.Add(time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	if attached.Attachment == nil || attached.Attachment.Generation != 1 {
		t.Fatalf("attachment = %#v", attached.Attachment)
	}
	if _, err := store.AttachVolume(ctx, volume.Owner, volume.ID, "sbx_02", ReadWrite, now.Add(time.Minute), now); !errors.Is(err, ErrAttached) {
		t.Fatalf("second attach = %v", err)
	}
	if _, err := store.DetachVolume(ctx, volume.Owner, volume.ID, 2, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale detach = %v", err)
	}
	if _, err := store.DetachVolume(ctx, volume.Owner, volume.ID, 1, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.TombstoneVolume(ctx, volume.Owner, volume.ID, 1, now); err != nil {
		t.Fatal(err)
	}

	reopened := openTestStore(t, directory)
	if _, err := reopened.GetVolume(ctx, volume.Owner, volume.ID); !errors.Is(err, ErrTombstoned) {
		t.Fatalf("tombstoned volume = %v", err)
	}
	if _, err := reopened.CreateVolume(ctx, testVolume(now)); !errors.Is(err, ErrConflict) {
		t.Fatalf("reused identity = %v", err)
	}
}

func TestStoreRequiresReconciliationBeforeReplacingAnExpiredVolumeLease(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	store := openTestStore(t, t.TempDir())
	volume, err := store.CreateVolume(ctx, testVolume(now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AttachVolume(ctx, volume.Owner, volume.ID, "sbx_01", ReadWrite, now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AttachVolume(ctx, volume.Owner, volume.ID, "sbx_02", ReadWrite, now.Add(2*time.Minute), now.Add(time.Minute)); !errors.Is(err, ErrAttached) {
		t.Fatalf("unreconciled expired attachment = %v", err)
	}
	reconciled, err := store.ReconcileExpiredAttachments(ctx, now.Add(time.Minute))
	if err != nil || len(reconciled) != 1 || reconciled[0].Attachment != nil {
		t.Fatalf("reconciled = %#v, %v", reconciled, err)
	}
	attached, err := store.AttachVolume(ctx, volume.Owner, volume.ID, "sbx_02", ReadWrite, now.Add(3*time.Minute), now.Add(time.Minute))
	if err != nil || attached.Attachment == nil || attached.Attachment.Generation != 2 {
		t.Fatalf("new generation = %#v, %v", attached.Attachment, err)
	}
}

func TestStorePinsMountSourceIdentityAndFailsClosedOnReplacement(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	store := openTestStore(t, t.TempDir())
	lease, err := store.AcquireMount(ctx, MountLease{ID: "mnt_01", Owner: "tenant:alice", SandboxID: "sbx_01", Source: SourceIdentity{ExportID: "export-workspace", Device: 7, Inode: 9, Generation: 3}, Target: "/workspace", Mode: ReadOnly, View: "frozen", LeaseExpiresAt: now.Add(time.Minute)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateMountLease(ctx, lease.Owner, lease.ID, lease.Generation, lease.Source, now); err != nil {
		t.Fatal(err)
	}
	replaced := lease.Source
	replaced.Inode++
	if err := store.ValidateMountLease(ctx, lease.Owner, lease.ID, lease.Generation, replaced, now); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("replaced source = %v", err)
	}
	if err := store.ValidateMountLease(ctx, lease.Owner, lease.ID, lease.Generation, lease.Source, now.Add(time.Minute)); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("expired lease = %v", err)
	}
}

func TestStoreEncryptsPublishesVerifiesAndTombstonesSnapshot(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	store := openTestStore(t, directory)
	manifest := testSnapshot(now)
	created, err := store.CreateSnapshot(ctx, manifest, strings.NewReader("quiesced disk bytes"), now)
	if err != nil {
		t.Fatal(err)
	}
	if created.PlaintextDigest == "" || created.CiphertextDigest == "" || created.PlaintextDigest == created.CiphertextDigest || created.SizeBytes != uint64(len("quiesced disk bytes")) {
		t.Fatalf("created snapshot = %#v", created)
	}
	reader, observed, err := store.OpenSnapshot(ctx, manifest.Owner, manifest.ID)
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(reader)
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err != nil || string(content) != "quiesced disk bytes" || observed.ID != manifest.ID {
		t.Fatalf("snapshot contents = %q, %#v, %v", content, observed, err)
	}
	leased, err := store.AcquireSnapshotLease(ctx, manifest.Owner, manifest.ID, "op_restore", now.Add(time.Minute), now)
	if err != nil || leased.Lease == nil || leased.Lease.Generation != 1 {
		t.Fatalf("snapshot lease = %#v, %v", leased.Lease, err)
	}
	if _, err := store.TombstoneSnapshot(ctx, manifest.Owner, manifest.ID, now.Add(time.Second)); !errors.Is(err, ErrAttached) {
		t.Fatalf("delete while leased = %v", err)
	}
	if _, err := store.ReleaseSnapshotLease(ctx, manifest.Owner, manifest.ID, leased.Lease.Generation); err != nil {
		t.Fatal(err)
	}
	if _, err := store.TombstoneSnapshot(ctx, manifest.Owner, manifest.ID, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.OpenSnapshot(ctx, manifest.Owner, manifest.ID); !errors.Is(err, ErrTombstoned) {
		t.Fatalf("tombstoned snapshot = %v", err)
	}
	if _, err := store.CreateSnapshot(ctx, manifest, strings.NewReader("new bytes"), now); !errors.Is(err, ErrConflict) {
		t.Fatalf("reused snapshot = %v", err)
	}
}

func TestStoreRestoresOnlyTheExactLeasedPolicyCeiling(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	store, err := Open(t.TempDir(), Config{MaximumVolumeBytes: 1024, MaximumVolumeInodes: 128, MaximumSnapshotBytes: 1024}, bytesOf(7, 32))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := store.CreateSnapshot(context.Background(), testSnapshot(now), strings.NewReader("quiesced disk bytes"), now)
	if err != nil {
		t.Fatal(err)
	}
	leased, err := store.AcquireSnapshotLease(context.Background(), manifest.Owner, manifest.ID, "restore_01", now.Add(time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	sink := &recordingRestoreSink{}
	request := SnapshotRestoreRequest{Owner: manifest.Owner, ID: manifest.ID, Holder: "restore_01", Generation: leased.Lease.Generation, SandboxID: manifest.SourceSandboxID, EffectiveSpecDigest: manifest.SourceEffectiveSpecDigest, CapabilityDigest: manifest.CapabilityDigest, ImageDigest: manifest.ImageDigest}
	if _, err := store.RestoreSnapshot(context.Background(), request, sink, now); err != nil {
		t.Fatalf("RestoreSnapshot() error = %v", err)
	}
	if got := string(sink.bytes); got != "quiesced disk bytes" {
		t.Fatalf("restored = %q", got)
	}
	request.CapabilityDigest = "sha256:widened"
	if _, err := store.RestoreSnapshot(context.Background(), request, sink, now); !errors.Is(err, ErrSnapshotDenied) {
		t.Fatalf("RestoreSnapshot() widened ceiling = %v", err)
	}
}

type recordingRestoreSink struct{ bytes []byte }

func (sink *recordingRestoreSink) RestoreSnapshot(_ context.Context, _ SnapshotManifest, reader io.Reader) error {
	value, err := io.ReadAll(reader)
	sink.bytes = append([]byte(nil), value...)
	return err
}

func TestStoreDeniesTaintedSnapshotWithoutBoundAttestation(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	store := openTestStore(t, t.TempDir())
	manifest := testSnapshot(now)
	manifest.Taint = Taint{KnownSecretPath: true, Provenance: []TaintProvenance{{OperationID: "op_01", Class: "sdk-secret/v1"}}}
	if _, err := store.CreateSnapshot(context.Background(), manifest, strings.NewReader("disk bytes"), now); !errors.Is(err, ErrSnapshotDenied) {
		t.Fatalf("unattested tainted snapshot = %v", err)
	}
	manifest.RiskAttestation = "operator:alice:op_01"
	if _, err := store.CreateSnapshot(context.Background(), manifest, strings.NewReader("disk bytes"), now); err != nil {
		t.Fatal(err)
	}
}

func TestFileDataPlaneRejectsCiphertextTampering(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	store := openTestStore(t, directory)
	manifest, err := store.CreateSnapshot(context.Background(), testSnapshot(now), strings.NewReader("disk bytes"), now)
	if err != nil {
		t.Fatal(err)
	}
	filename := store.payloads.payloadPath(manifest.ID)
	if err := osWriteByte(filename); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.OpenSnapshot(context.Background(), manifest.Owner, manifest.ID); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampered snapshot = %v", err)
	}
}

func openTestStore(t *testing.T, directory string) *Store {
	t.Helper()
	store, err := Open(directory, Config{MaximumVolumeBytes: 1024, MaximumVolumeInodes: 128, MaximumSnapshotBytes: 1024}, bytesOf(7, 32))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testVolume(now time.Time) VolumeManifest {
	return VolumeManifest{Owner: "tenant:alice", ID: "vol_01", Format: "ext4", Encryption: "aes-gcm", Integrity: "sha256", SizeBytes: 1024, Inodes: 8, CreatedAt: now, RetentionExpiresAt: now.Add(time.Hour)}
}
func testSnapshot(now time.Time) SnapshotManifest {
	return SnapshotManifest{Owner: "tenant:alice", ID: "snap_01", SourceSandboxID: "sbx_01", SourceEffectiveSpecDigest: "sha256:effective", CapabilityDigest: "sha256:capabilities", ImageDigest: "sha256:image", RequestID: "op_snapshot", Format: "ext4-overlay", Encryption: "aes-256-gcm", Integrity: "sha256", RetentionExpiresAt: now.Add(time.Hour)}
}
func bytesOf(value byte, length int) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = value
	}
	return result
}

func osWriteByte(filename string) error {
	content, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	content[len(content)-1] ^= 0xff
	return os.WriteFile(filename, content, 0o600)
}
