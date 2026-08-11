// Package sandboxresource owns durable, principal-scoped volume, snapshot and
// mount-lease manifests.  It deliberately does not make an adapter capability
// claim: a host must separately prove the corresponding data plane.
package sandboxresource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

var (
	// ErrAttached means a volume still has a live or unreconciled attachment.
	ErrAttached = errors.New("sandbox resource is attached")
	// ErrConflict means a durable identity or generation was superseded.
	ErrConflict = errors.New("sandbox resource conflict")
	// ErrIntegrity means persisted content or its declared identity did not verify.
	ErrIntegrity = errors.New("sandbox resource integrity check failed")
	// ErrLeaseExpired means a caller tried to use an expired finite lease.
	ErrLeaseExpired = errors.New("sandbox resource lease expired")
	// ErrNotFound means an owner-scoped resource is absent.
	ErrNotFound = errors.New("sandbox resource not found")
	// ErrSnapshotDenied means taint policy did not permit a snapshot.
	ErrSnapshotDenied = errors.New("sandbox snapshot denied by taint policy")
	// ErrTombstoned means an identity is retained but can never be reused.
	ErrTombstoned = errors.New("sandbox resource is tombstoned")
)

const (
	volumeSchema   = "sandbox.volume/v1"
	snapshotSchema = "sandbox.snapshot/v1"
	stateFilename  = "resource-manifests.json"
)

// AttachmentMode declares the authority granted to an attached named volume.
type AttachmentMode string

const (
	// ReadOnly permits a coherent read-only attachment when a future host profile proves it.
	ReadOnly AttachmentMode = "read-only"
	// ReadWrite is exclusive and must always be generation fenced.
	ReadWrite AttachmentMode = "read-write"
)

// Attachment records the single current volume attachment and its finite fence.
type Attachment struct {
	SandboxID      string
	Mode           AttachmentMode
	LeaseExpiresAt time.Time
	Generation     uint64
}

// TaintProvenance records safe known-secret exposure metadata, never a value or name.
type TaintProvenance struct {
	OperationID string
	Class       string
}

// Taint records only SDK-known secret exposure and observable unknown paths.
type Taint struct {
	KnownSecretPath bool
	UnknownPath     bool
	Provenance      []TaintProvenance
}

// VolumeManifest is the durable authority record for one principal-owned volume.
type VolumeManifest struct {
	SchemaVersion      string
	Owner              string
	ID                 string
	Format             string
	Encryption         string
	Integrity          string
	SizeBytes          uint64
	Inodes             uint64
	CreatedAt          time.Time
	UpdatedAt          time.Time
	RetentionExpiresAt time.Time
	Generation         uint64
	Attachment         *Attachment
	Taint              Taint
	TombstonedAt       time.Time
}

// SourceIdentity is the descriptor-first identity a future mount data plane must pin.
// It intentionally contains no resolvable host pathname.
type SourceIdentity struct {
	ExportID   string
	Device     uint64
	Inode      uint64
	Generation uint64
}

// MountLease binds a descriptor identity to one sandbox for a finite period.
// It is an authority contract, not evidence that a sharing daemon exists.
type MountLease struct {
	ID             string
	Owner          string
	SandboxID      string
	Source         SourceIdentity
	Target         string
	Mode           AttachmentMode
	View           string
	Generation     uint64
	LeaseExpiresAt time.Time
	ReleasedAt     time.Time
}

// SnapshotManifest is a durable disk-only snapshot record.  Content lives in
// the encrypted data plane and is referred to only by immutable digests.
type SnapshotManifest struct {
	SchemaVersion             string
	Owner                     string
	ID                        string
	SourceSandboxID           string
	SourceEffectiveSpecDigest string
	CapabilityDigest          string
	ImageDigest               string
	RequestID                 string
	Format                    string
	Encryption                string
	Integrity                 string
	PlaintextDigest           string
	CiphertextDigest          string
	SizeBytes                 uint64
	CreatedAt                 time.Time
	RetentionExpiresAt        time.Time
	Taint                     Taint
	RiskAttestation           string
	Lease                     *SnapshotLease
	TombstonedAt              time.Time
}

// SnapshotLease serializes restore and delete against one snapshot generation.
type SnapshotLease struct {
	Holder         string
	Generation     uint64
	LeaseExpiresAt time.Time
}

// SnapshotRestoreRequest binds a restore sink to an exact snapshot lease and
// an admitted restore ceiling. It never permits a snapshot to widen image,
// policy, or capability authority.
type SnapshotRestoreRequest struct {
	Owner, ID, Holder                                  string
	Generation                                         uint64
	SandboxID                                          string
	EffectiveSpecDigest, CapabilityDigest, ImageDigest string
}

// SnapshotRestoreSink owns the destination data plane. Store supplies only a
// verified bounded plaintext reader and never chooses a guest path or mount.
type SnapshotRestoreSink interface {
	RestoreSnapshot(context.Context, SnapshotManifest, io.Reader) error
}

// Config bounds a resource authority instance.  All limits must be explicit.
type Config struct {
	MaximumVolumeBytes   uint64
	MaximumVolumeInodes  uint64
	MaximumSnapshotBytes uint64
}

// Store persists manifests atomically to a private directory.  Its data plane
// is usable for encrypted snapshot artifacts, but Store itself is deliberately
// not connected to a sandbox adapter or a capability descriptor.
type Store struct {
	mu       sync.Mutex
	root     string
	config   Config
	state    persistentState
	payloads *FileDataPlane
}

type persistentState struct {
	Volumes map[string]VolumeManifest   `json:"volumes"`
	Mounts  map[string]MountLease       `json:"mounts"`
	Snaps   map[string]SnapshotManifest `json:"snapshots"`
}

// Open creates or recovers a private manifest store rooted at directory.
func Open(directory string, config Config, dataKey []byte) (*Store, error) {
	if directory == "" || !validConfig(config) || len(dataKey) != 32 {
		return nil, fmt.Errorf("open sandbox resource store: invalid directory, limits, or data key")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("open sandbox resource store: create private directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("open sandbox resource store: protect private directory: %w", err)
	}
	state, err := readState(filepath.Join(directory, stateFilename))
	if err != nil {
		return nil, err
	}
	if !validState(state, config) {
		return nil, fmt.Errorf("open sandbox resource store: %w", ErrIntegrity)
	}
	payloads, err := OpenFileDataPlane(filepath.Join(directory, "snapshots"), dataKey, config.MaximumSnapshotBytes)
	if err != nil {
		return nil, err
	}
	return &Store{root: directory, config: config, state: state, payloads: payloads}, nil
}

// CreateVolume writes one immutable volume identity.  Tombstoned IDs are never reused.
func (store *Store) CreateVolume(ctx context.Context, volume VolumeManifest) (VolumeManifest, error) {
	if err := contextErr(ctx); err != nil {
		return VolumeManifest{}, err
	}
	if store == nil || !validNewVolume(volume, store.config) {
		return VolumeManifest{}, fmt.Errorf("create sandbox volume: %w", ErrConflict)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.state.Volumes[volume.ID]; exists {
		return VolumeManifest{}, fmt.Errorf("create sandbox volume: %w", ErrConflict)
	}
	volume = copyVolume(volume)
	volume.SchemaVersion = volumeSchema
	volume.CreatedAt = volume.CreatedAt.UTC()
	volume.UpdatedAt = volume.CreatedAt
	volume.Generation = 0
	store.state.Volumes[volume.ID] = volume
	if err := store.saveLocked(); err != nil {
		delete(store.state.Volumes, volume.ID)
		return VolumeManifest{}, err
	}
	return copyVolume(volume), nil
}

// GetVolume returns a defensive principal-scoped manifest snapshot.
func (store *Store) GetVolume(ctx context.Context, owner, id string) (VolumeManifest, error) {
	if err := contextErr(ctx); err != nil {
		return VolumeManifest{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	volume, ok := store.state.Volumes[id]
	if !ok || volume.Owner != owner {
		return VolumeManifest{}, ErrNotFound
	}
	if !volume.TombstonedAt.IsZero() {
		return VolumeManifest{}, ErrTombstoned
	}
	return copyVolume(volume), nil
}

// AttachVolume atomically grants one exclusive read-write generation lease.
func (store *Store) AttachVolume(ctx context.Context, owner, id, sandboxID string, mode AttachmentMode, leaseExpiresAt, now time.Time) (VolumeManifest, error) {
	if err := contextErr(ctx); err != nil {
		return VolumeManifest{}, err
	}
	if store == nil || !validOwnerID(owner, id) || sandboxID == "" || !validAttachmentMode(mode) || !validFutureLease(leaseExpiresAt, now) {
		return VolumeManifest{}, fmt.Errorf("attach sandbox volume: %w", ErrConflict)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	volume, ok := store.state.Volumes[id]
	if !ok || volume.Owner != owner {
		return VolumeManifest{}, ErrNotFound
	}
	if !volume.TombstonedAt.IsZero() {
		return VolumeManifest{}, ErrTombstoned
	}
	if volume.Attachment != nil {
		return VolumeManifest{}, ErrAttached
	}
	volume.Generation++
	volume.Attachment = &Attachment{SandboxID: sandboxID, Mode: mode, Generation: volume.Generation, LeaseExpiresAt: leaseExpiresAt.UTC()}
	volume.UpdatedAt = now.UTC()
	store.state.Volumes[id] = volume
	if err := store.saveLocked(); err != nil {
		return VolumeManifest{}, err
	}
	return copyVolume(volume), nil
}

// DetachVolume releases only the exact current attachment generation.
func (store *Store) DetachVolume(ctx context.Context, owner, id string, generation uint64, now time.Time) (VolumeManifest, error) {
	if err := contextErr(ctx); err != nil {
		return VolumeManifest{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	volume, ok := store.state.Volumes[id]
	if !ok || volume.Owner != owner {
		return VolumeManifest{}, ErrNotFound
	}
	if volume.Attachment == nil || generation == 0 || volume.Attachment.Generation != generation {
		return VolumeManifest{}, fmt.Errorf("detach sandbox volume: %w", ErrConflict)
	}
	volume.Attachment = nil
	volume.UpdatedAt = now.UTC()
	store.state.Volumes[id] = volume
	if err := store.saveLocked(); err != nil {
		return VolumeManifest{}, err
	}
	return copyVolume(volume), nil
}

// ReconcileExpiredAttachments fences abandoned attachments before a new attach may proceed.
func (store *Store) ReconcileExpiredAttachments(ctx context.Context, now time.Time) ([]VolumeManifest, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	var reconciled []VolumeManifest
	for id, volume := range store.state.Volumes {
		if volume.Attachment == nil || volume.Attachment.LeaseExpiresAt.After(now) {
			continue
		}
		volume.Attachment = nil
		volume.UpdatedAt = now.UTC()
		store.state.Volumes[id] = volume
		reconciled = append(reconciled, copyVolume(volume))
	}
	if len(reconciled) > 0 {
		if err := store.saveLocked(); err != nil {
			return nil, err
		}
	}
	sort.Slice(reconciled, func(left, right int) bool { return reconciled[left].ID < reconciled[right].ID })
	return reconciled, nil
}

// TombstoneVolume irreversibly prevents ID reuse after the exact detached generation.
func (store *Store) TombstoneVolume(ctx context.Context, owner, id string, generation uint64, now time.Time) (VolumeManifest, error) {
	if err := contextErr(ctx); err != nil {
		return VolumeManifest{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	volume, ok := store.state.Volumes[id]
	if !ok || volume.Owner != owner {
		return VolumeManifest{}, ErrNotFound
	}
	if volume.Attachment != nil {
		return VolumeManifest{}, ErrAttached
	}
	if volume.Generation != generation {
		return VolumeManifest{}, fmt.Errorf("tombstone sandbox volume: %w", ErrConflict)
	}
	if !volume.TombstonedAt.IsZero() {
		return VolumeManifest{}, ErrTombstoned
	}
	volume.TombstonedAt = now.UTC()
	volume.UpdatedAt = now.UTC()
	store.state.Volumes[id] = volume
	if err := store.saveLocked(); err != nil {
		return VolumeManifest{}, err
	}
	return copyVolume(volume), nil
}

// MarkVolumeTainted preserves safe exposure provenance through attachment and tombstone.
func (store *Store) MarkVolumeTainted(ctx context.Context, owner, id string, taint Taint, now time.Time) (VolumeManifest, error) {
	if err := contextErr(ctx); err != nil {
		return VolumeManifest{}, err
	}
	if !validTaint(taint) {
		return VolumeManifest{}, fmt.Errorf("taint sandbox volume: %w", ErrConflict)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	volume, ok := store.state.Volumes[id]
	if !ok || volume.Owner != owner {
		return VolumeManifest{}, ErrNotFound
	}
	volume.Taint = mergeTaint(volume.Taint, taint)
	volume.UpdatedAt = now.UTC()
	store.state.Volumes[id] = volume
	if err := store.saveLocked(); err != nil {
		return VolumeManifest{}, err
	}
	return copyVolume(volume), nil
}

// AcquireMount records the source identity that a sharing daemon must recheck.
// No call here makes a mount available to a sandbox.
func (store *Store) AcquireMount(ctx context.Context, lease MountLease, now time.Time) (MountLease, error) {
	if err := contextErr(ctx); err != nil {
		return MountLease{}, err
	}
	if store == nil || !validMountLease(lease, now) {
		return MountLease{}, fmt.Errorf("acquire sandbox mount lease: %w", ErrConflict)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if prior, exists := store.state.Mounts[lease.ID]; exists {
		if prior.ReleasedAt.IsZero() {
			return MountLease{}, fmt.Errorf("acquire sandbox mount lease: %w", ErrConflict)
		}
		lease.Generation = prior.Generation
	}
	if lease.Generation == ^uint64(0) {
		return MountLease{}, fmt.Errorf("acquire sandbox mount lease: %w", ErrConflict)
	}
	lease.Generation++
	lease.LeaseExpiresAt = lease.LeaseExpiresAt.UTC()
	store.state.Mounts[lease.ID] = lease
	if err := store.saveLocked(); err != nil {
		return MountLease{}, err
	}
	return lease, nil
}

// ValidateMountLease proves that the source identity supplied by a host still matches its lease.
func (store *Store) ValidateMountLease(ctx context.Context, owner, id string, generation uint64, observed SourceIdentity, now time.Time) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lease, ok := store.state.Mounts[id]
	if !ok || lease.Owner != owner {
		return ErrNotFound
	}
	if lease.Generation != generation || !lease.ReleasedAt.IsZero() || !lease.LeaseExpiresAt.After(now) {
		return ErrLeaseExpired
	}
	if lease.Source != observed {
		return fmt.Errorf("validate sandbox mount source: %w", ErrIntegrity)
	}
	return nil
}

// ReleaseMount releases only the exact lease generation.
func (store *Store) ReleaseMount(ctx context.Context, owner, id string, generation uint64, now time.Time) (MountLease, error) {
	if err := contextErr(ctx); err != nil {
		return MountLease{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lease, ok := store.state.Mounts[id]
	if !ok || lease.Owner != owner {
		return MountLease{}, ErrNotFound
	}
	if lease.Generation != generation || !lease.ReleasedAt.IsZero() {
		return MountLease{}, fmt.Errorf("release sandbox mount lease: %w", ErrConflict)
	}
	lease.ReleasedAt = now.UTC()
	store.state.Mounts[id] = lease
	if err := store.saveLocked(); err != nil {
		return MountLease{}, err
	}
	return lease, nil
}

// CreateSnapshot stages, encrypts, verifies and atomically publishes disk-only content before its manifest.
func (store *Store) CreateSnapshot(ctx context.Context, manifest SnapshotManifest, content io.Reader, now time.Time) (SnapshotManifest, error) {
	if err := contextErr(ctx); err != nil {
		return SnapshotManifest{}, err
	}
	if store == nil || content == nil || !validNewSnapshot(manifest, store.config, now) {
		return SnapshotManifest{}, fmt.Errorf("create sandbox snapshot: %w", ErrConflict)
	}
	if (manifest.Taint.KnownSecretPath || manifest.Taint.UnknownPath) && manifest.RiskAttestation == "" {
		return SnapshotManifest{}, ErrSnapshotDenied
	}
	stage, err := store.payloads.Stage(ctx, manifest.ID, content)
	if err != nil {
		return SnapshotManifest{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = store.payloads.Discard(stage)
		}
	}()
	manifest = copySnapshot(manifest)
	manifest.SchemaVersion = snapshotSchema
	manifest.CreatedAt = now.UTC()
	manifest.PlaintextDigest = stage.PlaintextDigest
	manifest.CiphertextDigest = stage.CiphertextDigest
	manifest.SizeBytes = stage.SizeBytes
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.state.Snaps[manifest.ID]; exists {
		return SnapshotManifest{}, fmt.Errorf("create sandbox snapshot: %w", ErrConflict)
	}
	if err := store.payloads.Publish(stage); err != nil {
		return SnapshotManifest{}, err
	}
	store.state.Snaps[manifest.ID] = manifest
	if err := store.saveLocked(); err != nil {
		delete(store.state.Snaps, manifest.ID)
		_ = store.payloads.Remove(manifest.ID)
		return SnapshotManifest{}, err
	}
	cleanup = false
	return copySnapshot(manifest), nil
}

// OpenSnapshot returns a verified plaintext reader only to the owning principal.
func (store *Store) OpenSnapshot(ctx context.Context, owner, id string) (io.ReadCloser, SnapshotManifest, error) {
	if err := contextErr(ctx); err != nil {
		return nil, SnapshotManifest{}, err
	}
	store.mu.Lock()
	manifest, ok := store.state.Snaps[id]
	store.mu.Unlock()
	if !ok || manifest.Owner != owner {
		return nil, SnapshotManifest{}, ErrNotFound
	}
	if !manifest.TombstonedAt.IsZero() {
		return nil, SnapshotManifest{}, ErrTombstoned
	}
	reader, err := store.payloads.Open(ctx, id, manifest)
	if err != nil {
		return nil, SnapshotManifest{}, err
	}
	return reader, copySnapshot(manifest), nil
}

// AcquireSnapshotLease serializes a restore or delete operation using a finite fence.
func (store *Store) AcquireSnapshotLease(ctx context.Context, owner, id, holder string, leaseExpiresAt, now time.Time) (SnapshotManifest, error) {
	if err := contextErr(ctx); err != nil {
		return SnapshotManifest{}, err
	}
	if holder == "" || !validFutureLease(leaseExpiresAt, now) {
		return SnapshotManifest{}, fmt.Errorf("acquire snapshot lease: %w", ErrConflict)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	manifest, ok := store.state.Snaps[id]
	if !ok || manifest.Owner != owner {
		return SnapshotManifest{}, ErrNotFound
	}
	if !manifest.TombstonedAt.IsZero() {
		return SnapshotManifest{}, ErrTombstoned
	}
	if manifest.Lease != nil && manifest.Lease.LeaseExpiresAt.After(now) {
		return SnapshotManifest{}, ErrAttached
	}
	generation := uint64(1)
	if manifest.Lease != nil {
		if manifest.Lease.Generation == ^uint64(0) {
			return SnapshotManifest{}, fmt.Errorf("acquire snapshot lease: %w", ErrConflict)
		}
		generation = manifest.Lease.Generation + 1
	}
	manifest.Lease = &SnapshotLease{Holder: holder, Generation: generation, LeaseExpiresAt: leaseExpiresAt.UTC()}
	store.state.Snaps[id] = manifest
	if err := store.saveLocked(); err != nil {
		return SnapshotManifest{}, err
	}
	return copySnapshot(manifest), nil
}

// ReleaseSnapshotLease releases only the exact restore/delete generation.
func (store *Store) ReleaseSnapshotLease(ctx context.Context, owner, id string, generation uint64) (SnapshotManifest, error) {
	if err := contextErr(ctx); err != nil {
		return SnapshotManifest{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	manifest, ok := store.state.Snaps[id]
	if !ok || manifest.Owner != owner {
		return SnapshotManifest{}, ErrNotFound
	}
	if manifest.Lease == nil || manifest.Lease.Generation != generation {
		return SnapshotManifest{}, fmt.Errorf("release snapshot lease: %w", ErrConflict)
	}
	manifest.Lease = nil
	store.state.Snaps[id] = manifest
	if err := store.saveLocked(); err != nil {
		return SnapshotManifest{}, err
	}
	return copySnapshot(manifest), nil
}

// RestoreSnapshot opens exactly one leased, verified disk snapshot and hands
// it to an admitted sink. The lease remains held on sink failure so reaper
// reconciliation, rather than a racing delete, remains authoritative.
func (store *Store) RestoreSnapshot(ctx context.Context, request SnapshotRestoreRequest, sink SnapshotRestoreSink, now time.Time) (SnapshotManifest, error) {
	if err := contextErr(ctx); err != nil {
		return SnapshotManifest{}, err
	}
	if store == nil || sink == nil || request.Owner == "" || request.ID == "" || request.Holder == "" || request.Generation == 0 || request.SandboxID == "" || request.EffectiveSpecDigest == "" || request.CapabilityDigest == "" || request.ImageDigest == "" {
		return SnapshotManifest{}, fmt.Errorf("restore sandbox snapshot: %w", ErrConflict)
	}
	store.mu.Lock()
	manifest, ok := store.state.Snaps[request.ID]
	store.mu.Unlock()
	if !ok || manifest.Owner != request.Owner {
		return SnapshotManifest{}, ErrNotFound
	}
	if !manifest.TombstonedAt.IsZero() {
		return SnapshotManifest{}, ErrTombstoned
	}
	if manifest.Lease == nil || manifest.Lease.Holder != request.Holder || manifest.Lease.Generation != request.Generation || !manifest.Lease.LeaseExpiresAt.After(now) {
		return SnapshotManifest{}, fmt.Errorf("restore sandbox snapshot: %w", ErrConflict)
	}
	if manifest.SourceSandboxID != request.SandboxID || manifest.SourceEffectiveSpecDigest != request.EffectiveSpecDigest || manifest.CapabilityDigest != request.CapabilityDigest || manifest.ImageDigest != request.ImageDigest {
		return SnapshotManifest{}, fmt.Errorf("restore sandbox snapshot: %w", ErrSnapshotDenied)
	}
	reader, err := store.payloads.Open(ctx, request.ID, manifest)
	if err != nil {
		return SnapshotManifest{}, err
	}
	defer reader.Close()
	if err := sink.RestoreSnapshot(ctx, copySnapshot(manifest), reader); err != nil {
		return SnapshotManifest{}, fmt.Errorf("restore sandbox snapshot: sink unavailable")
	}
	if err := contextErr(ctx); err != nil {
		return SnapshotManifest{}, err
	}
	return copySnapshot(manifest), nil
}

// TombstoneSnapshot removes ciphertext and permanently retains the identity.
func (store *Store) TombstoneSnapshot(ctx context.Context, owner, id string, now time.Time) (SnapshotManifest, error) {
	if err := contextErr(ctx); err != nil {
		return SnapshotManifest{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	manifest, ok := store.state.Snaps[id]
	if !ok || manifest.Owner != owner {
		return SnapshotManifest{}, ErrNotFound
	}
	if !manifest.TombstonedAt.IsZero() {
		return SnapshotManifest{}, ErrTombstoned
	}
	if manifest.Lease != nil {
		return SnapshotManifest{}, ErrAttached
	}
	if err := store.payloads.Remove(id); err != nil && !errors.Is(err, os.ErrNotExist) {
		return SnapshotManifest{}, err
	}
	manifest.TombstonedAt = now.UTC()
	store.state.Snaps[id] = manifest
	if err := store.saveLocked(); err != nil {
		return SnapshotManifest{}, err
	}
	return copySnapshot(manifest), nil
}

func (store *Store) saveLocked() error {
	if err := writeState(filepath.Join(store.root, stateFilename), store.state); err != nil {
		return fmt.Errorf("persist sandbox resource manifests: %w", err)
	}
	return nil
}

func validConfig(config Config) bool {
	return config.MaximumVolumeBytes > 0 && config.MaximumVolumeInodes > 0 && config.MaximumSnapshotBytes > 0 && config.MaximumSnapshotBytes <= uint64(^uint(0)>>1)-1
}

func validNewVolume(volume VolumeManifest, config Config) bool {
	return validOwnerID(volume.Owner, volume.ID) && volume.CreatedAt.Equal(volume.CreatedAt.UTC()) && !volume.CreatedAt.IsZero() && volume.RetentionExpiresAt.After(volume.CreatedAt) && volume.SizeBytes > 0 && volume.SizeBytes <= config.MaximumVolumeBytes && volume.Inodes > 0 && volume.Inodes <= config.MaximumVolumeInodes && volume.Format != "" && volume.Encryption != "" && volume.Integrity != "" && validTaint(volume.Taint)
}

func validNewSnapshot(manifest SnapshotManifest, config Config, now time.Time) bool {
	return validOwnerID(manifest.Owner, manifest.ID) && manifest.SourceSandboxID != "" && manifest.SourceEffectiveSpecDigest != "" && manifest.CapabilityDigest != "" && manifest.ImageDigest != "" && manifest.RequestID != "" && manifest.Format != "" && manifest.Encryption != "" && manifest.Integrity != "" && manifest.RetentionExpiresAt.After(now) && config.MaximumSnapshotBytes > 0 && validTaint(manifest.Taint)
}

func validOwnerID(owner, id string) bool {
	return owner != "" && len(owner) <= 512 && validResourceID(id)
}
func validResourceID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, character := range id {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '-') {
			return false
		}
	}
	return true
}
func validAttachmentMode(mode AttachmentMode) bool { return mode == ReadOnly || mode == ReadWrite }
func validFutureLease(expiresAt, now time.Time) bool {
	return !expiresAt.IsZero() && expiresAt.After(now) && expiresAt.Sub(now) <= time.Hour
}
func validMountLease(lease MountLease, now time.Time) bool {
	return validOwnerID(lease.Owner, lease.ID) && lease.SandboxID != "" && validSourceIdentity(lease.Source) && lease.Target != "" && validAttachmentMode(lease.Mode) && (lease.View == "live" || lease.View == "frozen") && validFutureLease(lease.LeaseExpiresAt, now)
}
func validSourceIdentity(identity SourceIdentity) bool {
	return identity.ExportID != "" && identity.Device != 0 && identity.Inode != 0 && identity.Generation != 0
}
func validTaint(taint Taint) bool {
	if len(taint.Provenance) > 64 {
		return false
	}
	for _, item := range taint.Provenance {
		if item.OperationID == "" || item.Class == "" || len(item.OperationID) > 128 || len(item.Class) > 128 {
			return false
		}
	}
	return true
}

func mergeTaint(left, right Taint) Taint {
	merged := Taint{KnownSecretPath: left.KnownSecretPath || right.KnownSecretPath, UnknownPath: left.UnknownPath || right.UnknownPath, Provenance: append(append([]TaintProvenance(nil), left.Provenance...), right.Provenance...)}
	sort.Slice(merged.Provenance, func(i, j int) bool {
		return merged.Provenance[i].OperationID+"\x00"+merged.Provenance[i].Class < merged.Provenance[j].OperationID+"\x00"+merged.Provenance[j].Class
	})
	return merged
}

func copyVolume(value VolumeManifest) VolumeManifest {
	value.Attachment = copyAttachment(value.Attachment)
	value.Taint = copyTaint(value.Taint)
	return value
}
func copyAttachment(value *Attachment) *Attachment {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}
func copyTaint(value Taint) Taint {
	value.Provenance = append([]TaintProvenance(nil), value.Provenance...)
	return value
}
func copySnapshot(value SnapshotManifest) SnapshotManifest {
	value.Taint = copyTaint(value.Taint)
	if value.Lease != nil {
		copied := *value.Lease
		value.Lease = &copied
	}
	return value
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("sandbox resource context is required")
	}
	return ctx.Err()
}

func readState(filename string) (persistentState, error) {
	state := persistentState{Volumes: map[string]VolumeManifest{}, Mounts: map[string]MountLease{}, Snaps: map[string]SnapshotManifest{}}
	content, err := os.ReadFile(filename)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return persistentState{}, fmt.Errorf("read sandbox resource manifests: %w", err)
	}
	if err := json.Unmarshal(content, &state); err != nil {
		return persistentState{}, fmt.Errorf("decode sandbox resource manifests: %w", err)
	}
	if state.Volumes == nil {
		state.Volumes = map[string]VolumeManifest{}
	}
	if state.Mounts == nil {
		state.Mounts = map[string]MountLease{}
	}
	if state.Snaps == nil {
		state.Snaps = map[string]SnapshotManifest{}
	}
	return state, nil
}

func validState(state persistentState, config Config) bool {
	for id, volume := range state.Volumes {
		if id != volume.ID || volume.SchemaVersion != volumeSchema || !validNewVolume(volume, config) {
			return false
		}
		if volume.Attachment != nil && (volume.Attachment.Generation != volume.Generation || volume.Attachment.SandboxID == "" || !validAttachmentMode(volume.Attachment.Mode) || volume.Attachment.LeaseExpiresAt.IsZero()) {
			return false
		}
	}
	for id, lease := range state.Mounts {
		if id != lease.ID || !validOwnerID(lease.Owner, lease.ID) || !validSourceIdentity(lease.Source) || lease.Generation == 0 {
			return false
		}
	}
	for id, snapshot := range state.Snaps {
		if id != snapshot.ID || snapshot.SchemaVersion != snapshotSchema || !validOwnerID(snapshot.Owner, snapshot.ID) || snapshot.SourceSandboxID == "" || snapshot.PlaintextDigest == "" || snapshot.CiphertextDigest == "" || snapshot.SizeBytes > config.MaximumSnapshotBytes || !validTaint(snapshot.Taint) {
			return false
		}
		if snapshot.Lease != nil && (snapshot.Lease.Holder == "" || snapshot.Lease.Generation == 0 || snapshot.Lease.LeaseExpiresAt.IsZero()) {
			return false
		}
	}
	return true
}

func writeState(filename string, state persistentState) error {
	content, err := json.Marshal(state)
	if err != nil {
		return err
	}
	directory := filepath.Dir(filename)
	file, err := os.CreateTemp(directory, ".resource-manifests-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, filename); err != nil {
		return err
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryFile.Close()
	return directoryFile.Sync()
}

// StagedSnapshot is an opaque encrypted temporary payload awaiting atomic publish.
type StagedSnapshot struct {
	id, path                          string
	PlaintextDigest, CiphertextDigest string
	SizeBytes                         uint64
}

// FileDataPlane stores bounded encrypted snapshot payloads in a private directory.
type FileDataPlane struct {
	root         string
	key          []byte
	maximumBytes uint64
}

// OpenFileDataPlane opens one private encrypted snapshot payload store.
func OpenFileDataPlane(directory string, key []byte, maximumBytes uint64) (*FileDataPlane, error) {
	if directory == "" || len(key) != 32 || maximumBytes == 0 {
		return nil, fmt.Errorf("open snapshot data plane: invalid directory, key, or byte limit")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("open snapshot data plane: create private directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("open snapshot data plane: protect private directory: %w", err)
	}
	return &FileDataPlane{root: directory, key: append([]byte(nil), key...), maximumBytes: maximumBytes}, nil
}

// Stage copies, encrypts and digests bounded disk-only bytes before any manifest is published.
func (plane *FileDataPlane) Stage(ctx context.Context, id string, input io.Reader) (StagedSnapshot, error) {
	if err := contextErr(ctx); err != nil {
		return StagedSnapshot{}, err
	}
	if plane == nil || !validOwnerID("payload", id) || input == nil {
		return StagedSnapshot{}, fmt.Errorf("stage snapshot data: %w", ErrConflict)
	}
	plain, err := readBounded(ctx, input, plane.maximumBytes)
	if err != nil {
		return StagedSnapshot{}, err
	}
	plainDigest := digest(plain)
	// The envelope uses an authenticated stream-equivalent format implemented in payload.go.
	ciphertext, err := encryptSnapshot(plane.key, plain)
	if err != nil {
		return StagedSnapshot{}, err
	}
	file, err := os.CreateTemp(plane.root, ".snapshot-")
	if err != nil {
		return StagedSnapshot{}, fmt.Errorf("stage snapshot data: create temporary ciphertext: %w", err)
	}
	temporary := file.Name()
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		os.Remove(temporary)
		return StagedSnapshot{}, err
	}
	if _, err := file.Write(ciphertext); err != nil {
		file.Close()
		os.Remove(temporary)
		return StagedSnapshot{}, err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(temporary)
		return StagedSnapshot{}, err
	}
	if err := file.Close(); err != nil {
		os.Remove(temporary)
		return StagedSnapshot{}, err
	}
	return StagedSnapshot{id: id, path: temporary, PlaintextDigest: plainDigest, CiphertextDigest: digest(ciphertext), SizeBytes: uint64(len(plain))}, nil
}

// Publish atomically makes a staged ciphertext visible under its immutable snapshot ID.
func (plane *FileDataPlane) Publish(stage StagedSnapshot) error {
	if plane == nil || stage.id == "" || stage.path == "" {
		return fmt.Errorf("publish snapshot data: %w", ErrConflict)
	}
	destination := plane.payloadPath(stage.id)
	if _, err := os.Lstat(destination); err == nil {
		return fmt.Errorf("publish snapshot data: %w", ErrConflict)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(stage.path, destination); err != nil {
		return fmt.Errorf("publish snapshot data: %w", err)
	}
	directory, err := os.Open(plane.root)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// Discard removes a staged payload and is safe to repeat.
func (plane *FileDataPlane) Discard(stage StagedSnapshot) error {
	if stage.path == "" {
		return nil
	}
	if err := os.Remove(stage.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Remove removes one published payload during a tombstone transition.
func (plane *FileDataPlane) Remove(id string) error { return os.Remove(plane.payloadPath(id)) }

// Open decrypts and verifies a snapshot payload before exposing a bounded reader.
func (plane *FileDataPlane) Open(ctx context.Context, id string, manifest SnapshotManifest) (io.ReadCloser, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	ciphertext, err := os.ReadFile(plane.payloadPath(id))
	if err != nil {
		return nil, fmt.Errorf("open snapshot data: %w", err)
	}
	if digest(ciphertext) != manifest.CiphertextDigest {
		return nil, ErrIntegrity
	}
	plain, err := decryptSnapshot(plane.key, ciphertext)
	if err != nil {
		return nil, err
	}
	if uint64(len(plain)) != manifest.SizeBytes || digest(plain) != manifest.PlaintextDigest {
		return nil, ErrIntegrity
	}
	return io.NopCloser(bytes.NewReader(plain)), nil
}

func (plane *FileDataPlane) payloadPath(id string) string {
	return filepath.Join(plane.root, id+".snapshot")
}
func readBounded(ctx context.Context, input io.Reader, maximum uint64) ([]byte, error) {
	limited := io.LimitReader(input, int64(maximum)+1)
	content, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("stage snapshot data: read disk bytes: %w", err)
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if uint64(len(content)) > maximum {
		return nil, fmt.Errorf("stage snapshot data: %w", ErrIntegrity)
	}
	return content, nil
}
func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
