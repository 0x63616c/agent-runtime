package firecrackerbootprobev2

import (
	"bytes"
	"context"
	"math"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
)

var (
	// ErrStateConflict identifies an attempted initial create that reuses a host-instance session for different immutable state.
	ErrStateConflict = errors.New("Firecracker boot-probe v2 state conflict")
	// ErrVersionConflict identifies a compare-and-swap against a stale recovery snapshot.
	ErrVersionConflict = errors.New("Firecracker boot-probe v2 state version conflict")
	// ErrVersionOverflow identifies a compare-and-swap that cannot assign the next monotonic persistence version.
	ErrVersionOverflow = errors.New("Firecracker boot-probe v2 state version overflow")
)

// Snapshot is one immutable recovery view of a private boot-probe v2 compound session record.
// Wire is the exact canonical session encoding retained by the store; callers receive a copy.
type Snapshot struct {
	Version uint64
	Session Session
	Wire    []byte
}

// StateStore is the private persistence boundary for one host-instance boot-probe v2 compound session.
// It atomically creates the lifecycle with its delivery chain and admits exactly one validated session transition through compare-and-swap.
type StateStore interface {
	LoadOrCreate(context.Context, Session) (Snapshot, bool, error)
	Load(context.Context, string) (Snapshot, bool, error)
	CompareAndSwap(context.Context, Snapshot, Session, time.Time) (Snapshot, error)
}

// MemoryStateStore is a deterministic, hermetic StateStore implementation for private boot-probe v2 compound-session tests.
type MemoryStateStore struct {
	mu      sync.Mutex
	records map[string]memoryRecord
}

type memoryRecord struct {
	version uint64
	wire    []byte
}

var _ StateStore = (*MemoryStateStore)(nil)

// NewMemoryStateStore constructs an empty deterministic private boot-probe v2 state store.
func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{records: make(map[string]memoryRecord)}
}

// LoadOrCreate atomically persists one prepared initial session or returns its identical existing recovery snapshot.
func (store *MemoryStateStore) LoadOrCreate(ctx context.Context, initial Session) (Snapshot, bool, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, false, errors.Wrap(err, "load or create Firecracker boot-probe v2 state")
	}
	if err := initial.Validate(); err != nil || initial.Lifecycle.Phase != LifecyclePrepared || initial.Lifecycle.LaunchDelivery != nil || len(initial.Delivery.Superseded) != 0 {
		return Snapshot{}, false, errors.Wrap(ErrSuccessorRefused, "refuse non-initial Firecracker boot-probe v2 session")
	}
	wire, err := EncodeSession(initial)
	if err != nil {
		return Snapshot{}, false, errors.Wrap(err, "encode initial Firecracker boot-probe v2 state")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if record, exists := store.records[initial.Delivery.HostInstanceSessionID]; exists {
		snapshot, err := snapshotFromRecord(record)
		if err != nil {
			return Snapshot{}, false, errors.Wrap(err, "recover existing Firecracker boot-probe v2 state")
		}
		if !bytes.Equal(snapshot.Wire, wire) {
			return Snapshot{}, false, errors.Wrap(ErrStateConflict, "compare initial Firecracker boot-probe v2 state")
		}
		return snapshot, false, nil
	}
	record := memoryRecord{version: 1, wire: append([]byte(nil), wire...)}
	store.records[initial.Delivery.HostInstanceSessionID] = record
	snapshot, err := snapshotFromRecord(record)
	if err != nil {
		return Snapshot{}, false, errors.Wrap(err, "recover created Firecracker boot-probe v2 state")
	}
	return snapshot, true, nil
}

// Load returns a copied canonical recovery snapshot for one host-instance session.
func (store *MemoryStateStore) Load(ctx context.Context, hostInstanceSessionID string) (Snapshot, bool, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, false, errors.Wrap(err, "load Firecracker boot-probe v2 state")
	}
	if !validSessionID(hostInstanceSessionID) {
		return Snapshot{}, false, errors.Wrap(ErrInvalidState, "validate Firecracker boot-probe v2 host-instance session")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[hostInstanceSessionID]
	if !exists {
		return Snapshot{}, false, nil
	}
	snapshot, err := snapshotFromRecord(record)
	if err != nil {
		return Snapshot{}, false, errors.Wrap(err, "recover Firecracker boot-probe v2 state")
	}
	return snapshot, true, nil
}

// CompareAndSwap atomically stores precisely one next compound-session transition of expected or refuses without mutation.
func (store *MemoryStateStore) CompareAndSwap(ctx context.Context, expected Snapshot, successor Session, now time.Time) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, errors.Wrap(err, "compare and swap Firecracker boot-probe v2 state")
	}
	expectedWire, err := EncodeSession(expected.Session)
	if err != nil || !bytes.Equal(expected.Wire, expectedWire) {
		return Snapshot{}, errors.Wrap(ErrVersionConflict, "validate expected canonical Firecracker boot-probe v2 snapshot")
	}
	if successor.Delivery.HostInstanceSessionID != expected.Session.Delivery.HostInstanceSessionID {
		return Snapshot{}, errors.Wrap(ErrSuccessorRefused, "refuse cross-instance Firecracker boot-probe v2 successor")
	}
	if err := successor.Validate(); err != nil {
		return Snapshot{}, errors.Wrap(ErrSuccessorRefused, "validate successor Firecracker boot-probe v2 state")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[expected.Session.Delivery.HostInstanceSessionID]
	if !exists {
		return Snapshot{}, errors.Wrap(ErrVersionConflict, "compare absent Firecracker boot-probe v2 state")
	}
	if expected.Version != record.version || !bytes.Equal(expected.Wire, record.wire) {
		return Snapshot{}, errors.Wrap(ErrVersionConflict, "compare stale Firecracker boot-probe v2 state version")
	}
	current, err := snapshotFromRecord(record)
	if err != nil {
		return Snapshot{}, errors.Wrap(err, "recover compared Firecracker boot-probe v2 state")
	}
	if err := validateSessionSuccessor(current.Session, successor, now); err != nil {
		return Snapshot{}, errors.Wrap(ErrSuccessorRefused, "accept compared Firecracker boot-probe v2 session transition")
	}
	nextWire, err := EncodeSession(successor)
	if err != nil {
		return Snapshot{}, errors.Wrap(ErrSuccessorRefused, "encode compared Firecracker boot-probe v2 session transition")
	}
	if record.version == math.MaxUint64 {
		return Snapshot{}, errors.Wrap(ErrVersionOverflow, "advance Firecracker boot-probe v2 state version")
	}
	record = memoryRecord{version: record.version + 1, wire: append([]byte(nil), nextWire...)}
	store.records[current.Session.Delivery.HostInstanceSessionID] = record
	snapshot, err := snapshotFromRecord(record)
	if err != nil {
		return Snapshot{}, errors.Wrap(err, "recover advanced Firecracker boot-probe v2 state")
	}
	return snapshot, nil
}

func snapshotFromRecord(record memoryRecord) (Snapshot, error) {
	if record.version == 0 {
		return Snapshot{}, errors.Wrap(ErrInvalidState, "validate Firecracker boot-probe v2 state version")
	}
	session, err := DecodeSession(record.wire)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Version: record.version, Session: session, Wire: append([]byte(nil), record.wire...)}, nil
}

func validateSessionSuccessor(previous, successor Session, now time.Time) error {
	if err := previous.Validate(); err != nil {
		return err
	}
	if err := successor.Validate(); err != nil {
		return err
	}
	if previous.Delivery.HostInstanceSessionID != successor.Delivery.HostInstanceSessionID || previous.Delivery.Binding != successor.Delivery.Binding {
		return errors.Wrap(ErrSuccessorRefused, "validate Firecracker boot-probe v2 session identity")
	}
	if sameState(previous.Delivery, successor.Delivery) {
		if validLifecycleSuccessor(previous.Lifecycle, successor.Lifecycle, previous.Delivery, now) {
			return nil
		}
		return errors.Wrap(ErrSuccessorRefused, "validate Firecracker boot-probe v2 lifecycle transition")
	}
	if previous.Lifecycle.Phase == LifecycleCleanupConfirmed {
		return errors.Wrap(ErrSuccessorRefused, "refuse Firecracker boot-probe v2 delivery renewal after cleanup")
	}
	next, err := previous.AcceptAuthenticatedSuccessor(successor.Delivery.Current, now)
	if err != nil || !sameSession(next, successor) {
		return errors.Wrap(ErrSuccessorRefused, "validate exact Firecracker boot-probe v2 delivery successor")
	}
	return nil
}

func validLifecycleSuccessor(previous, successor Lifecycle, delivery State, now time.Time) bool {
	if previous.Phase == LifecyclePrepared && successor.Phase == LifecycleLaunchAuthorized && successor.LaunchDelivery != nil && sameDelivery(*successor.LaunchDelivery, delivery.Current) {
		return previous.LaunchDelivery == nil && validTimestamp(now) && !now.Before(delivery.Current.IssuedAt) && now.Before(delivery.Current.ExpiresAt)
	}
	if previous.Phase == LifecyclePrepared && successor.Phase == LifecycleCleanupPending && previous.LaunchDelivery == nil && successor.LaunchDelivery == nil {
		return true
	}
	if previous.Phase == LifecycleLaunchAuthorized && successor.Phase == LifecycleLaunchStarted && previous.LaunchDelivery != nil && successor.LaunchDelivery != nil && sameDelivery(*previous.LaunchDelivery, *successor.LaunchDelivery) {
		return validTimestamp(now) && !now.Before(delivery.Current.IssuedAt) && now.Before(delivery.Current.ExpiresAt)
	}
	if (previous.Phase == LifecycleLaunchAuthorized || previous.Phase == LifecycleLaunchStarted) && successor.Phase == LifecycleCleanupPending && sameLifecycleDelivery(previous, successor) {
		return true
	}
	return previous.Phase == LifecycleCleanupPending && successor.Phase == LifecycleCleanupConfirmed && sameLifecycleDelivery(previous, successor)
}

func sameState(left, right State) bool {
	leftWire, leftErr := Encode(left)
	rightWire, rightErr := Encode(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftWire, rightWire)
}

func sameSession(left, right Session) bool {
	leftWire, leftErr := EncodeSession(left)
	rightWire, rightErr := EncodeSession(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftWire, rightWire)
}

func sameLifecycleDelivery(left, right Lifecycle) bool {
	if left.LaunchDelivery == nil || right.LaunchDelivery == nil {
		return left.LaunchDelivery == nil && right.LaunchDelivery == nil
	}
	return sameDelivery(*left.LaunchDelivery, *right.LaunchDelivery)
}
