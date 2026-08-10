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

// Snapshot is one immutable recovery view of a private boot-probe v2 state record.
// Wire is the exact canonical state encoding retained by the store; callers receive a copy.
type Snapshot struct {
	Version uint64
	State   State
	Wire    []byte
}

// StateStore is the private persistence boundary for one host-instance boot-probe v2 lease chain.
// It atomically creates an initial state and admits only the exact next authenticated successor through compare-and-swap.
type StateStore interface {
	LoadOrCreate(context.Context, State) (Snapshot, bool, error)
	Load(context.Context, string) (Snapshot, bool, error)
	CompareAndSwap(context.Context, Snapshot, State, time.Time) (Snapshot, error)
}

// MemoryStateStore is a deterministic, hermetic StateStore implementation for private boot-probe v2 lifecycle tests.
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

// LoadOrCreate atomically persists an initial state or returns its identical existing recovery snapshot.
func (store *MemoryStateStore) LoadOrCreate(ctx context.Context, initial State) (Snapshot, bool, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, false, errors.Wrap(err, "load or create Firecracker boot-probe v2 state")
	}
	if len(initial.Superseded) != 0 {
		return Snapshot{}, false, errors.Wrap(ErrSuccessorRefused, "refuse advanced initial Firecracker boot-probe v2 state")
	}
	wire, err := Encode(initial)
	if err != nil {
		return Snapshot{}, false, errors.Wrap(err, "encode initial Firecracker boot-probe v2 state")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if record, exists := store.records[initial.HostInstanceSessionID]; exists {
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
	store.records[initial.HostInstanceSessionID] = record
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

// CompareAndSwap atomically stores precisely one next authenticated successor of expected or refuses without mutation.
func (store *MemoryStateStore) CompareAndSwap(ctx context.Context, expected Snapshot, successor State, now time.Time) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, errors.Wrap(err, "compare and swap Firecracker boot-probe v2 state")
	}
	expectedWire, err := Encode(expected.State)
	if err != nil || !bytes.Equal(expected.Wire, expectedWire) {
		return Snapshot{}, errors.Wrap(ErrVersionConflict, "validate expected canonical Firecracker boot-probe v2 snapshot")
	}
	if successor.HostInstanceSessionID != expected.State.HostInstanceSessionID {
		return Snapshot{}, errors.Wrap(ErrSuccessorRefused, "refuse cross-instance Firecracker boot-probe v2 successor")
	}
	if err := successor.Validate(); err != nil {
		return Snapshot{}, errors.Wrap(ErrSuccessorRefused, "validate successor Firecracker boot-probe v2 state")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[expected.State.HostInstanceSessionID]
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
	next, err := current.State.AcceptAuthenticatedSuccessor(current.State.HostInstanceSessionID, successor.Current, now)
	if err != nil {
		return Snapshot{}, errors.Wrap(ErrSuccessorRefused, "accept compared Firecracker boot-probe v2 successor")
	}
	nextWire, err := Encode(next)
	if err != nil {
		return Snapshot{}, errors.Wrap(ErrSuccessorRefused, "encode compared Firecracker boot-probe v2 successor")
	}
	successorWire, err := Encode(successor)
	if err != nil || !bytes.Equal(successorWire, nextWire) {
		return Snapshot{}, errors.Wrap(ErrSuccessorRefused, "refuse non-exact Firecracker boot-probe v2 successor")
	}
	if record.version == math.MaxUint64 {
		return Snapshot{}, errors.Wrap(ErrVersionOverflow, "advance Firecracker boot-probe v2 state version")
	}
	record = memoryRecord{version: record.version + 1, wire: append([]byte(nil), nextWire...)}
	store.records[current.State.HostInstanceSessionID] = record
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
	state, err := Decode(record.wire)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Version: record.version, State: state, Wire: append([]byte(nil), record.wire...)}, nil
}
