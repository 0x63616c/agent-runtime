package firecrackerbootprobev2

import (
	"context"
	"reflect"
	"time"

	"github.com/cockroachdb/errors"
)

// Coordinator composes the private boot-probe v2 state contract with its caller-owned persistence boundary.
// It only admits already-authenticated state transitions and classifies acknowledgements; it never launches a guest or performs acknowledgement effects.
type Coordinator struct {
	store StateStore
}

// AcknowledgementResult is the recovered snapshot and effect-free classification for one valid acknowledgement.
// Found is false only when no state exists for the acknowledgement's host-instance session.
type AcknowledgementResult struct {
	Snapshot       Snapshot
	Found          bool
	Classification AcknowledgementClassification
}

// NewCoordinator constructs a private boot-probe v2 coordinator over one required state store.
func NewCoordinator(store StateStore) (*Coordinator, error) {
	if nilStateStore(store) {
		return nil, errors.Wrap(ErrInvalidState, "construct Firecracker boot-probe v2 coordinator without state store")
	}
	return &Coordinator{store: store}, nil
}

// Create atomically seals and persists an initial already-authenticated delivery or recovers its identical existing snapshot.
func (coordinator *Coordinator) Create(ctx context.Context, binding Binding, hostInstanceSessionID string, initial Delivery, now time.Time) (Snapshot, bool, error) {
	state, err := NewState(binding, hostInstanceSessionID, initial, now)
	if err != nil {
		return Snapshot{}, false, errors.Wrap(err, "seal initial Firecracker boot-probe v2 state")
	}
	snapshot, created, err := coordinator.store.LoadOrCreate(ctx, state)
	if err != nil {
		return Snapshot{}, false, errors.Wrap(err, "persist initial Firecracker boot-probe v2 state")
	}
	return snapshot, created, nil
}

// Load recovers one canonical private boot-probe v2 snapshot without producing a sandbox effect.
func (coordinator *Coordinator) Load(ctx context.Context, hostInstanceSessionID string) (Snapshot, bool, error) {
	snapshot, found, err := coordinator.store.Load(ctx, hostInstanceSessionID)
	if err != nil {
		return Snapshot{}, false, errors.Wrap(err, "load Firecracker boot-probe v2 coordinator state")
	}
	return snapshot, found, nil
}

// RenewAuthenticated constructs and atomically persists exactly the next already-authenticated delivery from the expected recovery snapshot.
func (coordinator *Coordinator) RenewAuthenticated(ctx context.Context, expected Snapshot, successor Delivery, now time.Time) (Snapshot, error) {
	next, err := expected.State.AcceptAuthenticatedSuccessor(expected.State.HostInstanceSessionID, successor, now)
	if err != nil {
		return Snapshot{}, errors.Wrap(err, "construct exact Firecracker boot-probe v2 successor")
	}
	snapshot, err := coordinator.store.CompareAndSwap(ctx, expected, next, now)
	if err != nil {
		return Snapshot{}, errors.Wrap(err, "persist exact Firecracker boot-probe v2 successor")
	}
	return snapshot, nil
}

// ClassifyAcknowledgement recovers the lease chain and classifies one valid acknowledgement without mutating state or acknowledging a host.
func (coordinator *Coordinator) ClassifyAcknowledgement(ctx context.Context, acknowledgement Acknowledgement) (AcknowledgementResult, error) {
	if !acknowledgement.valid() {
		return AcknowledgementResult{}, errors.Wrap(ErrInvalidAcknowledgement, "validate Firecracker boot-probe v2 coordinator acknowledgement")
	}
	snapshot, found, err := coordinator.Load(ctx, acknowledgement.HostInstanceSessionID)
	if err != nil {
		return AcknowledgementResult{}, errors.Wrap(err, "recover Firecracker boot-probe v2 acknowledgement state")
	}
	if !found {
		return AcknowledgementResult{Classification: AcknowledgementUnknown}, nil
	}
	classification, err := snapshot.State.ClassifyAcknowledgement(acknowledgement)
	if err != nil {
		return AcknowledgementResult{}, errors.Wrap(err, "classify Firecracker boot-probe v2 acknowledgement")
	}
	return AcknowledgementResult{Snapshot: snapshot, Found: true, Classification: classification}, nil
}

func nilStateStore(store StateStore) bool {
	if store == nil {
		return true
	}
	value := reflect.ValueOf(store)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
