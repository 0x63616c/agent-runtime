package firecrackerbootprobev2

import (
	"bytes"
	"context"
	"errors"
	"math"
	"reflect"
	"testing"
	"time"
)

func TestMemoryStateStoreAtomicallyLoadsOrCreatesACanonicalRecoverySnapshot(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 10, 16, 0, 0, 0, time.UTC)
	initial, err := NewState(validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	store := NewMemoryStateStore()

	created, didCreate, err := store.LoadOrCreate(ctx, initial)
	if err != nil {
		t.Fatalf("LoadOrCreate() error = %v", err)
	}
	if !didCreate || created.Version != 1 || !reflect.DeepEqual(created.State, initial) {
		t.Fatalf("LoadOrCreate() = (%#v, %t), want version-one initial snapshot and create", created, didCreate)
	}
	wantWire, err := Encode(initial)
	if err != nil {
		t.Fatalf("Encode(initial) error = %v", err)
	}
	if !bytes.Equal(created.Wire, wantWire) {
		t.Fatalf("LoadOrCreate() wire = %q, want canonical %q", created.Wire, wantWire)
	}

	loaded, found, err := store.Load(ctx, initial.HostInstanceSessionID)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !found || !reflect.DeepEqual(loaded, created) {
		t.Fatalf("Load() = (%#v, %t), want (%#v, true)", loaded, found, created)
	}
	loaded.Wire[0] ^= 1
	loaded.State.Current.DeliveryID = "caller-mutation"
	recovered, found, err := store.Load(ctx, initial.HostInstanceSessionID)
	if err != nil || !found || !reflect.DeepEqual(recovered, created) {
		t.Fatalf("Load() after caller mutation = (%#v, %t, %v), want original immutable snapshot", recovered, found, err)
	}

	prior, didCreate, err := store.LoadOrCreate(ctx, initial)
	if err != nil {
		t.Fatalf("LoadOrCreate(existing) error = %v", err)
	}
	if didCreate || !reflect.DeepEqual(prior, created) {
		t.Fatalf("LoadOrCreate(existing) = (%#v, %t), want existing snapshot without create", prior, didCreate)
	}
}

func TestMemoryStateStoreCompareAndSwapPersistsOnlyOneExactSuccessorAndRetainsAcknowledgementHistory(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 10, 16, 0, 0, 0, time.UTC)
	initial, err := NewState(validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	store := NewMemoryStateStore()
	before, _, err := store.LoadOrCreate(ctx, initial)
	if err != nil {
		t.Fatalf("LoadOrCreate() error = %v", err)
	}

	successor := exactSuccessor(initial.Current, now.Add(time.Minute))
	next, err := initial.AcceptAuthenticatedSuccessor(initial.HostInstanceSessionID, successor, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("AcceptAuthenticatedSuccessor() error = %v", err)
	}
	after, err := store.CompareAndSwap(ctx, before, next, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	if after.Version != before.Version+1 || !reflect.DeepEqual(after.State, next) {
		t.Fatalf("CompareAndSwap() = %#v, want exact version successor %#v", after, next)
	}
	classification, err := after.State.ClassifyAcknowledgement(Acknowledgement{HostInstanceSessionID: initial.HostInstanceSessionID, DeliveryID: initial.Current.DeliveryID, Nonce: initial.Current.Nonce, LeaseEpoch: initial.Current.LeaseEpoch, FencingToken: initial.Current.FencingToken})
	if err != nil || classification != AcknowledgementKnownSuperseded {
		t.Fatalf("recovered ClassifyAcknowledgement(delayed) = (%q, %v), want (%q, nil)", classification, err, AcknowledgementKnownSuperseded)
	}
	classification, err = after.State.ClassifyAcknowledgement(Acknowledgement{HostInstanceSessionID: initial.HostInstanceSessionID, DeliveryID: successor.DeliveryID, Nonce: successor.Nonce, LeaseEpoch: successor.LeaseEpoch, FencingToken: successor.FencingToken})
	if err != nil || classification != AcknowledgementCurrent {
		t.Fatalf("recovered ClassifyAcknowledgement(current) = (%q, %v), want (%q, nil)", classification, err, AcknowledgementCurrent)
	}
}

func TestMemoryStateStoreRefusesStaleForkedCrossInstanceAndOverflowWritesWithoutMutation(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 10, 16, 0, 0, 0, time.UTC)
	initial, err := NewState(validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	store := NewMemoryStateStore()
	before, _, err := store.LoadOrCreate(ctx, initial)
	if err != nil {
		t.Fatalf("LoadOrCreate() error = %v", err)
	}
	successor := exactSuccessor(initial.Current, now.Add(time.Minute))
	next, err := initial.AcceptAuthenticatedSuccessor(initial.HostInstanceSessionID, successor, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("AcceptAuthenticatedSuccessor() error = %v", err)
	}

	stale := before
	stale.Version--
	assertStoreRefusalWithoutMutation(t, store, ctx, before, stale, next, now.Add(time.Minute), ErrVersionConflict)

	forked := next
	forked.Current.FencingToken++
	assertStoreRefusalWithoutMutation(t, store, ctx, before, before, forked, now.Add(time.Minute), ErrSuccessorRefused)

	crossInstance := next
	crossInstance.HostInstanceSessionID = "host-session-02"
	assertStoreRefusalWithoutMutation(t, store, ctx, before, before, crossInstance, now.Add(time.Minute), ErrSuccessorRefused)

	overflowDelivery := validDelivery(now)
	overflowDelivery.LeaseEpoch = math.MaxUint64
	overflowDelivery.FencingToken = math.MaxUint64
	overflowInitial, err := NewState(validBinding(), "host-session-overflow", overflowDelivery, now)
	if err != nil {
		t.Fatalf("NewState(maximum fence) error = %v", err)
	}
	overflowStore := NewMemoryStateStore()
	overflowBefore, _, err := overflowStore.LoadOrCreate(ctx, overflowInitial)
	if err != nil {
		t.Fatalf("LoadOrCreate(maximum fence) error = %v", err)
	}
	overflowNext := overflowInitial
	overflowNext.Current = Delivery{DeliveryID: "delivery-overflow", Nonce: "YWJjZGVmZ2hpamtsbW5vcA", IssuedAt: now.Add(time.Minute), ExpiresAt: now.Add(3 * time.Minute), LeaseEpoch: math.MaxUint64, FencingToken: math.MaxUint64}
	assertStoreRefusalWithoutMutation(t, overflowStore, ctx, overflowBefore, overflowBefore, overflowNext, now.Add(time.Minute), ErrSuccessorRefused)

	forgedState := before
	forgedState.State.Current.DeliveryID = "forged-delivery"
	forgedState.Wire, err = Encode(forgedState.State)
	if err != nil {
		t.Fatalf("Encode(forged expected state) error = %v", err)
	}
	assertStoreRefusalWithoutMutation(t, store, ctx, before, forgedState, next, now.Add(time.Minute), ErrVersionConflict)

	forgedWire := before
	forgedWire.Wire = append([]byte(" "), forgedWire.Wire...)
	assertStoreRefusalWithoutMutation(t, store, ctx, before, forgedWire, next, now.Add(time.Minute), ErrVersionConflict)

	conflicting := initial
	conflicting.Binding.AssignmentID = "assignment-other"
	if _, _, err := store.LoadOrCreate(ctx, conflicting); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("LoadOrCreate(conflicting initial) error = %v, want ErrStateConflict", err)
	}
	loaded, found, err := store.Load(ctx, initial.HostInstanceSessionID)
	if err != nil || !found || !reflect.DeepEqual(loaded, before) {
		t.Fatalf("Load() after conflicting create = (%#v, %t, %v), want unchanged %#v", loaded, found, err, before)
	}
}

func TestMemoryStateStoreRefusesAnAlreadyAdvancedInitialStateWithoutMutation(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 10, 16, 0, 0, 0, time.UTC)
	initial, err := NewState(validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	advanced, err := initial.AcceptAuthenticatedSuccessor(initial.HostInstanceSessionID, exactSuccessor(initial.Current, now.Add(time.Minute)), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("AcceptAuthenticatedSuccessor() error = %v", err)
	}
	store := NewMemoryStateStore()
	if _, _, err := store.LoadOrCreate(ctx, advanced); !errors.Is(err, ErrSuccessorRefused) {
		t.Fatalf("LoadOrCreate(already advanced) error = %v, want ErrSuccessorRefused", err)
	}
	loaded, found, err := store.Load(ctx, initial.HostInstanceSessionID)
	if err != nil || found {
		t.Fatalf("Load() after refused create = (%#v, %t, %v), want absent state", loaded, found, err)
	}
}

func TestMemoryStateStoreRefusesVersionCounterOverflowWithoutMutation(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 10, 16, 0, 0, 0, time.UTC)
	initial, err := NewState(validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	store := NewMemoryStateStore()
	before, _, err := store.LoadOrCreate(ctx, initial)
	if err != nil {
		t.Fatalf("LoadOrCreate() error = %v", err)
	}
	store.records[initial.HostInstanceSessionID] = memoryRecord{version: math.MaxUint64, wire: append([]byte(nil), before.Wire...)}
	maximum := before
	maximum.Version = math.MaxUint64
	next, err := initial.AcceptAuthenticatedSuccessor(initial.HostInstanceSessionID, exactSuccessor(initial.Current, now.Add(time.Minute)), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("AcceptAuthenticatedSuccessor() error = %v", err)
	}
	assertStoreRefusalWithoutMutation(t, store, ctx, maximum, maximum, next, now.Add(time.Minute), ErrVersionOverflow)
}

func assertStoreRefusalWithoutMutation(t *testing.T, store *MemoryStateStore, ctx context.Context, identity Snapshot, expected Snapshot, candidate State, now time.Time, want error) {
	t.Helper()
	before, found, err := store.Load(ctx, identity.State.HostInstanceSessionID)
	if err != nil || !found {
		t.Fatalf("Load(before refusal) = (%#v, %t, %v), want existing state", before, found, err)
	}
	if _, err := store.CompareAndSwap(ctx, expected, candidate, now); !errors.Is(err, want) {
		t.Fatalf("CompareAndSwap() error = %v, want %v", err, want)
	}
	after, found, err := store.Load(ctx, identity.State.HostInstanceSessionID)
	if err != nil || !found || !reflect.DeepEqual(after, before) {
		t.Fatalf("Load(after refusal) = (%#v, %t, %v), want unchanged %#v", after, found, err, before)
	}
}
