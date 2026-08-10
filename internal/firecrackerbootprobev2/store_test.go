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

func TestMemoryStateStoreAtomicallyLoadsOrCreatesOneCanonicalCompoundSessionSnapshot(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 10, 16, 0, 0, 0, time.UTC)
	delivery, err := NewState(validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	initial, err := NewSession(delivery)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	store := NewMemoryStateStore()

	created, didCreate, err := store.LoadOrCreate(ctx, initial)
	if err != nil || !didCreate || created.Version != 1 || !reflect.DeepEqual(created.Session, initial) {
		t.Fatalf("LoadOrCreate() = (%#v, %t, %v), want version-one initial compound snapshot", created, didCreate, err)
	}
	wantWire, err := EncodeSession(initial)
	if err != nil || !bytes.Equal(created.Wire, wantWire) {
		t.Fatalf("LoadOrCreate() wire = %q, want canonical compound wire %q (error %v)", created.Wire, wantWire, err)
	}
	created.Wire[0] ^= 1
	created.Session.Delivery.Current.DeliveryID = "caller-mutation"
	recovered, found, err := store.Load(ctx, initial.Delivery.HostInstanceSessionID)
	if err != nil || !found || !reflect.DeepEqual(recovered.Session, initial) {
		t.Fatalf("Load() after caller mutation = (%#v, %t, %v), want original compound session", recovered, found, err)
	}
	prior, didCreate, err := store.LoadOrCreate(ctx, initial)
	if err != nil || didCreate || !reflect.DeepEqual(prior, recovered) {
		t.Fatalf("LoadOrCreate(existing) = (%#v, %t, %v), want existing snapshot", prior, didCreate, err)
	}
}

func TestMemoryStateStoreCASPersistsLifecycleAndDeliveryTransitionsInOneRecord(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 10, 16, 0, 0, 0, time.UTC)
	delivery, err := NewState(validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	initial, err := NewSession(delivery)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	store := NewMemoryStateStore()
	prepared, _, err := store.LoadOrCreate(ctx, initial)
	if err != nil {
		t.Fatalf("LoadOrCreate() error = %v", err)
	}
	authorizedSession, err := prepared.Session.AuthorizeLaunch(now)
	if err != nil {
		t.Fatalf("AuthorizeLaunch() error = %v", err)
	}
	authorized, err := store.CompareAndSwap(ctx, prepared, authorizedSession, now)
	if err != nil || authorized.Version != prepared.Version+1 || authorized.Session.Lifecycle.Phase != LifecycleLaunchAuthorized {
		t.Fatalf("CompareAndSwap(authorize) = (%#v, %v), want persisted launch authorization", authorized, err)
	}
	startedSession, err := authorized.Session.RecordLaunchStarted(now)
	if err != nil {
		t.Fatalf("RecordLaunchStarted() error = %v", err)
	}
	started, err := store.CompareAndSwap(ctx, authorized, startedSession, now)
	if err != nil || started.Version != authorized.Version+1 || started.Session.Lifecycle.Phase != LifecycleLaunchStarted {
		t.Fatalf("CompareAndSwap(start) = (%#v, %v), want persisted launch start", started, err)
	}
	renewedSession, err := started.Session.AcceptAuthenticatedSuccessor(exactSuccessor(started.Session.Delivery.Current, now.Add(time.Minute)), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("AcceptAuthenticatedSuccessor() error = %v", err)
	}
	renewed, err := store.CompareAndSwap(ctx, started, renewedSession, now.Add(time.Minute))
	if err != nil || renewed.Version != started.Version+1 || renewed.Session.Lifecycle.Phase != LifecycleLaunchStarted || len(renewed.Session.Delivery.Superseded) != 1 {
		t.Fatalf("CompareAndSwap(renewal) = (%#v, %v), want one atomic delivery/lifecycle recovery record", renewed, err)
	}
	classification, err := renewed.Session.Delivery.ClassifyAcknowledgement(acknowledgementFor(started.Session.Delivery))
	if err != nil || classification != AcknowledgementKnownSuperseded {
		t.Fatalf("ClassifyAcknowledgement(delayed) = (%q, %v), want known-superseded", classification, err)
	}
}

func TestMemoryStateStoreRefusesRecreatedLaunchAndForgedOrStaleTransitionsWithoutMutation(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 10, 16, 0, 0, 0, time.UTC)
	delivery, err := NewState(validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	initial, err := NewSession(delivery)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	store := NewMemoryStateStore()
	prepared, _, err := store.LoadOrCreate(ctx, initial)
	if err != nil {
		t.Fatalf("LoadOrCreate() error = %v", err)
	}
	authorizedSession, err := prepared.Session.AuthorizeLaunch(now)
	if err != nil {
		t.Fatalf("AuthorizeLaunch() error = %v", err)
	}
	authorized, err := store.CompareAndSwap(ctx, prepared, authorizedSession, now)
	if err != nil {
		t.Fatalf("CompareAndSwap(authorize) error = %v", err)
	}

	staleStart, err := authorized.Session.RecordLaunchStarted(now)
	if err != nil {
		t.Fatalf("RecordLaunchStarted() error = %v", err)
	}
	stale := prepared
	assertStoreRefusalWithoutMutation(t, store, ctx, authorized, stale, staleStart, now, ErrVersionConflict)

	forged := authorized.Session
	forged.Lifecycle.Phase = LifecycleLaunchStarted
	forged.Lifecycle.LaunchDelivery = nil
	assertStoreRefusalWithoutMutation(t, store, ctx, authorized, authorized, forged, now, ErrSuccessorRefused)

	cleanup, err := authorized.Session.BeginCleanup()
	if err != nil {
		t.Fatalf("BeginCleanup() error = %v", err)
	}
	cleaned, err := store.CompareAndSwap(ctx, authorized, cleanup, now)
	if err != nil {
		t.Fatalf("CompareAndSwap(cleanup) error = %v", err)
	}
	if _, err := cleaned.Session.AuthorizeLaunch(now.Add(time.Minute)); !errors.Is(err, ErrLifecycleTransitionRefused) {
		t.Fatalf("AuthorizeLaunch(cleanup) error = %v, want ErrLifecycleTransitionRefused", err)
	}

	expiredStore := NewMemoryStateStore()
	expiredPrepared, _, err := expiredStore.LoadOrCreate(ctx, initial)
	if err != nil {
		t.Fatalf("LoadOrCreate(expired authorization fixture) error = %v", err)
	}
	expiredAuthorization := expiredPrepared.Session
	expiredDelivery := expiredAuthorization.Delivery.Current
	expiredAuthorization.Lifecycle = Lifecycle{Phase: LifecycleLaunchAuthorized, LaunchDelivery: &expiredDelivery}
	assertStoreRefusalWithoutMutation(t, expiredStore, ctx, expiredPrepared, expiredPrepared, expiredAuthorization, now.Add(3*time.Minute), ErrSuccessorRefused)
	expiredAuthorized, err := expiredStore.CompareAndSwap(ctx, expiredPrepared, expiredAuthorization, now)
	if err != nil {
		t.Fatalf("CompareAndSwap(non-expired authorization) error = %v", err)
	}
	expiredStart := expiredAuthorized.Session
	expiredStart.Lifecycle.Phase = LifecycleLaunchStarted
	assertStoreRefusalWithoutMutation(t, expiredStore, ctx, expiredAuthorized, expiredAuthorized, expiredStart, now.Add(3*time.Minute), ErrSuccessorRefused)

	advanced, err := delivery.AcceptAuthenticatedSuccessor(delivery.HostInstanceSessionID, exactSuccessor(delivery.Current, now.Add(time.Minute)), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("AcceptAuthenticatedSuccessor() error = %v", err)
	}
	recreated := Session{Version: sessionVersion, Delivery: advanced, Lifecycle: Lifecycle{Phase: LifecyclePrepared}}
	if _, _, err := NewMemoryStateStore().LoadOrCreate(ctx, recreated); !errors.Is(err, ErrSuccessorRefused) {
		t.Fatalf("LoadOrCreate(recreated after renewal) error = %v, want ErrSuccessorRefused", err)
	}
}

func TestMemoryStateStoreRefusesVersionCounterOverflowWithoutMutation(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 10, 16, 0, 0, 0, time.UTC)
	delivery, err := NewState(validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	initial, err := NewSession(delivery)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	store := NewMemoryStateStore()
	before, _, err := store.LoadOrCreate(ctx, initial)
	if err != nil {
		t.Fatalf("LoadOrCreate() error = %v", err)
	}
	store.records[delivery.HostInstanceSessionID] = memoryRecord{version: math.MaxUint64, wire: append([]byte(nil), before.Wire...)}
	maximum := before
	maximum.Version = math.MaxUint64
	authorized, err := initial.AuthorizeLaunch(now)
	if err != nil {
		t.Fatalf("AuthorizeLaunch() error = %v", err)
	}
	assertStoreRefusalWithoutMutation(t, store, ctx, maximum, maximum, authorized, now, ErrVersionOverflow)
}

func assertStoreRefusalWithoutMutation(t *testing.T, store *MemoryStateStore, ctx context.Context, identity Snapshot, expected Snapshot, candidate Session, now time.Time, want error) {
	t.Helper()
	before, found, err := store.Load(ctx, identity.Session.Delivery.HostInstanceSessionID)
	if err != nil || !found {
		t.Fatalf("Load(before refusal) = (%#v, %t, %v), want existing session", before, found, err)
	}
	if _, err := store.CompareAndSwap(ctx, expected, candidate, now); !errors.Is(err, want) {
		t.Fatalf("CompareAndSwap() error = %v, want %v", err, want)
	}
	after, found, err := store.Load(ctx, identity.Session.Delivery.HostInstanceSessionID)
	if err != nil || !found || !reflect.DeepEqual(after, before) {
		t.Fatalf("Load(after refusal) = (%#v, %t, %v), want unchanged %#v", after, found, err, before)
	}
}
