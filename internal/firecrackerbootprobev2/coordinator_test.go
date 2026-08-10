package firecrackerbootprobev2

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestCoordinatorCreatesLoadsAndRenewsOnlyOneExactPersistedSuccessor(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 10, 16, 0, 0, 0, time.UTC)
	coordinator, err := NewCoordinator(NewMemoryStateStore())
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}

	created, didCreate, err := coordinator.Create(ctx, validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil || !didCreate || created.Version != 1 {
		t.Fatalf("Create() = (%#v, %t, %v), want version-one created snapshot", created, didCreate, err)
	}
	recovered, found, err := coordinator.Load(ctx, "host-session-01")
	if err != nil || !found || !reflect.DeepEqual(recovered, created) {
		t.Fatalf("Load() = (%#v, %t, %v), want (%#v, true, nil)", recovered, found, err, created)
	}

	successor := exactSuccessor(created.Session.Delivery.Current, now.Add(time.Minute))
	renewed, err := coordinator.RenewAuthenticated(ctx, created, successor, now.Add(time.Minute))
	if err != nil || renewed.Version != created.Version+1 || renewed.Session.Delivery.Current != successor {
		t.Fatalf("RenewAuthenticated() = (%#v, %v), want one exact persisted successor", renewed, err)
	}
	if _, err := coordinator.RenewAuthenticated(ctx, created, successor, now.Add(time.Minute)); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("RenewAuthenticated(stale) error = %v, want ErrVersionConflict", err)
	}

	current, found, err := coordinator.Load(ctx, "host-session-01")
	if err != nil || !found || !reflect.DeepEqual(current, renewed) {
		t.Fatalf("Load() after stale renewal = (%#v, %t, %v), want unchanged %#v", current, found, err, renewed)
	}
}

func TestCoordinatorClassifiesOnlyValidAcknowledgementsWithoutWritingState(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 10, 16, 0, 0, 0, time.UTC)
	coordinator, err := NewCoordinator(NewMemoryStateStore())
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}
	created, _, err := coordinator.Create(ctx, validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	successor := exactSuccessor(created.Session.Delivery.Current, now.Add(time.Minute))
	renewed, err := coordinator.RenewAuthenticated(ctx, created, successor, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("RenewAuthenticated() error = %v", err)
	}

	delayed := acknowledgementFor(created.Session.Delivery)
	result, err := coordinator.ClassifyAcknowledgement(ctx, delayed)
	if err != nil || !result.Found || result.Classification != AcknowledgementKnownSuperseded || !reflect.DeepEqual(result.Snapshot, renewed) {
		t.Fatalf("ClassifyAcknowledgement(delayed) = (%#v, %v), want recovered known-superseded result", result, err)
	}
	current := acknowledgementFor(renewed.Session.Delivery)
	result, err = coordinator.ClassifyAcknowledgement(ctx, current)
	if err != nil || !result.Found || result.Classification != AcknowledgementCurrent || !reflect.DeepEqual(result.Snapshot, renewed) {
		t.Fatalf("ClassifyAcknowledgement(current) = (%#v, %v), want recovered current result", result, err)
	}
	unknown := current
	unknown.HostInstanceSessionID = "host-session-02"
	result, err = coordinator.ClassifyAcknowledgement(ctx, unknown)
	if err != nil || result.Found || result.Classification != AcknowledgementUnknown {
		t.Fatalf("ClassifyAcknowledgement(unknown) = (%#v, %v), want absent unknown result", result, err)
	}
	invalid := current
	invalid.Nonce += "="
	if _, err := coordinator.ClassifyAcknowledgement(ctx, invalid); !errors.Is(err, ErrInvalidAcknowledgement) {
		t.Fatalf("ClassifyAcknowledgement(invalid) error = %v, want ErrInvalidAcknowledgement", err)
	}

	after, found, err := coordinator.Load(ctx, "host-session-01")
	if err != nil || !found || !reflect.DeepEqual(after, renewed) {
		t.Fatalf("Load() after acknowledgement classification = (%#v, %t, %v), want unchanged %#v", after, found, err, renewed)
	}
}

func TestCoordinatorAtomicallyPersistsAuthorizationExpiryAndRenewalLifecycleDecisions(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 10, 16, 0, 0, 0, time.UTC)
	coordinator, err := NewCoordinator(NewMemoryStateStore())
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}
	created, _, err := coordinator.Create(ctx, validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	authorized, err := coordinator.AuthorizeLaunch(ctx, created, now)
	if err != nil || authorized.Session.Lifecycle.Phase != LifecycleLaunchAuthorized {
		t.Fatalf("AuthorizeLaunch() = (%#v, %v), want persisted launch authorization", authorized, err)
	}
	renewed, err := coordinator.RenewAuthenticated(ctx, authorized, exactSuccessor(authorized.Session.Delivery.Current, now.Add(time.Minute)), now.Add(time.Minute))
	if err != nil || renewed.Session.Lifecycle.Phase != LifecycleCleanupPending {
		t.Fatalf("RenewAuthenticated(authorized) = (%#v, %v), want one CAS record converged to cleanup-pending", renewed, err)
	}
	if _, err := coordinator.RecordLaunchStarted(ctx, renewed, now.Add(time.Minute)); !errors.Is(err, ErrLifecycleTransitionRefused) {
		t.Fatalf("RecordLaunchStarted(after authorization renewal) error = %v, want ErrLifecycleTransitionRefused", err)
	}

	expired, _, err := coordinator.Create(ctx, validBinding(), "host-session-02", validDelivery(now), now)
	if err != nil {
		t.Fatalf("Create(expired fixture) error = %v", err)
	}
	cleaned, err := coordinator.AuthorizeLaunch(ctx, expired, now.Add(3*time.Minute))
	if err != nil || cleaned.Session.Lifecycle.Phase != LifecycleCleanupPending {
		t.Fatalf("AuthorizeLaunch(expired) = (%#v, %v), want persisted cleanup-pending", cleaned, err)
	}

	startExpired, _, err := coordinator.Create(ctx, validBinding(), "host-session-03", validDelivery(now), now)
	if err != nil {
		t.Fatalf("Create(start expiry fixture) error = %v", err)
	}
	startAuthorized, err := coordinator.AuthorizeLaunch(ctx, startExpired, now)
	if err != nil {
		t.Fatalf("AuthorizeLaunch(start expiry fixture) error = %v", err)
	}
	startCleanup, err := coordinator.RecordLaunchStarted(ctx, startAuthorized, now.Add(3*time.Minute))
	if err != nil || startCleanup.Session.Lifecycle.Phase != LifecycleCleanupPending {
		t.Fatalf("RecordLaunchStarted(expired) = (%#v, %v), want persisted cleanup-pending", startCleanup, err)
	}
}

func acknowledgementFor(state State) Acknowledgement {
	return Acknowledgement{
		HostInstanceSessionID: state.HostInstanceSessionID,
		DeliveryID:            state.Current.DeliveryID,
		Nonce:                 state.Current.Nonce,
		LeaseEpoch:            state.Current.LeaseEpoch,
		FencingToken:          state.Current.FencingToken,
	}
}
