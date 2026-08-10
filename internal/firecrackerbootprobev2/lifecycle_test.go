package firecrackerbootprobev2

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestSessionMovesOneBoundDeliveryThroughTheIrreversibleLaunchAndCleanupLifecycle(t *testing.T) {
	now := time.Date(2026, time.August, 10, 18, 0, 0, 0, time.UTC)
	deliveryState, err := NewState(validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	session, err := NewSession(deliveryState)
	if err != nil || session.Lifecycle.Phase != LifecyclePrepared {
		t.Fatalf("NewSession() = (%#v, %v), want prepared session", session, err)
	}

	authorized, err := session.AuthorizeLaunch(now)
	if err != nil || authorized.Lifecycle.Phase != LifecycleLaunchAuthorized || authorized.Lifecycle.LaunchDelivery == nil || *authorized.Lifecycle.LaunchDelivery != deliveryState.Current {
		t.Fatalf("AuthorizeLaunch() = (%#v, %v), want launch-authorized bound to exact current delivery", authorized, err)
	}
	started, err := authorized.RecordLaunchStarted(now)
	if err != nil || started.Lifecycle.Phase != LifecycleLaunchStarted {
		t.Fatalf("RecordLaunchStarted() = (%#v, %v), want launch-started", started, err)
	}
	pending, err := started.BeginCleanup()
	if err != nil || pending.Lifecycle.Phase != LifecycleCleanupPending {
		t.Fatalf("BeginCleanup() = (%#v, %v), want cleanup-pending", pending, err)
	}
	confirmed, err := pending.ConfirmCleanup()
	if err != nil || confirmed.Lifecycle.Phase != LifecycleCleanupConfirmed {
		t.Fatalf("ConfirmCleanup() = (%#v, %v), want cleanup-confirmed", confirmed, err)
	}
	if err := confirmed.Validate(); err != nil {
		t.Fatalf("confirmed session Validate() error = %v", err)
	}
}

func TestSessionRefusesRelaunchOrOutOfOrderLifecycleTransitions(t *testing.T) {
	now := time.Date(2026, time.August, 10, 18, 0, 0, 0, time.UTC)
	deliveryState, err := NewState(validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	session, err := NewSession(deliveryState)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	if _, err := session.RecordLaunchStarted(now); !errors.Is(err, ErrLifecycleTransitionRefused) {
		t.Fatalf("RecordLaunchStarted(prepared) error = %v, want ErrLifecycleTransitionRefused", err)
	}
	if _, err := session.ConfirmCleanup(); !errors.Is(err, ErrLifecycleTransitionRefused) {
		t.Fatalf("ConfirmCleanup(prepared) error = %v, want ErrLifecycleTransitionRefused", err)
	}
	authorized, err := session.AuthorizeLaunch(now)
	if err != nil {
		t.Fatalf("AuthorizeLaunch() error = %v", err)
	}
	started, err := authorized.RecordLaunchStarted(now)
	if err != nil {
		t.Fatalf("RecordLaunchStarted() error = %v", err)
	}
	if _, err := started.AuthorizeLaunch(now); !errors.Is(err, ErrLifecycleTransitionRefused) {
		t.Fatalf("AuthorizeLaunch(started) error = %v, want ErrLifecycleTransitionRefused", err)
	}
	if _, err := started.RecordLaunchStarted(now); !errors.Is(err, ErrLifecycleTransitionRefused) {
		t.Fatalf("RecordLaunchStarted(started) error = %v, want ErrLifecycleTransitionRefused", err)
	}
	cleaned, err := started.BeginCleanup()
	if err != nil {
		t.Fatalf("BeginCleanup() error = %v", err)
	}
	confirmed, err := cleaned.ConfirmCleanup()
	if err != nil {
		t.Fatalf("ConfirmCleanup() error = %v", err)
	}
	if _, err := confirmed.BeginCleanup(); !errors.Is(err, ErrLifecycleTransitionRefused) {
		t.Fatalf("BeginCleanup(confirmed) error = %v, want ErrLifecycleTransitionRefused", err)
	}
}

func TestSessionConvergesAnExpiredAuthorizationToCleanupInsteadOfRecordingLaunchStart(t *testing.T) {
	now := time.Date(2026, time.August, 10, 18, 0, 0, 0, time.UTC)
	deliveryState, err := NewState(validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	session, err := NewSession(deliveryState)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	authorized, err := session.AuthorizeLaunch(now)
	if err != nil {
		t.Fatalf("AuthorizeLaunch() error = %v", err)
	}
	cleanup, err := authorized.RecordLaunchStarted(deliveryState.Current.ExpiresAt)
	if err != nil || cleanup.Lifecycle.Phase != LifecycleCleanupPending || cleanup.Lifecycle.LaunchDelivery == nil {
		t.Fatalf("RecordLaunchStarted(expired) = (%#v, %v), want cleanup-pending with the original authorization retained", cleanup, err)
	}
}

func TestSessionRefusesARecreatedLifecycleAfterTheDeliveryChainAdvanced(t *testing.T) {
	now := time.Date(2026, time.August, 10, 18, 0, 0, 0, time.UTC)
	deliveryState, err := NewState(validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	advanced, err := deliveryState.AcceptAuthenticatedSuccessor("host-session-01", exactSuccessor(deliveryState.Current, now.Add(time.Minute)), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("AcceptAuthenticatedSuccessor() error = %v", err)
	}
	if _, err := NewSession(advanced); !errors.Is(err, ErrInvalidLifecycle) {
		t.Fatalf("NewSession(advanced delivery chain) error = %v, want ErrInvalidLifecycle", err)
	}
}

func TestSessionConvergesAnExpiredPreparedDeliveryToCleanupInsteadOfAuthorizingLaunch(t *testing.T) {
	now := time.Date(2026, time.August, 10, 18, 0, 0, 0, time.UTC)
	deliveryState, err := NewState(validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	session, err := NewSession(deliveryState)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	cleanup, err := session.AuthorizeLaunch(now.Add(3 * time.Minute))
	if err != nil || cleanup.Lifecycle.Phase != LifecycleCleanupPending || cleanup.Lifecycle.LaunchDelivery != nil {
		t.Fatalf("AuthorizeLaunch(expired) = (%#v, %v), want cleanup-pending without authorization", cleanup, err)
	}
}

func TestSessionAllowsPreLaunchAmbiguityToConvergeThroughCleanupWithoutInventingALaunchDelivery(t *testing.T) {
	now := time.Date(2026, time.August, 10, 18, 0, 0, 0, time.UTC)
	deliveryState, err := NewState(validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	session, err := NewSession(deliveryState)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	pending, err := session.BeginCleanup()
	if err != nil || pending.Lifecycle.Phase != LifecycleCleanupPending || pending.Lifecycle.LaunchDelivery != nil {
		t.Fatalf("BeginCleanup(prepared) = (%#v, %v), want cleanup-pending without a fabricated launch delivery", pending, err)
	}
	confirmed, err := pending.ConfirmCleanup()
	if err != nil || confirmed.Lifecycle.Phase != LifecycleCleanupConfirmed || confirmed.Lifecycle.LaunchDelivery != nil {
		t.Fatalf("ConfirmCleanup() = (%#v, %v), want terminal cleanup-confirmed without a fabricated launch delivery", confirmed, err)
	}
}

func TestSessionTurnsAnAuthorizedStaleDeliveryIntoCleanupInsteadOfAuthorizingARelaunch(t *testing.T) {
	now := time.Date(2026, time.August, 10, 18, 0, 0, 0, time.UTC)
	deliveryState, err := NewState(validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	session, err := NewSession(deliveryState)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	authorized, err := session.AuthorizeLaunch(now)
	if err != nil {
		t.Fatalf("AuthorizeLaunch() error = %v", err)
	}
	renewed, err := authorized.AcceptAuthenticatedSuccessor(exactSuccessor(deliveryState.Current, now.Add(time.Minute)), now.Add(time.Minute))
	if err != nil || renewed.Lifecycle.Phase != LifecycleCleanupPending {
		t.Fatalf("AcceptAuthenticatedSuccessor(authorized) = (%#v, %v), want cleanup-pending without a second authorization", renewed, err)
	}
	if _, err := renewed.RecordLaunchStarted(now.Add(time.Minute)); !errors.Is(err, ErrLifecycleTransitionRefused) {
		t.Fatalf("RecordLaunchStarted(stale authorized delivery) error = %v, want ErrLifecycleTransitionRefused", err)
	}
	if renewed.Lifecycle.LaunchDelivery == nil || *renewed.Lifecycle.LaunchDelivery != deliveryState.Current {
		t.Fatalf("renewed lifecycle launch delivery = %#v, want retained original delivery", renewed.Lifecycle.LaunchDelivery)
	}
}

func TestSessionUsesOneCanonicalWireAndRejectsDetachedLifecycleMeaning(t *testing.T) {
	now := time.Date(2026, time.August, 10, 18, 0, 0, 0, time.UTC)
	deliveryState, err := NewState(validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	session, err := NewSession(deliveryState)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	authorized, err := session.AuthorizeLaunch(now)
	if err != nil {
		t.Fatalf("AuthorizeLaunch() error = %v", err)
	}
	wire, err := EncodeSession(authorized)
	if err != nil {
		t.Fatalf("EncodeSession() error = %v", err)
	}
	recovered, err := DecodeSession(wire)
	if err != nil || !reflect.DeepEqual(recovered, authorized) {
		t.Fatalf("DecodeSession(EncodeSession()) = (%#v, %v), want (%#v, nil)", recovered, err, authorized)
	}
	detached := authorized
	detached.Lifecycle.LaunchDelivery = &Delivery{EnvelopeID: "envelope-unknown", DeliveryID: "delivery-unknown", Nonce: "MDEyMzQ1Njc4OWFiY2RlZg", IssuedAt: now, ExpiresAt: now.Add(time.Minute), LeaseEpoch: 99, FencingToken: 99}
	if _, err := EncodeSession(detached); !errors.Is(err, ErrInvalidLifecycle) {
		t.Fatalf("EncodeSession(detached lifecycle) error = %v, want ErrInvalidLifecycle", err)
	}
	if _, err := DecodeSession(append([]byte(" "), wire...)); !errors.Is(err, ErrInvalidLifecycle) {
		t.Fatalf("DecodeSession(non-canonical) error = %v, want ErrInvalidLifecycle", err)
	}
}
