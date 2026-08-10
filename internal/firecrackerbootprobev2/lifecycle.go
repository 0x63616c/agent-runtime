package firecrackerbootprobev2

import (
	"bytes"
	"encoding/json"
	"io"
	"time"

	"github.com/cockroachdb/errors"
)

var (
	// ErrInvalidLifecycle identifies malformed, detached, or non-canonical private boot-probe v2 session lifecycle state.
	ErrInvalidLifecycle = errors.New("invalid Firecracker boot-probe v2 lifecycle")
	// ErrLifecycleTransitionRefused identifies a lifecycle transition that could relaunch a boot probe or skip required cleanup.
	ErrLifecycleTransitionRefused = errors.New("Firecracker boot-probe v2 lifecycle transition refused")
)

const (
	sessionVersion          = "firecracker-boot-probe/session/v2"
	maximumSessionWireBytes = 64 << 10
)

// LifecyclePhase is one irreversible private boot-probe session lifecycle phase.
type LifecyclePhase string

const (
	// LifecyclePrepared means the delivery chain exists but no launch has been authorized.
	LifecyclePrepared LifecyclePhase = "prepared"
	// LifecycleLaunchAuthorized means exactly State.Current was authorized for one possible launch.
	LifecycleLaunchAuthorized LifecyclePhase = "launch-authorized"
	// LifecycleLaunchStarted means the exact authorized current delivery recorded an irreversible launch start.
	LifecycleLaunchStarted LifecyclePhase = "launch-started"
	// LifecycleCleanupPending means future launch is prohibited until the host records cleanup completion.
	LifecycleCleanupPending LifecyclePhase = "cleanup-pending"
	// LifecycleCleanupConfirmed means cleanup completed and this session can never authorize or start another launch.
	LifecycleCleanupConfirmed LifecyclePhase = "cleanup-confirmed"
)

// Lifecycle is the effect-free irreversible part of one private boot-probe session.
// LaunchDelivery identifies the delivery that was allowed to start once; it remains nil when cleanup began before any launch authorization.
type Lifecycle struct {
	Phase          LifecyclePhase `json:"phase"`
	LaunchDelivery *Delivery      `json:"launch_delivery,omitempty"`
}

// Session binds the private lifecycle to its one canonical v2 delivery chain so a durable store can persist both under one CAS record.
// It is a value object: its transitions return a new Session and never cause a launch or cleanup effect.
type Session struct {
	Version   string    `json:"version"`
	Delivery  State     `json:"delivery"`
	Lifecycle Lifecycle `json:"lifecycle"`
}

// NewSession creates a prepared lifecycle bound to an already-valid private boot-probe v2 delivery state.
func NewSession(delivery State) (Session, error) {
	if len(delivery.Superseded) != 0 {
		return Session{}, errors.Wrap(ErrInvalidLifecycle, "refuse recreated Firecracker boot-probe v2 lifecycle after delivery renewal")
	}
	session := Session{Version: sessionVersion, Delivery: delivery, Lifecycle: Lifecycle{Phase: LifecyclePrepared}}
	if err := session.Validate(); err != nil {
		return Session{}, err
	}
	return session, nil
}

// AuthorizeLaunch records that the exact current delivery may start one launch.
// It is a pure authorization transition; durable CAS and all host effects belong to later adapters.
func (session Session) AuthorizeLaunch(now time.Time) (Session, error) {
	if err := session.Validate(); err != nil {
		return Session{}, err
	}
	if session.Lifecycle.Phase != LifecyclePrepared {
		return Session{}, errors.Wrap(ErrLifecycleTransitionRefused, "authorize Firecracker boot-probe v2 launch")
	}
	if !validTimestamp(now) || now.Before(session.Delivery.Current.IssuedAt) {
		return Session{}, errors.Wrap(ErrLifecycleTransitionRefused, "authorize Firecracker boot-probe v2 launch outside delivery lifetime")
	}
	if !now.Before(session.Delivery.Current.ExpiresAt) {
		return session.BeginCleanup()
	}
	next := session.clone()
	delivery := next.Delivery.Current
	next.Lifecycle = Lifecycle{Phase: LifecycleLaunchAuthorized, LaunchDelivery: &delivery}
	return next.validTransition("authorize Firecracker boot-probe v2 launch")
}

// RecordLaunchStarted records an irreversible launch start only for the exact authorized delivery while it remains current and unexpired.
// When authorization has expired, it returns cleanup-pending instead of recording a launch start.
func (session Session) RecordLaunchStarted(now time.Time) (Session, error) {
	if err := session.Validate(); err != nil {
		return Session{}, err
	}
	if session.Lifecycle.Phase != LifecycleLaunchAuthorized || session.Lifecycle.LaunchDelivery == nil || !sameDelivery(*session.Lifecycle.LaunchDelivery, session.Delivery.Current) {
		return Session{}, errors.Wrap(ErrLifecycleTransitionRefused, "record Firecracker boot-probe v2 launch start")
	}
	if !validTimestamp(now) || now.Before(session.Delivery.Current.IssuedAt) {
		return Session{}, errors.Wrap(ErrLifecycleTransitionRefused, "record Firecracker boot-probe v2 launch start outside delivery lifetime")
	}
	if !now.Before(session.Delivery.Current.ExpiresAt) {
		return session.BeginCleanup()
	}
	next := session.clone()
	next.Lifecycle.Phase = LifecycleLaunchStarted
	return next.validTransition("record Firecracker boot-probe v2 launch start")
}

// BeginCleanup irreversibly prohibits launch and records that cleanup must be completed.
// It may be used before launch when authority becomes ambiguous, expired, or revoked.
func (session Session) BeginCleanup() (Session, error) {
	if err := session.Validate(); err != nil {
		return Session{}, err
	}
	switch session.Lifecycle.Phase {
	case LifecyclePrepared, LifecycleLaunchAuthorized, LifecycleLaunchStarted:
		next := session.clone()
		next.Lifecycle.Phase = LifecycleCleanupPending
		return next.validTransition("begin Firecracker boot-probe v2 cleanup")
	default:
		return Session{}, errors.Wrap(ErrLifecycleTransitionRefused, "begin Firecracker boot-probe v2 cleanup")
	}
}

// ConfirmCleanup records the terminal cleanup confirmation after cleanup was required.
func (session Session) ConfirmCleanup() (Session, error) {
	if err := session.Validate(); err != nil {
		return Session{}, err
	}
	if session.Lifecycle.Phase != LifecycleCleanupPending {
		return Session{}, errors.Wrap(ErrLifecycleTransitionRefused, "confirm Firecracker boot-probe v2 cleanup")
	}
	next := session.clone()
	next.Lifecycle.Phase = LifecycleCleanupConfirmed
	return next.validTransition("confirm Firecracker boot-probe v2 cleanup")
}

// AcceptAuthenticatedSuccessor advances the delivery chain without letting a renewed delivery reuse a stale launch authorization.
// A prepared session remains prepared; an authorized-but-not-started session converges to cleanup-pending; terminal cleanup cannot renew.
func (session Session) AcceptAuthenticatedSuccessor(successor Delivery, now time.Time) (Session, error) {
	if err := session.Validate(); err != nil {
		return Session{}, err
	}
	if session.Lifecycle.Phase == LifecycleCleanupConfirmed {
		return Session{}, errors.Wrap(ErrLifecycleTransitionRefused, "renew cleaned Firecracker boot-probe v2 session")
	}
	nextDelivery, err := session.Delivery.AcceptAuthenticatedSuccessor(session.Delivery.HostInstanceSessionID, successor, now)
	if err != nil {
		return Session{}, errors.Wrap(err, "renew Firecracker boot-probe v2 session delivery")
	}
	next := session.clone()
	next.Delivery = nextDelivery
	if next.Lifecycle.Phase == LifecycleLaunchAuthorized {
		next.Lifecycle.Phase = LifecycleCleanupPending
	}
	return next.validTransition("renew Firecracker boot-probe v2 session")
}

// EncodeSession writes one canonical private boot-probe v2 compound session suitable for persistence next to its CAS version.
func EncodeSession(session Session) ([]byte, error) {
	if err := session.Validate(); err != nil {
		return nil, err
	}
	wire, err := json.Marshal(session)
	if err != nil || len(wire) > maximumSessionWireBytes {
		return nil, errors.Wrap(ErrInvalidLifecycle, "encode bounded canonical Firecracker boot-probe v2 session")
	}
	return wire, nil
}

// DecodeSession reads one canonical private boot-probe v2 compound session.
func DecodeSession(wire []byte) (Session, error) {
	if len(wire) == 0 || len(wire) > maximumSessionWireBytes {
		return Session{}, errors.Wrap(ErrInvalidLifecycle, "decode bounded Firecracker boot-probe v2 session")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var session Session
	if err := decoder.Decode(&session); err != nil {
		return Session{}, errors.Wrap(ErrInvalidLifecycle, "decode Firecracker boot-probe v2 session")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Session{}, errors.Wrap(ErrInvalidLifecycle, "decode trailing Firecracker boot-probe v2 session")
	}
	if err := session.Validate(); err != nil {
		return Session{}, err
	}
	canonical, err := EncodeSession(session)
	if err != nil || !bytes.Equal(canonical, wire) {
		return Session{}, errors.Wrap(ErrInvalidLifecycle, "decode non-canonical Firecracker boot-probe v2 session")
	}
	return session, nil
}

// Validate verifies that the lifecycle has no separate delivery identity or legal relaunch path.
func (session Session) Validate() error {
	if session.Version != sessionVersion {
		return errors.Wrap(ErrInvalidLifecycle, "validate Firecracker boot-probe v2 session version")
	}
	if err := session.Delivery.Validate(); err != nil {
		return errors.Wrap(ErrInvalidLifecycle, "validate Firecracker boot-probe v2 session delivery")
	}
	switch session.Lifecycle.Phase {
	case LifecyclePrepared:
		if session.Lifecycle.LaunchDelivery != nil {
			return errors.Wrap(ErrInvalidLifecycle, "validate prepared Firecracker boot-probe v2 session")
		}
		return nil
	case LifecycleLaunchAuthorized:
		if session.Lifecycle.LaunchDelivery == nil || !sameDelivery(*session.Lifecycle.LaunchDelivery, session.Delivery.Current) {
			return errors.Wrap(ErrInvalidLifecycle, "validate exact authorized Firecracker boot-probe v2 delivery")
		}
	case LifecycleLaunchStarted:
		if session.Lifecycle.LaunchDelivery == nil || !deliveryInState(*session.Lifecycle.LaunchDelivery, session.Delivery) {
			return errors.Wrap(ErrInvalidLifecycle, "validate retained Firecracker boot-probe v2 launch delivery")
		}
	case LifecycleCleanupPending, LifecycleCleanupConfirmed:
		if session.Lifecycle.LaunchDelivery != nil && !deliveryInState(*session.Lifecycle.LaunchDelivery, session.Delivery) {
			return errors.Wrap(ErrInvalidLifecycle, "validate retained Firecracker boot-probe v2 cleanup delivery")
		}
	default:
		return errors.Wrap(ErrInvalidLifecycle, "validate Firecracker boot-probe v2 lifecycle phase")
	}
	return nil
}

func (session Session) clone() Session {
	next := session
	if session.Lifecycle.LaunchDelivery != nil {
		delivery := *session.Lifecycle.LaunchDelivery
		next.Lifecycle.LaunchDelivery = &delivery
	}
	return next
}

func (session Session) validTransition(action string) (Session, error) {
	if err := session.Validate(); err != nil {
		return Session{}, errors.Wrap(ErrLifecycleTransitionRefused, action)
	}
	return session, nil
}

func sameDelivery(left, right Delivery) bool {
	return left == right
}

func deliveryInState(candidate Delivery, state State) bool {
	if sameDelivery(candidate, state.Current) {
		return true
	}
	for _, delivery := range state.Superseded {
		if sameDelivery(candidate, delivery) {
			return true
		}
	}
	return false
}
