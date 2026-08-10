// Package firecrackerbootprobelease owns the private persisted lease guard for one sealed Firecracker boot probe.
package firecrackerbootprobelease

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"sync"
	"time"

	"github.com/0x63616c/agent-runtime/internal/firecrackerlaunchgrant"
	"github.com/cockroachdb/errors"
)

var (
	// ErrInvalidState identifies a malformed or non-canonical persisted boot-probe lease state.
	ErrInvalidState = errors.New("invalid Firecracker boot-probe lease state")
	// ErrRenewalRefused identifies a stale, forked, mismatched, or non-successive authenticated renewal.
	ErrRenewalRefused = errors.New("Firecracker boot-probe renewal refused")
	// ErrLeaseExpired identifies an expired lease that must remain cleanup-pending.
	ErrLeaseExpired = errors.New("Firecracker boot-probe lease expired")
	// ErrProbeAlreadyStarted identifies a duplicate probe-start transition.
	ErrProbeAlreadyStarted = errors.New("Firecracker boot probe already started")
)

const (
	stateVersion = "firecracker-boot-probe-lease/v1"

	maximumWireBytes = 40 << 10
)

// Phase is the durable lifecycle phase of a private boot-probe lease.
type Phase string

const (
	// PhaseActive means the current grant is not yet expired and may be renewed or recorded as started.
	PhaseActive Phase = "active"
	// PhaseExpiredCleanupPending means expiry was observed and no later transition may revive or launch the probe.
	PhaseExpiredCleanupPending Phase = "expired-cleanup-pending"
)

// Probe is the persisted, effect-free boot-probe intent state.
type Probe string

const (
	// ProbePending means no probe start was durably recorded.
	ProbePending Probe = "pending"
	// ProbeStarted means the one allowed probe start was durably recorded; a restart or renewal must never start it again.
	ProbeStarted Probe = "started"
)

// State is the serializable, redacted snapshot for one sealed private boot-probe lease.
// Initial never changes. Current advances only through the next exact authenticated delivery tuple and fence.
// The state includes no control signature, raw request, credential, host path, or guest output.
type State struct {
	Version          string                       `json:"version"`
	Initial          firecrackerlaunchgrant.Grant `json:"initial"`
	Current          firecrackerlaunchgrant.Grant `json:"current"`
	Phase            Phase                        `json:"phase"`
	Probe            Probe                        `json:"probe"`
	ProbeStartedAt   time.Time                    `json:"probe_started_at,omitempty"`
	CleanupPendingAt time.Time                    `json:"cleanup_pending_at,omitempty"`
	RenewalCount     uint64                       `json:"renewal_count"`
}

// Guard serializes transitions for one recovered or newly sealed State.
// Persist callers store Snapshot with their own expected-version/CAS boundary; Guard prevents in-process renewal forks.
type Guard struct {
	mu    sync.Mutex
	state State
}

// NewGuard seals an already-authenticated initial grant into an active private lease state.
func NewGuard(initial firecrackerlaunchgrant.Grant, now time.Time) (*Guard, error) {
	state, err := seal(initial, now)
	if err != nil {
		return nil, err
	}
	return &Guard{state: state}, nil
}

// Restore recovers a Guard from an already-decoded, validated state snapshot.
func Restore(state State) (*Guard, error) {
	if err := state.Validate(); err != nil {
		return nil, err
	}
	return &Guard{state: state}, nil
}

// Snapshot returns the exact serializable state after the last accepted transition.
func (guard *Guard) Snapshot() State {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	return guard.state
}

// AdvanceTime records expiry as cleanup-pending. It never infers cleanup and never revives an expired lease.
func (guard *Guard) AdvanceTime(now time.Time) (State, error) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if err := validNow(now); err != nil {
		return guard.state, err
	}
	if err := guard.state.Validate(); err != nil {
		return guard.state, err
	}
	guard.advanceTimeLocked(now)
	return guard.state, nil
}

// RecordProbeStarted records one durable probe-start intent without launching a Jailer, VMM, guest, or PING.
func (guard *Guard) RecordProbeStarted(now time.Time) (State, error) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if err := validNow(now); err != nil {
		return guard.state, err
	}
	if err := guard.state.Validate(); err != nil {
		return guard.state, err
	}
	guard.advanceTimeLocked(now)
	if guard.state.Phase != PhaseActive {
		return guard.state, ErrLeaseExpired
	}
	if guard.state.Probe == ProbeStarted {
		return guard.state, ErrProbeAlreadyStarted
	}
	if now.Before(guard.state.Current.Envelope.IssuedAt) {
		return guard.state, errors.Wrap(ErrInvalidState, "record probe before current grant issuance")
	}
	guard.state.Probe, guard.state.ProbeStartedAt = ProbeStarted, now.UTC()
	return guard.state, nil
}

// RenewAuthenticated accepts exactly the next already-authenticated renewal for this Guard.
// Callers authenticate the M3 envelope and derive the trusted M4 identity before passing renewal here.
// A renewal changes only Current and RenewalCount; it cannot create a new probe-start authorization.
func (guard *Guard) RenewAuthenticated(renewal firecrackerlaunchgrant.Grant, now time.Time) (State, error) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if err := validNow(now); err != nil {
		return guard.state, err
	}
	if err := guard.state.Validate(); err != nil {
		return guard.state, err
	}
	guard.advanceTimeLocked(now)
	if guard.state.Phase != PhaseActive {
		return guard.state, ErrLeaseExpired
	}
	if err := validRenewal(guard.state.Current, renewal, now); err != nil {
		return guard.state, err
	}
	guard.state.Current = renewal
	guard.state.RenewalCount++
	return guard.state, nil
}

// CleanupPending reports whether expiry has been durably surfaced for operator-owned cleanup.
func (state State) CleanupPending() bool {
	return state.Phase == PhaseExpiredCleanupPending
}

// Encode writes canonical private state bytes suitable for persistence or replay.
func Encode(state State) ([]byte, error) {
	if err := state.Validate(); err != nil {
		return nil, err
	}
	wire, err := json.Marshal(state)
	if err != nil || len(wire) > maximumWireBytes {
		return nil, errors.Wrap(ErrInvalidState, "encode bounded canonical lease state")
	}
	return wire, nil
}

// Decode reads one canonical persisted private state snapshot.
func Decode(wire []byte) (State, error) {
	if len(wire) == 0 || len(wire) > maximumWireBytes {
		return State{}, errors.Wrap(ErrInvalidState, "decode bounded lease state")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var state State
	if err := decoder.Decode(&state); err != nil {
		return State{}, errors.Wrap(ErrInvalidState, "decode lease state")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return State{}, errors.Wrap(ErrInvalidState, "decode trailing lease state data")
	}
	if err := state.Validate(); err != nil {
		return State{}, err
	}
	canonical, err := Encode(state)
	if err != nil || !bytes.Equal(canonical, wire) {
		return State{}, errors.Wrap(ErrInvalidState, "decode non-canonical lease state")
	}
	return state, nil
}

// Validate verifies that State is a redacted replay-safe snapshot of one linear lease chain.
func (state State) Validate() error {
	if state.Version != stateVersion || state.Phase != PhaseActive && state.Phase != PhaseExpiredCleanupPending || state.Probe != ProbePending && state.Probe != ProbeStarted {
		return errors.Wrap(ErrInvalidState, "validate lease state version or enum")
	}
	if err := state.Initial.Validate(); err != nil {
		return errors.Wrap(ErrInvalidState, "validate initial grant")
	}
	if err := state.Current.Validate(); err != nil {
		return errors.Wrap(ErrInvalidState, "validate current grant")
	}
	if !sameSealedScope(state.Initial, state.Current) || state.Initial.M4 != state.Current.M4 {
		return errors.Wrap(ErrInvalidState, "validate immutable sealed grant binding")
	}
	if state.Initial.Envelope.LeaseEpoch > math.MaxUint64-state.RenewalCount || state.Initial.Envelope.FencingToken > math.MaxUint64-state.RenewalCount || state.Current.Envelope.LeaseEpoch != state.Initial.Envelope.LeaseEpoch+state.RenewalCount || state.Current.Envelope.FencingToken != state.Initial.Envelope.FencingToken+state.RenewalCount {
		return errors.Wrap(ErrInvalidState, "validate monotonic lease and fence")
	}
	if state.RenewalCount == 0 && state.Current != state.Initial {
		return errors.Wrap(ErrInvalidState, "validate initial current grant")
	}
	if state.RenewalCount > 0 && (!newDeliveryTuple(state.Initial.Envelope, state.Current.Envelope) || !strictlyLaterGrant(state.Initial, state.Current)) {
		return errors.Wrap(ErrInvalidState, "validate renewed current grant")
	}
	if state.Probe == ProbePending && !state.ProbeStartedAt.IsZero() || state.Probe == ProbeStarted && (!validTimestamp(state.ProbeStartedAt) || state.ProbeStartedAt.Before(state.Initial.Envelope.IssuedAt) || !state.ProbeStartedAt.Before(state.Current.Envelope.ExpiresAt)) {
		return errors.Wrap(ErrInvalidState, "validate probe-start transition")
	}
	if state.Phase == PhaseActive && !state.CleanupPendingAt.IsZero() {
		return errors.Wrap(ErrInvalidState, "validate active cleanup state")
	}
	if state.Phase == PhaseExpiredCleanupPending && (!validTimestamp(state.CleanupPendingAt) || state.CleanupPendingAt.Before(state.Current.Envelope.ExpiresAt)) {
		return errors.Wrap(ErrInvalidState, "validate expiry cleanup state")
	}
	return nil
}

func seal(initial firecrackerlaunchgrant.Grant, now time.Time) (State, error) {
	if err := validNow(now); err != nil {
		return State{}, err
	}
	if err := initial.Validate(); err != nil {
		return State{}, errors.Wrap(ErrInvalidState, "seal valid initial grant")
	}
	if now.Before(initial.Envelope.IssuedAt) || !now.Before(initial.Envelope.ExpiresAt) {
		return State{}, errors.Wrap(ErrLeaseExpired, "seal live initial grant")
	}
	return State{Version: stateVersion, Initial: initial, Current: initial, Phase: PhaseActive, Probe: ProbePending}, nil
}

func (guard *Guard) advanceTimeLocked(now time.Time) {
	if guard.state.Phase == PhaseActive && !now.Before(guard.state.Current.Envelope.ExpiresAt) {
		guard.state.Phase, guard.state.CleanupPendingAt = PhaseExpiredCleanupPending, now.UTC()
	}
}

func validRenewal(current, renewal firecrackerlaunchgrant.Grant, now time.Time) error {
	if err := renewal.Validate(); err != nil {
		return errors.Wrap(ErrRenewalRefused, "validate renewal grant")
	}
	if !sameSealedScope(current, renewal) || current.M4 != renewal.M4 || current.GuestProtocol != renewal.GuestProtocol || current.SerialMarker != renewal.SerialMarker || current.Envelope.LeaseEpoch == math.MaxUint64 || current.Envelope.FencingToken == math.MaxUint64 || renewal.Envelope.LeaseEpoch != current.Envelope.LeaseEpoch+1 || renewal.Envelope.FencingToken != current.Envelope.FencingToken+1 || !newDeliveryTuple(current.Envelope, renewal.Envelope) || !strictlyLaterGrant(current, renewal) || renewal.Envelope.IssuedAt.After(now) || !now.Before(renewal.Envelope.ExpiresAt) {
		return errors.Wrap(ErrRenewalRefused, "validate exact renewal successor")
	}
	return nil
}

func sameSealedScope(left, right firecrackerlaunchgrant.Grant) bool {
	return left.Version == right.Version && left.M4 == right.M4 && left.GuestProtocol == right.GuestProtocol && left.SerialMarker == right.SerialMarker && left.Envelope.HostID == right.Envelope.HostID && left.Envelope.HostGeneration == right.Envelope.HostGeneration && left.Envelope.AssignmentID == right.Envelope.AssignmentID && left.Envelope.Tenant == right.Envelope.Tenant && left.Envelope.Principal == right.Envelope.Principal && left.Envelope.SandboxID == right.Envelope.SandboxID && left.Envelope.OperationID == right.Envelope.OperationID && left.Envelope.OperationKind == right.Envelope.OperationKind && left.Envelope.EffectiveSpecDigest == right.Envelope.EffectiveSpecDigest && left.Envelope.CapabilityDigest == right.Envelope.CapabilityDigest && left.Envelope.CanonicalRequestDigest == right.Envelope.CanonicalRequestDigest
}

func newDeliveryTuple(current, renewal firecrackerlaunchgrant.EnvelopeTuple) bool {
	return current.EnvelopeID != renewal.EnvelopeID && current.DeliveryID != renewal.DeliveryID && current.Nonce != renewal.Nonce
}

func strictlyLaterGrant(current, renewal firecrackerlaunchgrant.Grant) bool {
	return renewal.Envelope.IssuedAt.After(current.Envelope.IssuedAt) && renewal.Envelope.ExpiresAt.After(current.Envelope.ExpiresAt)
}

func validNow(now time.Time) error {
	if !validTimestamp(now) {
		return errors.Wrap(ErrInvalidState, "validate UTC transition time")
	}
	return nil
}

func validTimestamp(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC
}
