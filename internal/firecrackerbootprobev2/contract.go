// Package firecrackerbootprobev2 owns the private, persisted successor and acknowledgement contract for one sealed Firecracker boot-probe lease.
package firecrackerbootprobev2

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/0x63616c/agent-runtime/sandbox"
	"github.com/cockroachdb/errors"
	"golang.org/x/text/unicode/norm"
)

var (
	// ErrInvalidState identifies malformed, widened, or non-canonical private boot-probe v2 state.
	ErrInvalidState = errors.New("invalid Firecracker boot-probe v2 state")
	// ErrSuccessorRefused identifies a stale, forked, cross-instance, or non-successive authenticated delivery.
	ErrSuccessorRefused = errors.New("Firecracker boot-probe v2 successor refused")
	// ErrInvalidAcknowledgement identifies a malformed acknowledgement that cannot be classified.
	ErrInvalidAcknowledgement = errors.New("invalid Firecracker boot-probe v2 acknowledgement")
)

const (
	stateVersion      = "firecracker-boot-probe/v2"
	operatorBootProbe = "firecracker-boot-probe"
	maximumWireBytes  = 48 << 10
	maximumHistory    = 64
)

// Binding is the immutable, redacted control tuple shared by every delivery in one private boot-probe lease chain.
// It contains bounded opaque identities and digests, never a signed envelope, request payload, credential, or host path.
type Binding struct {
	HostID                 string         `json:"host_id"`
	HostGeneration         uint64         `json:"host_generation"`
	AssignmentID           string         `json:"assignment_id"`
	Tenant                 string         `json:"tenant"`
	Principal              string         `json:"principal"`
	SandboxID              string         `json:"sandbox_id"`
	OperationID            string         `json:"operation_id"`
	OperationKind          string         `json:"operation_kind"`
	EffectiveSpecDigest    sandbox.Digest `json:"effective_spec_digest"`
	CapabilityDigest       sandbox.Digest `json:"capability_digest"`
	CanonicalRequestDigest sandbox.Digest `json:"canonical_request_digest"`
}

// Delivery is the bounded metadata for one already-authenticated control delivery.
// Nonce is canonical raw base64url text, so encoding differences cannot create distinct delivery identities.
type Delivery struct {
	DeliveryID   string    `json:"delivery_id"`
	Nonce        string    `json:"nonce"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	LeaseEpoch   uint64    `json:"lease_epoch"`
	FencingToken uint64    `json:"fencing_token"`
}

// State is the canonical private persisted state for one host-instance session.
// Superseded is ordered oldest first and retained only to classify delayed exact acknowledgements; it is not a launch queue.
type State struct {
	Version               string     `json:"version"`
	Binding               Binding    `json:"binding"`
	HostInstanceSessionID string     `json:"host_instance_session_id"`
	Current               Delivery   `json:"current"`
	Superseded            []Delivery `json:"superseded"`
}

// Acknowledgement identifies one host acknowledgement without carrying payload, output, credentials, or signatures.
type Acknowledgement struct {
	HostInstanceSessionID string `json:"host_instance_session_id"`
	DeliveryID            string `json:"delivery_id"`
	Nonce                 string `json:"nonce"`
	LeaseEpoch            uint64 `json:"lease_epoch"`
	FencingToken          uint64 `json:"fencing_token"`
}

// AcknowledgementClassification tells a caller whether an exact acknowledgement is current, retained as superseded, or unknown.
type AcknowledgementClassification string

const (
	// AcknowledgementCurrent means the acknowledgement identifies State.Current exactly.
	AcknowledgementCurrent AcknowledgementClassification = "current"
	// AcknowledgementKnownSuperseded means the acknowledgement identifies a retained earlier delivery exactly and must not revive it.
	AcknowledgementKnownSuperseded AcknowledgementClassification = "known-superseded"
	// AcknowledgementUnknown means a valid acknowledgement is not part of this host-instance lease chain.
	AcknowledgementUnknown AcknowledgementClassification = "unknown"
)

// NewState seals one already-authenticated initial delivery under its immutable control binding and host-instance session.
func NewState(binding Binding, hostInstanceSessionID string, initial Delivery, now time.Time) (State, error) {
	state := State{Version: stateVersion, Binding: binding, HostInstanceSessionID: hostInstanceSessionID, Current: initial, Superseded: []Delivery{}}
	if !validTimestamp(now) || !binding.valid() || !validSessionID(hostInstanceSessionID) || !initial.valid() || now.Before(initial.IssuedAt) || !now.Before(initial.ExpiresAt) {
		return State{}, errors.Wrap(ErrInvalidState, "seal initial boot-probe v2 state")
	}
	if err := state.Validate(); err != nil {
		return State{}, err
	}
	return state, nil
}

// AcceptAuthenticatedSuccessor appends exactly the next authenticated delivery for this same host-instance session.
// Authentication and durable compare-and-swap are caller-owned; this pure contract neither launches a guest nor stores state.
func (state State) AcceptAuthenticatedSuccessor(hostInstanceSessionID string, successor Delivery, now time.Time) (State, error) {
	if err := state.Validate(); err != nil {
		return State{}, err
	}
	if !validTimestamp(now) || hostInstanceSessionID != state.HostInstanceSessionID || !validSuccessor(state, successor, now) {
		return State{}, errors.Wrap(ErrSuccessorRefused, "accept exact boot-probe v2 successor")
	}
	next := state
	next.Superseded = append(append([]Delivery(nil), state.Superseded...), state.Current)
	next.Current = successor
	if err := next.Validate(); err != nil {
		return State{}, errors.Wrap(ErrSuccessorRefused, "accept persistable boot-probe v2 successor")
	}
	return next, nil
}

// ClassifyAcknowledgement identifies a current, known-superseded, or unknown exact acknowledgement without producing effects.
func (state State) ClassifyAcknowledgement(acknowledgement Acknowledgement) (AcknowledgementClassification, error) {
	if err := state.Validate(); err != nil {
		return "", err
	}
	if !acknowledgement.valid() {
		return "", errors.Wrap(ErrInvalidAcknowledgement, "validate boot-probe v2 acknowledgement")
	}
	if acknowledgement.HostInstanceSessionID != state.HostInstanceSessionID {
		return AcknowledgementUnknown, nil
	}
	if acknowledgement.matches(state.Current) {
		return AcknowledgementCurrent, nil
	}
	for _, delivery := range state.Superseded {
		if acknowledgement.matches(delivery) {
			return AcknowledgementKnownSuperseded, nil
		}
	}
	return AcknowledgementUnknown, nil
}

// Encode writes canonical private boot-probe v2 state bytes suitable for caller-owned persistence.
func Encode(state State) ([]byte, error) {
	if err := state.Validate(); err != nil {
		return nil, err
	}
	wire, err := json.Marshal(state)
	if err != nil || len(wire) > maximumWireBytes {
		return nil, errors.Wrap(ErrInvalidState, "encode bounded canonical boot-probe v2 state")
	}
	return wire, nil
}

// Decode reads one canonical private boot-probe v2 state snapshot.
func Decode(wire []byte) (State, error) {
	if len(wire) == 0 || len(wire) > maximumWireBytes {
		return State{}, errors.Wrap(ErrInvalidState, "decode bounded boot-probe v2 state")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var state State
	if err := decoder.Decode(&state); err != nil {
		return State{}, errors.Wrap(ErrInvalidState, "decode boot-probe v2 state")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return State{}, errors.Wrap(ErrInvalidState, "decode trailing boot-probe v2 state")
	}
	if err := state.Validate(); err != nil {
		return State{}, err
	}
	canonical, err := Encode(state)
	if err != nil || !bytes.Equal(canonical, wire) {
		return State{}, errors.Wrap(ErrInvalidState, "decode non-canonical boot-probe v2 state")
	}
	return state, nil
}

// Validate verifies State is one linear, immutable boot-probe delivery chain with no reusable delivery identity.
func (state State) Validate() error {
	if state.Version != stateVersion || !state.Binding.valid() || !validSessionID(state.HostInstanceSessionID) || !state.Current.valid() || len(state.Superseded) > maximumHistory {
		return errors.Wrap(ErrInvalidState, "validate boot-probe v2 state shape")
	}
	seenDeliveryIDs := map[string]struct{}{state.Current.DeliveryID: {}}
	seenNonces := map[string]struct{}{state.Current.Nonce: {}}
	previous := Delivery{}
	for index, delivery := range state.Superseded {
		if !delivery.valid() {
			return errors.Wrap(ErrInvalidState, "validate superseded boot-probe v2 delivery")
		}
		if _, exists := seenDeliveryIDs[delivery.DeliveryID]; exists {
			return errors.Wrap(ErrInvalidState, "validate unique boot-probe v2 delivery ID")
		}
		if _, exists := seenNonces[delivery.Nonce]; exists {
			return errors.Wrap(ErrInvalidState, "validate unique boot-probe v2 nonce")
		}
		seenDeliveryIDs[delivery.DeliveryID] = struct{}{}
		seenNonces[delivery.Nonce] = struct{}{}
		if index > 0 && !isExactSuccessor(previous, delivery) {
			return errors.Wrap(ErrInvalidState, "validate linear superseded boot-probe v2 history")
		}
		previous = delivery
	}
	if len(state.Superseded) > 0 && !isExactSuccessor(previous, state.Current) {
		return errors.Wrap(ErrInvalidState, "validate current boot-probe v2 successor")
	}
	if wire, err := json.Marshal(state); err != nil || len(wire) > maximumWireBytes {
		return errors.Wrap(ErrInvalidState, "validate bounded canonical boot-probe v2 state")
	}
	return nil
}

func validSuccessor(state State, successor Delivery, now time.Time) bool {
	if len(state.Superseded) >= maximumHistory || !successor.valid() || !now.Before(state.Current.ExpiresAt) || successor.IssuedAt.After(now) || !now.Before(successor.ExpiresAt) || !isExactSuccessor(state.Current, successor) {
		return false
	}
	for _, delivery := range append(append([]Delivery(nil), state.Superseded...), state.Current) {
		if successor.DeliveryID == delivery.DeliveryID || successor.Nonce == delivery.Nonce {
			return false
		}
	}
	return true
}

func isExactSuccessor(previous, successor Delivery) bool {
	return previous.LeaseEpoch != math.MaxUint64 && previous.FencingToken != math.MaxUint64 && successor.LeaseEpoch == previous.LeaseEpoch+1 && successor.FencingToken == previous.FencingToken+1 && successor.IssuedAt.After(previous.IssuedAt) && successor.ExpiresAt.After(previous.ExpiresAt)
}

func (binding Binding) valid() bool {
	return validID(binding.HostID, 128) && binding.HostGeneration > 0 && validID(binding.AssignmentID, 128) && validID(binding.Tenant, 256) && validID(binding.Principal, 512) && strings.HasPrefix(binding.Principal, binding.Tenant+":") && validID(binding.SandboxID, 128) && validID(binding.OperationID, 128) && binding.OperationKind == operatorBootProbe && validDigest(binding.EffectiveSpecDigest) && validDigest(binding.CapabilityDigest) && validDigest(binding.CanonicalRequestDigest)
}

func (delivery Delivery) valid() bool {
	return validID(delivery.DeliveryID, 128) && validNonce(delivery.Nonce) && validDeadline(delivery.IssuedAt, delivery.ExpiresAt) && delivery.LeaseEpoch > 0 && delivery.FencingToken > 0
}

func (acknowledgement Acknowledgement) valid() bool {
	return validSessionID(acknowledgement.HostInstanceSessionID) && validID(acknowledgement.DeliveryID, 128) && validNonce(acknowledgement.Nonce) && acknowledgement.LeaseEpoch > 0 && acknowledgement.FencingToken > 0
}

func (acknowledgement Acknowledgement) matches(delivery Delivery) bool {
	return acknowledgement.DeliveryID == delivery.DeliveryID && acknowledgement.Nonce == delivery.Nonce && acknowledgement.LeaseEpoch == delivery.LeaseEpoch && acknowledgement.FencingToken == delivery.FencingToken
}

func validDeadline(issuedAt, expiresAt time.Time) bool {
	return validTimestamp(issuedAt) && validTimestamp(expiresAt) && expiresAt.After(issuedAt) && expiresAt.Sub(issuedAt) <= 5*time.Minute
}

func validTimestamp(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC
}

func validNonce(nonce string) bool {
	if len(nonce) == 0 || len(nonce) > 86 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(nonce)
	return err == nil && len(decoded) >= 16 && len(decoded) <= 64 && base64.RawURLEncoding.EncodeToString(decoded) == nonce
}

func validSessionID(value string) bool {
	return validID(value, 128)
}

func validID(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && norm.NFC.IsNormalString(value) && !strings.ContainsRune(value, '\x00')
}

func validDigest(value sandbox.Digest) bool {
	if len(value) != 71 || !strings.HasPrefix(string(value), "sha256:") {
		return false
	}
	for _, character := range value[7:] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
