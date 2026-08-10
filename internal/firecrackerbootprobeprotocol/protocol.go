// Package firecrackerbootprobeprotocol owns the private signed M3-to-M4 boot-probe command and M4 observation wire.
package firecrackerbootprobeprotocol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"time"

	"github.com/0x63616c/agent-runtime/internal/firecracker"
	"github.com/0x63616c/agent-runtime/internal/firecrackerbootprobev2"
	"github.com/0x63616c/agent-runtime/internal/firecrackerlaunchgrant"
	"github.com/cockroachdb/errors"
)

var (
	// ErrInvalidCommand identifies a malformed, detached, untrusted, or expired private boot-probe command.
	ErrInvalidCommand = errors.New("invalid Firecracker boot-probe v2 command")
	// ErrInvalidObservation identifies a malformed, altered, delayed, or detached private boot-probe observation.
	ErrInvalidObservation = errors.New("invalid Firecracker boot-probe v2 observation")
	// ErrInvalidStageReady identifies a malformed, detached, untrusted, or expired M4 stage-ready record.
	ErrInvalidStageReady = errors.New("invalid Firecracker boot-probe v2 stage-ready record")
)

const (
	// Version is the distinct private M3-to-M4 boot-probe protocol. It never falls back to host-control v1.
	Version = "sandbox.host-control/v2/firecracker-boot-probe"
	// ObservationKind identifies the sole accepted signed host observation.
	ObservationKind = "boot-observation"
	// StageReadyKind identifies the sole M4-to-M3 pre-launch record.
	StageReadyKind = "stage-ready"
	// GuestProtocolPong is the sole guest observation a boot probe may report.
	GuestProtocolPong = "pong"

	maximumWireBytes = 32 << 10
)

// Command is one M3-signed, launch-authorized delivery to an exact M4 host instance.
// It contains no plan, host path, fixture source, Jailer argument, credential, or public sandbox capability.
type Command struct {
	ProtocolVersion       string                          `json:"protocol_version"`
	HostInstanceSessionID string                          `json:"host_instance_session_id"`
	Binding               firecrackerbootprobev2.Binding  `json:"binding"`
	Delivery              firecrackerbootprobev2.Delivery `json:"delivery"`
	Grant                 firecrackerlaunchgrant.Grant    `json:"grant"`
	GuestNonce            string                          `json:"guest_nonce"`
	Signature             string                          `json:"signature"`
}

// VerifiedCommand is an opaque result of VerifyCommand. It prevents an
// observation path from accepting a caller-constructed command that has not
// passed the M3 signature, enrolled-host, and compiled-M4 identity checks.
type VerifiedCommand struct {
	command              Command
	observationPublicKey ed25519.PublicKey
}

// Command returns a copy of the exact command that VerifyCommand accepted.
func (verified VerifiedCommand) Command() Command { return verified.command }

// HostTrustResolver resolves the already-enrolled control and observation keys for one exact host generation.
// It is an M3 authority seam: callers must not infer keys from a command or accept host-supplied key material.
type HostTrustResolver interface {
	ResolveBootProbeHostTrust(context.Context, string, uint64) (HostTrust, error)
}

// HostTrust is the bounded verification material returned by an authoritative enrollment resolver.
// It intentionally carries no certificate, secret, enrollment policy, or M4 identity.
type HostTrust struct {
	HostID               string
	HostGeneration       uint64
	ControlPublicKey     ed25519.PublicKey
	ObservationPublicKey ed25519.PublicKey
}

// StageReady is the M4-owned pre-launch request. Its identity is produced by
// the sealed local compiler, and its signature uses the separately enrolled
// observation key rather than the M3 control-signing key.
type StageReady struct {
	ProtocolVersion       string                                   `json:"protocol_version"`
	Kind                  string                                   `json:"kind"`
	HostInstanceSessionID string                                   `json:"host_instance_session_id"`
	ExpectedVersion       uint64                                   `json:"expected_version"`
	Binding               firecrackerbootprobev2.Binding           `json:"binding"`
	Delivery              firecrackerbootprobev2.Delivery          `json:"delivery"`
	M4                    firecrackerlaunchgrant.TrustedM4Identity `json:"m4"`
	GuestNonce            string                                   `json:"guest_nonce"`
	Signature             string                                   `json:"signature"`
}

// VerifiedStageReady is the opaque result of VerifyStageReady. M3 must use it
// with its locked persisted session rather than trust a caller-built record.
type VerifiedStageReady struct{ stageReady StageReady }

// StageReady returns a copy of the exact M4 record VerifyStageReady accepted.
func (verified VerifiedStageReady) StageReady() StageReady { return verified.stageReady }

// Observation is one M4-signed, bounded result for the exact command delivery.
// Its identity is compared to the already verified command by VerifyObservation; an observation never grants launch authority.
type Observation struct {
	ProtocolVersion       string                                   `json:"protocol_version"`
	Kind                  string                                   `json:"kind"`
	HostInstanceSessionID string                                   `json:"host_instance_session_id"`
	EnvelopeID            string                                   `json:"envelope_id"`
	DeliveryID            string                                   `json:"delivery_id"`
	Nonce                 string                                   `json:"nonce"`
	LeaseEpoch            uint64                                   `json:"lease_epoch"`
	FencingToken          uint64                                   `json:"fencing_token"`
	M4                    firecrackerlaunchgrant.TrustedM4Identity `json:"m4"`
	SerialMarker          string                                   `json:"serial_marker"`
	GuestNonce            string                                   `json:"guest_nonce"`
	GuestProtocolResult   string                                   `json:"guest_protocol_result"`
	ObservedAt            time.Time                                `json:"observed_at"`
	Signature             string                                   `json:"signature"`
}

// SignCommand writes one canonical M3-signed command after a caller has atomically recorded launch authorization.
// The caller owns durable CAS and enrolment; this function only seals a fixed-purpose command.
func SignCommand(session firecrackerbootprobev2.Session, grant firecrackerlaunchgrant.Grant, guestNonce string, privateKey ed25519.PrivateKey) ([]byte, error) {
	if err := session.Validate(); err != nil || session.Lifecycle.Phase != firecrackerbootprobev2.LifecycleLaunchAuthorized || session.Lifecycle.LaunchDelivery == nil || !sameDelivery(*session.Lifecycle.LaunchDelivery, session.Delivery.Current) {
		return nil, errors.Wrap(ErrInvalidCommand, "sign only launch-authorized Firecracker boot-probe v2 session")
	}
	command := Command{ProtocolVersion: Version, HostInstanceSessionID: session.Delivery.HostInstanceSessionID, Binding: session.Delivery.Binding, Delivery: session.Delivery.Current, Grant: grant, GuestNonce: guestNonce}
	if err := validateCommand(command); err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.Wrap(ErrInvalidCommand, "sign exact bounded Firecracker boot-probe v2 command")
	}
	unsigned, err := json.Marshal(command)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidCommand, "encode unsigned Firecracker boot-probe v2 command")
	}
	command.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, unsigned))
	return encodeCommand(command)
}

// SignStageReady writes the canonical M4-to-M3 record after M4 has compiled
// its exact staged identity. It neither grants nor starts a launch.
func SignStageReady(snapshot firecrackerbootprobev2.Snapshot, identity firecracker.TrustedM4Identity, guestNonce string, privateKey ed25519.PrivateKey) ([]byte, error) {
	m4, err := identity.LaunchGrantIdentity()
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStageReady, "sign stage-ready with uncompiled M4 identity")
	}
	return signStageReady(snapshot, m4, guestNonce, privateKey)
}

func signStageReady(snapshot firecrackerbootprobev2.Snapshot, identity firecrackerlaunchgrant.TrustedM4Identity, guestNonce string, privateKey ed25519.PrivateKey) ([]byte, error) {
	if snapshot.Version == 0 || snapshot.Session.Validate() != nil || snapshot.Session.Lifecycle.Phase != firecrackerbootprobev2.LifecyclePrepared || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.Wrap(ErrInvalidStageReady, "sign only a persisted prepared Firecracker boot-probe v2 session")
	}
	ready := StageReady{ProtocolVersion: Version, Kind: StageReadyKind, HostInstanceSessionID: snapshot.Session.Delivery.HostInstanceSessionID, ExpectedVersion: snapshot.Version, Binding: snapshot.Session.Delivery.Binding, Delivery: snapshot.Session.Delivery.Current, M4: identity, GuestNonce: guestNonce}
	if err := validateStageReady(ready); err != nil {
		return nil, errors.Wrap(ErrInvalidStageReady, "sign exact bounded Firecracker boot-probe v2 stage-ready record")
	}
	unsigned, err := json.Marshal(ready)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStageReady, "encode unsigned Firecracker boot-probe v2 stage-ready record")
	}
	ready.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, unsigned))
	return encodeStageReady(ready)
}

// VerifyStageReady verifies the distinct enrolled observation key and exact
// prepared-delivery shape. It does not mutate a session or authorize launch.
func VerifyStageReady(ctx context.Context, wire []byte, now time.Time, resolver HostTrustResolver) (VerifiedStageReady, error) {
	if ctx == nil || resolver == nil || !validTime(now) {
		return VerifiedStageReady{}, errors.Wrap(ErrInvalidStageReady, "verify Firecracker boot-probe v2 stage-ready dependencies")
	}
	ready, err := decodeStageReady(wire)
	if err != nil || now.Before(ready.Delivery.IssuedAt) || !now.Before(ready.Delivery.ExpiresAt) {
		return VerifiedStageReady{}, errors.Wrap(ErrInvalidStageReady, "verify exact Firecracker boot-probe v2 stage-ready record")
	}
	trust, err := resolver.ResolveBootProbeHostTrust(ctx, ready.Binding.HostID, ready.Binding.HostGeneration)
	if err != nil || trust.HostID != ready.Binding.HostID || trust.HostGeneration != ready.Binding.HostGeneration || len(trust.ObservationPublicKey) != ed25519.PublicKeySize {
		return VerifiedStageReady{}, errors.Wrap(ErrInvalidStageReady, "resolve enrolled Firecracker boot-probe v2 observation key")
	}
	signature, err := base64.RawURLEncoding.DecodeString(ready.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return VerifiedStageReady{}, errors.Wrap(ErrInvalidStageReady, "decode Firecracker boot-probe v2 stage-ready signature")
	}
	unsigned := ready
	unsigned.Signature = ""
	unsignedWire, err := json.Marshal(unsigned)
	if err != nil || !ed25519.Verify(trust.ObservationPublicKey, unsignedWire, signature) {
		return VerifiedStageReady{}, errors.Wrap(ErrInvalidStageReady, "verify Firecracker boot-probe v2 stage-ready signature")
	}
	return VerifiedStageReady{stageReady: ready}, nil
}

// VerifyCommand strictly decodes and verifies an M3 command for the one enrolled host and locally compiled M4 identity.
// Passing a different self-reported M4 identity never widens the signed command's authority.
func VerifyCommand(ctx context.Context, wire []byte, now time.Time, resolver HostTrustResolver, identity firecracker.CompiledM4IdentityVerifier) (VerifiedCommand, error) {
	return verifyCommand(ctx, wire, now, resolver, identity.VerifyTrustedM4Identity)
}

func verifyCommand(ctx context.Context, wire []byte, now time.Time, resolver HostTrustResolver, verifyM4Identity func(firecrackerlaunchgrant.TrustedM4Identity) error) (VerifiedCommand, error) {
	if ctx == nil || resolver == nil || verifyM4Identity == nil || !validTime(now) {
		return VerifiedCommand{}, errors.Wrap(ErrInvalidCommand, "verify Firecracker boot-probe v2 command dependencies")
	}
	command, err := decodeCommand(wire)
	if err != nil {
		return VerifiedCommand{}, errors.Wrap(ErrInvalidCommand, "verify exact Firecracker boot-probe v2 command")
	}
	trust, err := resolver.ResolveBootProbeHostTrust(ctx, command.Binding.HostID, command.Binding.HostGeneration)
	if err != nil || trust.HostID != command.Binding.HostID || trust.HostGeneration != command.Binding.HostGeneration || len(trust.ControlPublicKey) != ed25519.PublicKeySize || len(trust.ObservationPublicKey) != ed25519.PublicKeySize {
		return VerifiedCommand{}, errors.Wrap(ErrInvalidCommand, "resolve enrolled Firecracker boot-probe v2 host trust")
	}
	expected := envelopeTuple(command.Binding, command.Delivery)
	if err := firecrackerlaunchgrant.ValidateBinding(command.Grant, expected, command.Grant.M4, now); err != nil || verifyM4Identity(command.Grant.M4) != nil {
		return VerifiedCommand{}, errors.Wrap(ErrInvalidCommand, "verify trusted M4 identity on Firecracker boot-probe v2 command")
	}
	signature, err := base64.RawURLEncoding.DecodeString(command.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return VerifiedCommand{}, errors.Wrap(ErrInvalidCommand, "decode Firecracker boot-probe v2 command signature")
	}
	unsigned := command
	unsigned.Signature = ""
	unsignedWire, err := json.Marshal(unsigned)
	if err != nil || !ed25519.Verify(trust.ControlPublicKey, unsignedWire, signature) {
		return VerifiedCommand{}, errors.Wrap(ErrInvalidCommand, "verify Firecracker boot-probe v2 command signature")
	}
	return VerifiedCommand{command: command, observationPublicKey: append(ed25519.PublicKey(nil), trust.ObservationPublicKey...)}, nil
}

// SignObservation writes a canonical M4-signed bounded observation. Control must call VerifyObservation with the exact verified command before accepting it.
func SignObservation(observation Observation, privateKey ed25519.PrivateKey) ([]byte, error) {
	if !validObservationShape(observation) || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.Wrap(ErrInvalidObservation, "sign bounded Firecracker boot-probe v2 observation")
	}
	observation.Signature = ""
	unsigned, err := json.Marshal(observation)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidObservation, "encode unsigned Firecracker boot-probe v2 observation")
	}
	observation.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, unsigned))
	return encodeObservation(observation)
}

// VerifyObservation strictly verifies a host signature and exact command binding without launching, acknowledging, or changing durable session state.
// The command must have been verified through VerifyCommand against the operator-enrolled host and compiled M4 identity.

func VerifyObservation(wire []byte, verified VerifiedCommand, now time.Time) (Observation, error) {
	command := verified.command
	if err := validateCommand(command); err != nil || !validTime(now) || len(verified.observationPublicKey) != ed25519.PublicKeySize {
		return Observation{}, errors.Wrap(ErrInvalidObservation, "verify Firecracker boot-probe v2 observation command")
	}
	observation, err := decodeObservation(wire)
	if err != nil || !exactObservation(command, observation) || observation.ObservedAt.Before(command.Delivery.IssuedAt) || observation.ObservedAt.After(now) || !observation.ObservedAt.Before(command.Delivery.ExpiresAt) {
		return Observation{}, errors.Wrap(ErrInvalidObservation, "verify exact Firecracker boot-probe v2 observation")
	}
	signature, err := base64.RawURLEncoding.DecodeString(observation.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Observation{}, errors.Wrap(ErrInvalidObservation, "decode Firecracker boot-probe v2 observation signature")
	}
	unsigned := observation
	unsigned.Signature = ""
	unsignedWire, err := json.Marshal(unsigned)
	if err != nil || !ed25519.Verify(verified.observationPublicKey, unsignedWire, signature) {
		return Observation{}, errors.Wrap(ErrInvalidObservation, "verify Firecracker boot-probe v2 observation signature")
	}
	return observation, nil
}

func decodeCommand(wire []byte) (Command, error) {
	if len(wire) == 0 || len(wire) > maximumWireBytes {
		return Command{}, ErrInvalidCommand
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var command Command
	if err := decoder.Decode(&command); err != nil {
		return Command{}, ErrInvalidCommand
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Command{}, ErrInvalidCommand
	}
	canonical, err := encodeCommand(command)
	if err != nil || !bytes.Equal(canonical, wire) || command.Signature == "" || validateCommand(command) != nil {
		return Command{}, ErrInvalidCommand
	}
	return command, nil
}

func decodeObservation(wire []byte) (Observation, error) {
	if len(wire) == 0 || len(wire) > maximumWireBytes {
		return Observation{}, ErrInvalidObservation
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var observation Observation
	if err := decoder.Decode(&observation); err != nil {
		return Observation{}, ErrInvalidObservation
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Observation{}, ErrInvalidObservation
	}
	canonical, err := encodeObservation(observation)
	if err != nil || !bytes.Equal(canonical, wire) || observation.Signature == "" || !validObservationShape(observation) {
		return Observation{}, ErrInvalidObservation
	}
	return observation, nil
}

func decodeStageReady(wire []byte) (StageReady, error) {
	if len(wire) == 0 || len(wire) > maximumWireBytes {
		return StageReady{}, ErrInvalidStageReady
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var ready StageReady
	if err := decoder.Decode(&ready); err != nil {
		return StageReady{}, ErrInvalidStageReady
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return StageReady{}, ErrInvalidStageReady
	}
	canonical, err := encodeStageReady(ready)
	if err != nil || !bytes.Equal(canonical, wire) || ready.Signature == "" || validateStageReady(ready) != nil {
		return StageReady{}, ErrInvalidStageReady
	}
	return ready, nil
}

func encodeCommand(command Command) ([]byte, error) {
	wire, err := json.Marshal(command)
	if err != nil || len(wire) > maximumWireBytes {
		return nil, ErrInvalidCommand
	}
	return wire, nil
}

func encodeObservation(observation Observation) ([]byte, error) {
	wire, err := json.Marshal(observation)
	if err != nil || len(wire) > maximumWireBytes {
		return nil, ErrInvalidObservation
	}
	return wire, nil
}

func encodeStageReady(ready StageReady) ([]byte, error) {
	wire, err := json.Marshal(ready)
	if err != nil || len(wire) > maximumWireBytes {
		return nil, ErrInvalidStageReady
	}
	return wire, nil
}

func validateCommand(command Command) error {
	if command.ProtocolVersion != Version || !validNonce(command.GuestNonce) {
		return ErrInvalidCommand
	}
	state, err := firecrackerbootprobev2.NewState(command.Binding, command.HostInstanceSessionID, command.Delivery, command.Delivery.IssuedAt)
	if err != nil {
		return ErrInvalidCommand
	}
	if err := firecrackerlaunchgrant.ValidateBinding(command.Grant, envelopeTuple(state.Binding, state.Current), command.Grant.M4, command.Delivery.IssuedAt); err != nil {
		return ErrInvalidCommand
	}
	if command.GuestNonce == command.Delivery.Nonce {
		return ErrInvalidCommand
	}
	return nil
}

func validateStageReady(ready StageReady) error {
	if ready.ProtocolVersion != Version || ready.Kind != StageReadyKind || ready.ExpectedVersion == 0 || !validNonce(ready.GuestNonce) || ready.GuestNonce == ready.Delivery.Nonce {
		return ErrInvalidStageReady
	}
	state, err := firecrackerbootprobev2.NewState(ready.Binding, ready.HostInstanceSessionID, ready.Delivery, ready.Delivery.IssuedAt)
	if err != nil {
		return ErrInvalidStageReady
	}
	if _, err := firecrackerlaunchgrant.New(envelopeTuple(state.Binding, state.Current), ready.M4); err != nil {
		return ErrInvalidStageReady
	}
	return nil
}

func validObservationShape(observation Observation) bool {
	return observation.ProtocolVersion == Version && observation.Kind == ObservationKind && validID(observation.HostInstanceSessionID) && validID(observation.EnvelopeID) && validID(observation.DeliveryID) && validNonce(observation.Nonce) && observation.LeaseEpoch > 0 && observation.FencingToken > 0 && observation.SerialMarker != "" && validNonce(observation.GuestNonce) && observation.GuestProtocolResult == GuestProtocolPong && validTime(observation.ObservedAt)
}

func exactObservation(command Command, observation Observation) bool {
	return observation.HostInstanceSessionID == command.HostInstanceSessionID && observation.EnvelopeID == command.Delivery.EnvelopeID && observation.DeliveryID == command.Delivery.DeliveryID && observation.Nonce == command.Delivery.Nonce && observation.LeaseEpoch == command.Delivery.LeaseEpoch && observation.FencingToken == command.Delivery.FencingToken && observation.M4 == command.Grant.M4 && observation.SerialMarker == command.Grant.SerialMarker && observation.GuestNonce == command.GuestNonce && observation.GuestProtocolResult == GuestProtocolPong
}

func envelopeTuple(binding firecrackerbootprobev2.Binding, delivery firecrackerbootprobev2.Delivery) firecrackerlaunchgrant.EnvelopeTuple {
	return firecrackerlaunchgrant.EnvelopeTuple{EnvelopeID: delivery.EnvelopeID, DeliveryID: delivery.DeliveryID, Nonce: delivery.Nonce, IssuedAt: delivery.IssuedAt, ExpiresAt: delivery.ExpiresAt, HostID: binding.HostID, HostGeneration: binding.HostGeneration, AssignmentID: binding.AssignmentID, LeaseEpoch: delivery.LeaseEpoch, FencingToken: delivery.FencingToken, Tenant: binding.Tenant, Principal: binding.Principal, SandboxID: binding.SandboxID, OperationID: binding.OperationID, OperationKind: binding.OperationKind, EffectiveSpecDigest: binding.EffectiveSpecDigest, CapabilityDigest: binding.CapabilityDigest, CanonicalRequestDigest: binding.CanonicalRequestDigest}
}

func sameDelivery(left, right firecrackerbootprobev2.Delivery) bool { return left == right }

func validID(value string) bool { return value != "" && len(value) <= 128 }

func validTime(value time.Time) bool { return !value.IsZero() && value.Location() == time.UTC }

func validNonce(value string) bool {
	if len(value) == 0 || len(value) > 86 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) >= 16 && len(decoded) <= 64 && base64.RawURLEncoding.EncodeToString(decoded) == value
}
