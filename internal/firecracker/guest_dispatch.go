package firecracker

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
)

const maximumGuestDispatchBytes = 64 << 10

// GuestDispatch is the bounded private vsock frame that carries one already
// verified and fenced host envelope. It contains no host paths or secret bytes.
type GuestDispatch struct {
	Version               string                       `json:"version"`
	Envelope              sandboxhostprotocol.Envelope `json:"envelope"`
	AuthenticatedEnvelope []byte                       `json:"authenticated_envelope,omitempty"`
}

// EncodeGuestDispatch canonically bounds a verified host envelope before it crosses vsock.
func EncodeGuestDispatch(envelope sandboxhostprotocol.Envelope) ([]byte, error) {
	if envelope.EnvelopeID == "" || envelope.DeliveryID == "" || envelope.FencingToken == 0 || len(envelope.Payload) == 0 {
		return nil, fmt.Errorf("encode guest dispatch: %w", ErrCapabilityUnavailable)
	}
	frame, err := json.Marshal(GuestDispatch{Version: "agent-runtime.guest-dispatch/v1", Envelope: envelope})
	if err != nil || len(frame) > maximumGuestDispatchBytes {
		return nil, fmt.Errorf("encode guest dispatch: %w", ErrCapabilityUnavailable)
	}
	return frame, nil
}

// EncodeAuthenticatedGuestDispatch binds the exact control-signed canonical
// wire that host-process already verified to its private guest dispatch. The
// guest frame cannot substitute a different envelope beside that wire.
func EncodeAuthenticatedGuestDispatch(envelope sandboxhostprotocol.Envelope, authenticatedEnvelope []byte) ([]byte, error) {
	if len(authenticatedEnvelope) == 0 || len(authenticatedEnvelope) > maximumGuestDispatchBytes {
		return nil, fmt.Errorf("encode authenticated guest dispatch: %w", ErrCapabilityUnavailable)
	}
	var signed sandboxhostprotocol.Envelope
	decoder := json.NewDecoder(bytes.NewReader(authenticatedEnvelope))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signed); err != nil || !sameGuestDispatchEnvelope(signed, envelope) {
		return nil, fmt.Errorf("encode authenticated guest dispatch: %w", ErrCapabilityUnavailable)
	}
	canonical, err := json.Marshal(signed)
	if err != nil || !bytes.Equal(canonical, authenticatedEnvelope) {
		return nil, fmt.Errorf("encode authenticated guest dispatch: %w", ErrCapabilityUnavailable)
	}
	frame, err := json.Marshal(GuestDispatch{Version: "agent-runtime.guest-dispatch/v1", Envelope: envelope, AuthenticatedEnvelope: append([]byte(nil), authenticatedEnvelope...)})
	if err != nil || len(frame) > maximumGuestDispatchBytes {
		return nil, fmt.Errorf("encode authenticated guest dispatch: %w", ErrCapabilityUnavailable)
	}
	return frame, nil
}

// DecodeGuestDispatch accepts only one bounded canonical frame with matching payload digest.
func DecodeGuestDispatch(frame []byte) (sandboxhostprotocol.Envelope, error) {
	dispatch, err := decodeGuestDispatch(frame)
	if err != nil {
		return sandboxhostprotocol.Envelope{}, err
	}
	return dispatch.Envelope, nil
}

// DecodeAuthenticatedGuestDispatch returns the immutable envelope only when
// the private frame carries the exact same canonical control-signed wire.
// Signature/trust verification is deliberately performed at the host-control
// boundary before this frame is created.
func DecodeAuthenticatedGuestDispatch(frame []byte) (sandboxhostprotocol.Envelope, []byte, error) {
	dispatch, err := decodeGuestDispatch(frame)
	if err != nil || len(dispatch.AuthenticatedEnvelope) == 0 {
		return sandboxhostprotocol.Envelope{}, nil, fmt.Errorf("decode authenticated guest dispatch: %w", ErrCapabilityUnavailable)
	}
	var signed sandboxhostprotocol.Envelope
	decoder := json.NewDecoder(bytes.NewReader(dispatch.AuthenticatedEnvelope))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signed); err != nil || !sameGuestDispatchEnvelope(signed, dispatch.Envelope) {
		return sandboxhostprotocol.Envelope{}, nil, fmt.Errorf("decode authenticated guest dispatch: %w", ErrCapabilityUnavailable)
	}
	canonical, err := json.Marshal(signed)
	if err != nil || !bytes.Equal(canonical, dispatch.AuthenticatedEnvelope) {
		return sandboxhostprotocol.Envelope{}, nil, fmt.Errorf("decode authenticated guest dispatch: %w", ErrCapabilityUnavailable)
	}
	return dispatch.Envelope, append([]byte(nil), dispatch.AuthenticatedEnvelope...), nil
}

func decodeGuestDispatch(frame []byte) (GuestDispatch, error) {
	if len(frame) == 0 || len(frame) > maximumGuestDispatchBytes {
		return GuestDispatch{}, fmt.Errorf("decode guest dispatch: %w", ErrCapabilityUnavailable)
	}
	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.DisallowUnknownFields()
	var dispatch GuestDispatch
	if err := decoder.Decode(&dispatch); err != nil {
		return GuestDispatch{}, fmt.Errorf("decode guest dispatch: %w", ErrCapabilityUnavailable)
	}
	canonical, err := json.Marshal(dispatch)
	if err != nil || !bytes.Equal(canonical, frame) || dispatch.Version != "agent-runtime.guest-dispatch/v1" || dispatch.Envelope.PayloadDigest != sandboxhostprotocol.Digest(dispatch.Envelope.Payload) {
		return GuestDispatch{}, fmt.Errorf("decode guest dispatch: %w", ErrCapabilityUnavailable)
	}
	return dispatch, nil
}

func sameGuestDispatchEnvelope(left, right sandboxhostprotocol.Envelope) bool {
	leftPayload, rightPayload := append([]byte(nil), left.Payload...), append([]byte(nil), right.Payload...)
	left.Payload, right.Payload = nil, nil
	leftCanonical, leftErr := json.Marshal(left)
	rightCanonical, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftCanonical, rightCanonical) && bytes.Equal(leftPayload, rightPayload)
}
