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
	Version  string                       `json:"version"`
	Envelope sandboxhostprotocol.Envelope `json:"envelope"`
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

// DecodeGuestDispatch accepts only one bounded canonical frame with matching payload digest.
func DecodeGuestDispatch(frame []byte) (sandboxhostprotocol.Envelope, error) {
	if len(frame) == 0 || len(frame) > maximumGuestDispatchBytes {
		return sandboxhostprotocol.Envelope{}, fmt.Errorf("decode guest dispatch: %w", ErrCapabilityUnavailable)
	}
	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.DisallowUnknownFields()
	var dispatch GuestDispatch
	if err := decoder.Decode(&dispatch); err != nil {
		return sandboxhostprotocol.Envelope{}, fmt.Errorf("decode guest dispatch: %w", ErrCapabilityUnavailable)
	}
	canonical, err := json.Marshal(dispatch)
	if err != nil || !bytes.Equal(canonical, frame) || dispatch.Version != "agent-runtime.guest-dispatch/v1" || dispatch.Envelope.PayloadDigest != sandboxhostprotocol.Digest(dispatch.Envelope.Payload) {
		return sandboxhostprotocol.Envelope{}, fmt.Errorf("decode guest dispatch: %w", ErrCapabilityUnavailable)
	}
	return dispatch.Envelope, nil
}
