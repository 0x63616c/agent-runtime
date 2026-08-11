package firecracker

import (
	"encoding/json"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
)

func TestGuestDispatchUsesABoundedCanonicalPayloadBoundEnvelope(t *testing.T) {
	envelope := sandboxhostprotocol.Envelope{EnvelopeID: "env_01", DeliveryID: "delivery_01", FencingToken: 1, Payload: []byte(`{"kind":"close"}`)}
	envelope.PayloadDigest = sandboxhostprotocol.Digest(envelope.Payload)
	frame, err := EncodeGuestDispatch(envelope)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeGuestDispatch(frame)
	if err != nil || string(decoded.Payload) != string(envelope.Payload) {
		t.Fatalf("decoded=%#v err=%v", decoded, err)
	}
	frame[len(frame)-2] ^= 1
	if _, err := DecodeGuestDispatch(frame); err == nil {
		t.Fatal("tampered frame accepted")
	}
}

func TestAuthenticatedGuestDispatchBindsTheExactControlWireToTheGuestEnvelope(t *testing.T) {
	envelope := sandboxhostprotocol.Envelope{EnvelopeID: "env_01", DeliveryID: "delivery_01", FencingToken: 1, Payload: []byte(`{"kind":"close"}`)}
	envelope.PayloadDigest = sandboxhostprotocol.Digest(envelope.Payload)
	authenticated, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal authenticated envelope: %v", err)
	}
	frame, err := EncodeAuthenticatedGuestDispatch(envelope, authenticated)
	if err != nil {
		t.Fatalf("EncodeAuthenticatedGuestDispatch() error = %v", err)
	}
	decoded, wire, err := DecodeAuthenticatedGuestDispatch(frame)
	if err != nil || decoded.EnvelopeID != envelope.EnvelopeID || string(wire) != string(authenticated) {
		t.Fatalf("DecodeAuthenticatedGuestDispatch() = (%#v, %q, %v)", decoded, wire, err)
	}
	mutated := append([]byte(nil), frame...)
	for index := range mutated {
		if mutated[index] == 'd' {
			mutated[index] = 'e'
			break
		}
	}
	if _, _, err := DecodeAuthenticatedGuestDispatch(mutated); err == nil {
		t.Fatal("DecodeAuthenticatedGuestDispatch() accepted a mutated authenticated frame")
	}
}
