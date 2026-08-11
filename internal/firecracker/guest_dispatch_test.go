package firecracker

import (
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"testing"
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
