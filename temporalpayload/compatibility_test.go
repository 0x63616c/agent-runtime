package temporalpayload

import (
	"encoding/hex"
	"testing"

	commonpb "go.temporal.io/api/common/v1"
)

func TestV1SelectionVectorsRemainFrozen(t *testing.T) {
	t.Parallel()

	codec := newTestCodec(t, NewMemoryBlobStore())
	for _, test := range v1CompatibilityVectors() {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := codec.Encode([]*commonpb.Payload{test.source})
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			gotWire, err := marshalPayload(encoded[0])
			if err != nil {
				t.Fatalf("marshal encoded payload: %v", err)
			}
			if got := hex.EncodeToString(gotWire); got != test.encodedPayloadHex || len(gotWire) != test.encodedPayloadBytes {
				t.Fatalf("frozen vector mismatch: hex=%q size=%d", got, len(gotWire))
			}
		})
	}
}
