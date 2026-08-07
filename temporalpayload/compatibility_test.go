package temporalpayload

import (
	"context"
	"encoding/hex"
	stderrors "errors"
	"testing"
	"time"

	commonpb "go.temporal.io/api/common/v1"
)

func TestCompatibilitySeedUsesTheConfiguredIOTimeout(t *testing.T) {
	t.Parallel()

	configuredTimeout := 10 * time.Second
	codec, err := NewCodec(deadlineInspectingCompatibilityStore{maximumRemaining: configuredTimeout}, WithBlobPrefix("test/payloads"), WithIOTimeout(configuredTimeout))
	if err != nil {
		t.Fatalf("NewCodec() error = %v", err)
	}
	err = codec.CheckCompatibility(context.Background())
	if !stderrors.Is(err, errCompatibilitySeedObserved) {
		t.Fatalf("CheckCompatibility() error = %v, want observed bounded seed I/O", err)
	}
}

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

var (
	errCompatibilitySeedObserved = stderrors.New("compatibility seed received a bounded context")
	errCompatibilitySeedUnbound  = stderrors.New("compatibility seed context has no finite configured deadline")
)

type deadlineInspectingCompatibilityStore struct {
	maximumRemaining time.Duration
}

func (store deadlineInspectingCompatibilityStore) Put(ctx context.Context, _ BlobKey, _ []byte) error {
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > store.maximumRemaining {
		return errCompatibilitySeedUnbound
	}
	return errCompatibilitySeedObserved
}

func (deadlineInspectingCompatibilityStore) Get(context.Context, BlobKey, int) ([]byte, error) {
	return nil, ErrBlobNotFound
}
