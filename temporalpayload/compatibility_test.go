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

	codec, err := NewCodec(blockingCompatibilityStore{}, WithBlobPrefix("test/payloads"), WithIOTimeout(10*time.Millisecond))
	if err != nil {
		t.Fatalf("NewCodec() error = %v", err)
	}
	result := make(chan error, 1)
	go func() { result <- codec.CheckCompatibility(context.Background()) }()
	select {
	case err := <-result:
		if !stderrors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("CheckCompatibility() error = %v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("CheckCompatibility() did not bound frozen remote-vector seed I/O")
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

type blockingCompatibilityStore struct{}

func (blockingCompatibilityStore) Put(ctx context.Context, _ BlobKey, _ []byte) error {
	<-ctx.Done()
	return ctx.Err()
}

func (blockingCompatibilityStore) Get(context.Context, BlobKey, int) ([]byte, error) {
	return nil, ErrBlobNotFound
}
