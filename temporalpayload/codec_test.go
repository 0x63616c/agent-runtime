package temporalpayload

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"testing"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"
	"google.golang.org/protobuf/proto"
)

func TestCodecSelectsTheStrictlySmallestRepresentation(t *testing.T) {
	t.Parallel()

	store := NewMemoryBlobStore()
	codec := newTestCodec(t, store)

	for _, test := range []struct {
		name     string
		payload  *commonpb.Payload
		encoding string
	}{
		{name: "inline", payload: testPayload([]byte("small")), encoding: "json/plain"},
		{name: "zstd", payload: testSimplePayload(bytes.Repeat([]byte("x"), 1024)), encoding: EncodingZstd},
		{name: "remote", payload: testPayload(incompressibleBytes(64 * 1024)), encoding: EncodingRemote},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := codec.Encode([]*commonpb.Payload{test.payload})
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			if got := string(encoded[0].Metadata[converter.MetadataEncoding]); got != test.encoding {
				t.Fatalf("encoding = %q, want %q", got, test.encoding)
			}
			decoded, err := codec.Decode(encoded)
			if err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			if !proto.Equal(decoded[0], test.payload) {
				t.Fatalf("round trip = %v, want %v", decoded[0], test.payload)
			}
		})
	}
}

func TestCodecStoresTheCompressedInnerPayloadWhenRemoteReferenceWins(t *testing.T) {
	t.Parallel()

	store := NewMemoryBlobStore()
	codec := newTestCodec(t, store)
	block := append(bytes.Repeat([]byte("x"), 256), incompressibleBytes(256)...)
	payload := testSimplePayload(bytes.Repeat(block, 128))

	encoded, err := codec.Encode([]*commonpb.Payload{payload})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if got := string(encoded[0].Metadata[converter.MetadataEncoding]); got != EncodingRemote {
		t.Fatalf("encoding = %q, want %q", got, EncodingRemote)
	}
	reference, err := codec.parseReference(encoded[0].Data)
	if err != nil {
		t.Fatalf("parseReference() error = %v", err)
	}
	stored, err := store.Get(context.Background(), reference.Key, int(reference.Size))
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	inner := &commonpb.Payload{}
	if err := proto.Unmarshal(stored, inner); err != nil {
		t.Fatalf("unmarshal stored inner payload: %v", err)
	}
	if got := string(inner.Metadata[converter.MetadataEncoding]); got != EncodingZstd {
		t.Fatalf("stored encoding = %q, want %q", got, EncodingZstd)
	}
}

func TestCodecDoesNotWriteABlobUnlessItsReferenceIsStrictlySmaller(t *testing.T) {
	t.Parallel()

	store := NewMemoryBlobStore()
	codec := newTestCodec(t, store)

	if _, err := codec.Encode([]*commonpb.Payload{testPayload([]byte("small"))}); err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if got := store.Count(); got != 0 {
		t.Fatalf("stored blobs = %d, want 0", got)
	}
}

func TestCodecRejectsMissingAndCorruptRemoteContent(t *testing.T) {
	t.Parallel()

	store := NewMemoryBlobStore()
	codec := newTestCodec(t, store)
	encoded, err := codec.Encode([]*commonpb.Payload{testPayload(incompressibleBytes(64 * 1024))})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	reference, err := codec.parseReference(encoded[0].Data)
	if err != nil {
		t.Fatalf("parseReference() error = %v", err)
	}
	if err := store.Delete(context.Background(), reference.Key); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := codec.Decode(encoded); !errors.Is(err, ErrBlobNotFound) {
		t.Fatalf("Decode() error = %v, want ErrBlobNotFound", err)
	}

	encoded, err = codec.Encode([]*commonpb.Payload{testPayload(incompressibleBytes(64 * 1024))})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	reference, err = codec.parseReference(encoded[0].Data)
	if err != nil {
		t.Fatalf("parseReference() error = %v", err)
	}
	store.replace(reference.Key, []byte("corrupt"))
	if _, err := codec.Decode(encoded); !errors.Is(err, ErrBlobIntegrity) {
		t.Fatalf("Decode() error = %v, want ErrBlobIntegrity", err)
	}
}

func TestCodecLeavesLegacyPlainPayloadsUntouchedAndRejectsUnsupportedVersions(t *testing.T) {
	t.Parallel()

	codec := newTestCodec(t, NewMemoryBlobStore())
	plain := testPayload([]byte("legacy plain payload"))
	decoded, err := codec.Decode([]*commonpb.Payload{plain})
	if err != nil {
		t.Fatalf("Decode() legacy payload error = %v", err)
	}
	if decoded[0] != plain {
		t.Fatal("Decode() replaced a payload outside the codec compatibility window")
	}

	unsupported := &commonpb.Payload{Metadata: map[string][]byte{
		converter.MetadataEncoding: []byte(EncodingZstd),
		metadataVersion:            []byte("99"),
	}, Data: []byte("not a supported payload")}
	if _, err := codec.Decode([]*commonpb.Payload{unsupported}); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("Decode() error = %v, want ErrUnsupportedVersion", err)
	}
}

func TestCodecDecodesTheFrozenV1ZstdCompatibilityVector(t *testing.T) {
	t.Parallel()

	codec := newTestCodec(t, NewMemoryBlobStore())
	compressed := mustDecodeHex(t, "28b52ffd04008901000a160a08656e636f64696e67120a6a736f6e2f706c61696e12176167656e742d72756e74696d652d76312d676f6c64656e877a7521")
	decoded, err := codec.Decode([]*commonpb.Payload{{Metadata: map[string][]byte{
		converter.MetadataEncoding: []byte(EncodingZstd),
		metadataVersion:            []byte("1"),
	}, Data: compressed}})
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got, want := string(decoded[0].Data), "agent-runtime-v1-golden"; got != want {
		t.Fatalf("decoded data = %q, want %q", got, want)
	}
}

func TestCodecDoesNotMutateCallerPayloads(t *testing.T) {
	t.Parallel()

	codec := newTestCodec(t, NewMemoryBlobStore())
	payload := testPayload(incompressibleBytes(64 * 1024))
	before := proto.Clone(payload)
	if _, err := codec.Encode([]*commonpb.Payload{payload}); err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if !proto.Equal(payload, before) {
		t.Fatalf("Encode() mutated payload: got %v, want %v", payload, before)
	}
}

func TestDataConverterRoundTripsWithoutApplicationSizeBranches(t *testing.T) {
	t.Parallel()

	codec := newTestCodec(t, NewMemoryBlobStore())
	dataConverter := codec.DataConverter()
	want := payloadValue{Bytes: incompressibleBytes(64 * 1024)}
	payload, err := dataConverter.ToPayload(want)
	if err != nil {
		t.Fatalf("ToPayload() error = %v", err)
	}
	if got := string(payload.Metadata[converter.MetadataEncoding]); got != EncodingRemote {
		t.Fatalf("encoding = %q, want %q", got, EncodingRemote)
	}
	var got payloadValue
	if err := dataConverter.FromPayload(payload, &got); err != nil {
		t.Fatalf("FromPayload() error = %v", err)
	}
	if !bytes.Equal(got.Bytes, want.Bytes) {
		t.Fatalf("FromPayload() = %#v, want %#v", got, want)
	}
}

func TestCodecIsSafeForConcurrentEncodeDecode(t *testing.T) {
	t.Parallel()

	codec := newTestCodec(t, NewMemoryBlobStore())
	errs := make(chan error, 32)
	for range 32 {
		go func() {
			payload := testPayload(incompressibleBytes(8 * 1024))
			encoded, err := codec.Encode([]*commonpb.Payload{payload})
			if err == nil {
				_, err = codec.Decode(encoded)
			}
			errs <- err
		}()
	}
	for range 32 {
		if err := <-errs; err != nil {
			t.Errorf("concurrent round trip: %v", err)
		}
	}
}

func TestCodecReportsOnlyBoundedByteObservations(t *testing.T) {
	t.Parallel()

	observer := &recordingObserver{}
	codec, err := NewCodec(NewMemoryBlobStore(), WithBlobPrefix("test/payloads"), WithObserver(observer))
	if err != nil {
		t.Fatalf("NewCodec() error = %v", err)
	}
	encoded, err := codec.Encode([]*commonpb.Payload{testPayload(incompressibleBytes(64 * 1024))})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if _, err := codec.Decode(encoded); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	observations := observer.observations()
	if len(observations) != 2 {
		t.Fatalf("observations = %d, want encode + remote decode", len(observations))
	}
	for _, observation := range observations {
		if observation.InputSizeBytes <= 0 || observation.OutputSizeBytes <= 0 {
			t.Fatalf("observation = %#v, want positive bounded byte sizes", observation)
		}
	}
}

type payloadValue struct {
	Bytes []byte `json:"bytes"`
}

func newTestCodec(t *testing.T, store BlobStore) *Codec {
	t.Helper()
	codec, err := NewCodec(store, WithBlobPrefix("test/payloads"), WithMaximumBlobBytes(1<<20))
	if err != nil {
		t.Fatalf("NewCodec() error = %v", err)
	}
	return codec
}

func testPayload(data []byte) *commonpb.Payload {
	return &commonpb.Payload{Metadata: map[string][]byte{
		converter.MetadataEncoding: []byte("json/plain"),
		"source":                   []byte("test"),
	}, Data: bytes.Clone(data)}
}

func testSimplePayload(data []byte) *commonpb.Payload {
	return &commonpb.Payload{Metadata: map[string][]byte{
		converter.MetadataEncoding: []byte("json/plain"),
	}, Data: bytes.Clone(data)}
}

func incompressibleBytes(size int) []byte {
	result := make([]byte, size)
	state := uint64(1)
	for index := range result {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		result[index] = byte(state)
	}
	return result
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	result, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode golden hex: %v", err)
	}
	return result
}

type recordingObserver struct {
	mu     sync.Mutex
	values []Observation
}

func (observer *recordingObserver) ObservePayload(observation Observation) {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	observer.values = append(observer.values, observation)
}

func (observer *recordingObserver) observations() []Observation {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	return append([]Observation(nil), observer.values...)
}
