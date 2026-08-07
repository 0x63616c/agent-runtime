package temporalpayload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	stderrors "errors"
	"strconv"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/klauspost/compress/zstd"
	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"
	"google.golang.org/protobuf/proto"
)

const (
	// EncodingZstd identifies a v1 zstd-wrapped Temporal payload.
	EncodingZstd = "binary/zstd"
	// EncodingRemote identifies a v1 immutable blob-reference Temporal payload.
	EncodingRemote = "binary/remote-payload"

	metadataVersion       = "agent-runtime-payload-v"
	codecVersion          = 1
	defaultMaximumBlob    = 64 << 20
	defaultIOTimeout      = 30 * time.Second
	referenceWireSize     = 1 + sha256.Size + 8
	selectionInline       = "inline"
	selectionCompressed   = "zstd"
	selectionRemote       = "remote"
	maximumReferenceDepth = 1
)

var (
	// ErrUnsupportedVersion reports a payload written by a codec version outside the declared compatibility window.
	ErrUnsupportedVersion = errors.New("unsupported temporal payload codec version")
	// ErrInvalidPayload reports malformed codec metadata, references, or nested payload bytes.
	ErrInvalidPayload = errors.New("invalid temporal payload codec payload")
)

// Observation is a bounded payload codec observation suitable for a metrics adapter.
type Observation struct {
	Operation       string
	Selection       string
	InputSizeBytes  int
	OutputSizeBytes int
}

// Observer records bounded codec observations without receiving payload bytes or blob keys.
type Observer interface {
	ObservePayload(Observation)
}

// Option configures a Codec. It is sealed so codecs cannot receive unchecked configuration.
type Option interface {
	apply(*codecConfig) error
}

type optionFunc func(*codecConfig) error

func (option optionFunc) apply(config *codecConfig) error {
	return option(config)
}

// WithBlobPrefix configures the explicit object-store prefix that owns this codec's content-addressed keys.
func WithBlobPrefix(prefix string) Option {
	return optionFunc(func(config *codecConfig) error {
		validated, err := validateBlobPrefix(prefix)
		if err != nil {
			return err
		}
		config.blobPrefix = validated
		return nil
	})
}

// WithMaximumBlobBytes configures the maximum immutable payload object the codec will write or read.
func WithMaximumBlobBytes(maximum int) Option {
	return optionFunc(func(config *codecConfig) error {
		if maximum <= 0 {
			return errors.New("temporal payload maximum blob bytes must be positive")
		}
		config.maximumBlobBytes = maximum
		return nil
	})
}

// WithIOTimeout configures the finite background I/O bound required by Temporal's payload codec API.
func WithIOTimeout(timeout time.Duration) Option {
	return optionFunc(func(config *codecConfig) error {
		if timeout <= 0 || timeout > time.Minute {
			return errors.New("temporal payload I/O timeout must be positive and no longer than one minute")
		}
		config.ioTimeout = timeout
		return nil
	})
}

// WithObserver configures a bounded metrics observer for codec outcomes.
func WithObserver(observer Observer) Option {
	return optionFunc(func(config *codecConfig) error {
		config.observer = observer
		return nil
	})
}

type codecConfig struct {
	blobPrefix       string
	maximumBlobBytes int
	ioTimeout        time.Duration
	observer         Observer
}

// Codec implements Temporal's PayloadCodec using a local zstd/blob transformation chain.
type Codec struct {
	store            BlobStore
	blobPrefix       string
	maximumBlobBytes int
	ioTimeout        time.Duration
	observer         Observer
	encoder          *zstd.Encoder
	decoder          *zstd.Decoder
	compressionMu    sync.Mutex
}

var _ converter.PayloadCodec = (*Codec)(nil)

// NewCodec creates a local payload codec with explicit immutable blob storage.
func NewCodec(store BlobStore, options ...Option) (*Codec, error) {
	if store == nil {
		return nil, errors.New("temporal payload blob store is required")
	}
	config := codecConfig{maximumBlobBytes: defaultMaximumBlob, ioTimeout: defaultIOTimeout}
	for _, option := range options {
		if option == nil {
			return nil, errors.New("temporal payload option is nil")
		}
		if err := option.apply(&config); err != nil {
			return nil, errors.Wrap(err, "configure temporal payload codec")
		}
	}
	if config.blobPrefix == "" {
		return nil, errors.New("temporal payload blob prefix is required")
	}
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBetterCompression))
	if err != nil {
		return nil, errors.Wrap(err, "create temporal payload zstd encoder")
	}
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		failure := errors.Wrap(err, "create temporal payload zstd decoder")
		if closeErr := encoder.Close(); closeErr != nil {
			return nil, stderrors.Join(failure, errors.Wrap(closeErr, "close temporal payload zstd encoder after decoder construction failure"))
		}
		return nil, failure
	}
	return &Codec{
		store:            store,
		blobPrefix:       config.blobPrefix,
		maximumBlobBytes: config.maximumBlobBytes,
		ioTimeout:        config.ioTimeout,
		observer:         config.observer,
		encoder:          encoder,
		decoder:          decoder,
	}, nil
}

// DataConverter returns the local Temporal DataConverter that owns payload selection transparently.
func (codec *Codec) DataConverter() converter.DataConverter {
	return converter.NewCodecDataConverter(converter.GetDefaultDataConverter(), codec)
}

// Encode transforms each ordinary Temporal payload into its strictly smallest supported representation.
func (codec *Codec) Encode(payloads []*commonpb.Payload) ([]*commonpb.Payload, error) {
	result := make([]*commonpb.Payload, len(payloads))
	for index, payload := range payloads {
		encoded, err := codec.encodeOne(payload)
		if err != nil {
			return result, errors.Wrapf(err, "encode temporal payload %d", index)
		}
		result[index] = encoded
	}
	return result, nil
}

// Decode restores every representation within the declared v1 compatibility window.
func (codec *Codec) Decode(payloads []*commonpb.Payload) ([]*commonpb.Payload, error) {
	result := make([]*commonpb.Payload, len(payloads))
	for index, payload := range payloads {
		decoded, err := codec.decodeOne(payload, 0)
		if err != nil {
			return result, errors.Wrapf(err, "decode temporal payload %d", index)
		}
		result[index] = decoded
	}
	return result, nil
}

func (codec *Codec) encodeOne(payload *commonpb.Payload) (*commonpb.Payload, error) {
	if payload == nil {
		return nil, errors.Wrap(ErrInvalidPayload, "nil payload")
	}
	originalWire, err := marshalPayload(payload)
	if err != nil {
		return nil, err
	}
	winner := payload
	winnerWire := originalWire
	selection := selectionInline

	compressed, err := codec.compress(originalWire)
	if err != nil {
		return nil, err
	}
	compressedPayload := codec.wrappedPayload(EncodingZstd, compressed)
	compressedWire, err := marshalPayload(compressedPayload)
	if err != nil {
		return nil, err
	}
	if len(compressedWire) < len(winnerWire) {
		winner = compressedPayload
		winnerWire = compressedWire
		selection = selectionCompressed
	}

	digest := sha256.Sum256(winnerWire)
	reference := codec.newReference(digest, uint64(len(winnerWire)))
	remotePayload := codec.wrappedPayload(EncodingRemote, reference.marshal())
	remoteWire, err := marshalPayload(remotePayload)
	if err != nil {
		return nil, err
	}
	if len(remoteWire) < len(winnerWire) {
		if len(winnerWire) > codec.maximumBlobBytes {
			return nil, errors.Wrapf(ErrBlobTooLarge, "encoded content has %d bytes, configured limit is %d", len(winnerWire), codec.maximumBlobBytes)
		}
		ctx, cancel := codec.ioContext(context.Background())
		defer cancel()
		if err := codec.store.Put(ctx, reference.Key, winnerWire); err != nil {
			return nil, blobStoreError("put", reference.Key, err)
		}
		codec.observe("encode", selectionRemote, len(originalWire), len(remoteWire))
		return remotePayload, nil
	}
	codec.observe("encode", selection, len(originalWire), len(winnerWire))
	return winner, nil
}

func (codec *Codec) decodeOne(payload *commonpb.Payload, depth int) (*commonpb.Payload, error) {
	if payload == nil {
		return nil, errors.Wrap(ErrInvalidPayload, "nil payload")
	}
	encoding := string(payload.Metadata[converter.MetadataEncoding])
	switch encoding {
	case EncodingZstd:
		if err := validateVersion(payload.Metadata); err != nil {
			return nil, err
		}
		decodedWire, err := codec.decompress(payload.Data)
		if err != nil {
			return nil, errors.Wrap(err, "decompress zstd payload")
		}
		decoded, err := unmarshalPayload(decodedWire)
		if err != nil {
			return nil, errors.Wrap(err, "unmarshal zstd payload")
		}
		codec.observe("decode", selectionCompressed, len(payload.Data), len(decodedWire))
		return decoded, nil
	case EncodingRemote:
		if depth >= maximumReferenceDepth {
			return nil, errors.Wrap(ErrInvalidPayload, "nested remote payload reference")
		}
		if err := validateVersion(payload.Metadata); err != nil {
			return nil, err
		}
		reference, err := codec.parseReference(payload.Data)
		if err != nil {
			return nil, err
		}
		if err := checkReadLimit(reference.Size, codec.maximumBlobBytes); err != nil {
			return nil, err
		}
		ctx, cancel := codec.ioContext(context.Background())
		defer cancel()
		stored, err := codec.store.Get(ctx, reference.Key, codec.maximumBlobBytes)
		if err != nil {
			return nil, blobStoreError("get", reference.Key, err)
		}
		if err := verifyBlob(reference, stored); err != nil {
			return nil, err
		}
		inner, err := unmarshalPayload(stored)
		if err != nil {
			return nil, errors.Wrap(err, "unmarshal remote payload")
		}
		codec.observe("decode", selectionRemote, len(payload.Data), len(stored))
		return codec.decodeOne(inner, depth+1)
	default:
		return payload, nil
	}
}

func (codec *Codec) ioContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, codec.ioTimeout)
}

func (codec *Codec) wrappedPayload(encoding string, data []byte) *commonpb.Payload {
	return &commonpb.Payload{Metadata: map[string][]byte{
		converter.MetadataEncoding: []byte(encoding),
		metadataVersion:            []byte(strconv.Itoa(codecVersion)),
	}, Data: bytes.Clone(data)}
}

func (codec *Codec) newReference(digest [sha256.Size]byte, size uint64) remoteReference {
	return remoteReference{Key: blobKey(codec.blobPrefix, digest), Digest: digest, Size: size}
}

func (codec *Codec) parseReference(data []byte) (remoteReference, error) {
	if len(data) != referenceWireSize || data[0] != codecVersion {
		return remoteReference{}, errors.Wrap(ErrInvalidPayload, "remote reference has invalid canonical length or version")
	}
	var digest [sha256.Size]byte
	copy(digest[:], data[1:1+sha256.Size])
	size := binary.BigEndian.Uint64(data[1+sha256.Size:])
	if size == 0 {
		return remoteReference{}, errors.Wrap(ErrInvalidPayload, "remote reference has zero size")
	}
	return codec.newReference(digest, size), nil
}

func (codec *Codec) compress(value []byte) ([]byte, error) {
	codec.compressionMu.Lock()
	defer codec.compressionMu.Unlock()
	return codec.encoder.EncodeAll(value, nil), nil
}

func (codec *Codec) decompress(value []byte) ([]byte, error) {
	codec.compressionMu.Lock()
	defer codec.compressionMu.Unlock()
	return codec.decoder.DecodeAll(value, nil)
}

func (codec *Codec) observe(operation, selection string, inputSizeBytes, outputSizeBytes int) {
	if codec.observer != nil {
		codec.observer.ObservePayload(Observation{Operation: operation, Selection: selection, InputSizeBytes: inputSizeBytes, OutputSizeBytes: outputSizeBytes})
	}
}

type remoteReference struct {
	Key    BlobKey
	Digest [sha256.Size]byte
	Size   uint64
}

func (reference remoteReference) marshal() []byte {
	result := make([]byte, referenceWireSize)
	result[0] = codecVersion
	copy(result[1:1+sha256.Size], reference.Digest[:])
	binary.BigEndian.PutUint64(result[1+sha256.Size:], reference.Size)
	return result
}

func marshalPayload(payload *commonpb.Payload) ([]byte, error) {
	value, err := proto.MarshalOptions{Deterministic: true}.Marshal(payload)
	if err != nil {
		return nil, errors.Wrap(err, "marshal temporal payload")
	}
	return value, nil
}

func unmarshalPayload(value []byte) (*commonpb.Payload, error) {
	payload := &commonpb.Payload{}
	if err := proto.Unmarshal(value, payload); err != nil {
		return nil, errors.Wrap(err, "unmarshal temporal payload")
	}
	return payload, nil
}

func validateVersion(metadata map[string][]byte) error {
	if got := string(metadata[metadataVersion]); got != strconv.Itoa(codecVersion) {
		return errors.Wrapf(ErrUnsupportedVersion, "payload version %q is outside v%d compatibility", got, codecVersion)
	}
	return nil
}
