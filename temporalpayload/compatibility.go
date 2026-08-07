package temporalpayload

import (
	"bytes"
	"context"
	"encoding/hex"

	"github.com/cockroachdb/errors"
	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"
	"google.golang.org/protobuf/proto"
)

type compatibilityVector struct {
	name                string
	source              *commonpb.Payload
	encoding            string
	encodedPayloadHex   string
	encodedPayloadBytes int
	storedInnerHex      string
}

func v1CompatibilityVectors() []compatibilityVector {
	vectors := []compatibilityVector{
		{
			name:                "inline",
			source:              vectorPayload([]byte("agent-runtime-v1-inline")),
			encoding:            "json/plain",
			encodedPayloadHex:   "0a160a08656e636f64696e67120a6a736f6e2f706c61696e12176167656e742d72756e74696d652d76312d696e6c696e65",
			encodedPayloadBytes: 49,
		},
		{
			name:                "zstd",
			source:              vectorPayload(bytes.Repeat([]byte("x"), 1024)),
			encoding:            EncodingZstd,
			encodedPayloadHex:   "0a1c0a176167656e742d72756e74696d652d7061796c6f61642d761201310a170a08656e636f64696e67120b62696e6172792f7a737464123328b52ffd641b032d0100c4010a160a08656e636f64696e67120a6a736f6e2f706c61696e12800878015415022df027b5b4b221",
			encodedPayloadBytes: 108,
			storedInnerHex:      "0a160a08656e636f64696e67120a6a736f6e2f706c61696e128002414129256501710dff2ee489e6a3e47b2531af5cf0b9a2d97a9c69b76a0c1404381cf6fd52b80b2b3b59ab82c5025286fbdab3ca0dc1d4035d15eb5a6832487ed0217bb3f2ed1020967f83da45cdea7fbd00a67d5f971a9649035bf55c1856021c869fc8959e8170ec930cd839d7e0b71aaeb1741ec2176fef6e541ef42533afe2ab84c150ea7f994a7898e3a6eb74d039d1e8f3c06b2f1f95eeab08ac578bfe87ca71632b9f3200e4db0a22d4c1b47bd99079279f0886735b29afa0156f574fdfccbb1ae2c74818980b29cbe62173e582d5b22d39212d5169c59ce9e6a5465e300608347072980331192bf122cec78ebd08f2871a444a54365e440c86955e26",
		},
		{
			name:                "remote",
			source:              vectorPayload(vectorIncompressibleBytes(256)),
			encoding:            EncodingRemote,
			encodedPayloadHex:   "0a1c0a176167656e742d72756e74696d652d7061796c6f61642d761201310a210a08656e636f64696e67121562696e6172792f72656d6f74652d7061796c6f6164122901adb4968c30adc51138e2526c1c0a246c756d5eb59a78ce484125f9aadc10f7b1000000000000011b",
			encodedPayloadBytes: 108,
		},
	}
	vectors[2].storedInnerHex = vectors[1].storedInnerHex
	vectors[1].storedInnerHex = ""
	return vectors
}

func vectorPayload(data []byte) *commonpb.Payload {
	return &commonpb.Payload{Metadata: map[string][]byte{
		converter.MetadataEncoding: []byte("json/plain"),
	}, Data: bytes.Clone(data)}
}

func vectorIncompressibleBytes(sizeBytes int) []byte {
	result := make([]byte, sizeBytes)
	state := uint64(1)
	for index := range result {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		result[index] = byte(state)
	}
	return result
}

// CheckCompatibility verifies retained v1 inline, zstd, and remote payload vectors before accepting work.
func (codec *Codec) CheckCompatibility(ctx context.Context) error {
	for _, vector := range v1CompatibilityVectors() {
		if err := ctx.Err(); err != nil {
			return errors.Wrap(err, "check temporal payload compatibility")
		}
		wantWire, err := hex.DecodeString(vector.encodedPayloadHex)
		if err != nil {
			return errors.Wrapf(err, "decode retained temporal payload %q fixture", vector.name)
		}
		retained, err := unmarshalPayload(wantWire)
		if err != nil {
			return errors.Wrapf(err, "unmarshal retained temporal payload %q", vector.name)
		}
		if vector.storedInnerHex != "" {
			reference, err := codec.parseReference(retained.Data)
			if err != nil {
				return errors.Wrapf(err, "parse retained temporal payload %q reference", vector.name)
			}
			stored, err := hex.DecodeString(vector.storedInnerHex)
			if err != nil {
				return errors.Wrapf(err, "decode retained temporal payload %q stored inner fixture", vector.name)
			}
			seedContext, cancel := codec.ioContext(ctx)
			err = codec.store.Put(seedContext, reference.Key, stored)
			cancel()
			if err != nil {
				return errors.Wrapf(err, "seed retained temporal payload %q blob", vector.name)
			}
		}
		decoded, err := codec.Decode([]*commonpb.Payload{retained})
		if err != nil {
			return errors.Wrapf(err, "decode retained temporal payload %q", vector.name)
		}
		if !proto.Equal(decoded[0], vector.source) {
			return errors.Newf("retained temporal payload %q does not match its frozen source", vector.name)
		}

		encoded, err := codec.Encode([]*commonpb.Payload{proto.Clone(vector.source).(*commonpb.Payload)})
		if err != nil {
			return errors.Wrapf(err, "encode retained temporal payload %q", vector.name)
		}
		if got := string(encoded[0].Metadata[converter.MetadataEncoding]); got != vector.encoding {
			return errors.Newf("retained temporal payload %q encoding = %q, want %q", vector.name, got, vector.encoding)
		}
		gotWire, err := marshalPayload(encoded[0])
		if err != nil {
			return errors.Wrapf(err, "marshal retained temporal payload %q", vector.name)
		}
		if len(gotWire) != vector.encodedPayloadBytes || !bytes.Equal(gotWire, wantWire) {
			return errors.Newf("retained temporal payload %q emission vector changed", vector.name)
		}
		decoded, err = codec.Decode(encoded)
		if err != nil {
			return errors.Wrapf(err, "decode retained temporal payload %q", vector.name)
		}
		if !proto.Equal(decoded[0], vector.source) {
			return errors.Newf("retained temporal payload %q did not round trip", vector.name)
		}
	}
	return nil
}
