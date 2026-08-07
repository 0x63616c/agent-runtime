package testdata

import (
	. "go.temporal.io/sdk/converter"
	temporalconverter "go.temporal.io/sdk/converter"
)

func rawTemporalRemoteCodecConstructors() {
	newRemotePayloadCodec := temporalconverter.NewRemotePayloadCodec
	newRemotePayloadCodec()
	NewRemoteDataConverter()
}
