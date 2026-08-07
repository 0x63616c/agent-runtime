// Package temporalpayloadruntime owns the sole runtime Temporal client and worker converter factory.
package temporalpayloadruntime

import (
	"context"

	"github.com/0x63616c/agent-runtime/temporalpayload"
	"github.com/cockroachdb/errors"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/worker"
)

// Factory applies one local temporalpayload codec to every runtime-owned Temporal client and worker.
type Factory struct {
	codec         *temporalpayload.Codec
	dataConverter converter.DataConverter
}

// NewFactory creates the only runtime-owned factory for Temporal converter configuration.
func NewFactory(codec *temporalpayload.Codec) (*Factory, error) {
	if codec == nil {
		return nil, errors.New("temporal payload codec is required")
	}
	return &Factory{codec: codec, dataConverter: codec.DataConverter()}, nil
}

// ClientOptions replaces any caller converter with the runtime-owned local converter.
func (factory *Factory) ClientOptions(options client.Options) client.Options {
	options.DataConverter = factory.dataConverter
	return options
}

// NewWorker creates a runtime worker from a client configured by ClientOptions.
//
// The Temporal Go SDK takes the DataConverter from its client, not from
// worker.Options. Keeping worker creation beside ClientOptions prevents a
// second raw client/worker composition seam from appearing in runtime code.
func (factory *Factory) NewWorker(temporalClient client.Client, taskQueue string, options worker.Options) (worker.Worker, error) {
	if temporalClient == nil {
		return nil, errors.New("configured Temporal client is required")
	}
	if taskQueue == "" {
		return nil, errors.New("Temporal task queue is required")
	}
	return worker.New(temporalClient, taskQueue, options), nil
}

// CheckStartup verifies that this exact configured codec chain can encode and decode an offloaded compatibility probe before work is accepted.
func (factory *Factory) CheckStartup(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errors.Wrap(err, "check Temporal payload codec startup compatibility")
	}
	probe := startupProbe()
	payload, err := factory.dataConverter.ToPayload(probe)
	if err != nil {
		return errors.Wrap(err, "encode Temporal payload compatibility probe")
	}
	var decoded []byte
	if err := factory.dataConverter.FromPayload(payload, &decoded); err != nil {
		return errors.Wrap(err, "decode Temporal payload compatibility probe")
	}
	if string(decoded) != string(probe) {
		return errors.New("Temporal payload compatibility probe did not round trip")
	}
	return nil
}

func startupProbe() []byte {
	result := make([]byte, 64*1024)
	state := uint64(1)
	for index := range result {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		result[index] = byte(state)
	}
	return result
}
