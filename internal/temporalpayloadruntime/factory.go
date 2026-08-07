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

// Client is a Temporal client created by Factory with the runtime-owned converter.
type Client struct {
	temporalClient client.Client
	dataConverter  converter.DataConverter
}

// NewFactory creates the only runtime-owned factory for Temporal converter configuration.
func NewFactory(codec *temporalpayload.Codec) (*Factory, error) {
	if codec == nil {
		return nil, errors.New("temporal payload codec is required")
	}
	return &Factory{codec: codec, dataConverter: codec.DataConverter()}, nil
}

// DataConverter returns the Factory-owned converter for runtime adapter composition.
func (factory *Factory) DataConverter() converter.DataConverter {
	return factory.dataConverter
}

func (factory *Factory) clientOptions(options client.Options) client.Options {
	options.DataConverter = factory.dataConverter
	return options
}

// NewClient checks retained compatibility before creating a runtime-owned Temporal client.
func (factory *Factory) NewClient(ctx context.Context, options client.Options) (*Client, error) {
	if err := factory.checkStartup(ctx); err != nil {
		return nil, err
	}
	temporalClient, err := client.DialContext(ctx, factory.clientOptions(options))
	if err != nil {
		return nil, errors.Wrap(err, "create runtime-owned Temporal client")
	}
	return &Client{temporalClient: temporalClient, dataConverter: factory.dataConverter}, nil
}

// NewWorker creates a runtime worker from a checked runtime-owned client.
//
// The Temporal Go SDK takes the DataConverter from its client, not from
// worker.Options. Keeping worker creation beside NewClient prevents a
// second raw client/worker composition seam from appearing in runtime code.
func (factory *Factory) NewWorker(temporalClient *Client, taskQueue string, options worker.Options) (worker.Worker, error) {
	if temporalClient == nil || temporalClient.temporalClient == nil {
		return nil, errors.New("configured Temporal client is required")
	}
	if taskQueue == "" {
		return nil, errors.New("Temporal task queue is required")
	}
	return worker.New(temporalClient.temporalClient, taskQueue, options), nil
}

func (factory *Factory) checkStartup(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errors.Wrap(err, "check Temporal payload codec startup compatibility")
	}
	if err := factory.codec.CheckCompatibility(ctx); err != nil {
		return errors.Wrap(err, "check retained Temporal payload compatibility vectors")
	}
	return nil
}
