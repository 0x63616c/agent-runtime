// Package temporalpayloadruntime owns the sole runtime Temporal client and worker converter factory.
package temporalpayloadruntime

import (
	"context"
	"net/url"
	"strings"

	"github.com/0x63616c/agent-runtime/temporalpayload"
	temporals3 "github.com/0x63616c/agent-runtime/temporalpayload/s3"
	"github.com/cockroachdb/errors"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	enumspb "go.temporal.io/api/enums/v1"
	historypb "go.temporal.io/api/history/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/worker"
)

// Factory applies one local temporalpayload codec to every runtime-owned Temporal client and worker.
type Factory struct {
	codec         *temporalpayload.Codec
	dataConverter converter.DataConverter
}

// S3Config is the explicit payload-only object-store capability required to
// construct the local runtime codec. It intentionally has no runtime-content
// fields or public identity.
type S3Config struct {
	Endpoint  string
	Bucket    string
	Prefix    string
	AccessKey string
	SecretKey string
}

// Client is a Temporal client created by Factory with the runtime-owned converter.
type Client struct {
	temporalClient client.Client
	dataConverter  converter.DataConverter
}

// ExecuteWorkflow starts one private runtime workflow through the configured client.
func (client *Client) ExecuteWorkflow(ctx context.Context, options client.StartWorkflowOptions, workflow any, arguments ...any) (client.WorkflowRun, error) {
	if client == nil || client.temporalClient == nil {
		return nil, errors.New("execute runtime workflow: configured Temporal client is required")
	}
	return client.temporalClient.ExecuteWorkflow(ctx, options, workflow, arguments...)
}

// SignalWorkflow sends one private signal through the configured client.
func (client *Client) SignalWorkflow(ctx context.Context, workflowID, runID, signal string, argument any) error {
	if client == nil || client.temporalClient == nil {
		return errors.New("signal runtime workflow: configured Temporal client is required")
	}
	return client.temporalClient.SignalWorkflow(ctx, workflowID, runID, signal, argument)
}

// SignalWithStartWorkflow atomically reaches an existing private workflow or
// starts it through the runtime-owned converter before delivering the signal.
func (owned *Client) SignalWithStartWorkflow(ctx context.Context, workflowID, signal string, argument any, options client.StartWorkflowOptions, workflow any, arguments ...any) (client.WorkflowRun, error) {
	if owned == nil || owned.temporalClient == nil {
		return nil, errors.New("signal with start runtime workflow: configured Temporal client is required")
	}
	return owned.temporalClient.SignalWithStartWorkflow(ctx, workflowID, signal, argument, options, workflow, arguments...)
}

// Close closes the owned Temporal client.
func (client *Client) Close() {
	if client != nil && client.temporalClient != nil {
		client.temporalClient.Close()
	}
}

// WorkflowHistory obtains one complete private workflow history through the
// owned client. It is intended for retained replay evidence, not public API.
func (owned *Client) WorkflowHistory(ctx context.Context, workflowID, runID string) (*historypb.History, error) {
	if owned == nil || owned.temporalClient == nil {
		return nil, errors.New("read runtime workflow history: configured Temporal client is required")
	}
	iterator := owned.temporalClient.GetWorkflowHistory(ctx, workflowID, runID, false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	history := &historypb.History{}
	for iterator.HasNext() {
		event, err := iterator.Next()
		if err != nil {
			return nil, errors.Wrap(err, "read runtime workflow history")
		}
		history.Events = append(history.Events, event)
	}
	return history, nil
}

// NewFactory creates the only runtime-owned factory for Temporal converter configuration.
func NewFactory(codec *temporalpayload.Codec) (*Factory, error) {
	if codec == nil {
		return nil, errors.New("temporal payload codec is required")
	}
	return &Factory{codec: codec, dataConverter: codec.DataConverter()}, nil
}

// NewS3Factory creates the one owned codec/factory from the worker's separate
// temporal-payload bucket capability. Application code receives only Factory.
func NewS3Factory(config S3Config) (*Factory, error) {
	if config.Endpoint == "" || config.Bucket == "" || config.Prefix == "" || config.AccessKey == "" || config.SecretKey == "" {
		return nil, errors.New("create Temporal payload factory: complete payload S3 configuration is required")
	}
	endpoint, secure, err := parseS3Endpoint(config.Endpoint)
	if err != nil {
		return nil, err
	}
	client, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(config.AccessKey, config.SecretKey, ""), Secure: secure})
	if err != nil {
		return nil, errors.Wrap(err, "create Temporal payload factory: create S3 client")
	}
	store, err := temporals3.New(client, config.Bucket)
	if err != nil {
		return nil, err
	}
	codec, err := temporalpayload.NewCodec(store, temporalpayload.WithBlobPrefix(config.Prefix))
	if err != nil {
		return nil, err
	}
	return NewFactory(codec)
}

func parseS3Endpoint(raw string) (string, bool, error) {
	if !strings.Contains(raw, "://") {
		return raw, false, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.Path != "" {
		return "", false, errors.New("create Temporal payload factory: S3 endpoint is invalid")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false, errors.New("create Temporal payload factory: S3 endpoint scheme is unsupported")
	}
	return parsed.Host, parsed.Scheme == "https", nil
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

// NewWorkflowReplayer applies the exact owned converter to historic workflow
// replay so codec indirection cannot be bypassed in retained evidence.
func (factory *Factory) NewWorkflowReplayer() (worker.WorkflowReplayer, error) {
	if factory == nil || factory.dataConverter == nil {
		return nil, errors.New("create runtime workflow replayer: factory is required")
	}
	return worker.NewWorkflowReplayerWithOptions(worker.WorkflowReplayerOptions{DataConverter: factory.dataConverter})
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
