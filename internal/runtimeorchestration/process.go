// Package runtimeorchestration contains the private Temporal composition for
// state-backed Session work. It is intentionally unreachable from the public
// runtime API and SDK packages.
package runtimeorchestration

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimepostgres"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	"github.com/0x63616c/agent-runtime/internal/temporalpayloadruntime"
	"github.com/cockroachdb/errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
)

// ProcessConfig contains explicit private-role configuration. It has no
// public identity, bearer token, or runtime-content object-store fields.
type ProcessConfig struct {
	DatabaseDSN         string
	TemporalEndpoint    string
	TemporalToken       string
	Namespace           string
	TaskQueue           string
	PayloadBlobEndpoint string
	PayloadBlobBucket   string
	PayloadBlobPrefix   string
	PayloadAccessKey    string
	PayloadSecretKey    string
	// AuditSinkEndpoint enables optional delivery of already-committed audit
	// facts. It must be an explicit HTTPS endpoint; the worker never treats it
	// as a fail-closed state mutation boundary.
	AuditSinkEndpoint string
	AuditSinkTimeout  time.Duration
	// InvocationScheduled observes a committed model invocation intent. It is
	// an optional local process observer; it has no authority to alter durable
	// dispatch and must return promptly.
	InvocationScheduled func(InvocationSchedule)
}

// InvocationSchedule identifies one committed input-owned invocation intent.
type InvocationSchedule struct {
	Tenant      string
	SessionID   string
	TurnID      string
	OperationID runtimestate.OperationID
}

// Wait is the private scheduling seam used between durable outbox scans.
// Production waits for the supplied interval; tests can deterministically
// advance the worker without real-time sleeps.
type Wait func(context.Context, time.Duration) error

// Run starts the codec-enabled worker and drains only durable state/outbox
// routes until cancellation. It owns and closes every private client.
func Run(ctx context.Context, config ProcessConfig) error {
	return RunWithWait(ctx, config, waitForInterval)
}

// RunWithWait is Run with an injected private scheduling seam.
func RunWithWait(ctx context.Context, config ProcessConfig, wait Wait) error {
	if ctx == nil {
		return errors.New("run runtime orchestration worker: context is required")
	}
	if wait == nil {
		return errors.New("run runtime orchestration worker: wait is required")
	}
	if err := validateProcessConfig(config); err != nil {
		return err
	}
	pool, err := pgxpool.New(ctx, config.DatabaseDSN)
	if err != nil {
		return errors.Wrap(err, "run runtime orchestration worker: open PostgreSQL")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.Wrap(err, "run runtime orchestration worker: ping PostgreSQL")
	}
	timeSource := processClock{}
	state, err := runtimepostgres.NewRuntimeStateStore(pool, timeSource)
	if err != nil {
		return err
	}
	compiler, err := runtimestate.NewCompiler(rejectContentHandoff{})
	if err != nil {
		return err
	}
	ids := processIDs{}
	planner, err := runtimestate.NewRuntimeStatePlanner(timeSource, &ids)
	if err != nil {
		return err
	}
	factory, err := temporalpayloadruntime.NewS3Factory(temporalpayloadruntime.S3Config{Endpoint: config.PayloadBlobEndpoint, Bucket: config.PayloadBlobBucket, Prefix: config.PayloadBlobPrefix, AccessKey: config.PayloadAccessKey, SecretKey: config.PayloadSecretKey})
	if err != nil {
		return err
	}
	owned, err := factory.NewClient(ctx, client.Options{HostPort: config.TemporalEndpoint, Namespace: config.Namespace, Credentials: client.NewAPIKeyStaticCredentials(config.TemporalToken), ConnectionOptions: client.ConnectionOptions{TLSDisabled: true}, Identity: "agent-runtime-orchestration-codec"})
	if err != nil {
		return err
	}
	defer owned.Close()
	workerRuntime, err := factory.NewWorker(owned, config.TaskQueue, worker.Options{})
	if err != nil {
		return err
	}
	// Public input routes become model invocation intents only through this
	// private, state-backed scheduler. A dispatcher without the scheduler can
	// acknowledge Temporal delivery while leaving the input permanently
	// unprocessed.
	dispatcher, err := NewDurableStateDispatcherWithInvocationScheduler(state, compiler, planner, config.InvocationScheduled)
	if err != nil {
		return err
	}
	activities, err := NewActivities(dispatcher)
	if err != nil {
		return err
	}
	if err := Register(workerRuntime, activities); err != nil {
		return err
	}
	audit, err := configuredAuditExporter(config)
	if err != nil {
		return err
	}
	publisher, err := NewPublisher(PublisherConfig{Store: state, Tenants: state, Compiler: compiler, Planner: planner, Clock: timeSource, Publisher: temporalSessionPublisher{client: owned, taskQueue: config.TaskQueue}, AuditExporter: audit, Claimer: "orchestration-codec"})
	if err != nil {
		return err
	}
	if err := publisher.ScanOnce(ctx); err != nil {
		return errors.Wrap(err, "run runtime orchestration worker: publish initial outbox")
	}
	// Publish and acknowledge the currently durable routes before starting
	// activity dispatch. This prevents the activity which turns an accepted
	// Input into an invocation intent from racing the publisher's own lease
	// acknowledgement for that exact Input route.
	if err := workerRuntime.Start(); err != nil {
		return errors.Wrap(err, "run runtime orchestration worker: start Temporal worker")
	}
	defer workerRuntime.Stop()
	return publishUntilCancelled(ctx, wait, publisher.ScanOnce)
}

// publishUntilCancelled waits for a normal scheduler tick before scanning
// durable outbox work again. Cancellation ends the process without scheduling
// another scan; a timer's normal completion is successful work.
func publishUntilCancelled(ctx context.Context, wait Wait, scan func(context.Context) error) error {
	if scan == nil {
		return errors.New("run runtime orchestration worker: outbox scan is required")
	}
	for {
		if err := wait(ctx, time.Second); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.Wrap(err, "run runtime orchestration worker: wait to publish outbox")
		}
		if err := scan(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.Wrap(err, "run runtime orchestration worker: publish outbox")
		}
	}
}

func waitForInterval(ctx context.Context, interval time.Duration) error {
	wait, cancel := context.WithTimeout(ctx, interval)
	defer cancel()
	<-wait.Done()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

type temporalSessionPublisher struct {
	client    *temporalpayloadruntime.Client
	taskQueue string
}

func (publisher temporalSessionPublisher) StartSession(ctx context.Context, start SessionStart) error {
	_, err := publisher.client.ExecuteWorkflow(ctx, client.StartWorkflowOptions{ID: workflowID(start), TaskQueue: publisher.taskQueue}, SessionWorkflow, WorkflowInput{SessionID: start.SessionID, ContinueAfter: 1000})
	var alreadyStarted *serviceerror.WorkflowExecutionAlreadyStarted
	if errors.As(err, &alreadyStarted) {
		return nil
	}
	return err
}

func (publisher temporalSessionPublisher) SignalSession(ctx context.Context, start SessionStart, command Command) error {
	_, err := publisher.client.SignalWithStartWorkflow(ctx, workflowID(start), SessionCommandSignal, command, client.StartWorkflowOptions{ID: workflowID(start), TaskQueue: publisher.taskQueue}, SessionWorkflow, WorkflowInput{SessionID: start.SessionID, ContinueAfter: 1000})
	return err
}

func workflowID(start SessionStart) string {
	return "runtime-session-" + start.Tenant + "-" + start.SessionID
}

type rejectContentHandoff struct{}

func (rejectContentHandoff) ValidateAgentSpecificationBodyHandoff(runtimecontent.ContentHandoff) (runtimecontent.AgentSpecificationBodyCommitment, error) {
	return runtimecontent.AgentSpecificationBodyCommitment{}, runtimecontent.ErrNotFoundOrDenied
}

func (rejectContentHandoff) ValidateInputEnvelopeHandoff(runtimecontent.ContentHandoff) (runtimecontent.InputEnvelopeCommitment, error) {
	return runtimecontent.InputEnvelopeCommitment{}, runtimecontent.ErrNotFoundOrDenied
}

func (rejectContentHandoff) ValidateArtifactHandoff(runtimecontent.ContentHandoff) (runtimecontent.ArtifactCommitment, error) {
	return runtimecontent.ArtifactCommitment{}, runtimecontent.ErrNotFoundOrDenied
}

func (rejectContentHandoff) ValidateConversationEntryHandoff(runtimecontent.ContentHandoff) (runtimecontent.ConversationEntryCommitment, error) {
	return runtimecontent.ConversationEntryCommitment{}, runtimecontent.ErrNotFoundOrDenied
}
func (rejectContentHandoff) ValidateToolActionDescriptorHandoff(runtimecontent.ContentHandoff) (runtimecontent.ToolActionDescriptorCommitment, error) {
	return runtimecontent.ToolActionDescriptorCommitment{}, runtimecontent.ErrNotFoundOrDenied
}

type processClock struct{}

func (processClock) Now() time.Time { return time.Now().UTC() }

var _ clock.Clock = processClock{}

type processIDs struct{}

func (*processIDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", errors.Wrap(err, "allocate orchestration identifier")
	}
	for index := range bytes {
		bytes[index] = alphabet[int(bytes[index])%len(alphabet)]
	}
	return string(kind) + "_" + string(bytes), nil
}

func validateProcessConfig(config ProcessConfig) error {
	if config.DatabaseDSN == "" || config.TemporalEndpoint == "" || config.TemporalToken == "" || config.Namespace == "" || config.TaskQueue == "" || config.PayloadBlobEndpoint == "" || config.PayloadBlobBucket == "" || config.PayloadBlobPrefix == "" || config.PayloadAccessKey == "" || config.PayloadSecretKey == "" {
		return errors.New("run runtime orchestration worker: complete codec-enabled role configuration is required")
	}
	if _, err := configuredAuditExporter(config); err != nil {
		return err
	}
	return nil
}

func configuredAuditExporter(config ProcessConfig) (AuditExporter, error) {
	if config.AuditSinkEndpoint == "" {
		if config.AuditSinkTimeout != 0 {
			return nil, errors.New("run runtime orchestration worker: audit sink timeout requires an endpoint")
		}
		return nil, nil
	}
	endpoint, err := url.Parse(config.AuditSinkEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || config.AuditSinkTimeout < time.Second || config.AuditSinkTimeout > time.Minute {
		return nil, errors.New("run runtime orchestration worker: audit sink must be an explicit bounded HTTPS endpoint")
	}
	exporter, err := NewHTTPAuditExporter(config.AuditSinkEndpoint, &http.Client{Timeout: config.AuditSinkTimeout})
	if err != nil {
		return nil, errors.Wrap(err, "run runtime orchestration worker: configure audit sink")
	}
	return exporter, nil
}

var _ SessionWorkflowPublisher = temporalSessionPublisher{}

// Compile-time guard: no runtime-content reader is accepted by this process.
var _ runtimestate.ContentHandoffValidator = rejectContentHandoff{}

func (start SessionStart) String() string { return fmt.Sprintf("%s/%s", start.Tenant, start.SessionID) }
