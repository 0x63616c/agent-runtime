// Package localdemoworker composes the declared deterministic local Stack
// fixture. It is intentionally not a production model-provider adapter.
package localdemoworker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/roles"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimemodel"
	"github.com/0x63616c/agent-runtime/internal/runtimepostgres"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	"github.com/0x63616c/agent-runtime/internal/runtimetool"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/cockroachdb/errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Lookup reads one explicitly injected process environment value.
type Lookup func(string) (string, bool)

// Wait blocks until the next local worker scan. It is injected so recovery
// tests can drive an explicit scan boundary without sleeping on wall-clock
// time.
type Wait func(context.Context, time.Duration) error

// Run drains durable model or tool outbox work through the declared local
// fixture. It is only reachable after roles.Parse has accepted local-demo-v1.
func Run(ctx context.Context, role roles.Config, lookup Lookup, logger *slog.Logger) error {
	return run(ctx, role, lookup, systemClock{}, waitForInterval, logger)
}

func run(ctx context.Context, role roles.Config, lookup Lookup, source clock.Clock, wait Wait, logger *slog.Logger) error {
	if ctx == nil || lookup == nil || role.LocalDemoWorker() == nil || !role.LocalDemoWorker().Enabled {
		return errors.New("run local demo worker: context, lookup, and declared local demo capability are required")
	}
	if source == nil || wait == nil || logger == nil {
		return errors.New("run local demo worker: clock, wait, and logger are required")
	}
	declaration := role.LocalDemoWorker()
	if declaration.Fixture != "workspace-approval-v1" {
		return errors.New("run local demo worker: unsupported declared fixture")
	}
	approvalTTL, err := approvalTTLForScenario(declaration.FixtureScenario)
	if err != nil {
		return err
	}
	dsn, ok := lookup(declaration.StateDSNEnvironment)
	if !ok || dsn == "" {
		return errors.New("run local demo worker: state credential is unavailable")
	}
	accessKey, ok := lookup(declaration.ContentAccessKeyEnvironment)
	if !ok || accessKey == "" {
		return errors.New("run local demo worker: content access credential is unavailable")
	}
	secretKey, ok := lookup(declaration.ContentSecretKeyEnvironment)
	if !ok || secretKey == "" {
		return errors.New("run local demo worker: content secret credential is unavailable")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return errors.Wrap(err, "run local demo worker: open PostgreSQL")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.Wrap(err, "run local demo worker: ping PostgreSQL")
	}
	state, err := runtimepostgres.NewRuntimeStateStore(pool, source)
	if err != nil {
		return err
	}
	client, err := minio.New(declaration.ContentEndpoint, &minio.Options{Creds: credentials.NewStaticV4(accessKey, secretKey, ""), Secure: false})
	if err != nil {
		return errors.Wrap(err, "run local demo worker: create MinIO client")
	}
	immutable, err := runtimecontent.NewMinIOImmutableClient(client)
	if err != nil {
		return err
	}
	objects, err := runtimecontent.NewS3ImmutableObjects(immutable, declaration.ContentBucket)
	if err != nil {
		return err
	}
	content, err := runtimecontent.New("runtime-content", objects)
	if err != nil {
		return err
	}
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		return err
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(source, randomIDs{})
	if err != nil {
		return err
	}
	var scan func(context.Context) error
	switch role.Role() {
	case roles.RoleModel:
		broker, brokerErr := runtimetool.NewBroker(runtimetool.BrokerConfig{Store: state, Compiler: compiler, Planner: planner, Clock: source})
		if brokerErr != nil {
			return brokerErr
		}
		worker, createErr := runtimemodel.NewWorker(runtimemodel.WorkerConfig{Store: state, Tenants: state, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: modelFixture{approvalTTL: approvalTTL}, Broker: broker, Claimer: "local-demo-model"})
		if createErr != nil {
			return createErr
		}
		scan = worker.ScanOnce
	case roles.RoleTool:
		worker, createErr := runtimetool.NewWorker(runtimetool.Config{Store: state, Tenants: state, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: toolFixture{}, Claimer: "local-demo-tool", LeaseScheduler: runtimetool.NewRealtimeLeaseScheduler()})
		if createErr != nil {
			return createErr
		}
		scan = worker.ScanOnce
	default:
		return errors.New("run local demo worker: role is not model or tool")
	}
	return scanLoop(ctx, scan, 100*time.Millisecond, wait, logger)
}

// scanLoop retries only the StateRuntime's typed transient unavailable signal.
// Invalid fixture configuration, lost authority, and every other worker error
// stay visible rather than silently turning a broken demo into a healthy role.
func scanLoop(ctx context.Context, scan func(context.Context) error, interval time.Duration, wait Wait, logger *slog.Logger) error {
	if ctx == nil || scan == nil || wait == nil || logger == nil || interval <= 0 {
		return errors.New("run local demo worker: scan, wait, logger, and positive interval are required")
	}
	for {
		if err := scan(ctx); err != nil {
			if errors.Is(err, runtimestate.ErrUnavailable) {
				// This correlation-only record intentionally excludes the returned
				// error: even a future adapter must not turn local diagnostics into
				// a credential, descriptor, or provider-response disclosure path.
				logger.Warn("local demo worker transient unavailable", "reason", "state_unavailable")
			} else {
				if errors.Is(err, context.Canceled) {
					return nil
				}
				return errors.Wrap(err, "run local demo worker: scan")
			}
		}
		if err := wait(ctx, interval); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) && ctx.Err() != nil {
				return nil
			}
			// The production wait owns a child deadline for the next scan
			// boundary. A live parent context means that deadline is the normal
			// successful tick, not a worker failure.
			if errors.Is(err, context.DeadlineExceeded) {
				continue
			}
			return errors.Wrap(err, "run local demo worker: wait to scan")
		}
		if ctx.Err() != nil {
			return nil
		}
	}
}

func waitForInterval(ctx context.Context, interval time.Duration) error {
	wait, cancel := context.WithTimeout(ctx, interval)
	defer cancel()
	<-wait.Done()
	return wait.Err()
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

var _ clock.Clock = systemClock{}

type randomIDs struct{}

func (randomIDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	// Every public runtime identifier uses an exact sixteen-character opaque
	// payload. Eight random bytes encode as sixteen lowercase hexadecimal
	// characters and remain safe to persist through the public parsers.
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s_%x", kind, value[:]), nil
}

// modelFixture emits the one declared workspace-approval fixture request. The
// local demo owner must create its matching policy through the public admin
// contract. It never receives Agent configuration, raw Input, credentials, or
// a sandbox capability, so it cannot infer or perform workspace work.
type modelFixture struct {
	approvalTTL time.Duration
}

func (fixture modelFixture) Invoke(ctx context.Context, request runtimemodel.Request) (runtimemodel.Response, error) {
	return fixture.response(ctx, request)
}
func (fixture modelFixture) Reconcile(ctx context.Context, request runtimemodel.Request) (runtimemodel.Response, error) {
	return fixture.response(ctx, request)
}

func (fixture modelFixture) response(_ context.Context, request runtimemodel.Request) (runtimemodel.Response, error) {
	if request.OperationID == "" || request.CreatedAt.IsZero() {
		return runtimemodel.Response{}, errors.New("local demo model fixture: operation identity and durable creation time are required")
	}
	return fixtureModelResponseWithTTLAt(request, fixture.approvalTTL, request.CreatedAt), nil
}

func approvalTTLForScenario(scenario roles.LocalDemoFixtureScenario) (time.Duration, error) {
	switch scenario {
	case roles.LocalDemoFixtureScenarioWorkspaceApprovalReset:
		return 10 * time.Minute, nil
	case roles.LocalDemoFixtureScenarioWorkspaceApprovalExpiry:
		return 2 * time.Second, nil
	default:
		return 0, errors.New("run local demo worker: unsupported declared fixture scenario")
	}
}

func fixtureModelResponseWithTTLAt(request runtimemodel.Request, approvalTTL time.Duration, now time.Time) runtimemodel.Response {
	sum := sha256.Sum256([]byte(request.OperationID))
	identity := fmt.Sprintf("%x", sum[:])
	// Public Approval IDs have an exact sixteen-character opaque payload.
	// Keep the fixture deterministic while conforming to that public contract.
	approvalIdentity := identity[:16]
	descriptor := []byte(`{"kind":"local-demo-workspace-write","path":"workspace/fixture-report.txt","execution":"artifact-only"}`)
	return runtimemodel.Response{Tool: &runtimemodel.ToolRequest{
		ToolCallID:       "tcall_" + approvalIdentity,
		ApprovalID:       "appr_" + approvalIdentity,
		PolicyName:       "workspace-write-demo",
		PolicyRevision:   1,
		ToolName:         "workspace.write",
		ActionDigest:     fixtureDigest(descriptor),
		CapabilityDigest: fixtureDigest([]byte("local-demo-workspace-capability/" + identity)),
		// This describes the requested public Workspace operation. The fixture's
		// bounded output is an Artifact only; it does not execute a workspace
		// service or a Firecracker sandbox.
		Action:      agentruntime.ApprovalAction{Verb: "write", Target: "workspace-service"},
		MaximumUses: 1,
		ExpiresAt:   now.UTC().Add(approvalTTL),
		Descriptor:  descriptor,
	}}
}

func fixtureDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + fmt.Sprintf("%x", sum[:])
}

type toolFixture struct{}

func (toolFixture) Execute(_ context.Context, request runtimetool.Request) (runtimetool.Response, error) {
	return fixtureToolResponse(request), nil
}
func (toolFixture) Reconcile(_ context.Context, request runtimetool.Request) (runtimetool.Response, error) {
	return fixtureToolResponse(request), nil
}
func (toolFixture) ExternalEffectContract() runtimetool.ExternalEffectContract {
	return runtimetool.ExternalEffectContract{IdempotencyKey: "operation_id", Reconciles: true}
}
func fixtureToolResponse(request runtimetool.Request) runtimetool.Response {
	return runtimetool.Response{Output: []byte("Local demo workspace.write fixture recorded operation " + string(request.OperationID) + ". No workspace service or sandbox was executed; this owner artifact is topology evidence only."), MediaType: "text/plain; charset=utf-8"}
}
