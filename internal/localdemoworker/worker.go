// Package localdemoworker composes the declared deterministic local Stack
// fixture. It is intentionally not a production model-provider adapter.
package localdemoworker

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
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

// Run drains durable model or tool outbox work through the declared local
// fixture. It is only reachable after roles.Parse has accepted local-demo-v1.
func Run(ctx context.Context, role roles.Config, lookup Lookup) error {
	if ctx == nil || lookup == nil || role.LocalDemoWorker() == nil || !role.LocalDemoWorker().Enabled {
		return errors.New("run local demo worker: context, lookup, and declared local demo capability are required")
	}
	declaration := role.LocalDemoWorker()
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
	state, err := runtimepostgres.NewRuntimeStateStore(pool)
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
	planner, err := runtimestate.NewRuntimeStatePlanner(systemClock{}, randomIDs{})
	if err != nil {
		return err
	}
	var scan func(context.Context) error
	switch role.Role() {
	case roles.RoleModel:
		broker, brokerErr := runtimetool.NewBroker(runtimetool.BrokerConfig{Store: state, Compiler: compiler, Planner: planner, Clock: systemClock{}})
		if brokerErr != nil {
			return brokerErr
		}
		worker, createErr := runtimemodel.NewWorker(runtimemodel.WorkerConfig{Store: state, Tenants: state, Compiler: compiler, Planner: planner, Clock: systemClock{}, Content: content, Adapter: modelFixture{}, Broker: broker, Claimer: "local-demo-model"})
		if createErr != nil {
			return createErr
		}
		scan = worker.ScanOnce
	case roles.RoleTool:
		worker, createErr := runtimetool.NewWorker(runtimetool.Config{Store: state, Tenants: state, Compiler: compiler, Planner: planner, Clock: systemClock{}, Content: content, Adapter: toolFixture{}, Claimer: "local-demo-tool"})
		if createErr != nil {
			return createErr
		}
		scan = worker.ScanOnce
	default:
		return errors.New("run local demo worker: role is not model or tool")
	}
	return scanLoop(ctx, scan, 100*time.Millisecond)
}

// scanLoop retries only the StateRuntime's typed transient unavailable signal.
// Invalid fixture configuration, lost authority, and every other worker error
// stay visible rather than silently turning a broken demo into a healthy role.
func scanLoop(ctx context.Context, scan func(context.Context) error, interval time.Duration) error {
	for {
		if err := scan(ctx); err != nil && !errors.Is(err, runtimestate.ErrUnavailable) {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return errors.Wrap(err, "run local demo worker: scan")
		}
		// A child deadline makes the poll interval explicit while preserving the
		// caller's cancellation authority. The normal local deadline is merely
		// the next scan boundary; it is not a worker failure.
		wait, cancel := context.WithTimeout(ctx, interval)
		<-wait.Done()
		waitErr := wait.Err()
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if !errors.Is(waitErr, context.DeadlineExceeded) {
			return errors.Wrap(waitErr, "run local demo worker: wait to scan")
		}
	}
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

// modelFixture emits a synthetic approved-action candidate. The local demo
// owner must create its matching policy through the public admin contract.
type modelFixture struct{}

func (modelFixture) Invoke(_ context.Context, request runtimemodel.Request) (runtimemodel.Response, error) {
	return fixtureModelResponse(request), nil
}
func (modelFixture) Reconcile(_ context.Context, request runtimemodel.Request) (runtimemodel.Response, error) {
	return fixtureModelResponse(request), nil
}
func fixtureModelResponse(request runtimemodel.Request) runtimemodel.Response {
	sum := sha256.Sum256([]byte(request.OperationID))
	identity := fmt.Sprintf("%x", sum[:])
	// Public Approval IDs have an exact sixteen-character opaque payload.
	// Keep the fixture deterministic while conforming to that public contract.
	approvalIdentity := identity[:16]
	descriptor := []byte(`{"kind":"local-demo-research","citation":"https://example.invalid/local-demo"}`)
	return runtimemodel.Response{Tool: &runtimemodel.ToolRequest{
		ToolCallID:       "tcall_" + approvalIdentity,
		ApprovalID:       "appr_" + approvalIdentity,
		PolicyName:       "research-dossier-demo",
		PolicyRevision:   1,
		ToolName:         "research",
		ActionDigest:     fixtureDigest(descriptor),
		CapabilityDigest: fixtureDigest([]byte("local-demo-capability/" + identity)),
		// The tool remains named "research", but its bounded fixture output is
		// committed as an Artifact. The approval summary must use the canonical
		// closed action vocabulary accepted by the durable policy boundary.
		Action:      agentruntime.ApprovalAction{Verb: "write", Target: "artifact"},
		MaximumUses: 1,
		ExpiresAt:   time.Now().UTC().Add(10 * time.Minute),
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
	// Keep the final material large enough to exercise the public streaming
	// download path rather than merely returning an in-memory-looking fixture.
	// The deterministic repeated text is deliberately harmless and preserves a
	// human-readable citation at the start of the retained artifact.
	prefix := []byte("Local demo research fixture completed. Citation: https://example.invalid/local-demo/" + string(request.OperationID) + "\n")
	output := append([]byte(nil), prefix...)
	output = append(output, bytes.Repeat([]byte("local-demo-research-evidence\n"), (513*1024-len(output))/len("local-demo-research-evidence\n")+1)...)
	return runtimetool.Response{Output: output, MediaType: "text/plain; charset=utf-8"}
}
