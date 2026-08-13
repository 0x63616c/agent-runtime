package tooldispatch

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimepostgres"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	"github.com/0x63616c/agent-runtime/internal/runtimetool"
	"github.com/0x63616c/agent-runtime/sandbox"
	cerrors "github.com/cockroachdb/errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// MountedTrustSource resolves exactly one operator-mounted CA bundle; it never
// falls back to ambient system roots.
type MountedTrustSource struct {
	Path      string
	Reference sandbox.TrustBundleRef
}

func (source MountedTrustSource) ResolveTrustBundle(ctx context.Context, reference sandbox.TrustBundleRef) (sandbox.TrustBundle, error) {
	if err := ctx.Err(); err != nil {
		return sandbox.TrustBundle{}, err
	}
	if source.Path == "" || !filepath.IsAbs(source.Path) || reference != source.Reference {
		return sandbox.TrustBundle{}, errors.New("resolve tool dispatch trust: declared bundle is unavailable")
	}
	pem, err := os.ReadFile(source.Path)
	if err != nil || len(pem) == 0 {
		return sandbox.TrustBundle{}, errors.New("resolve tool dispatch trust: declared bundle is unavailable")
	}
	return sandbox.TrustBundle{Version: string(reference), PEMRoots: pem}, nil
}

// TokenCredentials applies the operator-provided control credential only to a
// sandbox client request; callers must not log or serialize this value.
type TokenCredentials string

func (value TokenCredentials) Apply(_ context.Context, sink sandbox.CredentialSink) error {
	if value == "" {
		return errors.New("apply tool dispatch control credential: unavailable")
	}
	return sink.SetAuthorization("Bearer", string(value))
}

// NewControlClient builds the only allowed dispatch adapter transport.
func NewControlClient(ctx context.Context, endpoint, serverName string, trust MountedTrustSource, token string) (sandbox.Client, error) {
	return sandbox.NewClient(ctx, sandbox.ClientConfig{Endpoint: sandbox.Endpoint{URL: endpoint}, TLS: sandbox.TLSConfig{ServerName: serverName, TrustBundleRef: trust.Reference}, TrustBundles: trust, Credentials: TokenCredentials(token), RequestTimeout: 15 * time.Second})
}

// ProcessConfig contains only the private authorities held by the broker
// process. The trigger endpoint and receipt never expose these fields.
type ProcessConfig struct {
	DatabaseDSN       string
	ContentEndpoint   string
	ContentBucket     string
	ContentAccessKey  string
	ContentSecretKey  string
	ControlEndpoint   string
	ControlServerName string
	ControlTrust      MountedTrustSource
	ControlToken      string
	Claimer           string
}

// Process owns the broker worker and every private client it requires.
type Process struct {
	server  *Server
	pool    *pgxpool.Pool
	control sandbox.Client
}

// NewProcess composes one broker-owned durable tool worker. It deliberately
// has no public request parameters: selection, grants, descriptors, and
// effect recovery stay inside runtimetool.Worker.
func NewProcess(ctx context.Context, triggerToken string, config ProcessConfig) (*Process, error) {
	contentURL, contentHost, validContentEndpoint := contentOrigin(config.ContentEndpoint)
	if ctx == nil || triggerToken == "" || config.DatabaseDSN == "" || !validContentEndpoint || contentURL == nil || contentHost == "" || config.ContentBucket == "" || config.ContentAccessKey == "" || config.ContentSecretKey == "" || config.ControlEndpoint == "" || config.ControlServerName == "" || !filepath.IsAbs(config.ControlTrust.Path) || config.ControlTrust.Reference == "" || config.ControlToken == "" || config.Claimer == "" {
		return nil, errors.New("compose tool dispatch process: declared private configuration is required")
	}
	pool, err := pgxpool.New(ctx, config.DatabaseDSN)
	if err != nil {
		return nil, cerrors.Wrap(err, "compose tool dispatch process: open PostgreSQL")
	}
	closePool := true
	defer func() {
		if closePool {
			pool.Close()
		}
	}()
	if err := pool.Ping(ctx); err != nil {
		return nil, cerrors.Wrap(err, "compose tool dispatch process: ping PostgreSQL")
	}
	source := systemClock{}
	state, err := runtimepostgres.NewRuntimeStateStore(pool, source)
	if err != nil {
		return nil, err
	}
	minioClient, err := minio.New(contentHost, &minio.Options{Creds: credentials.NewStaticV4(config.ContentAccessKey, config.ContentSecretKey, ""), Secure: true})
	if err != nil {
		return nil, cerrors.Wrap(err, "compose tool dispatch process: create content client")
	}
	immutable, err := runtimecontent.NewMinIOImmutableClient(minioClient)
	if err != nil {
		return nil, err
	}
	objects, err := runtimecontent.NewS3ImmutableObjects(immutable, config.ContentBucket)
	if err != nil {
		return nil, err
	}
	content, err := runtimecontent.New("tool-dispatch-content", objects)
	if err != nil {
		return nil, err
	}
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		return nil, err
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(source, processIDs{})
	if err != nil {
		return nil, err
	}
	control, err := NewControlClient(ctx, config.ControlEndpoint, config.ControlServerName, config.ControlTrust, config.ControlToken)
	if err != nil {
		return nil, cerrors.Wrap(err, "compose tool dispatch process: create sandbox control client")
	}
	adapter, err := runtimetool.NewSandboxAdapter(control)
	if err != nil {
		return nil, err
	}
	worker, err := runtimetool.NewWorker(runtimetool.Config{Store: state, Tenants: state, Compiler: compiler, Planner: planner, Clock: source, Content: content, Adapter: adapter, Claimer: config.Claimer, LeaseScheduler: runtimetool.NewRealtimeLeaseScheduler()})
	if err != nil {
		return nil, err
	}
	server, err := NewBrokerServer(triggerToken, worker)
	if err != nil {
		return nil, err
	}
	closePool = false
	return &Process{server: server, pool: pool, control: control}, nil
}

func contentOrigin(value string) (*url.URL, string, bool) {
	endpoint, err := url.Parse(value)
	if err != nil || endpoint == nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") {
		return nil, "", false
	}
	return endpoint, endpoint.Host, true
}

func (process *Process) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if process == nil || process.server == nil {
		http.Error(writer, "dispatch unavailable", http.StatusServiceUnavailable)
		return
	}
	process.server.ServeHTTP(writer, request)
}

// NewHTTPServer returns the bounded TLS-only server used by the dispatch role.
// The bearer-token peer policy is intentionally explicit: this private role
// authenticates callers at the handler and never accepts a plaintext listener.
func NewHTTPServer(handler http.Handler, certificate tls.Certificate, peerPolicy string) (*http.Server, error) {
	if handler == nil || len(certificate.Certificate) == 0 || peerPolicy != "bearer-token-v1" {
		return nil, errors.New("create tool dispatch TLS server: declared bearer peer policy and identity are required")
	}
	// Keeping the policy as an explicit input prevents a future configuration
	// profile from silently selecting a different peer-authentication scheme.
	return &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}}, nil
}

// Close releases the process-owned state connection pool. Sandbox client
// requests are self-contained and do not retain a closeable transport here.
func (process *Process) Close() {
	if process != nil && process.control != nil {
		_ = process.control.Close(context.Background())
	}
	if process != nil && process.pool != nil {
		process.pool.Close()
	}
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

var _ clock.Clock = systemClock{}

type processIDs struct{}

func (processIDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s_%x", kind, value[:]), nil
}
