package sandboxcontrolprocess

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxcontrol"
	"github.com/0x63616c/agent-runtime/internal/sandboxcontrolapi"
	"github.com/cockroachdb/errors"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SecretLookup resolves only the explicitly named, already-injected process
// environment values at the composition boundary.
type SecretLookup func(string) (string, bool)

// Run starts the TLS sandbox-control process and blocks until cancellation or
// a server failure. It never creates or migrates infrastructure.
func Run(ctx context.Context, config Config, lookup SecretLookup) error {
	if ctx == nil || lookup == nil {
		return errors.New("run sandbox-control process: context and secret lookup are required")
	}
	dsn, err := requiredSecret(lookup, config.databaseDSNEnvironment)
	if err != nil {
		return err
	}
	authorization, err := requiredSecret(lookup, config.authorizationEnv)
	if err != nil {
		return err
	}
	keyHex, err := requiredSecret(lookup, config.assertionKeyEnv)
	if err != nil {
		return err
	}
	assertionKey, err := hex.DecodeString(keyHex)
	if err != nil || len(assertionKey) < 32 || len(assertionKey) > 128 {
		return errors.New("run sandbox-control process: assertion key is invalid")
	}
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return errors.New("run sandbox-control process: database configuration is invalid")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.Wrap(err, "run sandbox-control process: open database")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.Wrap(err, "run sandbox-control process: ping database")
	}
	store, err := sandboxcontrol.NewPostgresLedger(pool)
	if err != nil {
		return err
	}
	authenticator, err := sandboxcontrolapi.NewStaticAuthenticator("Bearer "+authorization, config.identity)
	if err != nil {
		return err
	}
	handler, err := sandboxcontrolapi.NewHandler(sandboxcontrolapi.Config{Store: store, Authenticator: authenticator, AssertionKey: assertionKey, Entropy: rand.Reader, Clock: systemClock{}, BindingLifetime: config.bindingLifetime, Retention: config.retention, WaitInterval: config.waitInterval, Wait: boundedWait, Admission: config.admission})
	if err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(config.tlsCertificateFile, config.tlsPrivateKeyFile)
	if err != nil {
		return errors.Wrap(err, "run sandbox-control process: load TLS identity")
	}
	listener, err := net.Listen("tcp", config.listenAddress)
	if err != nil {
		return errors.Wrap(err, "run sandbox-control process: listen")
	}
	defer func() { _ = listener.Close() }()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", ready)
	mux.HandleFunc("GET /readyz", ready)
	mux.Handle("/", handler)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}}
	result := make(chan error, 1)
	go func() { result <- server.ServeTLS(listener, "", "") }()
	select {
	case err := <-result:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.Wrap(err, "run sandbox-control process")
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return errors.Wrap(err, "stop sandbox-control process")
		}
		err := <-result
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.Wrap(err, "stop sandbox-control process")
	}
}

func requiredSecret(lookup SecretLookup, name string) (string, error) {
	value, found := lookup(name)
	if !found || value == "" {
		return "", errors.Newf("run sandbox-control process: required secret environment %s is missing", name)
	}
	return value, nil
}

func ready(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(struct {
		Role   string `json:"role"`
		Status string `json:"status"`
	}{Role: "sandbox-control", Status: "ready"})
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

func boundedWait(ctx context.Context, duration time.Duration) error {
	waitContext, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	<-waitContext.Done()
	return waitContext.Err()
}
