package roles

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sync"

	"github.com/cockroachdb/errors"
)

// Serve exposes only role readiness and health until the role's product
// implementation is composed. It does not create or reconcile infrastructure.
func Serve(ctx context.Context, plan Plan, listener net.Listener) error {
	if listener == nil {
		return errors.New("serve runtime role: listener is required")
	}
	if ctx == nil {
		return errors.New("serve runtime role: context is required")
	}
	server := &http.Server{Handler: healthHandler(plan)}
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case err := <-result:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.Wrap(err, "serve runtime role")
	case <-ctx.Done():
		if err := server.Shutdown(context.WithoutCancel(ctx)); err != nil {
			return errors.Wrap(err, "stop runtime role")
		}
		err := <-result
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.Wrap(err, "serve runtime role")
	}
}

func healthHandler(plan Plan) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writeHealth(writer, plan)
	})
	mux.HandleFunc("GET /readyz", func(writer http.ResponseWriter, _ *http.Request) {
		writeHealth(writer, plan)
	})
	return mux
}

func writeHealth(writer http.ResponseWriter, plan Plan) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(struct {
		Role      Role   `json:"role"`
		Namespace string `json:"namespace"`
		Status    string `json:"status"`
	}{Role: plan.role, Namespace: plan.namespace, Status: "ready"})
}

// EnvironmentSecretSource reads an already-injected process environment key.
// The composition root owns this adapter; domain code never reads the environment.
type EnvironmentSecretSource struct {
	lookup func(string) (string, bool)
	mu     sync.Mutex
}

// NewEnvironmentSecretSource adapts an explicit environment lookup function.
func NewEnvironmentSecretSource(lookup func(string) (string, bool)) (*EnvironmentSecretSource, error) {
	if lookup == nil {
		return nil, errors.New("create environment secret source: lookup is required")
	}
	return &EnvironmentSecretSource{lookup: lookup}, nil
}

// Lookup resolves one secret environment value at process composition time.
func (source *EnvironmentSecretSource) Lookup(_ context.Context, environment string) (string, bool, error) {
	if source == nil || source.lookup == nil {
		return "", false, errors.New("read environment secret: source is not configured")
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	value, found := source.lookup(environment)
	return value, found, nil
}

// KnownCredentialEnvironmentNames enumerates present reviewed credential keys
// without disclosing their values.
func (source *EnvironmentSecretSource) KnownCredentialEnvironmentNames(ctx context.Context) ([]string, error) {
	if source == nil || source.lookup == nil {
		return nil, errors.New("enumerate environment credentials: source is not configured")
	}
	names := make([]string, 0)
	for _, environment := range KnownCredentialEnvironmentNames() {
		value, found, err := source.Lookup(ctx, environment)
		if err != nil {
			return nil, errors.Wrapf(err, "enumerate environment credential %s", environment)
		}
		if found && value != "" {
			names = append(names, environment)
		}
	}
	return names, nil
}
