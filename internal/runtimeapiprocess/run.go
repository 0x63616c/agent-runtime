package runtimeapiprocess

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtime/kernel"
	"github.com/0x63616c/agent-runtime/internal/runtimeapi"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/cockroachdb/errors"
)

// SecretLookup resolves only explicitly named, injected environment values at composition time.
type SecretLookup func(string) (string, bool)

// Run starts the public API role and blocks until cancellation or server failure.
func Run(ctx context.Context, config Config, lookup SecretLookup, ready func(string)) error {
	if ctx == nil || lookup == nil || ready == nil {
		return errors.New("run runtime API process: context, secret lookup, and readiness callback are required")
	}
	listener, err := net.Listen("tcp", config.listenAddress)
	if err != nil {
		return errors.Wrap(err, "run runtime API process: listen")
	}
	defer func() { _ = listener.Close() }()
	ready(listener.Addr().String())
	return Serve(ctx, config, lookup, listener)
}

// Serve runs the role on an already-owned listener so process tests need no timing guesses.
func Serve(ctx context.Context, config Config, lookup SecretLookup, listener net.Listener) error {
	if ctx == nil || lookup == nil || listener == nil {
		return errors.New("serve runtime API process: context, secret lookup, and listener are required")
	}
	authenticator := &digestAuthenticator{identities: make(map[[32]byte]runtimeapi.Identity, len(config.principals))}
	for _, configured := range config.principals {
		token, found := lookup(configured.environment)
		if !found || len(token) < 16 || len(token) > 4096 {
			return errors.New("serve runtime API process: required bearer token is missing or invalid")
		}
		digest := sha256.Sum256([]byte(token))
		if _, exists := authenticator.identities[digest]; exists {
			return errors.New("serve runtime API process: bearer token is duplicated")
		}
		authenticator.identities[digest] = configured.identity
	}
	ids := &cryptoIDs{}
	service, err := kernel.New(systemClock{}, ids, kernel.NewMemoryRepository(), config.modelProfiles)
	if err != nil {
		return err
	}
	runtime, err := runtimeapi.NewKernelRuntime(service)
	if err != nil {
		return err
	}
	handler, err := runtimeapi.NewHandler(runtimeapi.Config{Runtime: runtime, Authenticator: authenticator, RequestIDs: ids, MaxRequestBytes: config.maxRequestBytes})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", ready)
	mux.HandleFunc("GET /readyz", ready)
	mux.Handle("/", handler)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case err := <-result:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.Wrap(err, "serve runtime API process")
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return errors.Wrap(err, "stop runtime API process")
		}
		err := <-result
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.Wrap(err, "stop runtime API process")
	}
}

type digestAuthenticator struct {
	identities map[[32]byte]runtimeapi.Identity
}

func (authenticator *digestAuthenticator) Authenticate(ctx context.Context, token string) (runtimeapi.Identity, error) {
	if ctx == nil {
		return runtimeapi.Identity{}, errors.New("authenticate runtime request: context is required")
	}
	if err := ctx.Err(); err != nil {
		return runtimeapi.Identity{}, err
	}
	digest := sha256.Sum256([]byte(token))
	for expected, identity := range authenticator.identities {
		if subtle.ConstantTimeCompare(digest[:], expected[:]) == 1 {
			return identity, nil
		}
	}
	return runtimeapi.Identity{}, errors.New("authenticate runtime request: credential rejected")
}

type cryptoIDs struct{}

func (*cryptoIDs) Next() (string, error) { return randomPayload() }

func (*cryptoIDs) NextRequestID() (agentruntime.RequestID, error) {
	payload, err := randomPayload()
	if err != nil {
		return "", err
	}
	return agentruntime.ParseRequestID("req_" + payload)
}

func randomPayload() (string, error) {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	buffer := make([]byte, 16)
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", errors.Wrap(err, "allocate runtime identifier")
	}
	for index := range buffer {
		buffer[index] = alphabet[int(random[index])%len(alphabet)]
	}
	return string(buffer), nil
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

func ready(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(struct {
		Role   string `json:"role"`
		Status string `json:"status"`
	}{Role: "agent-runtime-api", Status: "ready"})
}
