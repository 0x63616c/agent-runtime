package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/roles"
	"github.com/0x63616c/agent-runtime/internal/tooldispatch"
)

func TestRunChecksOnlyTheConfiguredRoleCredentials(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "orchestration.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"role":"orchestration","namespace":"agent-runtime","listen_address":"127.0.0.1:8081","dependencies":[{"name":"state","endpoint":"postgres://state:5432/runtime","secret_environment":"STATE_DATABASE_DSN"},{"name":"telemetry","endpoint":"http://telemetry:4318"},{"name":"temporal","endpoint":"temporal:7233","secret_environment":"TEMPORAL_AUTH_TOKEN"}]}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	lookup := func(name string) (string, bool) {
		value, found := map[string]string{"STATE_DATABASE_DSN": "state", "TEMPORAL_AUTH_TOKEN": "temporal"}[name]
		return value, found
	}
	if err := run(context.Background(), []string{"serve", "--config", path, "--role", "orchestration", "--check"}, lookup); err != nil {
		t.Fatalf("run check: %v", err)
	}
	if err := run(context.Background(), []string{"serve", "--config", path, "--role", "model", "--check"}, lookup); err == nil {
		t.Fatal("expected mismatched role rejection")
	}
}

func TestRunAcceptsExplicitNonSecretConfigurationEnvironment(t *testing.T) {
	t.Parallel()
	configuration := `{"version":1,"role":"api","namespace":"agent-runtime","listen_address":"127.0.0.1:8080","dependencies":[{"name":"state","endpoint":"http://state:8080"},{"name":"telemetry","endpoint":"http://telemetry:4318"}]}`
	lookup := func(name string) (string, bool) {
		if name == "RUNTIME_ROLE_CONFIG" {
			return configuration, true
		}
		return "", false
	}
	if err := run(context.Background(), []string{"serve", "--config-env", "RUNTIME_ROLE_CONFIG", "--role", "api", "--check"}, lookup); err != nil {
		t.Fatalf("run config environment check: %v", err)
	}
	if err := run(context.Background(), []string{"--config-env", "RUNTIME_ROLE_CONFIG", "--config", "other.json", "--role", "api", "--check"}, lookup); err == nil {
		t.Fatal("expected mutually exclusive config source rejection")
	}
}

func TestRunRefusesToParseToolWithoutTheDeclaredTriggerCapability(t *testing.T) {
	t.Parallel()
	configuration := `{"version":1,"role":"tool","namespace":"agent-runtime","listen_address":"127.0.0.1:0","dependencies":[{"name":"telemetry","endpoint":"http://telemetry:4318"},{"name":"tool-broker","endpoint":"https://tool-dispatch.agent-runtime.svc:8089","secret_environment":"TOOL_BROKER_TOKEN"}]}`
	lookup := func(name string) (string, bool) {
		if name == "RUNTIME_ROLE_CONFIG" {
			return configuration, true
		}
		if name == "TOOL_BROKER_TOKEN" {
			return "trigger-only", true
		}
		return "", false
	}
	err := run(context.Background(), []string{"serve", "--config-env", "RUNTIME_ROLE_CONFIG", "--role", "tool"}, lookup)
	if err == nil || err.Error() != "validate runtime role configuration: tool trigger capability is required unless local demo worker is enabled" {
		t.Fatalf("run tool without trigger = %v", err)
	}
}

func TestServeToolTriggerDrainsTLSLoopAndHealthServerOnExternalCancellation(t *testing.T) {
	brokerListener, certificatePEM := loopbackTLSListener(t)
	brokerScanned := make(chan struct{})
	service, err := tooldispatch.NewServer("trigger-token", func(context.Context) error {
		close(brokerScanned)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := &http.Server{Handler: service}
	brokerDone := make(chan error, 1)
	go func() { brokerDone <- broker.Serve(brokerListener) }()
	t.Cleanup(func() {
		if err := broker.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
		if err := <-brokerDone; err != nil && err != http.ErrServerClosed {
			t.Error(err)
		}
	})

	trustPath := filepath.Join(t.TempDir(), "tool-dispatch-ca.pem")
	if err := os.WriteFile(trustPath, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	endpoint := "https://" + brokerListener.Addr().String()
	configuration := fmt.Sprintf(`{"version":1,"role":"tool","namespace":"agent-runtime","listen_address":"127.0.0.1:0","dependencies":[{"name":"telemetry","endpoint":"http://telemetry:4318"},{"name":"tool-broker","endpoint":%q,"secret_environment":"TOOL_BROKER_TOKEN"}],"tool_trigger":{"server_name":"127.0.0.1","trust_bundle_ref":"trust/tool-dispatch","trust_bundle_path":%q,"interval_seconds":5}}`, endpoint, trustPath)
	config, err := roles.Parse(strings.NewReader(configuration))
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := roles.NewEnvironmentSecretSource(func(name string) (string, bool) {
		return map[string]string{"TOOL_BROKER_TOKEN": "trigger-token"}[name], name == "TOOL_BROKER_TOKEN"
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := roles.Prepare(context.Background(), config, secrets)
	if err != nil {
		t.Fatal(err)
	}
	healthListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepting := &acceptingListener{Listener: healthListener, accepted: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() {
		finished <- serveToolTrigger(ctx, config, plan, accepting, func(name string) (string, bool) { return "trigger-token", name == "TOOL_BROKER_TOKEN" })
	}()
	<-accepting.accepted
	<-brokerScanned
	response, err := http.Get("http://" + healthListener.Addr().String() + "/healthz") // #nosec G107 -- listener is local test state.
	if err != nil {
		t.Fatal(err)
	}
	if closeErr := response.Body.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	cancel()
	if err := <-finished; err != nil {
		t.Fatalf("serveToolTrigger() = %v", err)
	}
}

type acceptingListener struct {
	net.Listener
	accepted chan struct{}
	once     sync.Once
}

func (listener *acceptingListener) Accept() (net.Conn, error) {
	listener.once.Do(func() { close(listener.accepted) })
	return listener.Listener.Accept()
}

func loopbackTLSListener(t *testing.T) (net.Listener, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tool-dispatch-test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Minute), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	raw, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
}
