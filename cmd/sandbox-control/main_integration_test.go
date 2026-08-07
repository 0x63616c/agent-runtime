//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/sandbox"
)

func TestSandboxControlSeparateProcessReconnectsAcrossRestart(t *testing.T) {
	binary := requiredEnvironment(t, "AR_SANDBOXCONTROL_BINARY")
	dsn := requiredEnvironment(t, "AR_SANDBOXCONTROL_POSTGRES_DSN")
	directory := t.TempDir()
	certificatePath, keyPath, roots := writeTestIdentity(t, directory)
	address := reserveAddress(t)
	configPath := filepath.Join(directory, "control.json")
	config := fmt.Sprintf(`{
  "version":1,"listen_address":%q,
  "tls_certificate_file":%q,"tls_private_key_file":%q,
  "database_dsn_environment":"TEST_DATABASE_DSN",
  "authorization_environment":"TEST_AUTHORIZATION",
  "assertion_key_environment":"TEST_ASSERTION_KEY",
  "identity":{"authority":"integration","tenant":"tenant_01","subject":"runtime_01","principal":"tenant_01:runtime_01"},
  "binding_lifetime_seconds":60,"retention_seconds":3600,"wait_interval_millis":10,"reconciliation_interval_millis":1000,"reconciliation_page_size":100,
  "admission":{"version":"policy-v1","canonicalizer_version":"sandbox.control/v1","capability_version":"capabilities-v1","image_admission_version":"images-v1",
    "defaults":{"milli_cpu":100,"memory_bytes":1024,"root_disk_bytes":1024,"tmpfs_bytes":1024,"pids":10,"process_count":10,"open_files":10,"inodes":10,"files":10,"lifetime_seconds":60,"produced_output_bytes":1024,"retained_output_bytes":1024,"transfer_bytes":1024,"network_connections":10,"volume_bytes":1024,"snapshot_bytes":1024},
    "maximum":{"milli_cpu":1000,"memory_bytes":1048576,"root_disk_bytes":1048576,"tmpfs_bytes":1048576,"pids":100,"process_count":100,"open_files":100,"inodes":100,"files":100,"lifetime_seconds":3600,"produced_output_bytes":1048576,"retained_output_bytes":1048576,"transfer_bytes":1048576,"network_connections":100,"volume_bytes":1048576,"snapshot_bytes":1048576},
    "capabilities":{},"admitted_images":{}}
}`, address, certificatePath, keyPath)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	const authorization = "integration-authorization-secret"
	const assertionKey = "4242424242424242424242424242424242424242424242424242424242424242"
	first := startControlProcess(t, binary, configPath, dsn, authorization, assertionKey)
	client := connectClient(t, "https://"+address, roots, authorization)
	request := sandbox.OperationRequest{ID: "op_process_restart", Kind: sandbox.OperationCloseSandbox, CloseSandbox: &sandbox.CloseSandboxRequest{SandboxID: "sbx_process_restart"}}
	ref, err := client.Submit(context.Background(), request)
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if err := client.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	first.stop(t, authorization, assertionKey, dsn)

	second := startControlProcess(t, binary, configPath, dsn, authorization, assertionKey)
	defer second.stop(t, authorization, assertionKey, dsn)
	reconnected := connectClient(t, "https://"+address, roots, authorization)
	defer reconnected.Close(context.Background())
	got, err := reconnected.GetOperation(context.Background(), request.ID)
	if err != nil || got.Ref != ref {
		t.Fatalf("GetOperation(after restart) = %#v, %v; want ref %#v", got, err, ref)
	}
	replayed, err := reconnected.Submit(context.Background(), request)
	if err != nil || replayed != ref {
		t.Fatalf("Submit(after restart) = %#v, %v; want %#v", replayed, err, ref)
	}
}

type controlProcess struct {
	command *exec.Cmd
	output  *bytes.Buffer
}

func startControlProcess(t *testing.T, binary, configPath, dsn, authorization, assertionKey string) *controlProcess {
	t.Helper()
	output := new(bytes.Buffer)
	command := exec.Command(binary, "--config", configPath)
	command.Env = append(os.Environ(), "TEST_DATABASE_DSN="+dsn, "TEST_AUTHORIZATION="+authorization, "TEST_ASSERTION_KEY="+assertionKey)
	command.Stdout, command.Stderr = output, output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	return &controlProcess{command: command, output: output}
}

func (process *controlProcess) stop(t *testing.T, secrets ...string) {
	t.Helper()
	if process.command.ProcessState == nil {
		if err := process.command.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatalf("signal sandbox-control: %v", err)
		}
		if err := process.command.Wait(); err != nil {
			t.Fatalf("wait sandbox-control: %v; output=%s", err, process.output.String())
		}
	}
	for _, secret := range secrets {
		if strings.Contains(process.output.String(), secret) {
			t.Fatalf("sandbox-control output disclosed a secret: %q", process.output.String())
		}
	}
}

func connectClient(t *testing.T, endpoint string, roots []byte, authorization string) sandbox.Client {
	t.Helper()
	trust, err := sandbox.NewStaticTrustBundleSource(map[sandbox.TrustBundleRef]sandbox.TrustBundle{"trust/integration": {Version: "integration/v1", PEMRoots: roots}})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		client, err := sandbox.NewClient(context.Background(), sandbox.ClientConfig{Endpoint: sandbox.Endpoint{URL: endpoint}, TLS: sandbox.TLSConfig{ServerName: "localhost", TrustBundleRef: "trust/integration"}, Credentials: integrationCredentials(authorization), TrustBundles: trust, RequestTimeout: time.Second})
		if err == nil {
			return client
		}
		if time.Now().After(deadline) {
			t.Fatalf("connect sandbox-control: %v", err)
		}
		waitContext, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		<-waitContext.Done()
		cancel()
	}
}

type integrationCredentials string

func (credential integrationCredentials) Apply(_ context.Context, sink sandbox.CredentialSink) error {
	return sink.SetAuthorization("Bearer", string(credential))
}

func reserveAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func writeTestIdentity(t *testing.T, directory string) (string, string, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	certificatePath, keyPath := filepath.Join(directory, "tls.crt"), filepath.Join(directory, "tls.key")
	if err := os.WriteFile(certificatePath, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, privateKey, 0o600); err != nil {
		t.Fatal(err)
	}
	return certificatePath, keyPath, certificate
}

func requiredEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}

var _ sandbox.CredentialSource = integrationCredentials("")
