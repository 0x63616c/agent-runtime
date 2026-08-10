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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
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
	address := "127.0.0.1:0"
	configPath := filepath.Join(directory, "control.json")
	config := fmt.Sprintf(`{
  "version":1,"listen_address":%q,
  "tls_certificate_file":%q,"tls_private_key_file":%q,
  "database_dsn_environment":"TEST_DATABASE_DSN",
  "authorization_environment":"TEST_AUTHORIZATION",
  "assertion_key_environment":"TEST_ASSERTION_KEY",
  "identity":{"authority":"integration","tenant":"tenant_01","subject":"runtime_01","principal":"tenant_01:runtime_01"},
  "binding_lifetime_seconds":60,"retention_seconds":3600,"wait_interval_millis":10,
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
	address = first.awaitReady(t).Public
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
	address = second.awaitReady(t).Public
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
	command    *exec.Cmd
	stdout     *controlOutput
	stderr     *boundedOutput
	redactions []string
	done       chan struct{}
	mu         sync.Mutex
	waitErr    error
}

func startControlProcess(t *testing.T, binary, configPath, dsn, authorization, assertionKey string) *controlProcess {
	t.Helper()
	return startCommand(t, binary, []string{"--config", configPath}, map[string]string{"TEST_DATABASE_DSN": dsn, "TEST_AUTHORIZATION": authorization, "TEST_ASSERTION_KEY": assertionKey})
}

func startCommand(t *testing.T, binary string, arguments []string, environment map[string]string) *controlProcess {
	t.Helper()
	stdout := newControlOutput()
	stderr := newBoundedOutput()
	command := exec.Command(binary, arguments...)
	command.Env = os.Environ()
	for name, value := range environment {
		command.Env = append(command.Env, name+"="+value)
	}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	process := &controlProcess{command: command, stdout: stdout, stderr: stderr, redactions: redactionsFromEnvironment(environment), done: make(chan struct{})}
	go func() {
		process.mu.Lock()
		process.waitErr = command.Wait()
		process.mu.Unlock()
		close(process.done)
	}()
	return process
}

func TestControlProcessHarnessRedactsEarlyExitDiagnostics(t *testing.T) {
	if os.Getenv("CONTROL_PROCESS_EARLY_EXIT_HELPER") == "1" {
		_, _ = fmt.Fprintln(os.Stderr, os.Getenv("CONTROL_PROCESS_EARLY_EXIT_SECRET"))
		os.Exit(7)
	}
	const secret = "control-process-secret"
	process := startCommand(t, os.Args[0], []string{"-test.run=^TestControlProcessHarnessRedactsEarlyExitDiagnostics$"}, map[string]string{"CONTROL_PROCESS_EARLY_EXIT_HELPER": "1", "CONTROL_PROCESS_EARLY_EXIT_SECRET": secret})
	if err := process.wait(); err == nil {
		t.Fatal("early-exit process error = nil")
	}
	diagnostics := process.diagnostics()
	if strings.Contains(diagnostics, secret) || !strings.Contains(diagnostics, "[redacted]") {
		t.Fatalf("early-exit diagnostics = %q", diagnostics)
	}
}

func TestControlProcessHarnessKillsAnUnresponsiveChild(t *testing.T) {
	if os.Getenv("CONTROL_PROCESS_IGNORE_TERM_HELPER") == "1" {
		signal.Ignore(syscall.SIGTERM)
		_, _ = fmt.Fprintln(os.Stdout, `{"msg":"sandbox control ready","role":"sandbox-control","public_address":"127.0.0.1:1","host_control_address":""}`)
		select {}
	}
	process := startCommand(t, os.Args[0], []string{"-test.run=^TestControlProcessHarnessKillsAnUnresponsiveChild$"}, map[string]string{"CONTROL_PROCESS_IGNORE_TERM_HELPER": "1"})
	process.awaitReady(t)
	forced, err := process.terminate()
	if err != nil {
		t.Fatalf("terminate() error = %v", err)
	}
	if !forced {
		t.Fatal("terminate() did not force-kill an unresponsive child")
	}
	if err := process.wait(); err == nil {
		t.Fatal("unresponsive child wait error = nil")
	}
}

func TestControlProcessHarnessPreservesGracefulStopWaitError(t *testing.T) {
	if os.Getenv("CONTROL_PROCESS_GRACEFUL_STOP_HELPER") == "1" {
		_, _ = fmt.Fprintln(os.Stdout, `{"msg":"sandbox control ready","role":"sandbox-control","public_address":"127.0.0.1:1","host_control_address":""}`)
		select {}
	}
	process := startCommand(t, os.Args[0], []string{"-test.run=^TestControlProcessHarnessPreservesGracefulStopWaitError$"}, map[string]string{"CONTROL_PROCESS_GRACEFUL_STOP_HELPER": "1"})
	process.awaitReady(t)
	forced, err := process.terminate()
	if err != nil {
		t.Fatalf("terminate() error = %v", err)
	}
	if forced {
		t.Fatal("terminate() force-killed a child that honored SIGTERM")
	}
	if err := process.wait(); err == nil {
		t.Fatal("graceful SIGTERM wait error = nil")
	}
}

func TestControlProcessHarnessBoundsReapWhenDescendantRetainsPipes(t *testing.T) {
	if os.Getenv("CONTROL_PROCESS_PIPE_HOLDER_DESCENDANT") == "1" {
		select {}
	}
	if os.Getenv("CONTROL_PROCESS_PIPE_HOLDER_HELPER") == "1" {
		signal.Ignore(syscall.SIGTERM)
		child := exec.Command(os.Args[0], "-test.run=^TestControlProcessHarnessBoundsReapWhenDescendantRetainsPipes$")
		child.Env = append(os.Environ(), "CONTROL_PROCESS_PIPE_HOLDER_DESCENDANT=1")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if err := os.WriteFile(os.Getenv("CONTROL_PROCESS_PIPE_HOLDER_PID_FILE"), []byte(fmt.Sprint(child.Process.Pid)), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		_, _ = fmt.Fprintln(os.Stdout, `{"msg":"sandbox control ready","role":"sandbox-control","public_address":"127.0.0.1:1","host_control_address":""}`)
		select {}
	}

	pidFile := filepath.Join(t.TempDir(), "pipe-holder.pid")
	process := startCommand(t, os.Args[0], []string{"-test.run=^TestControlProcessHarnessBoundsReapWhenDescendantRetainsPipes$"}, map[string]string{"CONTROL_PROCESS_PIPE_HOLDER_HELPER": "1", "CONTROL_PROCESS_PIPE_HOLDER_PID_FILE": pidFile})
	process.awaitReady(t)
	pidWire, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read descendant PID: %v", err)
	}
	descendant, err := os.FindProcess(parseProcessPID(t, string(pidWire)))
	if err != nil {
		t.Fatalf("find descendant: %v", err)
	}
	defer func() {
		_ = descendant.Kill()
		if err := process.wait(); err == nil {
			t.Fatal("killed parent wait error = nil")
		}
	}()

	forced, err := process.terminate()
	if !forced {
		t.Fatal("terminate() did not force-kill pipe-holder parent")
	}
	if err == nil || !strings.Contains(err.Error(), "did not exit after SIGKILL") {
		t.Fatalf("terminate() error = %v; want bounded reap error", err)
	}
}

func parseProcessPID(t *testing.T, value string) int {
	t.Helper()
	var pid int
	if _, err := fmt.Sscan(strings.TrimSpace(value), &pid); err != nil || pid <= 0 {
		t.Fatalf("invalid child PID %q: %v", value, err)
	}
	return pid
}

func (process *controlProcess) awaitReady(t *testing.T) controlReady {
	t.Helper()
	timeout, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	select {
	case ready := <-process.stdout.ready:
		return ready
	case <-process.done:
		t.Fatalf("sandbox-control exited before readiness: %v; diagnostics=%s", process.wait(), process.diagnostics())
	case <-timeout.Done():
		if _, err := process.terminate(); err != nil {
			t.Fatalf("signal sandbox-control after readiness timeout: %v", err)
		}
		_ = process.wait()
		t.Fatalf("sandbox-control did not report readiness: diagnostics=%s", process.diagnostics())
	}
	return controlReady{}
}

func (process *controlProcess) stop(t *testing.T, secrets ...string) {
	t.Helper()
	if _, err := process.terminate(); err != nil {
		t.Fatalf("signal sandbox-control: %v", err)
	}
	if err := process.wait(); err != nil {
		t.Fatalf("wait sandbox-control: %v; diagnostics=%s", err, process.diagnostics(secrets...))
	}
	for _, secret := range secrets {
		if strings.Contains(process.stdout.String(), secret) || strings.Contains(process.stderr.String(), secret) {
			t.Fatalf("sandbox-control output disclosed a secret: %s", process.diagnostics(secrets...))
		}
	}
}

const controlProcessTerminationGrace = time.Second

func (process *controlProcess) terminate() (bool, error) {
	select {
	case <-process.done:
		return false, nil
	default:
	}
	if err := process.command.Process.Signal(syscall.SIGTERM); err != nil {
		select {
		case <-process.done:
			return false, nil
		default:
			return false, err
		}
	}
	grace, cancel := context.WithTimeout(context.Background(), controlProcessTerminationGrace)
	defer cancel()
	select {
	case <-process.done:
		return false, nil
	case <-grace.Done():
	}
	if err := process.command.Process.Kill(); err != nil {
		select {
		case <-process.done:
			return false, nil
		default:
			return false, err
		}
	}
	reap, cancel := context.WithTimeout(context.Background(), controlProcessTerminationGrace)
	defer cancel()
	select {
	case <-process.done:
		return true, nil
	case <-reap.Done():
		return true, fmt.Errorf("sandbox-control did not exit after SIGKILL within %s", controlProcessTerminationGrace)
	}
}

func (process *controlProcess) wait() error {
	<-process.done
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.waitErr
}

func (process *controlProcess) diagnostics(secrets ...string) string {
	redactions := append(append([]string(nil), process.redactions...), secrets...)
	return redactDiagnostics(process.stdout.String()+process.stderr.String(), redactions...)
}

// redactionsFromEnvironment fails closed for each value supplied to the child.
// The harness must never emit a child-owned value merely because a caller omitted
// a secret argument on an early-exit/readiness diagnostic path.
func redactionsFromEnvironment(environment map[string]string) []string {
	values := make([]string, 0, len(environment))
	seen := make(map[string]struct{}, len(environment))
	for _, value := range environment {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values
}

type controlReady struct {
	Public      string `json:"public_address"`
	HostControl string `json:"host_control_address"`
}

type controlOutput struct {
	mu      sync.Mutex
	data    []byte
	pending []byte
	ready   chan controlReady
}

func newControlOutput() *controlOutput { return &controlOutput{ready: make(chan controlReady, 1)} }

func (output *controlOutput) Write(input []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	output.data = appendBounded(output.data, input)
	output.pending = appendBounded(output.pending, input)
	for {
		index := bytes.IndexByte(output.pending, '\n')
		if index < 0 {
			break
		}
		line := output.pending[:index]
		output.pending = output.pending[index+1:]
		var record struct {
			Message string `json:"msg"`
			Role    string `json:"role"`
			controlReady
		}
		if json.Unmarshal(line, &record) == nil && record.Message == "sandbox control ready" && record.Role == "sandbox-control" && record.Public != "" {
			select {
			case output.ready <- record.controlReady:
			default:
			}
		}
	}
	return len(input), nil
}

func (output *controlOutput) String() string {
	output.mu.Lock()
	defer output.mu.Unlock()
	return string(output.data)
}

type boundedOutput struct {
	mu   sync.Mutex
	data []byte
}

func newBoundedOutput() *boundedOutput { return &boundedOutput{} }

func (output *boundedOutput) Write(input []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	output.data = appendBounded(output.data, input)
	return len(input), nil
}

func (output *boundedOutput) String() string {
	output.mu.Lock()
	defer output.mu.Unlock()
	return string(output.data)
}

const maximumDiagnosticsBytes = 4 << 10

func appendBounded(current, input []byte) []byte {
	if len(input) >= maximumDiagnosticsBytes {
		return append(current[:0], input[len(input)-maximumDiagnosticsBytes:]...)
	}
	if len(current)+len(input) > maximumDiagnosticsBytes {
		current = append(current[:0], current[len(current)+len(input)-maximumDiagnosticsBytes:]...)
	}
	return append(current, input...)
}

func redactDiagnostics(value string, secrets ...string) string {
	for _, secret := range secrets {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[redacted]")
		}
	}
	return value
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
