//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxcontrol"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/0x63616c/agent-runtime/sandbox"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestReferenceHostMultiProcessLostAckQuarantineCleanupAndReassignment(t *testing.T) {
	controlBinary := requiredEnvironment(t, "AR_SANDBOXCONTROL_BINARY")
	hostBinary := requiredEnvironment(t, "AR_SANDBOXHOST_BINARY")
	dsn := requiredEnvironment(t, "AR_SANDBOXCONTROL_POSTGRES_DSN")
	directory := t.TempDir()
	identities := writeIdentities(t, directory)
	publicAddress, hostAddress := "127.0.0.1:0", "0.0.0.0:0"
	controlPublic, controlPrivate, _ := ed25519.GenerateKey(rand.Reader)
	hostPublic1, hostPrivate1, _ := ed25519.GenerateKey(rand.Reader)
	controlConfig := writeControlConfig(t, directory, publicAddress, hostAddress, identities)
	const authorization = "host-integration-authorization"
	const assertionKey = "5353535353535353535353535353535353535353535353535353535353535353"
	controlSigning := base64.RawStdEncoding.EncodeToString(controlPrivate)
	control := startProcess(t, controlBinary, []string{"--config", controlConfig}, map[string]string{"TEST_DATABASE_DSN": dsn, "TEST_AUTHORIZATION": authorization, "TEST_ASSERTION_KEY": assertionKey, "TEST_CONTROL_SIGNING_KEY": controlSigning})
	defer control.stop(t, true, authorization, assertionKey, dsn, controlSigning)
	addresses := control.awaitControlReady(t)
	publicAddress = addresses.Public
	hostAddress = loopbackAddress(t, addresses.HostControl)
	client := connectPublicClient(t, "https://"+publicAddress, identities.caPEM, authorization)
	defer client.Close(context.Background())

	request := sandbox.OperationRequest{ID: "op_host_lost_ack", Kind: sandbox.OperationCloseSandbox, CloseSandbox: &sandbox.CloseSandboxRequest{SandboxID: "sbx_host_lost_ack"}}
	ledger, pool := openLedger(t, dsn)
	defer pool.Close()
	if _, err := pool.Exec(context.Background(), `TRUNCATE runtime.sandbox_host_outputs, runtime.sandbox_host_dispatches, runtime.sandbox_host_enrollments, runtime.sandbox_operation_outbox, runtime.sandbox_operations RESTART IDENTITY`); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	operation, err := ledger.Get(context.Background(), "tenant_01:runtime_01", string(request.ID))
	if err != nil {
		t.Fatal(err)
	}
	host1 := sandboxcontrol.HostEnrollment{HostID: "host_01", Tenant: "tenant_01", Pool: "reference", Generation: 1, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: certificateDigest(identities.host1Certificate), SigningPublicKey: hostPublic1, CapabilityDigest: operation.CapabilityDigest, Status: sandboxcontrol.HostActive, ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if err := ledger.ProvisionHost(context.Background(), host1, sandboxcontrol.AttestationInput{Profile: sandboxcontrol.AttestationProfileLocalMetadata}, nil); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(directory, "receipts.json")
	faultConfig := writeHostConfig(t, directory, "host-fault.json", hostAddress, identities, 1, journalPath, true, false, false)
	hostSigning1 := base64.RawStdEncoding.EncodeToString(hostPrivate1)
	controlVerify := base64.RawStdEncoding.EncodeToString(controlPublic)
	fault := startProcess(t, hostBinary, hostArguments(faultConfig), map[string]string{"TEST_CONTROL_PUBLIC_KEY": controlVerify, "TEST_HOST_SIGNING_KEY": hostSigning1})
	fault.stop(t, false, controlVerify, hostSigning1)

	resumeConfig := writeHostConfig(t, directory, "host-resume.json", hostAddress, identities, 1, journalPath, false, false, false)
	resumed := startProcess(t, hostBinary, hostArguments(resumeConfig), map[string]string{"TEST_CONTROL_PUBLIC_KEY": controlVerify, "TEST_HOST_SIGNING_KEY": hostSigning1})
	waitForOperationState(t, client, request.ID, sandbox.OperationUncertain)
	resumed.awaitHostPoll(t)
	resumed.stop(t, true, controlVerify, hostSigning1)
	got, err := client.GetOperation(context.Background(), request.ID)
	if err != nil || got.State != sandbox.OperationUncertain {
		t.Fatalf("operation after lost-ack host restart = %#v, %v", got, err)
	}
	journalWire, err := os.ReadFile(journalPath)
	if err != nil || bytes.Count(journalWire, []byte(`"execution_count":1`)) != 1 {
		t.Fatalf("reference execution journal = %s, %v", journalWire, err)
	}

	resultRetryRequest := sandbox.OperationRequest{ID: "op_host_lost_result", Kind: sandbox.OperationCloseSandbox, CloseSandbox: &sandbox.CloseSandboxRequest{SandboxID: "sbx_host_lost_result"}}
	if _, err := client.Submit(context.Background(), resultRetryRequest); err != nil {
		t.Fatal(err)
	}
	resultJournalPath := filepath.Join(directory, "result-receipts.json")
	resultFaultConfig := writeHostConfig(t, directory, "host-result-fault.json", hostAddress, identities, 1, resultJournalPath, false, false, true)
	resultFault := startProcess(t, hostBinary, hostArguments(resultFaultConfig), map[string]string{"TEST_CONTROL_PUBLIC_KEY": controlVerify, "TEST_HOST_SIGNING_KEY": hostSigning1})
	resultFault.stop(t, false, controlVerify, hostSigning1)
	resultResumeConfig := writeHostConfig(t, directory, "host-result-resume.json", hostAddress, identities, 1, resultJournalPath, false, false, false)
	resultResumed := startProcess(t, hostBinary, hostArguments(resultResumeConfig), map[string]string{"TEST_CONTROL_PUBLIC_KEY": controlVerify, "TEST_HOST_SIGNING_KEY": hostSigning1})
	waitForOperationState(t, client, resultRetryRequest.ID, sandbox.OperationUncertain)
	resultResumed.awaitHostPoll(t)
	resultResumed.stop(t, true, controlVerify, hostSigning1)
	got, err = client.GetOperation(context.Background(), resultRetryRequest.ID)
	if err != nil || got.State != sandbox.OperationUncertain {
		t.Fatalf("operation after lost-result host restart = %#v, %v", got, err)
	}
	resultJournalWire, err := os.ReadFile(resultJournalPath)
	if err != nil || bytes.Count(resultJournalWire, []byte(`"execution_count":1`)) != 1 {
		t.Fatalf("reference lost-result journal = %s, %v", resultJournalWire, err)
	}

	quarantineRequest := sandbox.OperationRequest{ID: "op_host_quarantine", Kind: sandbox.OperationCloseSandbox, CloseSandbox: &sandbox.CloseSandboxRequest{SandboxID: "sbx_host_quarantine"}}
	if _, err := client.Submit(context.Background(), quarantineRequest); err != nil {
		t.Fatal(err)
	}
	roguePrivate := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	if _, err := rand.Read(roguePrivate); err != nil {
		t.Fatal(err)
	}
	rogueConfig := writeHostConfig(t, directory, "host-rogue.json", hostAddress, identities, 1, filepath.Join(directory, "rogue-receipts.json"), false, false, false)
	rogue := startProcess(t, hostBinary, hostArguments(rogueConfig), map[string]string{"TEST_CONTROL_PUBLIC_KEY": controlVerify, "TEST_HOST_SIGNING_KEY": base64.RawStdEncoding.EncodeToString(roguePrivate)})
	rogue.stop(t, false, controlVerify)
	quarantined, err := ledger.Get(context.Background(), "tenant_01:runtime_01", string(quarantineRequest.ID))
	if err != nil || quarantined.State != sandboxcontrol.StateUncertain || quarantined.Assignment.HostID != "" {
		t.Fatalf("quarantined operation = %#v, %v", quarantined, err)
	}
	if _, err := ledger.ConfirmHostCleanupAndRequeue(context.Background(), quarantined.Principal, quarantined.ID, quarantined.Version, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	hostPublic2, hostPrivate2, _ := ed25519.GenerateKey(rand.Reader)
	host2 := host1
	host2.Generation = 2
	host2.CertificateDigest = certificateDigest(identities.host2Certificate)
	host2.SigningPublicKey = hostPublic2
	host2.ExpiresAt = time.Now().UTC().Add(time.Hour)
	if err := ledger.ProvisionHost(context.Background(), host2, sandboxcontrol.AttestationInput{Profile: sandboxcontrol.AttestationProfileLocalMetadata}, nil); err != nil {
		t.Fatal(err)
	}
	reassignedConfig := writeHostConfig(t, directory, "host-reassigned.json", hostAddress, identities, 2, filepath.Join(directory, "reassigned-receipts.json"), false, false, false)
	reassigned := startProcess(t, hostBinary, hostArguments(reassignedConfig), map[string]string{"TEST_CONTROL_PUBLIC_KEY": controlVerify, "TEST_HOST_SIGNING_KEY": base64.RawStdEncoding.EncodeToString(hostPrivate2)})
	waitForOperationState(t, client, quarantineRequest.ID, sandbox.OperationUncertain)
	reassigned.awaitHostPoll(t)
	reassigned.stop(t, true, controlVerify)
	got, err = client.GetOperation(context.Background(), quarantineRequest.ID)
	if err != nil || got.State != sandbox.OperationUncertain {
		t.Fatalf("operation after cleanup/reassignment = %#v, %v", got, err)
	}
}

func TestHostProcessHarnessKillsAnUnresponsiveChild(t *testing.T) {
	if os.Getenv("HOST_PROCESS_IGNORE_TERM_HELPER") == "1" {
		signal.Ignore(syscall.SIGTERM)
		_, _ = fmt.Fprintln(os.Stdout, `{"msg":"sandbox host poll","ready":true}`)
		select {}
	}
	process := startProcess(t, os.Args[0], []string{"-test.run=^TestHostProcessHarnessKillsAnUnresponsiveChild$"}, map[string]string{"HOST_PROCESS_IGNORE_TERM_HELPER": "1"})
	process.awaitHostPoll(t)
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

func TestHostProcessHarnessRedactsEarlyExitDiagnostics(t *testing.T) {
	if os.Getenv("HOST_PROCESS_EARLY_EXIT_HELPER") == "1" {
		_, _ = fmt.Fprintln(os.Stderr, os.Getenv("HOST_PROCESS_EARLY_EXIT_SECRET"))
		os.Exit(7)
	}
	const secret = "host-process-secret"
	process := startProcess(t, os.Args[0], []string{"-test.run=^TestHostProcessHarnessRedactsEarlyExitDiagnostics$"}, map[string]string{"HOST_PROCESS_EARLY_EXIT_HELPER": "1", "HOST_PROCESS_EARLY_EXIT_SECRET": secret})
	if err := process.wait(); err == nil {
		t.Fatal("early-exit process error = nil")
	}
	diagnostics := process.diagnostics()
	if strings.Contains(diagnostics, secret) || !strings.Contains(diagnostics, "[redacted]") {
		t.Fatalf("early-exit diagnostics = %q", diagnostics)
	}
}

type identities struct {
	caPEM                                []byte
	publicCertificate, publicKey         string
	hostServerCertificate, hostServerKey string
	host1CertificatePath, host1KeyPath   string
	host2CertificatePath, host2KeyPath   string
	host1Certificate, host2Certificate   *x509.Certificate
}

func writeIdentities(t *testing.T, directory string) identities {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "integration-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := os.WriteFile(filepath.Join(directory, "ca.crt"), caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	publicCert, publicKey, _ := signCertificate(t, directory, "public", ca, caKey, nil, []string{"localhost"}, x509.ExtKeyUsageServerAuth, 101)
	hostServerCert, hostServerKey, _ := signCertificate(t, directory, "host-server", ca, caKey, nil, []string{"localhost"}, x509.ExtKeyUsageServerAuth, 102)
	uri1, _ := url.Parse("spiffe://agent-runtime/sandbox-host/host_01/generation/1")
	host1Cert, host1Key, parsed1 := signCertificate(t, directory, "host-1", ca, caKey, uri1, nil, x509.ExtKeyUsageClientAuth, 103)
	uri2, _ := url.Parse("spiffe://agent-runtime/sandbox-host/host_01/generation/2")
	host2Cert, host2Key, parsed2 := signCertificate(t, directory, "host-2", ca, caKey, uri2, nil, x509.ExtKeyUsageClientAuth, 104)
	return identities{caPEM: caPEM, publicCertificate: publicCert, publicKey: publicKey, hostServerCertificate: hostServerCert, hostServerKey: hostServerKey, host1CertificatePath: host1Cert, host1KeyPath: host1Key, host2CertificatePath: host2Cert, host2KeyPath: host2Key, host1Certificate: parsed1, host2Certificate: parsed2}
}

func signCertificate(t *testing.T, directory, name string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, identity *url.URL, dns []string, usage x509.ExtKeyUsage, serial int64) (string, string, *x509.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: dns, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, BasicConstraintsValid: true}
	if identity != nil {
		template.URIs = []*url.URL{identity}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certificate := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})...)
	certificatePath, keyPath := filepath.Join(directory, name+".crt"), filepath.Join(directory, name+".key")
	if err := os.WriteFile(certificatePath, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, _ := x509.ParseCertificate(der)
	return certificatePath, keyPath, parsed
}

func writeControlConfig(t *testing.T, directory, publicAddress, hostAddress string, identity identities) string {
	t.Helper()
	now := time.Now().UTC()
	config := fmt.Sprintf(`{"version":2,"listen_address":%q,"tls_certificate_file":%q,"tls_private_key_file":%q,"database_dsn_environment":"TEST_DATABASE_DSN","authorization_environment":"TEST_AUTHORIZATION","assertion_key_environment":"TEST_ASSERTION_KEY","identity":{"authority":"integration","tenant":"tenant_01","subject":"runtime_01","principal":"tenant_01:runtime_01"},"binding_lifetime_seconds":60,"retention_seconds":3600,"wait_interval_millis":10,"admission":{"version":"policy-v1","canonicalizer_version":"sandbox.control/v1","capability_version":"capabilities-v1","image_admission_version":"images-v1","defaults":{"milli_cpu":100,"memory_bytes":1024,"root_disk_bytes":1024,"tmpfs_bytes":1024,"pids":10,"process_count":10,"open_files":10,"inodes":10,"files":10,"lifetime_seconds":60,"produced_output_bytes":1024,"retained_output_bytes":1024,"transfer_bytes":1024,"network_connections":10,"volume_bytes":1024,"snapshot_bytes":1024},"maximum":{"milli_cpu":1000,"memory_bytes":1048576,"root_disk_bytes":1048576,"tmpfs_bytes":1048576,"pids":100,"process_count":100,"open_files":100,"inodes":100,"files":100,"lifetime_seconds":3600,"produced_output_bytes":1048576,"retained_output_bytes":1048576,"transfer_bytes":1048576,"network_connections":100,"volume_bytes":1048576,"snapshot_bytes":1048576},"capabilities":{},"admitted_images":{}},"host_control":{"listen_address":%q,"tls_certificate_file":%q,"tls_private_key_file":%q,"client_ca_file":%q,"control_trust_version":1,"control_revocation_epoch":1,"control_key_id":"control_01","control_key_version":1,"control_key_not_before":%q,"control_key_not_after":%q,"control_signing_key_environment":"TEST_CONTROL_SIGNING_KEY","lease_seconds":60}}`, publicAddress, identity.publicCertificate, identity.publicKey, hostAddress, identity.hostServerCertificate, identity.hostServerKey, filepath.Join(directory, "ca.crt"), now.Add(-time.Hour).Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339))
	path := filepath.Join(directory, "control.json")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeHostConfig(t *testing.T, directory, name, address string, identity identities, generation uint64, journal string, faultAfterJournal, faultAfterReceipt, faultAfterResultSend bool) string {
	t.Helper()
	certificate, key := identity.host1CertificatePath, identity.host1KeyPath
	if generation == 2 {
		certificate, key = identity.host2CertificatePath, identity.host2KeyPath
	}
	now := time.Now().UTC()
	config := fmt.Sprintf(`{"version":2,"control_url":%q,"server_name":"localhost","trust_bundle_file":%q,"client_certificate_file":%q,"client_private_key_file":%q,"host_id":"host_01","host_generation":%d,"journal_file":%q,"maximum_receipts":100,"control_trust":{"version":1,"revocation_epoch":1,"current":{"id":"control_01","version":1,"public_key_environment":"TEST_CONTROL_PUBLIC_KEY","not_before":%q,"not_after":%q}},"host_signing_key_environment":"TEST_HOST_SIGNING_KEY","request_timeout_seconds":5,"test_fault_after_journal":%t,"test_fault_after_receipt":%t,"test_fault_after_result_send":%t}`, "https://"+address, filepath.Join(directory, "ca.crt"), certificate, key, generation, journal, now.Add(-time.Hour).Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339), faultAfterJournal, faultAfterReceipt, faultAfterResultSend)
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type process struct {
	command    *exec.Cmd
	stdout     *processOutput
	stderr     *boundedOutput
	redactions []string
	done       chan struct{}
	mu         sync.Mutex
	waitErr    error
}

func startProcess(t *testing.T, binary string, args []string, environment map[string]string) *process {
	t.Helper()
	stdout := newProcessOutput()
	stderr := newBoundedOutput()
	command := exec.Command(binary, args...)
	command.Env = os.Environ()
	for name, value := range environment {
		command.Env = append(command.Env, name+"="+value)
	}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	process := &process{command: command, stdout: stdout, stderr: stderr, redactions: redactionsFromEnvironment(environment), done: make(chan struct{})}
	go func() {
		process.mu.Lock()
		process.waitErr = command.Wait()
		process.mu.Unlock()
		close(process.done)
	}()
	return process
}

func (process *process) awaitControlReady(t *testing.T) controlReady {
	t.Helper()
	return awaitReady(t, process, process.stdout.controlReady, "sandbox-control")
}

func (process *process) awaitHostPoll(t *testing.T) hostPoll {
	t.Helper()
	return awaitReady(t, process, process.stdout.hostPoll, "sandbox-host")
}

func awaitReady[T any](t *testing.T, process *process, ready <-chan T, role string) T {
	t.Helper()
	timeout, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	select {
	case value := <-ready:
		return value
	case <-process.done:
		t.Fatalf("%s exited before readiness: %v; diagnostics=%s", role, process.wait(), process.diagnostics())
	case <-timeout.Done():
		if _, err := process.terminate(); err != nil {
			t.Fatalf("signal %s after readiness timeout: %v", role, err)
		}
		_ = process.wait()
		t.Fatalf("%s did not report readiness: diagnostics=%s", role, process.diagnostics())
	}
	var zero T
	return zero
}

func hostArguments(config string) []string {
	return []string{"--config", config, "--poll-interval", "100ms"}
}

func (process *process) stop(t *testing.T, expectSuccess bool, secrets ...string) {
	t.Helper()
	if expectSuccess {
		if _, err := process.terminate(); err != nil {
			t.Fatal(err)
		}
	}
	err := process.wait()
	if expectSuccess && err != nil {
		t.Fatalf("process failed: %v diagnostics=%s", err, process.diagnostics(secrets...))
	}
	if !expectSuccess && err == nil {
		t.Fatalf("process unexpectedly succeeded: diagnostics=%s", process.diagnostics(secrets...))
	}
	for _, secret := range secrets {
		if strings.Contains(process.stdout.String(), secret) || strings.Contains(process.stderr.String(), secret) {
			t.Fatalf("process disclosed secret: %s", process.diagnostics(secrets...))
		}
	}
}

const hostProcessTerminationGrace = time.Second

func (process *process) terminate() (bool, error) {
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
	grace, cancel := context.WithTimeout(context.Background(), hostProcessTerminationGrace)
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
	reap, cancel := context.WithTimeout(context.Background(), hostProcessTerminationGrace)
	defer cancel()
	select {
	case <-process.done:
		return true, nil
	case <-reap.Done():
		return true, fmt.Errorf("sandbox-host did not exit after SIGKILL within %s", hostProcessTerminationGrace)
	}
}

func (process *process) wait() error {
	<-process.done
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.waitErr
}

func (process *process) diagnostics(secrets ...string) string {
	redactions := append(append([]string(nil), process.redactions...), secrets...)
	return redactDiagnostics(process.stdout.String()+process.stderr.String(), redactions...)
}

func TestRedactionsFromEnvironmentExcludesNonSecretFlags(t *testing.T) {
	got := redactionsFromEnvironment(map[string]string{
		"TEST_HOST_SIGNING_KEY":           "host-signing-secret",
		"HOST_PROCESS_IGNORE_TERM_HELPER": "1",
	})
	if len(got) != 1 || got[0] != "host-signing-secret" {
		t.Fatalf("redactionsFromEnvironment() = %#v", got)
	}
	const endpoint = "127.0.0.1:1"
	if redacted := redactDiagnostics(endpoint, got...); redacted != endpoint {
		t.Fatalf("redactDiagnostics(endpoint) = %q; want %q", redacted, endpoint)
	}
}

// redactionsFromEnvironment retains the exact sensitive values explicitly
// supplied to the child. Readiness failures use this set without relying on a
// caller to repeat the secrets, while ordinary test flags remain observable.
func redactionsFromEnvironment(environment map[string]string) []string {
	values := make([]string, 0, len(environment))
	seen := make(map[string]struct{}, len(environment))
	for name, value := range environment {
		if value == "" || !isSensitiveEnvironmentName(name) {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool {
		if len(values[i]) != len(values[j]) {
			return len(values[i]) > len(values[j])
		}
		return values[i] < values[j]
	})
	return values
}

func isSensitiveEnvironmentName(name string) bool {
	name = strings.ToLower(name)
	return strings.Contains(name, "dsn") ||
		strings.Contains(name, "authorization") ||
		strings.Contains(name, "assertion") ||
		strings.Contains(name, "secret") ||
		strings.Contains(name, "token") ||
		strings.Contains(name, "password") ||
		strings.Contains(name, "signing_key") ||
		strings.Contains(name, "private_key")
}

type controlReady struct {
	Public      string `json:"public_address"`
	HostControl string `json:"host_control_address"`
}

type hostPoll struct {
	Ready bool `json:"ready"`
}

type processOutput struct {
	mu           sync.Mutex
	data         []byte
	pending      []byte
	controlReady chan controlReady
	hostPoll     chan hostPoll
}

func newProcessOutput() *processOutput {
	return &processOutput{controlReady: make(chan controlReady, 1), hostPoll: make(chan hostPoll, 1)}
}

func (output *processOutput) Write(input []byte) (int, error) {
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
			hostPoll
		}
		if json.Unmarshal(line, &record) != nil {
			continue
		}
		switch {
		case record.Message == "sandbox control ready" && record.Role == "sandbox-control" && record.Public != "":
			select {
			case output.controlReady <- record.controlReady:
			default:
			}
		case record.Message == "sandbox host poll":
			select {
			case output.hostPoll <- record.hostPoll:
			default:
			}
		}
	}
	return len(input), nil
}

func (output *processOutput) String() string {
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

func waitForOperationState(t *testing.T, client sandbox.Client, id sandbox.OperationID, want sandbox.OperationState) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		operation, err := client.GetOperation(context.Background(), id)
		if err == nil && operation.State == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("operation %s did not reach %s: %#v, %v", id, want, operation, err)
		}
		interval, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		<-interval.Done()
		cancel()
	}
}

func connectPublicClient(t *testing.T, endpoint string, roots []byte, authorization string) sandbox.Client {
	t.Helper()
	trust, _ := sandbox.NewStaticTrustBundleSource(map[sandbox.TrustBundleRef]sandbox.TrustBundle{"trust/integration": {Version: "integration/v1", PEMRoots: roots}})
	deadline := time.Now().Add(15 * time.Second)
	for {
		client, err := sandbox.NewClient(context.Background(), sandbox.ClientConfig{Endpoint: sandbox.Endpoint{URL: endpoint}, TLS: sandbox.TLSConfig{ServerName: "localhost", TrustBundleRef: "trust/integration"}, Credentials: integrationCredentials(authorization), TrustBundles: trust, RequestTimeout: time.Second})
		if err == nil {
			return client
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		wait, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		<-wait.Done()
		cancel()
	}
}

type integrationCredentials string

func (credential integrationCredentials) Apply(_ context.Context, sink sandbox.CredentialSink) error {
	return sink.SetAuthorization("Bearer", string(credential))
}

func openLedger(t *testing.T, dsn string) (*sandboxcontrol.PostgresLedger, *pgxpool.Pool) {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := sandboxcontrol.NewPostgresLedger(pool)
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	return ledger, pool
}

func loopbackAddress(t *testing.T, address string) string {
	t.Helper()
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		t.Fatalf("parse bound host control address %q: %v", address, err)
	}
	if host == "0.0.0.0" || host == "::" {
		return net.JoinHostPort("127.0.0.1", port)
	}
	return address
}

func certificateDigest(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.Raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func requiredEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}
