package sandboxhostapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/sandboxcontrol"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
)

func TestHostHandlerPullLostAckReceiptRenewAndResult(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	fakeClock, _ := clock.NewFake(now)
	controlPublic, controlPrivate, _ := ed25519.GenerateKey(rand.Reader)
	hostPublic, hostPrivate, _ := ed25519.GenerateKey(rand.Reader)
	certificate := testPeerCertificate(t, "host_01", 1)
	store := sandboxcontrol.NewMemoryLedger()
	host := sandboxcontrol.HostEnrollment{HostID: "host_01", Tenant: "tenant_01", Pool: "pool_01", Generation: 1, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: certificateDigest(certificate), SigningPublicKey: hostPublic, CapabilityDigest: testDigest('b'), Status: sandboxcontrol.HostActive, ExpiresAt: now.Add(time.Hour)}
	if err := store.ProvisionHost(context.Background(), host, sandboxcontrol.AttestationInput{Profile: sandboxcontrol.AttestationProfileLocalMetadata}, nil); err != nil {
		t.Fatal(err)
	}
	operation := sandboxcontrol.Operation{Principal: "tenant_01:subject_01", Tenant: "tenant_01", ID: "op_host_api", Kind: "close-sandbox", TargetKind: "sandbox", TargetID: "sbx_host_api", InputDigest: testDigest('c'), CanonicalDigest: testDigest('d'), EffectiveSpecDigest: testDigest('e'), CapabilityDigest: host.CapabilityDigest, DispatchBody: `{"version":"sandbox.control/v1"}`, AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour), CleanupRequired: true}
	if _, _, err := store.Accept(context.Background(), operation); err != nil {
		t.Fatal(err)
	}
	controlTrust := testControlTrust(now, controlPublic)
	handler, err := NewHandler(Config{Store: store, ControlTrust: controlTrust, ControlSigningKey: controlPrivate, Entropy: bytes.NewReader(bytes.Repeat([]byte{0x42}, 4096)), Clock: fakeClock, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	first := perform(t, handler, certificate, http.MethodPost, pullPath, pullRequest{ProtocolVersion: sandboxhostprotocol.Version, Kind: "pull", HostID: host.HostID, HostGeneration: host.Generation})
	if first.Code != http.StatusOK {
		t.Fatalf("first pull status=%d body=%s", first.Code, first.Body.String())
	}
	envelope, err := sandboxhostprotocol.VerifyEnvelopeWithTrust(first.Body.Bytes(), host.HostID, host.Generation, now, controlTrust)
	if err != nil || envelope.ControlKeyVersion != 4 || envelope.ControlRevocationEpoch != 9 {
		t.Fatal(err)
	}
	duplicate := perform(t, handler, certificate, http.MethodPost, pullPath, pullRequest{ProtocolVersion: sandboxhostprotocol.Version, Kind: "pull", HostID: host.HostID, HostGeneration: host.Generation})
	if duplicate.Code != http.StatusOK || duplicate.Body.String() != first.Body.String() {
		t.Fatalf("lost-ack pull status=%d duplicate=%t", duplicate.Code, duplicate.Body.String() == first.Body.String())
	}
	receiptDigest := sandboxhostprotocol.Digest([]byte("receipt"))
	receipt := perform(t, handler, certificate, http.MethodPost, receiptPath, receiptRequest{ProtocolVersion: sandboxhostprotocol.Version, Kind: "receipt", AssignmentID: envelope.AssignmentID, FencingToken: envelope.FencingToken, ReceiptDigest: receiptDigest})
	if receipt.Code != http.StatusOK {
		t.Fatalf("receipt status=%d body=%s", receipt.Code, receipt.Body.String())
	}
	outputBytes, err := sandboxhostprotocol.SignOutput(sandboxhostprotocol.Output{ProtocolVersion: sandboxhostprotocol.Version, OutputID: "output_01", HostID: host.HostID, HostGeneration: host.Generation, AssignmentID: envelope.AssignmentID, LeaseEpoch: envelope.LeaseEpoch, FencingToken: envelope.FencingToken, Principal: operation.Principal, OperationID: operation.ID, Stream: "stdout", Sequence: 1, ChunkDigest: testDigest('f'), SizeBytes: 12, ObservedAt: now}, hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	output := performBytes(t, handler, certificate, http.MethodPost, outputPath, outputBytes)
	outputRetry := performBytes(t, handler, certificate, http.MethodPost, outputPath, outputBytes)
	if output.Code != http.StatusOK || outputRetry.Code != http.StatusOK || !bytes.Contains(outputRetry.Body.Bytes(), []byte(`"duplicate":true`)) {
		t.Fatalf("output statuses=%d/%d retry=%s", output.Code, outputRetry.Code, outputRetry.Body.String())
	}
	renew := perform(t, handler, certificate, http.MethodPost, heartbeatPath, heartbeatRequest{ProtocolVersion: sandboxhostprotocol.Version, Kind: "heartbeat", AssignmentID: envelope.AssignmentID, FencingToken: envelope.FencingToken})
	if renew.Code != http.StatusOK {
		t.Fatalf("heartbeat status=%d body=%s", renew.Code, renew.Body.String())
	}
	renewed, err := sandboxhostprotocol.VerifyEnvelopeWithTrust(renew.Body.Bytes(), host.HostID, host.Generation, now, controlTrust)
	if err != nil || renewed.FencingToken != envelope.FencingToken+1 {
		t.Fatalf("renewed envelope=%#v error=%v", renewed, err)
	}
	renewedReceipt := perform(t, handler, certificate, http.MethodPost, receiptPath, receiptRequest{ProtocolVersion: sandboxhostprotocol.Version, Kind: "receipt", AssignmentID: renewed.AssignmentID, FencingToken: renewed.FencingToken, ReceiptDigest: sandboxhostprotocol.Digest([]byte("renewed-receipt"))})
	if renewedReceipt.Code != http.StatusOK {
		t.Fatalf("renewed receipt status=%d body=%s", renewedReceipt.Code, renewedReceipt.Body.String())
	}
	terminalOutputBytes, err := sandboxhostprotocol.SignOutput(sandboxhostprotocol.Output{ProtocolVersion: sandboxhostprotocol.Version, OutputID: "output_02", HostID: host.HostID, HostGeneration: host.Generation, AssignmentID: renewed.AssignmentID, LeaseEpoch: renewed.LeaseEpoch, FencingToken: renewed.FencingToken, Principal: operation.Principal, OperationID: operation.ID, Stream: "stdout", Sequence: 2, ChunkDigest: testDigest('a'), SizeBytes: 6, ObservedAt: now}, hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	terminalOutput := performBytes(t, handler, certificate, http.MethodPost, outputPath, terminalOutputBytes)
	if terminalOutput.Code != http.StatusOK {
		t.Fatalf("terminal output status=%d body=%s", terminalOutput.Code, terminalOutput.Body.String())
	}
	resultBytes, err := sandboxhostprotocol.SignResult(sandboxhostprotocol.Result{ProtocolVersion: sandboxhostprotocol.Version, ResultID: "result_01", HostID: host.HostID, HostGeneration: host.Generation, AssignmentID: renewed.AssignmentID, LeaseEpoch: renewed.LeaseEpoch, FencingToken: renewed.FencingToken, Principal: operation.Principal, OperationID: operation.ID, EffectiveSpecDigest: operation.EffectiveSpecDigest, CapabilityDigest: operation.CapabilityDigest, State: "succeeded", ObservedAt: now}, hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	result := performBytes(t, handler, certificate, http.MethodPost, resultPath, resultBytes)
	if result.Code != http.StatusOK {
		t.Fatalf("result status=%d body=%s", result.Code, result.Body.String())
	}
	resultRetry := performBytes(t, handler, certificate, http.MethodPost, resultPath, resultBytes)
	if resultRetry.Code != http.StatusOK {
		t.Fatalf("result retry status=%d body=%s", resultRetry.Code, resultRetry.Body.String())
	}
	if err := fakeClock.Advance(2 * time.Minute); err != nil {
		t.Fatal(err)
	}
	lateOutputRetry := performBytes(t, handler, certificate, http.MethodPost, outputPath, terminalOutputBytes)
	lateResultRetry := performBytes(t, handler, certificate, http.MethodPost, resultPath, resultBytes)
	if lateOutputRetry.Code != http.StatusOK || !bytes.Contains(lateOutputRetry.Body.Bytes(), []byte(`"duplicate":true`)) || lateResultRetry.Code != http.StatusOK {
		t.Fatalf("post-lease ACK recovery output=%d/%s result=%d/%s", lateOutputRetry.Code, lateOutputRetry.Body.String(), lateResultRetry.Code, lateResultRetry.Body.String())
	}
	identity := sandboxcontrol.HostIdentity{HostID: host.HostID, Generation: host.Generation, CertificateDigest: host.CertificateDigest}
	if _, err := store.AuthenticateHost(context.Background(), identity, fakeClock.Now()); err != nil {
		t.Fatalf("host was quarantined after exact ACK recovery: %v", err)
	}
	got, err := store.Get(context.Background(), operation.Principal, operation.ID)
	if err != nil || got.State != sandboxcontrol.StateSucceeded {
		t.Fatalf("operation=%#v error=%v", got, err)
	}
}

func TestHostHandlerRejectsRogueTLSAndQuarantinesBadSignature(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	fakeClock, _ := clock.NewFake(now)
	_, controlPrivate, _ := ed25519.GenerateKey(rand.Reader)
	hostPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	certificate := testPeerCertificate(t, "host_01", 1)
	store := sandboxcontrol.NewMemoryLedger()
	host := sandboxcontrol.HostEnrollment{HostID: "host_01", Tenant: "tenant_01", Pool: "pool_01", Generation: 1, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: certificateDigest(certificate), SigningPublicKey: hostPublic, CapabilityDigest: testDigest('b'), Status: sandboxcontrol.HostActive, ExpiresAt: now.Add(time.Hour)}
	if err := store.ProvisionHost(context.Background(), host, sandboxcontrol.AttestationInput{Profile: sandboxcontrol.AttestationProfileLocalMetadata}, nil); err != nil {
		t.Fatal(err)
	}
	handler, _ := NewHandler(Config{Store: store, ControlTrust: testControlTrust(now, controlPrivate.Public().(ed25519.PublicKey)), ControlSigningKey: controlPrivate, Entropy: bytes.NewReader(bytes.Repeat([]byte{0x44}, 4096)), Clock: fakeClock, LeaseDuration: time.Minute})
	rogue := testPeerCertificate(t, "host_rogue", 1)
	response := perform(t, handler, rogue, http.MethodPost, pullPath, pullRequest{ProtocolVersion: sandboxhostprotocol.Version, Kind: "pull", HostID: "host_rogue", HostGeneration: 1})
	if response.Code != http.StatusForbidden {
		t.Fatalf("rogue pull status=%d", response.Code)
	}
	badResult := []byte(`{"protocol_version":"sandbox.host-control/v1","result_id":"bad"}`)
	response = performBytes(t, handler, certificate, http.MethodPost, resultPath, badResult)
	if response.Code != http.StatusForbidden {
		t.Fatalf("bad result status=%d", response.Code)
	}
	identity := sandboxcontrol.HostIdentity{HostID: host.HostID, Generation: host.Generation, CertificateDigest: host.CertificateDigest}
	if _, err := store.AuthenticateHost(context.Background(), identity, now); err == nil {
		t.Fatal("bad signature did not quarantine enrolled host")
	}
}

func testControlTrust(now time.Time, publicKey ed25519.PublicKey) sandboxhostprotocol.TrustBundle {
	return sandboxhostprotocol.TrustBundle{Version: 3, RevocationEpoch: 9, Current: sandboxhostprotocol.SigningKey{ID: "control_01", Version: 4, PublicKey: publicKey, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}}
}

func perform(t *testing.T, handler http.Handler, certificate *x509.Certificate, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return performBytes(t, handler, certificate, method, path, encoded)
}

func performBytes(t *testing.T, handler http.Handler, certificate *x509.Certificate, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, "https://control.test"+path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func testPeerCertificate(t *testing.T, hostID string, generation uint64) *x509.Certificate {
	t.Helper()
	identity, err := url.Parse("spiffe://agent-runtime/sandbox-host/" + hostID + "/generation/" + strconv.FormatUint(generation, 10))
	if err != nil {
		t.Fatal(err)
	}
	raw := sha256.Sum256([]byte(identity.String()))
	return &x509.Certificate{Raw: raw[:], URIs: []*url.URL{identity}}
}

func certificateDigest(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.Raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func testDigest(character byte) string {
	return "sha256:" + string(bytes.Repeat([]byte{character}, 64))
}
