package sandboxhostprocess

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostjournal"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/cockroachdb/errors"
)

const (
	pullPath     = "/sandbox.host-control/v1/pull"
	receiptPath  = "/sandbox.host-control/v1/receipt"
	resultPath   = "/sandbox.host-control/v1/result"
	maxBodyBytes = 1 << 20
)

var (
	// ErrNoWork is a successful bounded poll with no eligible operation.
	ErrNoWork = errors.New("sandbox reference host has no work")
	// ErrInjectedJournalFault is the explicit test-profile lost-ack boundary.
	ErrInjectedJournalFault = errors.New("sandbox reference host injected fault after journal commit")
	// ErrInjectedReceiptFault is the explicit test-profile lost-result boundary.
	ErrInjectedReceiptFault = errors.New("sandbox reference host injected fault after receipt commit")
	// ErrInjectedResultAcknowledgementFault is the explicit test profile after
	// control commits a result but before the host journals its acknowledgement.
	ErrInjectedResultAcknowledgementFault = errors.New("sandbox reference host injected fault after result send")
)

// SecretLookup resolves only explicitly named already-injected values.
type SecretLookup func(string) (string, bool)

type pullRequest struct {
	ProtocolVersion string `json:"protocol_version"`
	Kind            string `json:"kind"`
	HostID          string `json:"host_id"`
	HostGeneration  uint64 `json:"host_generation"`
}

type receiptRequest struct {
	ProtocolVersion string `json:"protocol_version"`
	Kind            string `json:"kind"`
	AssignmentID    string `json:"assignment_id"`
	FencingToken    uint64 `json:"fencing_token"`
	ReceiptDigest   string `json:"receipt_digest"`
}

// RunOnce polls, verifies, journals, acknowledges and completes at most one
// reference operation. It never claims real process or isolation execution.
func RunOnce(ctx context.Context, config Config, lookup SecretLookup, source clock.Clock) error {
	if ctx == nil || lookup == nil || source == nil {
		return errors.New("run sandbox reference host: context, secret lookup and clock are required")
	}
	hostPrivateEncoded, err := requiredSecret(lookup, config.hostSigningKeyEnvironment)
	if err != nil {
		return err
	}
	controlTrust, err := LoadControlTrust(config.controlTrust, lookup)
	if err != nil {
		return err
	}
	hostPrivate, err := base64.RawStdEncoding.DecodeString(hostPrivateEncoded)
	if err != nil || len(hostPrivate) != ed25519.PrivateKeySize {
		return errors.New("run sandbox reference host: host signing key is invalid")
	}
	client, err := newClient(config)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	journal, err := sandboxhostjournal.Open(config.journalFile, config.maximumReceipts)
	if err != nil {
		return err
	}
	for _, pending := range journal.PendingResults() {
		resultResponse, err := do(ctx, client, config.controlURL+resultPath, pending.Wire)
		if err != nil || resultResponse.status != http.StatusOK {
			return errors.New("run sandbox reference host: pending result was not accepted")
		}
		if err := journal.AcknowledgeResult(pending.ReceiptKey, sandboxhostprotocol.Digest(pending.Wire)); err != nil {
			return err
		}
	}
	pullBody, _ := json.Marshal(pullRequest{ProtocolVersion: sandboxhostprotocol.Version, Kind: "pull", HostID: config.hostID, HostGeneration: config.hostGeneration})
	response, err := do(ctx, client, config.controlURL+pullPath, pullBody)
	if err != nil {
		return err
	}
	if response.status == http.StatusNoContent {
		return ErrNoWork
	}
	if response.status != http.StatusOK {
		return errors.New("run sandbox reference host: pull denied or unavailable")
	}
	now := source.Now().UTC()
	envelope, err := sandboxhostprotocol.VerifyEnvelopeWithTrust(response.body, config.hostID, config.hostGeneration, now, controlTrust.Snapshot())
	if err != nil {
		return errors.New("run sandbox reference host: assignment refused")
	}
	entry, _, err := journal.Accept(envelope, sandboxhostprotocol.Digest(response.body))
	if err != nil {
		return err
	}
	if config.testFaultAfterJournal {
		return ErrInjectedJournalFault
	}
	receiptBody, _ := json.Marshal(receiptRequest{ProtocolVersion: sandboxhostprotocol.Version, Kind: "receipt", AssignmentID: envelope.AssignmentID, FencingToken: envelope.FencingToken, ReceiptDigest: entry.ReceiptDigest})
	receiptResponse, err := do(ctx, client, config.controlURL+receiptPath, receiptBody)
	if err != nil || receiptResponse.status != http.StatusOK {
		return errors.New("run sandbox reference host: receipt was not accepted")
	}
	if config.testFaultAfterReceipt {
		return ErrInjectedReceiptFault
	}
	resultWire, err := sandboxhostprotocol.SignResult(sandboxhostprotocol.Result{ProtocolVersion: sandboxhostprotocol.Version, ResultID: "result_" + envelope.DeliveryID, HostID: config.hostID, HostGeneration: config.hostGeneration, AssignmentID: envelope.AssignmentID, LeaseEpoch: envelope.LeaseEpoch, FencingToken: envelope.FencingToken, Principal: envelope.Principal, OperationID: envelope.OperationID, EffectiveSpecDigest: envelope.EffectiveSpecDigest, CapabilityDigest: envelope.CapabilityDigest, State: "succeeded", ObservedAt: source.Now().UTC()}, ed25519.PrivateKey(hostPrivate))
	if err != nil {
		return err
	}
	if err := journal.StageResult(envelope, resultWire); err != nil {
		return err
	}
	resultResponse, err := do(ctx, client, config.controlURL+resultPath, resultWire)
	if err != nil || resultResponse.status != http.StatusOK {
		return errors.New("run sandbox reference host: result was not accepted")
	}
	if config.testFaultAfterResultSend {
		return ErrInjectedResultAcknowledgementFault
	}
	if err := journal.AcknowledgeResult(entry.ReceiptKey, sandboxhostprotocol.Digest(resultWire)); err != nil {
		return err
	}
	return nil
}

type response struct {
	status int
	body   []byte
}

func do(ctx context.Context, client *http.Client, target string, body []byte) (response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return response{}, errors.New("run sandbox reference host: create request")
	}
	request.Header.Set("Content-Type", "application/json")
	httpResponse, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return response{}, errors.Wrap(ctx.Err(), "run sandbox reference host")
		}
		return response{}, errors.New("run sandbox reference host: transport unavailable")
	}
	wire, readErr := io.ReadAll(io.LimitReader(httpResponse.Body, maxBodyBytes+1))
	closeErr := httpResponse.Body.Close()
	if readErr != nil || closeErr != nil || len(wire) > maxBodyBytes {
		return response{}, errors.New("run sandbox reference host: invalid bounded response")
	}
	return response{status: httpResponse.StatusCode, body: wire}, nil
}

func newClient(config Config) (*http.Client, error) {
	certificate, err := tls.LoadX509KeyPair(config.clientCertificateFile, config.clientPrivateKeyFile)
	if err != nil {
		return nil, errors.Wrap(err, "run sandbox reference host: load TLS identity")
	}
	rootPEM, err := os.ReadFile(config.trustBundleFile)
	if err != nil || len(rootPEM) == 0 || len(rootPEM) > 1<<20 {
		return nil, errors.New("run sandbox reference host: trust bundle is unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, errors.New("run sandbox reference host: trust bundle is invalid")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: config.serverName, RootCAs: roots, Certificates: []tls.Certificate{certificate}}}
	return &http.Client{Transport: transport, Timeout: config.requestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("sandbox reference host redirect refused")
	}}, nil
}

func requiredSecret(lookup SecretLookup, name string) (string, error) {
	value, found := lookup(name)
	if !found || value == "" {
		return "", errors.Newf("run sandbox reference host: required secret environment %s is missing", name)
	}
	return value, nil
}
