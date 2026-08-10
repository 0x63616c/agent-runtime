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
	redirectRefused                       = errors.New("sandbox reference host redirect refused")
)

// SecretLookup resolves only explicitly named already-injected values.
type SecretLookup func(string) (string, bool)

// RunOnce polls one reference operation with the explicit unavailable executor.
// It fails closed to uncertain rather than claiming a fabricated effect.
func RunOnce(ctx context.Context, config Config, lookup SecretLookup, source clock.Clock) error {
	return RunOnceWithExecutor(ctx, config, lookup, source, unavailableExecutor{})
}

// RunOnceWithExecutor polls, verifies, receipts, durably records execution
// intent, then delegates at most one lease-fenced host effect.
func RunOnceWithExecutor(ctx context.Context, config Config, lookup SecretLookup, source clock.Clock, executor HostExecutor) error {
	if ctx == nil || lookup == nil || source == nil || executor == nil {
		return errors.New("run sandbox reference host: context, secret lookup, clock and executor are required")
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
	if config.bootProbe != nil {
		_, err := RunBootProbeV2Once(ctx, client, config.controlURL, config.bootProbe.principal, config.bootProbe.operationID, config.bootProbe.hostInstanceSessionID, config.bootProbe.journalFile)
		return err
	}
	journal, err := sandboxhostjournal.Open(config.journalFile, config.maximumReceipts)
	if err != nil {
		return err
	}
	defer journal.Close()
	for _, pending := range journal.PendingStarts() {
		if err := sendResult(ctx, client, config.controlURL, pending.Wire); err != nil {
			return err
		}
		if err := journal.AcknowledgeStarted(pending.ReceiptKey, sandboxhostprotocol.Digest(pending.Wire)); err != nil {
			return err
		}
	}
	if err := recoverIncompleteExecutions(ctx, source.Now().UTC(), journal, ed25519.PrivateKey(hostPrivate), func(sendCtx context.Context, wire []byte) error {
		return sendResult(sendCtx, client, config.controlURL, wire)
	}); err != nil {
		return err
	}
	for _, pending := range journal.PendingResults() {
		if err := sendResult(ctx, client, config.controlURL, pending.Wire); err != nil {
			return err
		}
		if err := journal.AcknowledgeResult(pending.ReceiptKey, sandboxhostprotocol.Digest(pending.Wire)); err != nil {
			return err
		}
	}
	pullBody, _ := json.Marshal(sandboxhostprotocol.PullRequest{ProtocolVersion: sandboxhostprotocol.Version, Kind: "pull", HostID: config.hostID, HostGeneration: config.hostGeneration})
	response, err := do(ctx, client, config.controlURL+pullPath, pullBody)
	if err != nil {
		return err
	}
	if response.status == http.StatusNoContent {
		return ErrNoWork
	}
	if err := requireControlStatus(response.status, "pull control endpoint is unavailable", "pull denied or unavailable"); err != nil {
		return err
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
	receiptBody, _ := json.Marshal(sandboxhostprotocol.ReceiptRequest{ProtocolVersion: sandboxhostprotocol.Version, Kind: "receipt", AssignmentID: envelope.AssignmentID, FencingToken: envelope.FencingToken, ReceiptDigest: entry.ReceiptDigest})
	receiptResponse, err := do(ctx, client, config.controlURL+receiptPath, receiptBody)
	if err != nil {
		return err
	}
	if err := requireControlStatus(receiptResponse.status, "receipt control endpoint is unavailable", "receipt was not accepted"); err != nil {
		return err
	}
	if config.testFaultAfterReceipt {
		return ErrInjectedReceiptFault
	}
	if err := executeEnvelopeWithAfterTerminalSend(ctx, envelope, source.Now().UTC(), journal, ed25519.PrivateKey(hostPrivate), executor, func(sendCtx context.Context, wire []byte) error {
		return sendResult(sendCtx, client, config.controlURL, wire)
	}, context.WithDeadline, func() error {
		if config.testFaultAfterResultSend {
			return ErrInjectedResultAcknowledgementFault
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

type unavailableExecutor struct{}

func (unavailableExecutor) Execute(context.Context, sandboxhostprotocol.Envelope) error {
	return errors.New("sandbox reference host executor is unavailable")
}

func sendResult(ctx context.Context, client *http.Client, controlURL string, wire []byte) error {
	resultResponse, err := do(ctx, client, controlURL+resultPath, wire)
	if err != nil {
		return err
	}
	return requireControlStatus(resultResponse.status, "result control endpoint is unavailable", "result was not accepted")
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
		if isTerminalTransportError(err) {
			return response{}, errors.Wrap(err, "run sandbox reference host transport refused")
		}
		return response{}, retryableControlError("transport unavailable")
	}
	wire, readErr := io.ReadAll(io.LimitReader(httpResponse.Body, maxBodyBytes+1))
	closeErr := httpResponse.Body.Close()
	if readErr != nil || closeErr != nil || len(wire) > maxBodyBytes {
		return response{}, errors.New("run sandbox reference host: invalid bounded response")
	}
	return response{status: httpResponse.StatusCode, body: wire}, nil
}

func retryableControlError(reason string) error {
	return errors.Mark(errors.New("run sandbox reference host: "+reason), ErrRetryable)
}

func requireControlStatus(status int, retryReason, refusalReason string) error {
	if status >= http.StatusInternalServerError {
		return retryableControlError(retryReason)
	}
	if status != http.StatusOK {
		return errors.New("run sandbox reference host: " + refusalReason)
	}
	return nil
}

func isTerminalTransportError(err error) bool {
	if errors.Is(err, redirectRefused) {
		return true
	}
	var unknownAuthority x509.UnknownAuthorityError
	return errors.As(err, &unknownAuthority)
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
		return redirectRefused
	}}, nil
}

func requiredSecret(lookup SecretLookup, name string) (string, error) {
	value, found := lookup(name)
	if !found || value == "" {
		return "", errors.Newf("run sandbox reference host: required secret environment %s is missing", name)
	}
	return value, nil
}
