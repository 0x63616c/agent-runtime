package sandbox

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const bindRouteV1 = "/sandbox.control/v1/bind"

var bindRequestV1 = []byte(`{"version":"sandbox.control/v1","kind":"bind-request"}`)

type httpControlClient struct {
	mu             sync.RWMutex
	endpoint       *url.URL
	client         *http.Client
	transport      *http.Transport
	credentials    CredentialSource
	requestTimeout time.Duration
	assertion      string
	expiresAt      time.Time
	closed         bool
}

func newHTTPControlClient(ctx context.Context, config ClientConfig) (*httpControlClient, error) {
	bundle, err := config.TrustBundles.ResolveTrustBundle(ctx, config.TLS.TrustBundleRef)
	if err != nil {
		if contextErr := contextFailure(ctx); contextErr != nil {
			return nil, contextErr
		}
		return nil, newFailure(FailureUnavailable, "sandbox trust bundle is unavailable", RetryAfterReconcile)
	}
	if bundle.Version == "" || len(bundle.PEMRoots) == 0 || len(bundle.PEMRoots) > maxTrustBundleBytes {
		return nil, newFailure(FailureInvalidArgument, "sandbox trust bundle is invalid", RetryNever)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(append([]byte(nil), bundle.PEMRoots...)) {
		return nil, newFailure(FailureInvalidArgument, "sandbox trust bundle contains no certificates", RetryNever)
	}
	endpoint, _ := url.Parse(config.Endpoint.URL)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: config.TLS.ServerName, RootCAs: roots}}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return newFailure(FailureUnavailable, "sandbox control redirect was refused", RetryNever)
	}}
	control := &httpControlClient{endpoint: endpoint, client: client, transport: transport, credentials: config.Credentials, requestTimeout: config.RequestTimeout}
	if err := control.bind(ctx); err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	return control, nil
}

func (client *httpControlClient) bind(ctx context.Context) error {
	requestCtx, cancel := context.WithTimeout(ctx, client.requestTimeout)
	defer cancel()
	authorization, err := applyAuthorization(requestCtx, client.credentials)
	if err != nil {
		return err
	}
	target := client.endpoint.ResolveReference(&url.URL{Path: bindRouteV1})
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, target.String(), bytes.NewReader(bindRequestV1))
	if err != nil {
		return newFailure(FailureUnavailable, "sandbox bind request could not be created", RetryAfterReconcile)
	}
	request.Header.Set("Authorization", authorization)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.client.Do(request)
	request.Header.Del("Authorization")
	if err != nil {
		if contextErr := contextFailure(requestCtx); contextErr != nil {
			return contextErr
		}
		return newFailure(FailureUnavailable, "sandbox bind failed", RetryAfterReconcile)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxControlV1Bytes+1))
	closeErr := response.Body.Close()
	if err != nil || len(data) > maxControlV1Bytes {
		return newFailure(FailureUnavailable, "sandbox bind response exceeded its finite limit", RetryAfterReconcile)
	}
	if closeErr != nil {
		return newFailure(FailureUnavailable, "sandbox bind response could not be closed", RetryAfterReconcile)
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return newFailure(FailureNotFoundOrDenied, "sandbox bind was denied", RetryNever)
	}
	if response.StatusCode != http.StatusOK {
		return newFailure(FailureUnavailable, "sandbox bind service is unavailable", RetryAfterReconcile)
	}
	bound, err := decodeBindResponse(data)
	if err != nil || !bound.ExpiresAt.After(time.Now().UTC()) {
		return newFailure(FailureNotFoundOrDenied, "sandbox bind response is invalid", RetryNever)
	}
	client.assertion = bound.Assertion
	client.expiresAt = bound.ExpiresAt
	return nil
}

func applyAuthorization(ctx context.Context, source CredentialSource) (string, error) {
	sink := &credentialSink{}
	defer sink.ClearAuthorization()
	if err := source.Apply(ctx, sink); err != nil {
		if contextErr := contextFailure(ctx); contextErr != nil {
			return "", contextErr
		}
		return "", newFailure(FailureUnavailable, "sandbox credentials are unavailable", RetryAfterReconcile)
	}
	return sink.consumeAuthorization()
}

func (client *httpControlClient) unavailable() error {
	return newFailure(FailureUnavailable, "sandbox control operation transport is not implemented", RetryAfterReconcile)
}

func (client *httpControlClient) Submit(context.Context, OperationRequest) (OperationRef, error) {
	return OperationRef{}, client.unavailable()
}
func (client *httpControlClient) GetOperation(context.Context, OperationID) (Operation, error) {
	return Operation{}, client.unavailable()
}
func (client *httpControlClient) WaitOperation(context.Context, OperationID) (Operation, error) {
	return Operation{}, client.unavailable()
}
func (client *httpControlClient) WatchOperation(context.Context, OperationID, OperationCursor) (OperationStream, error) {
	return nil, client.unavailable()
}
func (client *httpControlClient) GetSandbox(context.Context, SandboxID) (SandboxInfo, error) {
	return SandboxInfo{}, client.unavailable()
}
func (client *httpControlClient) GetProcess(context.Context, ProcessID) (ProcessInfo, error) {
	return ProcessInfo{}, client.unavailable()
}
func (client *httpControlClient) ReplayOutput(context.Context, ProcessID, OutputCursor) (OutputStream, error) {
	return nil, client.unavailable()
}
func (client *httpControlClient) GetVolume(context.Context, VolumeID) (VolumeInfo, error) {
	return VolumeInfo{}, client.unavailable()
}
func (client *httpControlClient) ListVolumes(context.Context, Page) (VolumePage, error) {
	return VolumePage{}, client.unavailable()
}
func (client *httpControlClient) GetSnapshot(context.Context, SnapshotID) (SnapshotInfo, error) {
	return SnapshotInfo{}, client.unavailable()
}
func (client *httpControlClient) ListSnapshots(context.Context, Page) (SnapshotPage, error) {
	return SnapshotPage{}, client.unavailable()
}

func (client *httpControlClient) Close(ctx context.Context) error {
	if err := contextFailure(ctx); err != nil {
		return err
	}
	client.mu.Lock()
	if !client.closed {
		client.closed = true
		client.assertion = ""
		client.expiresAt = time.Time{}
		client.transport.CloseIdleConnections()
	}
	client.mu.Unlock()
	return nil
}

var _ Client = (*httpControlClient)(nil)
