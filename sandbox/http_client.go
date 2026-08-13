package sandbox

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

const bindRouteV1 = "/sandbox.control/v1/bind"

const (
	operationsRouteV1   = "/sandbox.control/v1/operations"
	capabilitiesRouteV1 = "/sandbox.control/v1/capabilities"
	processesRouteV1    = "/sandbox.control/v1/processes/"
	volumesRouteV1      = "/sandbox.control/v1/volumes"
	bindingHeaderV1     = "Sandbox-Binding"
)

var bindRequestV1 = []byte(`{"version":"sandbox.control/v1","kind":"bind-request"}`)

type httpControlClient struct {
	mu             sync.Mutex
	endpoint       *url.URL
	client         *http.Client
	transport      *http.Transport
	credentials    CredentialSource
	requestTimeout time.Duration
	assertion      string
	expiresAt      time.Time
	closed         bool
	lifetime       context.Context
	cancelLifetime context.CancelFunc
	inFlight       uint64
	drained        chan struct{}
	drainedOnce    sync.Once
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
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	control := &httpControlClient{endpoint: endpoint, client: client, transport: transport, credentials: config.Credentials, requestTimeout: config.RequestTimeout, lifetime: lifetime, cancelLifetime: cancelLifetime, drained: make(chan struct{})}
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
	if err := contextFailure(ctx); err != nil {
		return "", err
	}
	sink := &credentialSink{}
	defer sink.ClearAuthorization()
	if err := source.Apply(ctx, cancellationCredentialSink{ctx: ctx, sink: sink}); err != nil {
		if contextErr := contextFailure(ctx); contextErr != nil {
			return "", contextErr
		}
		return "", newFailure(FailureUnavailable, "sandbox credentials are unavailable", RetryAfterReconcile)
	}
	if err := contextFailure(ctx); err != nil {
		return "", err
	}
	return sink.consumeAuthorization()
}

// cancellationCredentialSink rejects credentials that arrive after the owning
// HTTP attempt has been cancelled. A non-cooperative credential source must not
// be able to race Close and let a request reach the control service.
type cancellationCredentialSink struct {
	ctx  context.Context
	sink *credentialSink
}

func (sink cancellationCredentialSink) SetAuthorization(scheme, value string) error {
	if err := contextFailure(sink.ctx); err != nil {
		return err
	}
	if err := sink.sink.SetAuthorization(scheme, value); err != nil {
		return err
	}
	if err := contextFailure(sink.ctx); err != nil {
		sink.sink.ClearAuthorization()
		return err
	}
	return nil
}

func (sink cancellationCredentialSink) ClearAuthorization() {
	sink.sink.ClearAuthorization()
}

func (client *httpControlClient) Submit(ctx context.Context, request OperationRequest) (OperationRef, error) {
	body, err := encodeOperationRequestV1(request)
	if err != nil {
		return OperationRef{}, err
	}
	response, err := client.do(ctx, http.MethodPost, operationsRouteV1, body)
	if err != nil {
		return OperationRef{}, err
	}
	operation, err := decodeOperationResponseV1(response)
	if err != nil || operation.Ref.ID != request.ID || operation.Kind != request.Kind {
		return OperationRef{}, newFailure(FailureUnavailable, "sandbox submit response is invalid", RetryAfterReconcile)
	}
	return operation.Ref, nil
}
func (client *httpControlClient) GetOperation(ctx context.Context, id OperationID) (Operation, error) {
	if !validOperationID(id) {
		return Operation{}, newFailure(FailureInvalidArgument, "operation ID is invalid", RetryNever)
	}
	response, err := client.do(ctx, http.MethodGet, operationsRouteV1+"/"+url.PathEscape(string(id)), nil)
	if err != nil {
		return Operation{}, err
	}
	operation, err := decodeOperationResponseV1(response)
	if err != nil || operation.Ref.ID != id {
		return Operation{}, newFailure(FailureUnavailable, "sandbox operation response is invalid", RetryAfterReconcile)
	}
	return operation, nil
}
func (client *httpControlClient) WaitOperation(ctx context.Context, id OperationID) (Operation, error) {
	if !validOperationID(id) {
		return Operation{}, newFailure(FailureInvalidArgument, "operation ID is invalid", RetryNever)
	}
	response, err := client.do(ctx, http.MethodGet, operationsRouteV1+"/"+url.PathEscape(string(id))+"/wait", nil)
	if err != nil {
		return Operation{}, err
	}
	operation, err := decodeOperationResponseV1(response)
	if err != nil || operation.Ref.ID != id || !isTerminalOperation(operation.State) {
		return Operation{}, newFailure(FailureUnavailable, "sandbox wait response is invalid", RetryAfterReconcile)
	}
	return operation, nil
}
func (client *httpControlClient) WatchOperation(ctx context.Context, id OperationID, from OperationCursor) (OperationStream, error) {
	if !validOperationID(id) {
		return nil, newFailure(FailureInvalidArgument, "operation ID is invalid", RetryNever)
	}
	target := operationsRouteV1 + "/" + url.PathEscape(string(id)) + "/events"
	if from != "" {
		target += "?after=" + url.QueryEscape(string(from))
	}
	response, err := client.do(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	events, err := decodeOperationEventsV1(response)
	if err != nil {
		return nil, newFailure(FailureUnavailable, "sandbox operation events response is invalid", RetryAfterReconcile)
	}
	return &sliceOperationStream{events: events}, nil
}
func (client *httpControlClient) Capabilities(ctx context.Context) (CapabilitySnapshot, error) {
	response, err := client.do(ctx, http.MethodGet, capabilitiesRouteV1, nil)
	if err != nil {
		return CapabilitySnapshot{}, err
	}
	capabilities, err := decodeCapabilitiesResponseV1(response)
	if err != nil {
		return CapabilitySnapshot{}, newFailure(FailureUnavailable, "sandbox capabilities response is invalid", RetryAfterReconcile)
	}
	return capabilities, nil
}
func (client *httpControlClient) GetSandbox(context.Context, SandboxID) (SandboxInfo, error) {
	return SandboxInfo{}, newFailure(FailureUnavailable, "sandbox resource transport is not implemented", RetryAfterReconcile)
}
func (client *httpControlClient) GetProcess(ctx context.Context, id ProcessID) (ProcessInfo, error) {
	if !validProcessID(id) {
		return ProcessInfo{}, newFailure(FailureInvalidArgument, "sandbox process ID is invalid", RetryNever)
	}
	response, err := client.do(ctx, http.MethodGet, processesRouteV1+url.PathEscape(string(id)), nil)
	if err != nil {
		return ProcessInfo{}, err
	}
	process, err := decodeProcessResponseV1(response)
	if err != nil || process.ID != id {
		return ProcessInfo{}, newFailure(FailureUnavailable, "sandbox process response is invalid", RetryAfterReconcile)
	}
	return process, nil
}
func (client *httpControlClient) ReplayOutput(ctx context.Context, id ProcessID, from OutputCursor) (OutputStream, error) {
	if id == "" || len(id) > 128 {
		return nil, newFailure(FailureInvalidArgument, "sandbox process ID is invalid", RetryNever)
	}
	target := processesRouteV1 + url.PathEscape(string(id)) + "/output"
	if from != "" {
		target += "?after=" + url.QueryEscape(string(from))
	}
	response, err := client.do(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	events, err := decodeOutputEventsV1(response)
	if err != nil {
		return nil, newFailure(FailureUnavailable, "sandbox output response is invalid", RetryAfterReconcile)
	}
	// The server applies `after` against its durable window; applying it again
	// would reject a valid resumed page because that cursor is intentionally not
	// included in the response.
	return newSliceOutputStream(events, "")
}
func (client *httpControlClient) GetVolume(ctx context.Context, id VolumeID) (VolumeInfo, error) {
	if !validVolumeID(id) {
		return VolumeInfo{}, newFailure(FailureInvalidArgument, "sandbox volume ID is invalid", RetryNever)
	}
	response, err := client.do(ctx, http.MethodGet, volumesRouteV1+"/"+url.PathEscape(string(id)), nil)
	if err != nil {
		return VolumeInfo{}, err
	}
	volume, err := decodeVolumeResponseV1(response)
	if err != nil || volume.ID != id {
		return VolumeInfo{}, newFailure(FailureUnavailable, "sandbox volume response is invalid", RetryAfterReconcile)
	}
	return volume, nil
}
func (client *httpControlClient) ListVolumes(ctx context.Context, page Page) (VolumePage, error) {
	if page.Limit == 0 || page.Limit > 100 || (page.Cursor != "" && !validVolumeID(VolumeID(page.Cursor))) {
		return VolumePage{}, newFailure(FailureInvalidArgument, "sandbox volume page is invalid", RetryNever)
	}
	target := volumesRouteV1 + "?limit=" + strconv.FormatUint(uint64(page.Limit), 10)
	if page.Cursor != "" {
		target += "&after=" + url.QueryEscape(string(page.Cursor))
	}
	response, err := client.do(ctx, http.MethodGet, target, nil)
	if err != nil {
		return VolumePage{}, err
	}
	return decodeVolumePageResponseV1(response)
}
func (client *httpControlClient) GetSnapshot(context.Context, SnapshotID) (SnapshotInfo, error) {
	return SnapshotInfo{}, newFailure(FailureUnavailable, "sandbox resource transport is not implemented", RetryAfterReconcile)
}
func (client *httpControlClient) ListSnapshots(context.Context, Page) (SnapshotPage, error) {
	return SnapshotPage{}, newFailure(FailureUnavailable, "sandbox resource transport is not implemented", RetryAfterReconcile)
}

func (client *httpControlClient) do(ctx context.Context, method, targetPath string, body []byte) ([]byte, error) {
	if err := contextFailure(ctx); err != nil {
		return nil, err
	}
	client.mu.Lock()
	if client.closed {
		client.mu.Unlock()
		return nil, closedClientFailure()
	}
	assertion := client.assertion
	expiresAt := client.expiresAt
	client.inFlight++
	lifetime := client.lifetime
	client.mu.Unlock()
	defer client.finishAttempt()
	if assertion == "" || !expiresAt.After(time.Now().UTC()) {
		return nil, newFailure(FailureNotFoundOrDenied, "sandbox client binding is expired", RetryNever)
	}
	requestCtx, cancel := context.WithTimeout(ctx, client.requestTimeout)
	defer cancel()
	stopLifetimeCancellation := context.AfterFunc(lifetime, cancel)
	defer stopLifetimeCancellation()
	authorization, err := applyAuthorization(requestCtx, client.credentials)
	if err != nil {
		return nil, err
	}
	target := client.endpoint.ResolveReference(&url.URL{Path: targetPath})
	if parsed, err := url.Parse(targetPath); err == nil {
		target.RawQuery = parsed.RawQuery
		target.Path = parsed.Path
	}
	request, err := http.NewRequestWithContext(requestCtx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, newFailure(FailureUnavailable, "sandbox control request could not be created", RetryAfterReconcile)
	}
	request.Header.Set("Authorization", authorization)
	request.Header.Set(bindingHeaderV1, assertion)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.client.Do(request)
	request.Header.Del("Authorization")
	request.Header.Del(bindingHeaderV1)
	if err != nil {
		if contextErr := contextFailure(requestCtx); contextErr != nil {
			return nil, contextErr
		}
		return nil, newFailure(FailureUnavailable, "sandbox control request failed", RetryAfterReconcile)
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maxControlV1Bytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(data) > maxControlV1Bytes {
		return nil, newFailure(FailureUnavailable, "sandbox control response exceeded its finite limit", RetryAfterReconcile)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		failure, decodeErr := decodeFailureResponseV1(data)
		if decodeErr != nil {
			return nil, newFailure(FailureUnavailable, "sandbox control failure response is invalid", RetryAfterReconcile)
		}
		return nil, &Error{failure: failure}
	}
	return data, nil
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
		client.cancelLifetime()
		client.transport.CloseIdleConnections()
		if client.inFlight == 0 {
			client.drainedOnce.Do(func() { close(client.drained) })
		}
	}
	drained := client.drained
	client.mu.Unlock()
	select {
	case <-drained:
		return nil
	case <-ctx.Done():
		return contextFailure(ctx)
	}

	// The return above is deliberately the only successful close path: Close
	// publishes no state until every started request has observed cancellation.
}

func (client *httpControlClient) finishAttempt() {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.inFlight--
	if client.closed && client.inFlight == 0 {
		client.drainedOnce.Do(func() { close(client.drained) })
	}
}

var _ Client = (*httpControlClient)(nil)
