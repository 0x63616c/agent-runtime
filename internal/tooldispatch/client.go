package tooldispatch

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// ErrTransientUnavailable marks the narrow set of transport failures that can
// occur while the broker Service is being brought up. It deliberately does
// not cover a non-success HTTP response: authentication, authorization, and
// protocol failures must remain fatal to the trigger role.
var ErrTransientUnavailable = errors.New("tool dispatch temporarily unavailable")

// Client is the trigger-only RoleTool authority. It has no execution request
// fields and cannot select a tenant, operation, or recovery mode.
type Client struct {
	endpoint string
	token    string
	http     *http.Client
}

// NewTrustedClient creates the production trigger client from one mounted CA
// bundle. RoleTool cannot substitute ambient roots or skip hostname checks.
func NewTrustedClient(endpoint, token, serverName, trustPath string) (*Client, error) {
	if serverName == "" || trustPath == "" {
		return nil, errors.New("create trusted tool dispatch client: declared trust is required")
	}
	pem, err := os.ReadFile(trustPath)
	if err != nil || len(pem) == 0 {
		return nil, errors.New("create trusted tool dispatch client: declared trust is unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("create trusted tool dispatch client: declared trust is invalid")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: roots}}
	return NewClient(endpoint, token, &http.Client{Transport: transport, Timeout: 20 * time.Second})
}

func NewClient(endpoint, token string, client *http.Client) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u == nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || token == "" {
		return nil, errors.New("create tool dispatch client: endpoint and token are required")
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &Client{endpoint: strings.TrimRight(endpoint, "/") + "/private/v1/tool-dispatch/scan", token: token, http: client}, nil
}

func (client *Client) DispatchOnce(ctx context.Context) (Receipt, error) {
	if client == nil || client.http == nil {
		return Receipt{}, errors.New("dispatch tool work: client is not configured")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint, bytes.NewReader(nil))
	if err != nil {
		return Receipt{}, errors.New("dispatch tool work: create request")
	}
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("X-Tool-Dispatch-Audience", Audience)
	request.Header.Set("X-Tool-Dispatch-Role", Role)
	response, err := client.http.Do(request)
	if err != nil {
		if transientTransportFailure(err) {
			return Receipt{}, fmt.Errorf("dispatch tool work: %w", ErrTransientUnavailable)
		}
		return Receipt{}, errors.New("dispatch tool work: unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return Receipt{}, errors.New("dispatch tool work: unavailable")
	}
	var receipt Receipt
	decoder := json.NewDecoder(http.MaxBytesReader(nil, response.Body, 128))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || decoder.Decode(new(any)) == nil || !receipt.Attempted {
		return Receipt{}, errors.New("dispatch tool work: invalid receipt")
	}
	return receipt, nil
}

func transientTransportFailure(err error) bool {
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return true
	}
	var operationError *net.OpError
	if !errors.As(err, &operationError) {
		return false
	}
	return errors.Is(operationError.Err, syscall.ECONNREFUSED) ||
		errors.Is(operationError.Err, syscall.ECONNRESET) ||
		errors.Is(operationError.Err, syscall.EHOSTUNREACH) ||
		errors.Is(operationError.Err, syscall.ENETUNREACH)
}
