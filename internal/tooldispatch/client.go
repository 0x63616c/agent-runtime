package tooldispatch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// Client is the trigger-only RoleTool authority. It has no execution request
// fields and cannot select a tenant, operation, or recovery mode.
type Client struct {
	endpoint string
	token    string
	http     *http.Client
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
