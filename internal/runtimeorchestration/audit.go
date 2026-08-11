package runtimeorchestration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/0x63616c/agent-runtime/internal/runtimestate"
)

// AuditExporter delivers one already-committed redacted audit fact. It has no
// authority to create or alter runtime state; publisher acknowledgement is the
// durable record of a successful delivery attempt.
type AuditExporter interface {
	Export(context.Context, runtimestate.AuditFactRecord) error
}

// HTTPAuditExporter sends committed audit facts to one explicit HTTP(S) sink.
// A non-success response is returned to the outbox publisher for lease-based
// at-least-once recovery; it is never treated as a committed export.
type HTTPAuditExporter struct {
	endpoint string
	client   *http.Client
}

// NewHTTPAuditExporter constructs an explicit audit-delivery adapter.
func NewHTTPAuditExporter(endpoint string, client *http.Client) (*HTTPAuditExporter, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || client == nil {
		return nil, errors.New("create HTTP audit exporter: explicit HTTP(S) endpoint and client are required")
	}
	return &HTTPAuditExporter{endpoint: endpoint, client: client}, nil
}

// Export posts exactly one bounded redacted audit fact to the configured sink.
func (exporter *HTTPAuditExporter) Export(ctx context.Context, fact runtimestate.AuditFactRecord) error {
	if exporter == nil || exporter.client == nil || exporter.endpoint == "" || fact.Tenant == "" || fact.AuditFactID == "" || fact.OperationID == "" || fact.Kind == "" || fact.OccurredAt.IsZero() || fact.RetentionUntil.IsZero() {
		return errors.New("export HTTP audit fact: complete committed fact and exporter are required")
	}
	body, err := json.Marshal(fact)
	if err != nil {
		return fmt.Errorf("encode HTTP audit fact: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, exporter.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create HTTP audit export request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := exporter.client.Do(request)
	if err != nil {
		return fmt.Errorf("send HTTP audit fact: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("send HTTP audit fact: sink returned %s", response.Status)
	}
	return nil
}
