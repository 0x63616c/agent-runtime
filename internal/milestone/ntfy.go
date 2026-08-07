package milestone

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimeconfig"
	"github.com/cockroachdb/errors"
)

// HTTPClient is the injected HTTP boundary used by NtfyNotifier.
type HTTPClient interface {
	// Do submits an HTTP request and returns the provider response.
	Do(*http.Request) (*http.Response, error)
}

// NtfyNotifier posts exact status reports only to the configured ntfy topic.
type NtfyNotifier struct {
	client        HTTPClient
	authorization string
}

// NewNtfyNotifier creates a notifier with an explicit HTTP transport.
func NewNtfyNotifier(client HTTPClient) (*NtfyNotifier, error) {
	if client == nil {
		return nil, errors.New("create ntfy notifier: HTTP client is required")
	}
	return &NtfyNotifier{client: client}, nil
}

// SetBearerToken accepts authorization only from validated operator configuration.
func (notifier *NtfyNotifier) SetBearerToken(token string) {
	notifier.authorization = token
}

// Deliver posts the exact seven-field report to the fixed ntfy topic.
func (notifier *NtfyNotifier) Deliver(ctx context.Context, notification Notification) error {
	if err := ctx.Err(); err != nil {
		return errors.Wrap(err, "deliver ntfy notification")
	}
	if notification.Topic != runtimeconfig.NtfyTopic {
		return errors.New("deliver ntfy notification: invalid notifier topic")
	}
	if err := validateTransportReport(notification.Report); err != nil {
		return errors.Wrap(err, "deliver ntfy notification")
	}
	payload, err := json.Marshal(notification.Report)
	if err != nil {
		return errors.Wrap(err, "encode ntfy notification")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, notification.Topic, bytes.NewReader(payload))
	if err != nil {
		return errors.Wrap(err, "create ntfy notification request")
	}
	request.Header.Set("Content-Type", "text/plain")
	request.Header.Set("X-Sequence-ID", sequenceID(notification.Report))
	if notifier.authorization != "" {
		request.Header.Set("Authorization", "Bearer "+notifier.authorization)
	}
	response, err := notifier.client.Do(request)
	if err != nil {
		return NewDeliveryFailure(FailureUnavailable)
	}
	if response == nil {
		return NewDeliveryFailure(FailureUnavailable)
	}
	if response.Body != nil {
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	}
	if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
		return nil
	}
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= http.StatusInternalServerError {
		return NewDeliveryFailure(FailureUnavailable)
	}
	return NewDeliveryFailure(FailureRejected)
}

func sequenceID(report Report) string {
	digest := sha256.Sum256([]byte(string(report.Milestone) + "\x00" + string(report.CommitOrRevision)))
	return fmt.Sprintf("milestone-%x", digest[:16])
}

func validateTransportReport(report Report) error {
	if !validText(string(report.Milestone)) || !validText(string(report.NextMilestone)) || !validReference(string(report.CommitOrRevision)) || report.UTCTime.IsZero() || report.UTCTime.Location() != time.UTC {
		return errors.New("invalid report identity")
	}
	if report.EstimatedOverallPercent < 0 || report.EstimatedOverallPercent > 100 {
		return errors.New("invalid report estimate")
	}
	switch report.Status {
	case StatusCompleted, StatusInProgress, StatusBlocked:
	default:
		return errors.New("invalid report status")
	}
	if len(report.EvidenceSummary) == 0 {
		return errors.New("report evidence summary is required")
	}
	for _, reference := range report.EvidenceSummary {
		switch reference.Kind {
		case EvidenceCompleted, EvidenceInProgress, EvidenceBlocked, EvidenceUncertainty:
		default:
			return errors.New("invalid report evidence kind")
		}
		if !validReference(string(reference.Reference)) {
			return errors.New("invalid report evidence reference")
		}
	}
	return nil
}
