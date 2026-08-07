package milestone

import (
	"context"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimeconfig"
	"github.com/cockroachdb/errors"
)

// DeliveryFailure is the typed error a notifier may return for retained classification.
type DeliveryFailure struct{ code FailureCode }

// Error returns a safe classified message without provider error content.
func (failure DeliveryFailure) Error() string { return "notifier delivery " + string(failure.code) }

// NewDeliveryFailure creates a validated classified notifier failure.
func NewDeliveryFailure(code FailureCode) error {
	if code != FailureUnavailable {
		return errors.New("create notifier delivery failure: unsupported failure code")
	}
	return DeliveryFailure{code: code}
}

// EvidenceStore persists milestone evidence before a notifier attempt.
type EvidenceStore interface {
	// Retain stores a pending record before delivery.
	Retain(context.Context, Record) error
	// Lookup returns a previously retained record.
	Lookup(context.Context, MilestoneID) (Record, error)
	// MarkFailed records a classified retryable delivery failure.
	MarkFailed(context.Context, MilestoneID, FailureCode) (Record, error)
	// MarkSent records successful delivery.
	MarkSent(context.Context, MilestoneID) (Record, error)
}

// Notification binds a report to the configured allowlisted topic.
type Notification struct {
	// Topic is the fixed operator-configured ntfy endpoint.
	Topic string `json:"-"`
	// Report is the exact structured request body.
	Report Report `json:"-"`
}

// Notifier submits only a typed, fixed-topic report.
type Notifier interface {
	// Deliver submits one notification while honoring cancellation.
	Deliver(context.Context, Notification) error
}

// Service coordinates retained evidence and notifier delivery at seam S12.
type Service struct {
	config   runtimeconfig.NotifierConfig
	clock    clock.Clock
	store    EvidenceStore
	notifier Notifier
}

// NewService creates a Service from explicit configuration and dependencies.
func NewService(config runtimeconfig.NotifierConfig, source clock.Clock, store EvidenceStore, notifier Notifier) (*Service, error) {
	if config.Topic != runtimeconfig.NtfyTopic {
		return nil, errors.New("create milestone service: invalid notifier topic")
	}
	if source == nil || store == nil || notifier == nil {
		return nil, errors.New("create milestone service: clock, store, and notifier are required")
	}
	return &Service{config: config, clock: source, store: store, notifier: notifier}, nil
}

// Publish retains complete-catalog evidence before one notifier attempt.
func (service *Service) Publish(ctx context.Context, catalog Catalog, ledger Ledger, input ReportInput) (Record, error) {
	record, err := BuildRecord(catalog, ledger, input)
	if err != nil {
		return Record{}, errors.Wrap(err, "publish milestone status")
	}
	record.Report.UTCTime = service.clock.Now().UTC()
	if err := service.store.Retain(ctx, record); err != nil {
		return Record{}, errors.Wrap(err, "retain milestone evidence")
	}
	return service.deliver(ctx, record)
}

// Retry retries delivery only for retained failed evidence.
func (service *Service) Retry(ctx context.Context, milestone MilestoneID) (Record, error) {
	record, err := service.store.Lookup(ctx, milestone)
	if err != nil {
		return Record{}, errors.Wrap(err, "lookup milestone evidence for retry")
	}
	if record.Delivery != DeliveryFailed {
		return Record{}, errors.New("retry milestone delivery: record is not retryable")
	}
	return service.deliver(ctx, record)
}

func (service *Service) deliver(ctx context.Context, record Record) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, errors.Wrap(err, "deliver milestone status")
	}
	if err := service.notifier.Deliver(ctx, Notification{Topic: service.config.Topic, Report: record.Report}); err != nil {
		code := FailureUnclassified
		var typed DeliveryFailure
		if errors.As(err, &typed) {
			code = typed.code
		}
		failed, markErr := service.store.MarkFailed(ctx, record.Report.Milestone, code)
		if markErr != nil {
			return Record{}, errors.Wrap(markErr, "retain milestone delivery failure")
		}
		return failed, errors.Wrap(err, "deliver milestone status")
	}
	sent, err := service.store.MarkSent(ctx, record.Report.Milestone)
	if err != nil {
		return Record{}, errors.Wrap(err, "retain milestone delivery success")
	}
	return sent, nil
}
