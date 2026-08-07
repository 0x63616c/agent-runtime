package milestone

import (
	"context"
	"sync"

	"github.com/cockroachdb/errors"
)

// MemoryStore is a deterministic in-memory EvidenceStore for focused tests.
type MemoryStore struct {
	mu      sync.Mutex
	records map[MilestoneID]Record
	events  []string
}

// NewMemoryStore creates an empty MemoryStore.
func NewMemoryStore() *MemoryStore { return &MemoryStore{records: map[MilestoneID]Record{}} }

// Retain stores a pending record unless the context is cancelled.
func (store *MemoryStore) Retain(ctx context.Context, record Record) error {
	if err := ctx.Err(); err != nil {
		return errors.Wrap(err, "retain in-memory milestone evidence")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.Report.Milestone
	if _, exists := store.records[key]; exists {
		return errors.New("retain in-memory milestone evidence: record already exists")
	}
	store.records[key] = record
	store.events = append(store.events, "retained:"+string(key))
	return nil
}

// Lookup returns retained evidence unless the context is cancelled.
func (store *MemoryStore) Lookup(ctx context.Context, key MilestoneID) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, errors.Wrap(err, "lookup in-memory milestone evidence")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[key]
	if !exists {
		return Record{}, errors.New("lookup in-memory milestone evidence: record not found")
	}
	return record, nil
}

// MarkFailed records a safe failure unless the context is cancelled.
func (store *MemoryStore) MarkFailed(ctx context.Context, key MilestoneID, code FailureCode) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, errors.Wrap(err, "mark in-memory milestone delivery failed")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[key]
	if !exists {
		return Record{}, errors.New("mark in-memory milestone delivery failed: record not found")
	}
	record.Delivery = DeliveryFailed
	record.Failure = code
	record.Attempts++
	store.records[key] = record
	store.events = append(store.events, "failed:"+string(key))
	return record, nil
}

// MarkSent records success unless the context is cancelled.
func (store *MemoryStore) MarkSent(ctx context.Context, key MilestoneID) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, errors.Wrap(err, "mark in-memory milestone delivery sent")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[key]
	if !exists {
		return Record{}, errors.New("mark in-memory milestone delivery sent: record not found")
	}
	record.Delivery = DeliverySent
	record.Failure = ""
	record.Attempts++
	store.records[key] = record
	store.events = append(store.events, "sent:"+string(key))
	return record, nil
}

// Events returns the retained transition ordering.
func (store *MemoryStore) Events() []string {
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]string(nil), store.events...)
}

// FakeNotifier is a deterministic typed notifier adapter for S12 tests.
type FakeNotifier struct {
	mu         sync.Mutex
	failures   []error
	deliveries []Notification
}

// NewFakeNotifier creates a FakeNotifier that consumes failures in order.
func NewFakeNotifier(failures ...error) *FakeNotifier {
	return &FakeNotifier{failures: append([]error(nil), failures...)}
}

// Deliver records a notification and returns the next configured failure.
func (notifier *FakeNotifier) Deliver(ctx context.Context, notification Notification) error {
	if err := ctx.Err(); err != nil {
		return errors.Wrap(err, "deliver fake notification")
	}
	notifier.mu.Lock()
	defer notifier.mu.Unlock()
	notifier.deliveries = append(notifier.deliveries, notification)
	if len(notifier.failures) == 0 {
		return nil
	}
	err := notifier.failures[0]
	notifier.failures = notifier.failures[1:]
	return err
}

// SetFailures replaces the deterministic failure sequence.
func (notifier *FakeNotifier) SetFailures(failures ...error) {
	notifier.mu.Lock()
	defer notifier.mu.Unlock()
	notifier.failures = append([]error(nil), failures...)
}

// Deliveries returns attempted notifications in order.
func (notifier *FakeNotifier) Deliveries() []Notification {
	notifier.mu.Lock()
	defer notifier.mu.Unlock()
	return append([]Notification(nil), notifier.deliveries...)
}
