package temporalpayload

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestGarbageCollectorNeverDeletesReferencedOrYoungContent(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	oldReferenced := BlobKey("tenant/temporal-payload/v1/sha256/referenced")
	oldEligible := BlobKey("tenant/temporal-payload/v1/sha256/eligible")
	young := BlobKey("tenant/temporal-payload/v1/sha256/young")
	store := &retentionStoreFake{objects: []BlobObject{
		{Key: oldReferenced, CreatedAt: now.Add(-48 * time.Hour)},
		{Key: oldEligible, CreatedAt: now.Add(-48 * time.Hour)},
		{Key: young, CreatedAt: now.Add(-time.Hour)},
	}}
	collector, err := NewGarbageCollector(store, retentionAuthorityFake{allowed: map[BlobKey]bool{oldEligible: true}}, "tenant", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewGarbageCollector() error = %v", err)
	}
	deleted, err := collector.Collect(context.Background(), now)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(deleted) != 1 || deleted[0] != oldEligible {
		t.Fatalf("deleted = %v, want [%s]", deleted, oldEligible)
	}
	if len(store.deleted) != 1 || store.deleted[0] != oldEligible {
		t.Fatalf("store deleted = %v, want only eligible old blob", store.deleted)
	}
}

func TestGarbageCollectorTreatsConcurrentConditionalDeletionAsOneSafeOutcome(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	key := BlobKey("tenant/temporal-payload/v1/sha256/eligible")
	store := &concurrentRetentionStore{object: BlobObject{Key: key, CreatedAt: now.Add(-48 * time.Hour)}}
	collector, err := NewGarbageCollector(store, retentionAuthorityFake{allowed: map[BlobKey]bool{key: true}}, "tenant", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewGarbageCollector() error = %v", err)
	}

	errs := make(chan error, 2)
	for range 2 {
		go func() {
			_, collectErr := collector.Collect(context.Background(), now)
			errs <- collectErr
		}()
	}
	for range 2 {
		if collectErr := <-errs; collectErr != nil {
			t.Fatalf("Collect() error = %v", collectErr)
		}
	}
	if got := store.deleteCount(); got != 1 {
		t.Fatalf("successful deletions = %d, want 1", got)
	}
}

type retentionStoreFake struct {
	objects []BlobObject
	deleted []BlobKey
}

func (store *retentionStoreFake) List(context.Context, string) ([]BlobObject, error) {
	return append([]BlobObject(nil), store.objects...), nil
}

func (store *retentionStoreFake) DeleteIfUnchanged(_ context.Context, key BlobKey, _ time.Time) error {
	store.deleted = append(store.deleted, key)
	return nil
}

type retentionAuthorityFake struct{ allowed map[BlobKey]bool }

func (authority retentionAuthorityFake) CanDelete(_ context.Context, key BlobKey, _ time.Time) (bool, error) {
	return authority.allowed[key], nil
}

type concurrentRetentionStore struct {
	mu      sync.Mutex
	object  BlobObject
	deleted bool
}

func (store *concurrentRetentionStore) List(context.Context, string) ([]BlobObject, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return []BlobObject{store.object}, nil
}

func (store *concurrentRetentionStore) DeleteIfUnchanged(_ context.Context, key BlobKey, createdAt time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.deleted || key != store.object.Key || !createdAt.Equal(store.object.CreatedAt) {
		return ErrBlobNotFound
	}
	store.deleted = true
	return nil
}

func (store *concurrentRetentionStore) deleteCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.deleted {
		return 1
	}
	return 0
}
