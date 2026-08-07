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
	coordinator := &retentionCoordinatorFake{objects: []BlobObject{
		{Key: oldReferenced, CreatedAt: now.Add(-48 * time.Hour)},
		{Key: oldEligible, CreatedAt: now.Add(-48 * time.Hour)},
		{Key: young, CreatedAt: now.Add(-time.Hour)},
	}, eligible: map[BlobKey]bool{oldEligible: true}}
	collector, err := NewGarbageCollector(coordinator, "tenant", 24*time.Hour)
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
	if len(coordinator.deleted) != 1 || coordinator.deleted[0] != oldEligible {
		t.Fatalf("coordinator deleted = %v, want only eligible old blob", coordinator.deleted)
	}
}

func TestGarbageCollectorTreatsConcurrentFenceAndDeleteAsOneSafeOutcome(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	key := BlobKey("tenant/temporal-payload/v1/sha256/eligible")
	coordinator := &concurrentRetentionCoordinator{object: BlobObject{Key: key, CreatedAt: now.Add(-48 * time.Hour)}}
	collector, err := NewGarbageCollector(coordinator, "tenant", 24*time.Hour)
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
	if got := coordinator.deleteCount(); got != 1 {
		t.Fatalf("successful deletions = %d, want 1", got)
	}
}

func TestGarbageCollectorDoesNotDeleteWhenAReferenceIsCreatedAfterListing(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	key := BlobKey("tenant/temporal-payload/v1/sha256/reference-race")
	coordinator := &referenceRaceCoordinator{
		object:       BlobObject{Key: key, CreatedAt: now.Add(-48 * time.Hour)},
		listed:       make(chan struct{}),
		continueList: make(chan struct{}),
	}
	collector, err := NewGarbageCollector(coordinator, "tenant", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewGarbageCollector() error = %v", err)
	}

	result := make(chan error, 1)
	go func() {
		_, collectErr := collector.Collect(context.Background(), now)
		result <- collectErr
	}()
	<-coordinator.listed
	coordinator.CreateAuthoritativeReference(key)
	close(coordinator.continueList)
	if collectErr := <-result; collectErr != nil {
		t.Fatalf("Collect() error = %v", collectErr)
	}
	if coordinator.wasDeleted() {
		t.Fatal("collector deleted a blob after an authoritative reference was created")
	}
}

type retentionCoordinatorFake struct {
	objects  []BlobObject
	eligible map[BlobKey]bool
	deleted  []BlobKey
}

func (coordinator *retentionCoordinatorFake) List(context.Context, string) ([]BlobObject, error) {
	return append([]BlobObject(nil), coordinator.objects...), nil
}

func (coordinator *retentionCoordinatorFake) FenceAndDeleteUnreferenced(_ context.Context, key BlobKey, _ time.Time, _ time.Time) (bool, error) {
	if !coordinator.eligible[key] {
		return false, nil
	}
	coordinator.deleted = append(coordinator.deleted, key)
	return true, nil
}

type concurrentRetentionCoordinator struct {
	mu      sync.Mutex
	object  BlobObject
	deleted bool
}

func (coordinator *concurrentRetentionCoordinator) List(context.Context, string) ([]BlobObject, error) {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	return []BlobObject{coordinator.object}, nil
}

func (coordinator *concurrentRetentionCoordinator) FenceAndDeleteUnreferenced(_ context.Context, key BlobKey, createdAt time.Time, _ time.Time) (bool, error) {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.deleted || key != coordinator.object.Key || !createdAt.Equal(coordinator.object.CreatedAt) {
		return false, nil
	}
	coordinator.deleted = true
	return true, nil
}

func (coordinator *concurrentRetentionCoordinator) deleteCount() int {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.deleted {
		return 1
	}
	return 0
}

type referenceRaceCoordinator struct {
	mu           sync.Mutex
	object       BlobObject
	refs         map[BlobKey]bool
	deleted      bool
	listed       chan struct{}
	continueList chan struct{}
}

func (coordinator *referenceRaceCoordinator) List(context.Context, string) ([]BlobObject, error) {
	close(coordinator.listed)
	<-coordinator.continueList
	return []BlobObject{coordinator.object}, nil
}

func (coordinator *referenceRaceCoordinator) CreateAuthoritativeReference(key BlobKey) {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.refs == nil {
		coordinator.refs = make(map[BlobKey]bool)
	}
	coordinator.refs[key] = true
}

func (coordinator *referenceRaceCoordinator) FenceAndDeleteUnreferenced(_ context.Context, key BlobKey, createdAt time.Time, _ time.Time) (bool, error) {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.refs[key] || key != coordinator.object.Key || !createdAt.Equal(coordinator.object.CreatedAt) {
		return false, nil
	}
	coordinator.deleted = true
	return true, nil
}

func (coordinator *referenceRaceCoordinator) wasDeleted() bool {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	return coordinator.deleted
}
