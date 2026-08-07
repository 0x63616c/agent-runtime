package temporalpayload

import (
	"context"
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
