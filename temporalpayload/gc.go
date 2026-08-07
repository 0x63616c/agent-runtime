package temporalpayload

import (
	"context"
	"time"

	"github.com/cockroachdb/errors"
)

// BlobObject is immutable blob metadata exposed only to an explicit retention worker.
type BlobObject struct {
	Key       BlobKey
	CreatedAt time.Time
}

// RetentionCoordinator owns both the authoritative reference fence and deletion protocol.
//
// FenceAndDeleteUnreferenced must atomically fence new authoritative reference
// creation, prove that the object has no authoritative reference, and condition
// deletion on the listed object creation identity. When an external object
// store cannot be deleted under that durable fence, it returns deleted=false
// and leaves a durable tombstone/reconciliation record rather than guessing.
// Codec deliberately does not implement or receive this interface.
type RetentionCoordinator interface {
	List(context.Context, string) ([]BlobObject, error)
	FenceAndDeleteUnreferenced(context.Context, BlobKey, time.Time, time.Time) (deleted bool, err error)
}

// GarbageCollector computes and applies only explicitly authorized, age-bounded deletion.
type GarbageCollector struct {
	coordinator RetentionCoordinator
	prefix      string
	minimumAge  time.Duration
}

// NewGarbageCollector creates the retention-only deletion coordinator.
func NewGarbageCollector(coordinator RetentionCoordinator, prefix string, minimumAge time.Duration) (*GarbageCollector, error) {
	if coordinator == nil {
		return nil, errors.New("temporal payload retention coordinator is required")
	}
	validatedPrefix, err := validateBlobPrefix(prefix)
	if err != nil {
		return nil, err
	}
	if minimumAge <= 0 {
		return nil, errors.New("temporal payload retention minimum age must be positive")
	}
	return &GarbageCollector{coordinator: coordinator, prefix: validatedPrefix, minimumAge: minimumAge}, nil
}

// Collect deletes only objects older than the supplied evaluation time minus the configured minimum age through RetentionCoordinator.
func (collector *GarbageCollector) Collect(ctx context.Context, evaluatedAt time.Time) ([]BlobKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "collect temporal payload blobs")
	}
	if evaluatedAt.Location() != time.UTC {
		return nil, errors.New("temporal payload retention evaluation time must be UTC")
	}
	objects, err := collector.coordinator.List(ctx, collector.prefix)
	if err != nil {
		return nil, errors.Wrap(err, "list temporal payload retention candidates")
	}
	cutoff := evaluatedAt.Add(-collector.minimumAge)
	deleted := make([]BlobKey, 0, len(objects))
	for _, object := range objects {
		if object.CreatedAt.Location() != time.UTC {
			return deleted, errors.Newf("temporal payload retention object %q creation time must be UTC", object.Key)
		}
		if object.CreatedAt.After(cutoff) {
			continue
		}
		wasDeleted, err := collector.coordinator.FenceAndDeleteUnreferenced(ctx, object.Key, object.CreatedAt, evaluatedAt)
		if err != nil {
			return deleted, errors.Wrapf(err, "fence and delete temporal payload blob %q", object.Key)
		}
		if wasDeleted {
			deleted = append(deleted, object.Key)
		}
	}
	return deleted, nil
}
