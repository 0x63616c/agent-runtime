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

// RetentionStore is the separate destructive storage seam for explicit payload retention work.
//
// DeleteIfUnchanged must atomically refuse deletion when the object no longer
// has the listed creation identity. Codec deliberately does not implement or
// receive this interface.
type RetentionStore interface {
	List(context.Context, string) ([]BlobObject, error)
	DeleteIfUnchanged(context.Context, BlobKey, time.Time) error
}

// DeleteEligibility is the authoritative, transactionally coordinated reference-mark decision.
//
// An implementation normally queries the runtime's authoritative payload
// reference ledger under its retention lock. A cache, Temporal history scan, or
// eventually-consistent object-store listing is not a safe implementation.
type DeleteEligibility interface {
	CanDelete(context.Context, BlobKey, time.Time) (bool, error)
}

// GarbageCollector computes and applies only explicitly authorized, age-bounded deletion.
type GarbageCollector struct {
	store       RetentionStore
	eligibility DeleteEligibility
	prefix      string
	minimumAge  time.Duration
}

// NewGarbageCollector creates the retention-only deletion coordinator.
func NewGarbageCollector(store RetentionStore, eligibility DeleteEligibility, prefix string, minimumAge time.Duration) (*GarbageCollector, error) {
	if store == nil || eligibility == nil {
		return nil, errors.New("temporal payload retention store and delete eligibility authority are required")
	}
	validatedPrefix, err := validateBlobPrefix(prefix)
	if err != nil {
		return nil, err
	}
	if minimumAge <= 0 {
		return nil, errors.New("temporal payload retention minimum age must be positive")
	}
	return &GarbageCollector{store: store, eligibility: eligibility, prefix: validatedPrefix, minimumAge: minimumAge}, nil
}

// Collect deletes only objects older than the supplied evaluation time minus the configured minimum age and authorized by DeleteEligibility.
func (collector *GarbageCollector) Collect(ctx context.Context, evaluatedAt time.Time) ([]BlobKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "collect temporal payload blobs")
	}
	if evaluatedAt.Location() != time.UTC {
		return nil, errors.New("temporal payload retention evaluation time must be UTC")
	}
	objects, err := collector.store.List(ctx, collector.prefix)
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
		allowed, err := collector.eligibility.CanDelete(ctx, object.Key, evaluatedAt)
		if err != nil {
			return deleted, errors.Wrapf(err, "check temporal payload deletion eligibility for %q", object.Key)
		}
		if !allowed {
			continue
		}
		if err := collector.store.DeleteIfUnchanged(ctx, object.Key, object.CreatedAt); err != nil {
			if errors.Is(err, ErrBlobNotFound) {
				continue
			}
			return deleted, errors.Wrapf(err, "delete eligible temporal payload blob %q", object.Key)
		}
		deleted = append(deleted, object.Key)
	}
	return deleted, nil
}
