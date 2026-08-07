package sandbox

import (
	"context"
	"sync"
)

const maxTrustBundleBytes = 1 << 20

// StaticTrustBundleSource is a finite immutable trust adapter for callers that already own PEM roots.
type StaticTrustBundleSource struct {
	mu      sync.RWMutex
	bundles map[TrustBundleRef]TrustBundle
}

// NewStaticTrustBundleSource freezes a bounded set of named public trust roots.
func NewStaticTrustBundleSource(bundles map[TrustBundleRef]TrustBundle) (*StaticTrustBundleSource, error) {
	if len(bundles) == 0 || len(bundles) > 64 {
		return nil, newFailure(FailureInvalidArgument, "sandbox trust bundles must be finite and non-empty", RetryNever)
	}
	frozen := make(map[TrustBundleRef]TrustBundle, len(bundles))
	for reference, bundle := range bundles {
		if reference == "" || bundle.Version == "" || len(bundle.PEMRoots) == 0 || len(bundle.PEMRoots) > maxTrustBundleBytes {
			return nil, newFailure(FailureInvalidArgument, "sandbox trust bundle is invalid", RetryNever)
		}
		bundle.PEMRoots = append([]byte(nil), bundle.PEMRoots...)
		frozen[reference] = bundle
	}
	return &StaticTrustBundleSource{bundles: frozen}, nil
}

// ResolveTrustBundle returns a defensive trust snapshot selected by its opaque declared reference.
func (source *StaticTrustBundleSource) ResolveTrustBundle(ctx context.Context, reference TrustBundleRef) (TrustBundle, error) {
	if err := contextFailure(ctx); err != nil {
		return TrustBundle{}, err
	}
	if source == nil {
		return TrustBundle{}, newFailure(FailureUnavailable, "sandbox trust bundle source is unavailable", RetryAfterReconcile)
	}
	source.mu.RLock()
	bundle, found := source.bundles[reference]
	source.mu.RUnlock()
	if !found {
		return TrustBundle{}, newFailure(FailureUnavailable, "sandbox trust bundle is unavailable", RetryAfterReconcile)
	}
	bundle.PEMRoots = append([]byte(nil), bundle.PEMRoots...)
	return bundle, nil
}

var _ TrustBundleSource = (*StaticTrustBundleSource)(nil)
