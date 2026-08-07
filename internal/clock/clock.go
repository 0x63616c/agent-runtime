// Package clock provides explicit time sources for deterministic runtime decisions.
package clock

import (
	"sync"
	"time"

	"github.com/cockroachdb/errors"
)

// Clock supplies UTC wall-clock instants to a consumer.
type Clock interface {
	// Now returns the current UTC instant.
	Now() time.Time
}

// Fake is a concurrency-safe Clock whose time advances only when requested.
type Fake struct {
	mu  sync.RWMutex
	now time.Time
}

// NewFake creates a Fake at start, normalized to UTC.
func NewFake(start time.Time) (*Fake, error) {
	if start.IsZero() {
		return nil, errors.New("fake clock start time is required")
	}
	return &Fake{now: start.UTC()}, nil
}

// Now returns the fake clock's current UTC instant.
func (f *Fake) Now() time.Time {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.now
}

// Advance moves the fake clock forward by delta without waiting.
func (f *Fake) Advance(delta time.Duration) error {
	if delta < 0 {
		return errors.New("fake clock cannot move backwards")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(delta)
	return nil
}
