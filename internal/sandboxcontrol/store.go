// Package sandboxcontrol owns durable sandbox control persistence seams.
package sandboxcontrol

import (
	"context"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
)

// ErrConflict reports a principal-scoped operation ID reused with different immutable input.
var ErrConflict = errors.New("sandbox control operation conflict")

// AcceptedOperation is the durable acceptance record before dispatch.
type AcceptedOperation struct {
	Principal  string
	ID         string
	Digest     string
	AcceptedAt time.Time
	State      string
}

// Store persists principal-scoped accepted operations.
type Store interface {
	Accept(context.Context, AcceptedOperation) (AcceptedOperation, bool, error)
}

// MemoryStore is a deterministic Store used only for hermetic control tests.
type MemoryStore struct {
	mu         sync.Mutex
	operations map[string]AcceptedOperation
}

// NewMemoryStore constructs an empty deterministic Store.
func NewMemoryStore() *MemoryStore { return &MemoryStore{operations: map[string]AcceptedOperation{}} }

// Accept atomically accepts an operation or returns its prior matching record.
func (store *MemoryStore) Accept(ctx context.Context, operation AcceptedOperation) (AcceptedOperation, bool, error) {
	if err := ctx.Err(); err != nil {
		return AcceptedOperation{}, false, err
	}
	if operation.Principal == "" || operation.ID == "" || operation.Digest == "" || operation.AcceptedAt.IsZero() || operation.State != "accepted" {
		return AcceptedOperation{}, false, errors.New("invalid accepted operation")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := operation.Principal + "\x00" + operation.ID
	if prior, ok := store.operations[key]; ok {
		if prior.Digest != operation.Digest {
			return AcceptedOperation{}, false, ErrConflict
		}
		return prior, true, nil
	}
	store.operations[key] = operation
	return operation, false, nil
}
