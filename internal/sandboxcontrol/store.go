// Package sandboxcontrol owns durable sandbox control persistence seams.
package sandboxcontrol

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrConflict = errors.New("sandbox control operation conflict")

type AcceptedOperation struct {
	Principal  string
	ID         string
	Digest     string
	AcceptedAt time.Time
	State      string
}
type Store interface {
	Accept(context.Context, AcceptedOperation) (AcceptedOperation, bool, error)
}
type MemoryStore struct {
	mu         sync.Mutex
	operations map[string]AcceptedOperation
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{operations: map[string]AcceptedOperation{}} }
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
