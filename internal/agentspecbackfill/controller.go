package agentspecbackfill

import (
	"context"
	"time"

	"github.com/cockroachdb/errors"
)

// TerminalStatusStore atomically reads and conditionally records one request's terminal Status.
type TerminalStatusStore interface {
	ReadTerminal(context.Context, Request) (Status, bool, error)
	CreateTerminal(context.Context, Request, Status) (stored Status, created bool, err error)
}

// Reconciler coordinates one pure Agent-spec-backfill verification pass through the terminal-status port.
type Reconciler struct {
	statuses TerminalStatusStore
}

// NewReconciler constructs a Reconciler with its required terminal-status port.
func NewReconciler(statuses TerminalStatusStore) (*Reconciler, error) {
	if statuses == nil {
		return nil, errors.New("backfill terminal status store is required")
	}
	return &Reconciler{statuses: statuses}, nil
}

// Reconcile verifies one immutable request and persists only its terminal winner.
func (reconciler *Reconciler) Reconcile(ctx context.Context, request Request, reader FrozenLegacyReader, verifier ImmutableContentVerifier, now time.Time) (Status, error) {
	if err := ctx.Err(); err != nil {
		return Status{}, errors.Wrap(err, "reconcile backfill request")
	}
	stored, found, err := reconciler.statuses.ReadTerminal(ctx, request)
	if err != nil {
		return Status{}, errors.Wrap(err, "read terminal backfill status")
	}
	if err := ctx.Err(); err != nil {
		return Status{}, errors.Wrap(err, "read terminal backfill status")
	}
	if found {
		return reconciler.validateTerminal(request, stored, now)
	}

	candidate, err := Verify(ctx, request, reader, verifier, now)
	if err != nil {
		return Status{}, errors.Wrap(err, "verify backfill request")
	}
	if err := ctx.Err(); err != nil {
		return Status{}, errors.Wrap(err, "verify backfill request")
	}
	stored, _, err = reconciler.statuses.CreateTerminal(ctx, request, candidate)
	if err != nil {
		return Status{}, errors.Wrap(err, "record terminal backfill status")
	}
	if err := ctx.Err(); err != nil {
		return Status{}, errors.Wrap(err, "record terminal backfill status")
	}
	return reconciler.validateTerminal(request, stored, now)
}

func (reconciler *Reconciler) validateTerminal(request Request, status Status, now time.Time) (Status, error) {
	if err := status.ValidateFor(request, now); err != nil {
		return Status{}, errors.Wrap(err, "validate stored terminal backfill status")
	}
	return status, nil
}
