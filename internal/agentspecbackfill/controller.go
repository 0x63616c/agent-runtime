package agentspecbackfill

import (
	"context"
	"time"

	"github.com/cockroachdb/errors"
)

var (
	// ErrArchiveConflict reports an existing request-keyed archive whose observed canonical digest differs.
	ErrArchiveConflict = errors.New("agent spec backfill archive conflict")
)

// TerminalStatusStore atomically reads and conditionally records one request's terminal Status.
type TerminalStatusStore interface {
	ReadTerminal(context.Context, Request) (Status, bool, error)
	CreateTerminal(context.Context, Request, Status) (stored Status, created bool, err error)
}

// ArchiveWrite reports the immutable canonical digest observed after one conditional archive write.
type ArchiveWrite struct {
	Created         bool
	CanonicalDigest string
}

// ConditionalArchive conditionally retains one immutable request-keyed ArchiveBundle without overwriting it.
// It must verify and return the expected canonical digest when the object already exists.
type ConditionalArchive interface {
	PutIfAbsent(context.Context, ArchiveBundle, string) (ArchiveWrite, error)
}

// Reconciler coordinates one pure Agent-spec-backfill verification pass through terminal-status and archive ports.
type Reconciler struct {
	statuses TerminalStatusStore
	archives ConditionalArchive
}

// NewReconciler constructs a Reconciler with the required narrow durable ports.
func NewReconciler(statuses TerminalStatusStore, archives ConditionalArchive) (*Reconciler, error) {
	if statuses == nil || archives == nil {
		return nil, errors.New("backfill terminal status store and archive are required")
	}
	return &Reconciler{statuses: statuses, archives: archives}, nil
}

// Reconcile verifies one immutable request, persists only its terminal winner, and conditionally archives it.
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
		return reconciler.archive(ctx, request, stored, now)
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
	return reconciler.archive(ctx, request, stored, now)
}

func (reconciler *Reconciler) archive(ctx context.Context, request Request, status Status, now time.Time) (Status, error) {
	if err := status.ValidateFor(request, now); err != nil {
		return Status{}, errors.Wrap(err, "validate stored terminal backfill status")
	}
	bundle, err := NewArchiveBundle(request, status, Audit{Code: auditCode(status)}, nil)
	if err != nil {
		return Status{}, errors.Wrap(err, "construct terminal backfill archive")
	}
	if err := ctx.Err(); err != nil {
		return Status{}, errors.Wrap(err, "conditionally archive terminal backfill status")
	}
	digest, err := bundle.Digest()
	if err != nil {
		return Status{}, errors.Wrap(err, "digest terminal backfill archive")
	}
	write, err := reconciler.archives.PutIfAbsent(ctx, bundle, digest)
	if err != nil {
		return Status{}, errors.Wrap(err, "conditionally archive terminal backfill status")
	}
	if write.CanonicalDigest != digest {
		return Status{}, errors.Wrap(ErrArchiveConflict, "conditionally archive terminal backfill status")
	}
	if err := ctx.Err(); err != nil {
		return Status{}, errors.Wrap(err, "conditionally archive terminal backfill status")
	}
	return status, nil
}

func auditCode(status Status) string {
	if status.Phase == PhaseVerified {
		return "verified"
	}
	return string(status.Reason)
}
