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

// ArchiveReceipt reports the immutable canonical digest observed after one conditional archive write.
type ArchiveReceipt struct {
	Created         bool
	CanonicalDigest string
}

// ConditionalArchive conditionally retains one immutable request-keyed ArchiveBundle without overwriting it.
// It must verify and return the expected canonical digest when the object already exists.
type ConditionalArchive interface {
	PutIfAbsent(context.Context, ArchiveBundle, string) (ArchiveReceipt, error)
}

// TerminalArchiveExporter conditionally retains redacted evidence for one already-terminal backfill request.
type TerminalArchiveExporter struct{ archives ConditionalArchive }

// NewTerminalArchiveExporter constructs a TerminalArchiveExporter with its required conditional archive port.
func NewTerminalArchiveExporter(archives ConditionalArchive) (*TerminalArchiveExporter, error) {
	if archives == nil {
		return nil, errors.New("backfill conditional archive is required")
	}
	return &TerminalArchiveExporter{archives: archives}, nil
}

// Export conditionally retains the canonical certificate-absent archive bundle for one terminal status.
func (exporter *TerminalArchiveExporter) Export(ctx context.Context, request Request, status Status, now time.Time) (ArchiveReceipt, error) {
	if err := ctx.Err(); err != nil {
		return ArchiveReceipt{}, errors.Wrap(err, "export terminal backfill archive")
	}
	if err := status.ValidateFor(request, now); err != nil {
		return ArchiveReceipt{}, errors.Wrap(err, "validate terminal backfill archive status")
	}
	bundle, err := NewArchiveBundle(request, status, Audit{Code: auditCode(status)}, nil)
	if err != nil {
		return ArchiveReceipt{}, errors.Wrap(err, "construct terminal backfill archive")
	}
	digest, err := bundle.Digest()
	if err != nil {
		return ArchiveReceipt{}, errors.Wrap(err, "digest terminal backfill archive")
	}
	if err := ctx.Err(); err != nil {
		return ArchiveReceipt{}, errors.Wrap(err, "conditionally archive terminal backfill status")
	}
	receipt, err := exporter.archives.PutIfAbsent(ctx, bundle, digest)
	if err != nil {
		return ArchiveReceipt{}, errors.Wrap(err, "conditionally archive terminal backfill status")
	}
	if receipt.CanonicalDigest != digest {
		return ArchiveReceipt{}, errors.Wrap(ErrArchiveConflict, "conditionally archive terminal backfill status")
	}
	if err := ctx.Err(); err != nil {
		return ArchiveReceipt{}, errors.Wrap(err, "conditionally archive terminal backfill status")
	}
	return receipt, nil
}

func auditCode(status Status) string {
	if status.Phase == PhaseVerified {
		return "verified"
	}
	return string(status.Reason)
}
