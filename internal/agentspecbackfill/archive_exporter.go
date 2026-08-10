package agentspecbackfill

import (
	"context"
	"strings"
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
	Key             string
	CanonicalDigest string
}

// ConditionalArchive conditionally retains one immutable request-keyed ArchiveBundle without overwriting it.
// It must verify and return the expected canonical digest when the object already exists.
type ConditionalArchive interface {
	PutIfAbsent(context.Context, string, ArchiveBundle, string) (ArchiveReceipt, error)
}

// ArchiveExportConfig is the explicit capability-bounded object prefix for one archive exporter.
type ArchiveExportConfig struct{ Prefix string }

func (config ArchiveExportConfig) validate() error {
	if strings.Trim(config.Prefix, "/") == "" || strings.Trim(config.Prefix, "/") != config.Prefix || strings.Contains(config.Prefix, "//") {
		return errors.New("archive export prefix is invalid")
	}
	for _, segment := range strings.Split(config.Prefix, "/") {
		if segment == "." || segment == ".." {
			return errors.New("archive export prefix is invalid")
		}
	}
	return nil
}

// TerminalArchiveExporter conditionally retains redacted evidence for one already-terminal backfill request.
type TerminalArchiveExporter struct {
	config   ArchiveExportConfig
	archives ConditionalArchive
}

// NewTerminalArchiveExporter constructs a TerminalArchiveExporter with its required conditional archive port.
func NewTerminalArchiveExporter(config ArchiveExportConfig, archives ConditionalArchive) (*TerminalArchiveExporter, error) {
	if config.validate() != nil || archives == nil {
		return nil, errors.New("backfill archive export configuration and conditional archive are required")
	}
	return &TerminalArchiveExporter{config: config, archives: archives}, nil
}

// Export conditionally retains the CR-UID-bound canonical archive bundle for one terminal status.
// Terminal integrity is evaluated at completion, while observedAt only prevents exporting a result from the future.
func (exporter *TerminalArchiveExporter) Export(ctx context.Context, evidence TerminalArchiveEvidence, observedAt time.Time) (ArchiveReceipt, error) {
	if err := ctx.Err(); err != nil {
		return ArchiveReceipt{}, errors.Wrap(err, "export terminal backfill archive")
	}
	if observedAt.IsZero() || observedAt.Location() != time.UTC || evidence.Status.CompletedAt.After(observedAt) {
		return ArchiveReceipt{}, errors.New("validate terminal backfill archive status: completion time must not be after observation")
	}
	bundle, err := NewArchiveBundle(evidence)
	if err != nil {
		return ArchiveReceipt{}, errors.Wrap(err, "construct terminal backfill archive")
	}
	key := bundle.Key(exporter.config.Prefix)
	digest, err := bundle.Digest()
	if err != nil {
		return ArchiveReceipt{}, errors.Wrap(err, "digest terminal backfill archive")
	}
	if err := ctx.Err(); err != nil {
		return ArchiveReceipt{}, errors.Wrap(err, "conditionally archive terminal backfill status")
	}
	receipt, err := exporter.archives.PutIfAbsent(ctx, key, bundle, digest)
	if err != nil {
		return ArchiveReceipt{}, errors.Wrap(err, "conditionally archive terminal backfill status")
	}
	if receipt.Key != key || receipt.CanonicalDigest != digest {
		return ArchiveReceipt{}, errors.Wrap(ErrArchiveConflict, "conditionally archive terminal backfill status")
	}
	if err := ctx.Err(); err != nil {
		return ArchiveReceipt{}, errors.Wrap(err, "conditionally archive terminal backfill status")
	}
	return receipt, nil
}
