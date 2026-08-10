// Package agentspecbackfillexportprocess composes the separately-authorized terminal archive exporter.
package agentspecbackfillexportprocess

import (
	"context"
	"time"

	"github.com/0x63616c/agent-runtime/internal/agentspecbackfill"
	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/cockroachdb/errors"
)

const maximumPollInterval = time.Minute

// Config bounds polling for one explicitly composed archive-export process.
type Config struct{ PollInterval time.Duration }

func (config Config) validate() error {
	if config.PollInterval <= 0 || config.PollInterval > maximumPollInterval {
		return errors.New("agent spec backfill archive export configuration is invalid")
	}
	return nil
}

// Source exposes only already-terminal redacted CR evidence to the archive-export authority.
// It is intentionally distinct from the controller's request/status authority.
type Source interface {
	ListTerminalEvidence(context.Context) ([]agentspecbackfill.TerminalArchiveEvidence, error)
}

// Exporter conditionally retains one immutable terminal evidence bundle.
type Exporter interface {
	Export(context.Context, agentspecbackfill.TerminalArchiveEvidence, time.Time) (agentspecbackfill.ArchiveReceipt, error)
}

// Wait waits for an explicit bounded export poll interval without ambient wall-clock time.
type Wait func(context.Context, time.Duration) error

// Process is the separate composition and scheduling seam that invokes the archive exporter.
type Process struct {
	config   Config
	source   Source
	exporter Exporter
	clock    clock.Clock
	wait     Wait
}

// New constructs a Process from its distinct terminal-evidence source and archive authority.
func New(config Config, source Source, exporter Exporter, sourceClock clock.Clock, wait Wait) (*Process, error) {
	if config.validate() != nil || source == nil || exporter == nil || sourceClock == nil || wait == nil {
		return nil, errors.New("create agent spec backfill archive export process: explicit valid configuration and ports are required")
	}
	return &Process{config: config, source: source, exporter: exporter, clock: sourceClock, wait: wait}, nil
}

// Run schedules independent terminal-evidence export until the caller cancels its context.
func (process *Process) Run(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if _, err := process.RunOnce(ctx); err != nil {
			return err
		}
		if err := process.wait(ctx, process.config.PollInterval); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.Wrap(err, "wait to export agent spec backfill terminal evidence")
		}
	}
}

// RunOnce exports every terminal evidence item currently supplied by its narrowly scoped source.
func (process *Process) RunOnce(ctx context.Context) ([]agentspecbackfill.ArchiveReceipt, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "list agent spec backfill terminal evidence")
	}
	items, err := process.source.ListTerminalEvidence(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "list agent spec backfill terminal evidence")
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "export agent spec backfill terminal evidence")
	}
	receipts := make([]agentspecbackfill.ArchiveReceipt, 0, len(items))
	for _, item := range items {
		receipt, err := process.exporter.Export(ctx, item, process.clock.Now().UTC())
		if err != nil {
			return nil, errors.Wrap(err, "export agent spec backfill terminal evidence")
		}
		receipts = append(receipts, receipt)
	}
	return receipts, nil
}
