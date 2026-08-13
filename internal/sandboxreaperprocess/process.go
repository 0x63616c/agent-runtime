// Package sandboxreaperprocess composes the independently deployable durable
// sandbox reconciliation owner. It never performs backend cleanup by guess.
package sandboxreaperprocess

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"regexp"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/sandboxcontrol"
	"github.com/cockroachdb/errors"
	"github.com/jackc/pgx/v5/pgxpool"
)

var environmentName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

// Config is one strict independently scheduled reaper declaration.
type Config struct {
	databaseDSNEnvironment string
	interval               time.Duration
	pageSize               int
}

type document struct {
	Version                int    `json:"version"`
	DatabaseDSNEnvironment string `json:"database_dsn_environment"`
	IntervalMillis         uint32 `json:"interval_millis"`
	PageSize               uint16 `json:"page_size"`
}

// SecretLookup resolves only an explicitly named injected value.
type SecretLookup func(string) (string, bool)

// Wait blocks using the composition owner's cancellable scheduling primitive.
type Wait func(context.Context, time.Duration) error

// Observer receives one bounded content-free reconciliation summary.
type Observer func(Summary)

// Summary reports the durable decisions made by one reconciliation pass.
type Summary struct {
	ObservedAt           time.Time
	RecoveredAssignments int
	ClaimedCleanups      int
	ReapedOperations     int
}

// Store is the bounded durable recovery authority required by the reaper.
type Store interface {
	RecoverExpiredAssignments(context.Context, time.Time, int) ([]sandboxcontrol.Operation, error)
	ClaimExpiredCleanup(context.Context, time.Time, int) ([]sandboxcontrol.Operation, error)
	Reap(context.Context, time.Time, int) ([]sandboxcontrol.Operation, error)
}

// Parse decodes exactly one canonical versioned reaper declaration.
func Parse(input io.Reader) (Config, error) {
	if input == nil {
		return Config{}, errors.New("parse sandbox-reaper configuration: input is required")
	}
	wire, err := io.ReadAll(io.LimitReader(input, 64<<10+1))
	if err != nil || len(wire) == 0 || len(wire) > 64<<10 {
		return Config{}, errors.New("parse sandbox-reaper configuration: invalid bounded input")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var decoded document
	if err := decoder.Decode(&decoded); err != nil {
		return Config{}, errors.Wrap(err, "parse sandbox-reaper configuration")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Config{}, errors.New("parse sandbox-reaper configuration: exactly one document is required")
	}
	interval := time.Duration(decoded.IntervalMillis) * time.Millisecond
	if decoded.Version != 1 || !environmentName.MatchString(decoded.DatabaseDSNEnvironment) || interval <= 0 || interval > time.Minute || decoded.PageSize == 0 || decoded.PageSize > 1000 {
		return Config{}, errors.New("validate sandbox-reaper configuration: explicit finite authority is required")
	}
	return Config{databaseDSNEnvironment: decoded.DatabaseDSNEnvironment, interval: interval, pageSize: int(decoded.PageSize)}, nil
}

// Run opens only the declared PostgreSQL authority and reconciles until
// cancellation. Schema creation and destructive backend cleanup remain
// separate audited operator/backend responsibilities.
func Run(ctx context.Context, config Config, lookup SecretLookup, source clock.Clock, wait Wait, observe Observer) error {
	if ctx == nil || lookup == nil || source == nil || wait == nil || observe == nil {
		return errors.New("run sandbox reaper: context, secrets, clock, wait and observer are required")
	}
	dsn, found := lookup(config.databaseDSNEnvironment)
	if !found || dsn == "" {
		return errors.Newf("run sandbox reaper: required secret environment %s is missing", config.databaseDSNEnvironment)
	}
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return errors.New("run sandbox reaper: database configuration is invalid")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.Wrap(err, "run sandbox reaper: open database")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.Wrap(err, "run sandbox reaper: ping database")
	}
	store, err := sandboxcontrol.NewPostgresLedger(pool)
	if err != nil {
		return err
	}
	return Loop(ctx, store, source, config.interval, config.pageSize, wait, observe)
}

// Loop runs one immediate pass and then finite cancellable intervals.
func Loop(ctx context.Context, store Store, source clock.Clock, interval time.Duration, pageSize int, wait Wait, observe Observer) error {
	if ctx == nil || store == nil || source == nil || wait == nil || observe == nil || interval <= 0 || interval > time.Minute || pageSize <= 0 || pageSize > 1000 {
		return errors.New("run sandbox reaper loop: explicit finite authority is required")
	}
	failures := 0
	for {
		summary, err := ReconcileOnce(ctx, store, source.Now().UTC(), pageSize)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			failures++
		} else {
			failures = 0
			observe(summary)
		}
		if err := wait(ctx, retryDelay(interval, failures)); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) && ctx.Err() != nil {
				return nil
			}
			return errors.Wrap(err, "wait for sandbox reaper interval")
		}
	}
}

// retryDelay gives reconciliation failures an explicit finite exponential
// backoff. A successful pass resets it to the configured cadence. The cap is
// deliberately independent from the deployment interval so a bad store cannot
// create an unbounded silent retry period.
func retryDelay(interval time.Duration, failures int) time.Duration {
	if failures <= 1 {
		return interval
	}
	delay := interval
	for attempt := 1; attempt < failures && delay < time.Minute; attempt++ {
		if delay > time.Minute/2 {
			return time.Minute
		}
		delay *= 2
	}
	if delay > time.Minute {
		return time.Minute
	}
	return delay
}

// ReconcileOnce invokes every durable recovery owner in fixed order.
func ReconcileOnce(ctx context.Context, store Store, now time.Time, pageSize int) (Summary, error) {
	recovered, err := store.RecoverExpiredAssignments(ctx, now, pageSize)
	if err != nil {
		return Summary{}, errors.Wrap(err, "reconcile expired sandbox host assignments")
	}
	claimed, err := store.ClaimExpiredCleanup(ctx, now, pageSize)
	if err != nil {
		return Summary{}, errors.Wrap(err, "claim expired sandbox cleanup")
	}
	reaped, err := store.Reap(ctx, now, pageSize)
	if err != nil {
		return Summary{}, errors.Wrap(err, "reap expired sandbox operations")
	}
	return Summary{ObservedAt: now.UTC(), RecoveredAssignments: len(recovered), ClaimedCleanups: len(claimed), ReapedOperations: len(reaped)}, nil
}
