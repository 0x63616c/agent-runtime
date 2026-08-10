package sandboxhostprocess

import (
	"context"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/cockroachdb/errors"
)

const (
	maximumPollInterval = time.Minute
	maximumBackoff      = time.Minute
)

var (
	// ErrRetryable marks a control-plane failure that a host daemon can retry
	// without widening the journaled operation transaction.
	ErrRetryable = errors.New("sandbox reference host retryable control failure")
)

// Wait blocks using the composition owner's cancellable scheduling primitive.
type Wait func(context.Context, time.Duration) error

// Outcome is the bounded result of one host poll.
type Outcome string

const (
	// OutcomeNoWork confirms that an authenticated control poll found no eligible operation.
	OutcomeNoWork Outcome = "no_work"
	// OutcomeSucceeded confirms that one journaled reference operation completed.
	OutcomeSucceeded Outcome = "succeeded"
	// OutcomeRetrying reports a transient control-plane failure before the next retry.
	OutcomeRetrying Outcome = "retrying"
)

// Summary reports one bounded host-poll outcome without operation or secret material.
type Summary struct {
	ObservedAt          time.Time
	Outcome             Outcome
	Ready               bool
	ConsecutiveFailures uint
}

// Observer receives one bounded content-free host-poll summary.
type Observer func(Summary)

// Run repeatedly polls the declared control plane until cancellation. It keeps
// RunOnce as the sole mTLS, fencing, and journal transaction owner.
func Run(ctx context.Context, config Config, lookup SecretLookup, source clock.Clock, interval time.Duration, wait Wait, observe Observer) error {
	if ctx == nil || lookup == nil || source == nil || wait == nil || observe == nil || interval <= 0 || interval > maximumPollInterval {
		return errors.New("run sandbox reference host: explicit finite context, dependencies and poll interval are required")
	}
	return loop(ctx, source, interval, wait, func(ctx context.Context) error {
		return RunOnce(ctx, config, lookup, source)
	}, observe)
}

func loop(ctx context.Context, source clock.Clock, interval time.Duration, wait Wait, poll func(context.Context) error, observe Observer) error {
	if ctx == nil || source == nil || wait == nil || poll == nil || observe == nil || interval <= 0 || interval > maximumPollInterval {
		return errors.New("run sandbox reference host loop: explicit finite authority is required")
	}
	var failures uint
	for {
		if ctx.Err() != nil {
			return nil
		}
		err := poll(ctx)
		if ctx.Err() != nil {
			return nil
		}
		outcome, ready, delay := OutcomeSucceeded, true, interval
		switch {
		case err == nil:
			failures = 0
		case errors.Is(err, ErrNoWork):
			outcome, ready, failures = OutcomeNoWork, true, 0
		case errors.Is(err, ErrRetryable):
			failures++
			outcome, ready, delay = OutcomeRetrying, false, retryDelay(interval, failures)
		default:
			return err
		}
		observe(Summary{ObservedAt: source.Now().UTC(), Outcome: outcome, Ready: ready, ConsecutiveFailures: failures})
		if err := wait(ctx, delay); err != nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) && ctx.Err() != nil {
				return nil
			}
			return errors.Wrap(err, "wait for sandbox reference host poll")
		}
	}
}

func retryDelay(interval time.Duration, failures uint) time.Duration {
	delay := interval
	for count := uint(1); count < failures && delay < maximumBackoff; count++ {
		if delay > maximumBackoff/2 {
			return maximumBackoff
		}
		delay *= 2
	}
	if delay > maximumBackoff {
		return maximumBackoff
	}
	return delay
}
