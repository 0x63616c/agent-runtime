package tooldispatch

import (
	"context"
	"errors"
	"time"

	facebookclock "github.com/facebookgo/clock"
)

// TriggerClient is the narrow RoleTool authority required to ask the broker
// to scan already-authorized work.
type TriggerClient interface {
	DispatchOnce(context.Context) (Receipt, error)
}

// TriggerScheduler supplies the next declared trigger opportunity. Keeping it
// at the composition boundary makes the bounded loop deterministic in tests.
type TriggerScheduler interface {
	After(time.Duration) <-chan time.Time
}

type realtimeTriggerScheduler struct{ clock facebookclock.Clock }

const maximumConsecutiveStartupUnavailability = 12

// NewRealtimeTriggerScheduler returns the production scheduler for injection
// at the application composition root.
func NewRealtimeTriggerScheduler() TriggerScheduler {
	return realtimeTriggerScheduler{clock: facebookclock.New()}
}

func (scheduler realtimeTriggerScheduler) After(interval time.Duration) <-chan time.Time {
	return scheduler.clock.After(interval)
}

// RunTriggerLoop performs an immediate bounded scan followed by interval
// scans. It owns no execution input and stops promptly with its context.
func RunTriggerLoop(ctx context.Context, client TriggerClient, scheduler TriggerScheduler, interval time.Duration) error {
	if ctx == nil || client == nil || scheduler == nil || interval < time.Second || interval > 5*time.Minute {
		return errors.New("run tool dispatch trigger: declared client, scheduler, and interval are required")
	}
	consecutiveUnavailability := 0
	for {
		if _, err := client.DispatchOnce(ctx); err != nil {
			if errors.Is(err, ErrTransientUnavailable) && consecutiveUnavailability < maximumConsecutiveStartupUnavailability {
				consecutiveUnavailability++
				select {
				case <-ctx.Done():
					return nil
				case <-scheduler.After(interval):
					continue
				}
			}
			return err
		}
		consecutiveUnavailability = 0
		select {
		case <-ctx.Done():
			return nil
		case <-scheduler.After(interval):
		}
	}
}
