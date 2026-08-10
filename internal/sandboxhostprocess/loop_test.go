package sandboxhostprocess

import (
	"context"
	"crypto/x509"
	"net/http"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/cockroachdb/errors"
)

func TestLoopTreatsVerifiedNoWorkAsReadyAndWaitsWithoutOverlap(t *testing.T) {
	t.Parallel()

	source, _ := clock.NewFake(time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC))
	started := 0
	finished := 0
	waits := make([]time.Duration, 0, 1)
	summaries := make([]Summary, 0, 1)
	err := loop(context.Background(), source, time.Second, func(_ context.Context, duration time.Duration) error {
		waits = append(waits, duration)
		return context.Canceled
	}, func(context.Context) error {
		started++
		if started != finished+1 {
			t.Fatal("Loop() began a second poll before the first finished")
		}
		finished++
		return ErrNoWork
	}, func(summary Summary) {
		summaries = append(summaries, summary)
	})
	if err != nil {
		t.Fatal(err)
	}
	if started != 1 || finished != 1 || len(waits) != 1 || len(summaries) != 1 {
		t.Fatalf("Loop() polls=%d finished=%d waits=%v summaries=%#v", started, finished, waits, summaries)
	}
	if waits[0] != time.Second {
		t.Fatalf("Loop() no-work wait = %s, want configured poll interval %s", waits[0], time.Second)
	}
	if !summaries[0].Ready || summaries[0].Outcome != OutcomeNoWork || summaries[0].ObservedAt != source.Now().UTC() || summaries[0].ConsecutiveFailures != 0 {
		t.Fatalf("Loop() no-work summary = %#v", summaries[0])
	}
}

func TestLoopUsesCappedBackoffAndResetsAfterSuccess(t *testing.T) {
	t.Parallel()

	source, _ := clock.NewFake(time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC))
	retryable := errors.Mark(errors.New("temporary control failure"), ErrRetryable)
	results := []error{retryable, retryable, nil, retryable}
	resultCount := len(results)
	var waits []time.Duration
	var summaries []Summary
	err := loop(context.Background(), source, time.Second, func(_ context.Context, duration time.Duration) error {
		waits = append(waits, duration)
		if len(waits) == resultCount {
			return context.Canceled
		}
		return nil
	}, func(context.Context) error {
		result := results[0]
		results = results[1:]
		return result
	}, func(summary Summary) {
		summaries = append(summaries, summary)
	})
	if err != nil {
		t.Fatal(err)
	}
	wantWaits := []time.Duration{time.Second, 2 * time.Second, time.Second, time.Second}
	if len(waits) != len(wantWaits) {
		t.Fatalf("Loop() waits = %v, want %v", waits, wantWaits)
	}
	for index := range wantWaits {
		if waits[index] != wantWaits[index] {
			t.Fatalf("Loop() wait[%d] = %s, want %s", index, waits[index], wantWaits[index])
		}
	}
	if len(summaries) != resultCount {
		t.Fatalf("Loop() summaries = %#v", summaries)
	}
	if summaries[0].Outcome != OutcomeRetrying || summaries[0].Ready || summaries[0].ConsecutiveFailures != 1 || summaries[1].ConsecutiveFailures != 2 || summaries[2].Outcome != OutcomeSucceeded || !summaries[2].Ready || summaries[2].ConsecutiveFailures != 0 || summaries[3].ConsecutiveFailures != 1 {
		t.Fatalf("Loop() summaries = %#v", summaries)
	}
}

func TestLoopCapsRetryBackoffAndRefusesTerminalFailure(t *testing.T) {
	t.Parallel()

	source, _ := clock.NewFake(time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC))
	results := make([]error, 0, 8)
	for range 8 {
		results = append(results, errors.Mark(errors.New("temporary control failure"), ErrRetryable))
	}
	resultCount := len(results)
	var waits []time.Duration
	err := loop(context.Background(), source, 30*time.Second, func(_ context.Context, duration time.Duration) error {
		waits = append(waits, duration)
		if len(waits) == resultCount {
			return context.Canceled
		}
		return nil
	}, func(context.Context) error {
		result := results[0]
		results = results[1:]
		return result
	}, func(Summary) {})
	if err != nil {
		t.Fatal(err)
	}
	for index, duration := range waits {
		if duration > maximumBackoff || (index == 0 && duration != 30*time.Second) {
			t.Fatalf("Loop() wait[%d] = %s, maximum %s", index, duration, maximumBackoff)
		}
	}

	terminal := ErrInjectedJournalFault
	err = loop(context.Background(), source, time.Second, func(context.Context, time.Duration) error {
		t.Fatal("Loop() waited after a terminal failure")
		return nil
	}, func(context.Context) error { return terminal }, func(Summary) {})
	if !errors.Is(err, terminal) {
		t.Fatalf("Loop() terminal error = %v, want %v", err, terminal)
	}
}

func TestControlStatusClassifiesOnlyServerFailureAsRetryable(t *testing.T) {
	t.Parallel()

	if err := requireControlStatus(http.StatusServiceUnavailable, "pull control endpoint is unavailable", "pull denied or unavailable"); !errors.Is(err, ErrRetryable) {
		t.Fatalf("requireControlStatus() service failure = %v", err)
	}
	if err := requireControlStatus(http.StatusConflict, "receipt control endpoint is unavailable", "receipt was not accepted"); err == nil || errors.Is(err, ErrRetryable) {
		t.Fatalf("requireControlStatus() protocol refusal = %v", err)
	}
}

func TestTransportClassificationRefusesRedirectAndTrustFailures(t *testing.T) {
	t.Parallel()

	for _, input := range []error{redirectRefused, x509.UnknownAuthorityError{}} {
		if !isTerminalTransportError(input) {
			t.Fatalf("isTerminalTransportError(%T) = false", input)
		}
	}
}

func TestLoopHonorsCancellationWithoutPollingOrWaiting(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	source, _ := clock.NewFake(time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC))
	err := loop(ctx, source, time.Second, func(context.Context, time.Duration) error {
		t.Fatal("Loop() waited after cancellation")
		return nil
	}, func(context.Context) error {
		t.Fatal("Loop() polled after cancellation")
		return nil
	}, func(Summary) {})
	if err != nil {
		t.Fatal(err)
	}
}
