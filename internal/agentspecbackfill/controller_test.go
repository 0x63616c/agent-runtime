package agentspecbackfill_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/agentspecbackfill"
)

var errTransient = errors.New("transient verification failure")

func TestReconcilerRecordsVerifiedTerminalStatus(t *testing.T) {
	request := validRequest()
	statuses := &recordingTerminalStatuses{}
	reconciler, err := agentspecbackfill.NewReconciler(statuses)
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}

	status, err := reconciler.Reconcile(
		context.Background(),
		request,
		fixedReader{set: validFrozenSet(request)},
		passingVerifier{},
		time.Date(2026, 8, 9, 0, 1, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("reconcile verified request: %v", err)
	}
	if status.Phase != agentspecbackfill.PhaseVerified || statuses.creates != 1 {
		t.Fatalf("reconciled status = %#v, creates=%d", status, statuses.creates)
	}
}

func TestReconcilerRecordsEveryTerminalRefusal(t *testing.T) {
	now := time.Date(2026, 8, 9, 0, 1, 0, 0, time.UTC)
	for _, test := range []struct {
		name     string
		request  func(agentspecbackfill.Request) agentspecbackfill.Request
		reader   func(agentspecbackfill.Request) agentspecbackfill.FrozenLegacyReader
		verifier agentspecbackfill.ImmutableContentVerifier
		reason   agentspecbackfill.Reason
	}{
		{
			name: "not admitted",
			request: func(request agentspecbackfill.Request) agentspecbackfill.Request {
				request.CreatedAt = now.Add(time.Minute)
				request.ExpiresAt = request.CreatedAt.Add(time.Minute)
				return request
			},
			reader: func(request agentspecbackfill.Request) agentspecbackfill.FrozenLegacyReader {
				return fixedReader{set: validFrozenSet(request)}
			},
			verifier: passingVerifier{},
			reason:   agentspecbackfill.RefusalNotAdmitted,
		},
		{
			name: "expired",
			request: func(request agentspecbackfill.Request) agentspecbackfill.Request {
				request.ExpiresAt = now.Add(-time.Second)
				return request
			},
			reader: func(request agentspecbackfill.Request) agentspecbackfill.FrozenLegacyReader {
				return fixedReader{set: validFrozenSet(request)}
			},
			verifier: passingVerifier{},
			reason:   agentspecbackfill.RefusalExpired,
		},
		{
			name:    "snapshot",
			request: func(request agentspecbackfill.Request) agentspecbackfill.Request { return request },
			reader: func(request agentspecbackfill.Request) agentspecbackfill.FrozenLegacyReader {
				set := validFrozenSet(request)
				set.Snapshot.Fingerprint = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
				return fixedReader{set: set}
			},
			verifier: passingVerifier{},
			reason:   agentspecbackfill.RefusalSnapshot,
		},
		{
			name:    "content",
			request: func(request agentspecbackfill.Request) agentspecbackfill.Request { return request },
			reader: func(request agentspecbackfill.Request) agentspecbackfill.FrozenLegacyReader {
				return fixedReader{set: validFrozenSet(request)}
			},
			verifier: failingVerifier{err: agentspecbackfill.ErrWrongOwner},
			reason:   agentspecbackfill.RefusalContent,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := test.request(validRequest())
			statuses := &recordingTerminalStatuses{}
			reconciler, err := agentspecbackfill.NewReconciler(statuses)
			if err != nil {
				t.Fatalf("new reconciler: %v", err)
			}

			status, err := reconciler.Reconcile(context.Background(), request, test.reader(request), test.verifier, now)
			if err != nil {
				t.Fatalf("reconcile refusal: %v", err)
			}
			if status.Phase != agentspecbackfill.PhaseRefused || status.Reason != test.reason || statuses.creates != 1 {
				t.Fatalf("reconciled status = %#v, creates=%d", status, statuses.creates)
			}
		})
	}
}

func TestReconcilerLeavesTransientAndCancelledVerificationForFreshRetry(t *testing.T) {
	request := validRequest()
	now := time.Date(2026, 8, 9, 0, 1, 0, 0, time.UTC)
	for _, test := range []struct {
		name string
		ctx  func() context.Context
		read agentspecbackfill.FrozenLegacyReader
	}{
		{
			name: "transient reader",
			ctx:  context.Background,
			read: errorReader{err: errTransient},
		},
		{
			name: "cancelled context",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			read: fixedReader{set: validFrozenSet(request)},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			statuses := &recordingTerminalStatuses{}
			reconciler, err := agentspecbackfill.NewReconciler(statuses)
			if err != nil {
				t.Fatalf("new reconciler: %v", err)
			}

			if _, err := reconciler.Reconcile(test.ctx(), request, test.read, passingVerifier{}, now); err == nil {
				t.Fatal("retryable verification was recorded as terminal")
			}
			if statuses.creates != 0 {
				t.Fatalf("retryable verification writes = creates=%d", statuses.creates)
			}

			status, err := reconciler.Reconcile(context.Background(), request, fixedReader{set: validFrozenSet(request)}, passingVerifier{}, now)
			if err != nil || status.Phase != agentspecbackfill.PhaseVerified || statuses.creates != 1 {
				t.Fatalf("fresh retry = %#v, %v, creates=%d", status, err, statuses.creates)
			}
		})
	}
}

func TestReconcilerReturnsExistingTerminalWinnerWithoutOverwrite(t *testing.T) {
	request := validRequest()
	winner := agentspecbackfill.Status{
		Phase:               agentspecbackfill.PhaseRefused,
		RequestDigest:       mustDigest(t, request),
		SnapshotFingerprint: request.SnapshotFingerprint,
		SnapshotCount:       request.SnapshotCount,
		Reason:              agentspecbackfill.RefusalContent,
		CompletedAt:         time.Date(2026, 8, 9, 0, 1, 0, 0, time.UTC),
	}
	statuses := &recordingTerminalStatuses{winner: &winner}
	reconciler, err := agentspecbackfill.NewReconciler(statuses)
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}

	status, err := reconciler.Reconcile(context.Background(), request, fixedReader{set: validFrozenSet(request)}, passingVerifier{}, winner.CompletedAt)
	if err != nil || status != winner || statuses.creates != 1 {
		t.Fatalf("conflict winner = %#v, %v, creates=%d", status, err, statuses.creates)
	}
	status, err = reconciler.Reconcile(context.Background(), request, fixedReader{set: validFrozenSet(request)}, passingVerifier{}, winner.CompletedAt)
	if err != nil || status != winner || statuses.creates != 1 {
		t.Fatalf("idempotent winner = %#v, %v, creates=%d", status, err, statuses.creates)
	}
}

func TestReconcilerRefusesStaleRequestWithoutVerification(t *testing.T) {
	request := validRequest()
	now := request.ExpiresAt
	statuses := &recordingTerminalStatuses{}
	reader := &countingReader{set: validFrozenSet(request)}
	reconciler, err := agentspecbackfill.NewReconciler(statuses)
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}

	status, err := reconciler.Reconcile(context.Background(), request, reader, passingVerifier{}, now)
	if err != nil || status.Phase != agentspecbackfill.PhaseRefused || status.Reason != agentspecbackfill.RefusalExpired || reader.calls != 0 || statuses.creates != 1 {
		t.Fatalf("stale request = %#v, %v, reader=%d creates=%d", status, err, reader.calls, statuses.creates)
	}
}

func TestReconcilerCancellationPreventsExistingTerminalStatusIO(t *testing.T) {
	request := validRequest()
	status := agentbackfillVerifiedStatus(t, request)
	statuses := &recordingTerminalStatuses{status: status, found: true}
	reconciler, err := agentspecbackfill.NewReconciler(statuses)
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = reconciler.Reconcile(ctx, request, fixedReader{set: validFrozenSet(request)}, passingVerifier{}, status.CompletedAt)
	if !errors.Is(err, context.Canceled) || statuses.reads != 0 {
		t.Fatalf("cancelled existing terminal reconciliation = %v, reads=%d", err, statuses.reads)
	}
}

func TestReconcilerFencesCancellationBetweenVerificationAndTerminalWrite(t *testing.T) {
	request := validRequest()
	statuses := &recordingTerminalStatuses{}
	reconciler, err := agentspecbackfill.NewReconciler(statuses)
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	ctx := newCancellationFenceContext(3)

	_, err = reconciler.Reconcile(ctx, request, fixedReader{set: validFrozenSet(request)}, passingVerifier{}, request.ExpiresAt)
	if !errors.Is(err, context.Canceled) || statuses.creates != 0 {
		t.Fatalf("cancelled terminal write = %v, creates=%d", err, statuses.creates)
	}
}

func TestReconcilerRefusesFutureStoredStatus(t *testing.T) {
	request := validRequest()
	now := request.CreatedAt.Add(time.Second)
	status := agentbackfillVerifiedStatus(t, request)
	status.CompletedAt = now.Add(time.Second)
	statuses := &recordingTerminalStatuses{status: status, found: true}
	reconciler, err := agentspecbackfill.NewReconciler(statuses)
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}

	_, err = reconciler.Reconcile(context.Background(), request, fixedReader{set: validFrozenSet(request)}, passingVerifier{}, now)
	if err == nil {
		t.Fatalf("future stored status = %v", err)
	}
}

func validFrozenSet(request agentspecbackfill.Request) agentspecbackfill.FrozenLegacySet {
	return agentspecbackfill.FrozenLegacySet{
		Snapshot: agentspecbackfill.Snapshot{Fingerprint: request.SnapshotFingerprint, Count: 1},
		Revisions: []agentspecbackfill.LegacyRevision{{
			TenantID:               "tenant_a",
			AgentID:                "agent_0000000000000001",
			RevisionID:             "arev_0000000000000001",
			SpecificationDigest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			SpecificationSizeBytes: 42,
		}},
	}
}

type recordingTerminalStatuses struct {
	status  agentspecbackfill.Status
	found   bool
	winner  *agentspecbackfill.Status
	reads   int
	creates int
}

func (store *recordingTerminalStatuses) ReadTerminal(context.Context, agentspecbackfill.Request) (agentspecbackfill.Status, bool, error) {
	store.reads++
	return store.status, store.found, nil
}

func (store *recordingTerminalStatuses) CreateTerminal(_ context.Context, _ agentspecbackfill.Request, status agentspecbackfill.Status) (agentspecbackfill.Status, bool, error) {
	store.creates++
	if store.winner != nil {
		store.status, store.found = *store.winner, true
		return store.status, false, nil
	}
	if store.found {
		return store.status, false, nil
	}
	store.status, store.found = status, true
	return status, true, nil
}

type cancellationFenceContext struct {
	calls           int
	cancelOnErrCall int
	done            chan struct{}
	cancelled       bool
}

func newCancellationFenceContext(cancelOnErrCall int) *cancellationFenceContext {
	return &cancellationFenceContext{cancelOnErrCall: cancelOnErrCall, done: make(chan struct{})}
}

func (ctx *cancellationFenceContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (ctx *cancellationFenceContext) Done() <-chan struct{}       { return ctx.done }
func (ctx *cancellationFenceContext) Err() error {
	ctx.calls++
	if ctx.calls >= ctx.cancelOnErrCall {
		if !ctx.cancelled {
			close(ctx.done)
			ctx.cancelled = true
		}
		return context.Canceled
	}
	return nil
}
func (ctx *cancellationFenceContext) Value(any) any { return nil }
