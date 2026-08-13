package sandboxcontrol

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMemoryLedgerReconnectsTransitionsAndFencesStaleHostResults(t *testing.T) {
	ledger := NewMemoryLedger()
	acceptedAt := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	input := Operation{Principal: "tenant-a:principal-a", ID: "op_01", CanonicalDigest: "sha256:request", EffectiveSpecDigest: "sha256:effective", AcceptedAt: acceptedAt, RetentionExpiresAt: acceptedAt.Add(time.Hour)}

	accepted, replay, err := ledger.Accept(context.Background(), input)
	if err != nil || replay || accepted.State != StateAccepted || accepted.Version != 1 {
		t.Fatalf("Accept() = %#v, %v, %v", accepted, replay, err)
	}
	reconnected, replay, err := ledger.Accept(context.Background(), input)
	if err != nil || !replay || reconnected != accepted {
		t.Fatalf("reconnect Accept() = %#v, %v, %v; want original durable record", reconnected, replay, err)
	}
	assigned, err := ledger.Assign(context.Background(), input.Principal, input.ID, "host-a", acceptedAt.Add(time.Minute))
	if err != nil || assigned.Assignment.HostID != "host-a" || assigned.Assignment.FencingToken != 1 || assigned.State != StateDispatched {
		t.Fatalf("Assign() = %#v, %v", assigned, err)
	}
	reassigned, err := ledger.Assign(context.Background(), input.Principal, input.ID, "host-b", acceptedAt.Add(2*time.Minute))
	if err != nil || reassigned.Assignment.FencingToken != 2 {
		t.Fatalf("reassign Assign() = %#v, %v", reassigned, err)
	}
	_, err = ledger.RecordHostResult(context.Background(), input.Principal, input.ID, HostResult{HostID: "host-a", FencingToken: 1, State: StateSucceeded, ObservedAt: acceptedAt.Add(30 * time.Second)})
	if !errors.Is(err, ErrStaleFence) {
		t.Fatalf("stale host result error = %v, want ErrStaleFence", err)
	}
	completed, err := ledger.RecordHostResult(context.Background(), input.Principal, input.ID, HostResult{HostID: "host-b", FencingToken: 2, State: StateSucceeded, ObservedAt: acceptedAt.Add(90 * time.Second)})
	if err != nil || completed.State != StateSucceeded {
		t.Fatalf("RecordHostResult() = %#v, %v", completed, err)
	}
}

func TestMemoryLedgerReconnectUsesInputDigestAcrossPolicyChanges(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	ledger := NewMemoryLedger()
	first := Operation{Principal: "tenant-a:principal-a", ID: "op_policy", InputDigest: "sha256:wire", CanonicalDigest: "sha256:defaults-v1", EffectiveSpecDigest: "sha256:effective-v1", AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour)}
	accepted, replay, err := ledger.Accept(context.Background(), first)
	if err != nil || replay {
		t.Fatalf("Accept(first) = %#v, %t, %v", accepted, replay, err)
	}
	retry := first
	retry.CanonicalDigest = "sha256:defaults-v2"
	retry.EffectiveSpecDigest = "sha256:effective-v2"
	reconnected, replay, err := ledger.Accept(context.Background(), retry)
	if err != nil || !replay || reconnected.CanonicalDigest != first.CanonicalDigest {
		t.Fatalf("Accept(retry) = %#v, %t, %v", reconnected, replay, err)
	}
	changed := retry
	changed.InputDigest = "sha256:different-wire"
	if _, _, err := ledger.Accept(context.Background(), changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("Accept(changed) error = %v", err)
	}
}

func TestMemoryLedgerPreservesAdmittedResourceProjectionBinding(t *testing.T) {
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	binding := ResourceProjectionBinding{
		Kind:                   ResourceProjectionSandbox,
		ResourceID:             "sbx_bound",
		AdmittedSnapshotDigest: digest("a"),
		Transition:             ResourceProjectionReplaceSnapshot,
	}
	operation := Operation{
		Principal:                 "tenant-a:principal-a",
		ID:                        "op_bound",
		TargetKind:                "sandbox",
		TargetID:                  "sbx_bound",
		CanonicalDigest:           "sha256:request",
		EffectiveSpecDigest:       "sha256:effective",
		AcceptedAt:                now,
		RetentionExpiresAt:        now.Add(time.Hour),
		ResourceProjectionBinding: &binding,
	}
	ledger := NewMemoryLedger()
	accepted, replay, err := ledger.Accept(context.Background(), operation)
	if err != nil || replay || accepted.ResourceProjectionBinding == nil || *accepted.ResourceProjectionBinding != binding {
		t.Fatalf("Accept() = %#v, %t, %v; want persisted binding", accepted, replay, err)
	}
	accepted.ResourceProjectionBinding.AdmittedSnapshotDigest = digest("f")
	stored, err := ledger.Get(context.Background(), operation.Principal, operation.ID)
	if err != nil || stored.ResourceProjectionBinding == nil || *stored.ResourceProjectionBinding != binding {
		t.Fatalf("Get() after caller mutation = %#v, %v; want immutable persisted binding", stored, err)
	}
	changed := operation
	changed.ResourceProjectionBinding = &ResourceProjectionBinding{
		Kind:                   binding.Kind,
		ResourceID:             binding.ResourceID,
		AdmittedSnapshotDigest: digest("b"),
		Transition:             binding.Transition,
	}
	if _, _, err := ledger.Accept(context.Background(), changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("Accept(changed admitted snapshot) error = %v; want ErrConflict", err)
	}
	invalid := operation
	invalid.ResourceProjectionBinding = &ResourceProjectionBinding{
		Kind:                   binding.Kind,
		ResourceID:             "sbx_other",
		AdmittedSnapshotDigest: binding.AdmittedSnapshotDigest,
		Transition:             binding.Transition,
	}
	if _, _, err := NewMemoryLedger().Accept(context.Background(), invalid); err == nil {
		t.Fatal("Accept(mismatched projection target) succeeded")
	}
}

func TestMemoryLedgerExpiresLeaseBeforeAcceptingLateHostResult(t *testing.T) {
	ledger := NewMemoryLedger()
	now := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	operation := Operation{Principal: "tenant-a:principal-a", ID: "op_lease", CanonicalDigest: "sha256:request", EffectiveSpecDigest: "sha256:effective", AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour), CleanupRequired: true}
	if _, _, err := ledger.Accept(context.Background(), operation); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	assigned, err := ledger.Assign(context.Background(), operation.Principal, operation.ID, "host-a", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Assign() error = %v", err)
	}
	recovered, err := ledger.RecoverExpiredAssignments(context.Background(), now.Add(time.Minute), 10)
	if err != nil || len(recovered) != 1 || recovered[0].State != StateUncertain || recovered[0].Assignment.HostID != "" || recovered[0].Assignment.FencingToken != assigned.Assignment.FencingToken+1 {
		t.Fatalf("RecoverExpiredAssignments() = %#v, %v", recovered, err)
	}
	if _, err := ledger.RecordHostResult(context.Background(), operation.Principal, operation.ID, HostResult{HostID: "host-a", FencingToken: assigned.Assignment.FencingToken, State: StateSucceeded, ObservedAt: now.Add(time.Minute)}); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("late RecordHostResult() error = %v, want ErrStaleFence", err)
	}
}

func TestMemoryLedgerRequiresCleanupProofBeforeTombstone(t *testing.T) {
	ledger := NewMemoryLedger()
	now := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	operation := Operation{Principal: "tenant-a:principal-a", ID: "op_cleanup", CanonicalDigest: "sha256:request", EffectiveSpecDigest: "sha256:effective", AcceptedAt: now, RetentionExpiresAt: now.Add(time.Minute), CleanupRequired: true}
	accepted, _, err := ledger.Accept(context.Background(), operation)
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	pending, err := ledger.Transition(context.Background(), operation.Principal, operation.ID, accepted.Version, StateCleanupPending)
	if err != nil {
		t.Fatalf("Transition(cleanup-pending) error = %v", err)
	}
	reaped, err := ledger.Reap(context.Background(), now.Add(time.Minute), 10)
	if err != nil || len(reaped) != 0 {
		t.Fatalf("Reap() before proof = %#v, %v; want no tombstone", reaped, err)
	}
	confirmed, err := ledger.Transition(context.Background(), operation.Principal, operation.ID, pending.Version, StateCleanupConfirmed)
	if err != nil {
		t.Fatalf("Transition(cleanup-confirmed) error = %v", err)
	}
	reaped, err = ledger.Reap(context.Background(), now.Add(time.Minute), 10)
	if err != nil || len(reaped) != 1 || reaped[0].State != StateTombstoned || reaped[0].Version != confirmed.Version+1 {
		t.Fatalf("Reap() after proof = %#v, %v", reaped, err)
	}
	if _, _, err := ledger.Accept(context.Background(), operation); !errors.Is(err, ErrOperationIDExpired) {
		t.Fatalf("Accept() after tombstone error = %v, want ErrOperationIDExpired", err)
	}
}

func TestMemoryLedgerClaimsExpiredCleanupAndFencesOutstandingHost(t *testing.T) {
	ledger := NewMemoryLedger()
	now := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	operation := Operation{Principal: "tenant-a:principal-a", ID: "op_reaper", CanonicalDigest: "sha256:request", EffectiveSpecDigest: "sha256:effective", AcceptedAt: now, RetentionExpiresAt: now.Add(time.Minute), CleanupRequired: true}
	if _, _, err := ledger.Accept(context.Background(), operation); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	assigned, err := ledger.Assign(context.Background(), operation.Principal, operation.ID, "host-a", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Assign() error = %v", err)
	}
	claimed, err := ledger.ClaimExpiredCleanup(context.Background(), now.Add(time.Minute), 10)
	if err != nil || len(claimed) != 1 || claimed[0].State != StateCleanupPending || claimed[0].Assignment.HostID != "" || claimed[0].Assignment.FencingToken != assigned.Assignment.FencingToken+1 {
		t.Fatalf("ClaimExpiredCleanup() = %#v, %v", claimed, err)
	}
	if _, err := ledger.RecordHostResult(context.Background(), operation.Principal, operation.ID, HostResult{HostID: "host-a", FencingToken: assigned.Assignment.FencingToken, State: StateSucceeded, ObservedAt: now.Add(30 * time.Second)}); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("late RecordHostResult() error = %v, want ErrStaleFence", err)
	}
}

func TestMemoryLedgerWritesOrderedOutboxRecordsWithStateChanges(t *testing.T) {
	ledger := NewMemoryLedger()
	now := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	operation := Operation{Principal: "tenant-a:principal-a", ID: "op_outbox", CanonicalDigest: "sha256:request", EffectiveSpecDigest: "sha256:effective", AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour)}
	accepted, _, err := ledger.Accept(context.Background(), operation)
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	if _, err := ledger.Assign(context.Background(), operation.Principal, operation.ID, "host-a", now.Add(time.Minute)); err != nil {
		t.Fatalf("Assign() error = %v", err)
	}
	records, err := ledger.ReadOutbox(context.Background(), 0, 10)
	if err != nil {
		t.Fatalf("ReadOutbox() error = %v", err)
	}
	want := []OutboxEvent{OutboxAccepted, OutboxDispatched}
	if len(records) != len(want) {
		t.Fatalf("ReadOutbox() count = %d, want %d", len(records), len(want))
	}
	for index, event := range want {
		if records[index].ID != uint64(index+1) || records[index].Event != event || records[index].Principal != operation.Principal || records[index].OperationID != operation.ID || records[index].OperationVersion != accepted.Version+uint64(index) {
			t.Fatalf("ReadOutbox()[%d] = %#v", index, records[index])
		}
	}
	page, err := ledger.ReadOutbox(context.Background(), records[0].ID, 1)
	if err != nil || len(page) != 1 || page[0] != records[1] {
		t.Fatalf("ReadOutbox(after, limit) = %#v, %v", page, err)
	}
}

func TestMemoryLedgerHidesOtherPrincipalAndReapsExpiredCleanup(t *testing.T) {
	ledger := NewMemoryLedger()
	now := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	operation := Operation{Principal: "tenant-a:principal-a", ID: "op_01", CanonicalDigest: "sha256:request", EffectiveSpecDigest: "sha256:effective", AcceptedAt: now, RetentionExpiresAt: now.Add(time.Minute)}
	if _, _, err := ledger.Accept(context.Background(), operation); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	if _, err := ledger.Get(context.Background(), "tenant-b:principal-b", operation.ID); !errors.Is(err, ErrNotFoundOrDenied) {
		t.Fatalf("cross-principal Get() error = %v, want ErrNotFoundOrDenied", err)
	}
	pending, err := ledger.Transition(context.Background(), operation.Principal, operation.ID, 1, StateCleanupPending)
	if err != nil {
		t.Fatalf("Transition() error = %v", err)
	}
	if _, err := ledger.Transition(context.Background(), operation.Principal, operation.ID, pending.Version, StateCleanupConfirmed); err != nil {
		t.Fatalf("confirm cleanup Transition() error = %v", err)
	}
	reaped, err := ledger.Reap(context.Background(), now.Add(time.Minute), 10)
	if err != nil || len(reaped) != 1 || reaped[0].State != StateTombstoned {
		t.Fatalf("Reap() = %#v, %v", reaped, err)
	}
}

func TestMemoryLedgerRejectsChangedRequestAndIllegalTransition(t *testing.T) {
	ledger := NewMemoryLedger()
	now := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	operation := Operation{Principal: "tenant-a:principal-a", ID: "op_01", CanonicalDigest: "sha256:request", EffectiveSpecDigest: "sha256:effective", AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour)}
	if _, _, err := ledger.Accept(context.Background(), operation); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	operation.CanonicalDigest = "sha256:other"
	if _, _, err := ledger.Accept(context.Background(), operation); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed operation Accept() error = %v, want ErrConflict", err)
	}
	if _, err := ledger.Transition(context.Background(), "tenant-a:principal-a", "op_01", 1, StateSucceeded); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("Transition() error = %v, want ErrInvalidTransition", err)
	}
}

func TestMemoryLedgerRejectsUnboundedRecoveryIdentity(t *testing.T) {
	ledger := NewMemoryLedger()
	now := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	operation := Operation{Principal: strings.Repeat("p", maxPrincipalBytes+1), ID: "op_01", CanonicalDigest: "sha256:request", EffectiveSpecDigest: "sha256:effective", AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour)}
	if _, _, err := ledger.Accept(context.Background(), operation); err == nil {
		t.Fatal("Accept() error = nil, want bounded Principal rejection")
	}
}
