package firecrackerbootprobelease

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/firecrackerlaunchgrant"
	"github.com/0x63616c/agent-runtime/sandbox"
)

// The private boot-probe lease seam accepts only an already-authenticated,
// exactly-successive grant. It records probe-start intent, but does not launch
// a Jailer, guest, or PING.
func TestLeaseRecordsOneProbeStartAndPreservesItAcrossAnExactRenewal(t *testing.T) {
	now := time.Date(2026, time.August, 10, 13, 0, 0, 0, time.UTC)
	initial := validGrant(t, now)
	guard, err := NewGuard(initial, now)
	if err != nil {
		t.Fatalf("NewGuard() error = %v", err)
	}
	state := guard.Snapshot()
	if state.Phase != PhaseActive || state.Probe != ProbePending || state.Initial != initial || state.Current != initial || state.RenewalCount != 0 {
		t.Fatalf("Seal() = %#v, want active initial state", state)
	}

	started, err := guard.RecordProbeStarted(now.Add(time.Second))
	if err != nil {
		t.Fatalf("RecordProbeStarted() error = %v", err)
	}
	if started.Probe != ProbeStarted {
		t.Fatalf("RecordProbeStarted() Probe = %q, want %q", started.Probe, ProbeStarted)
	}

	renewal := exactRenewal(t, initial, now.Add(time.Minute))
	renewed, err := guard.RenewAuthenticated(renewal, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("RenewAuthenticated() error = %v", err)
	}
	if renewed.Initial != initial || renewed.Current != renewal || renewed.Probe != ProbeStarted || renewed.RenewalCount != 1 {
		t.Fatalf("RenewAuthenticated() = %#v, want initial binding, new current tuple, and one recorded start", renewed)
	}
	forked := exactRenewal(t, initial, now.Add(time.Minute))
	forked.Envelope.EnvelopeID = "envelope_03"
	forked.Envelope.DeliveryID = "delivery_03"
	forked.Envelope.Nonce = "MDEyMzQ1Njc4OWFiY2RlZg"
	forked, err = firecrackerlaunchgrant.New(forked.Envelope, forked.M4)
	if err != nil {
		t.Fatalf("firecrackerlaunchgrant.New(forked) error = %v", err)
	}
	if _, err := guard.RenewAuthenticated(forked, now.Add(time.Minute)); !errors.Is(err, ErrRenewalRefused) {
		t.Fatalf("RenewAuthenticated(forked) error = %v, want ErrRenewalRefused", err)
	}
	if _, err := guard.RecordProbeStarted(now.Add(time.Minute + time.Second)); !errors.Is(err, ErrProbeAlreadyStarted) {
		t.Fatalf("RecordProbeStarted() after renewal error = %v, want ErrProbeAlreadyStarted", err)
	}

	wire, err := Encode(renewed)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	replayed, err := Decode(wire)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if !reflect.DeepEqual(replayed, renewed) {
		t.Fatalf("Decode(Encode()) = %#v, want %#v", replayed, renewed)
	}
	recovered, err := Restore(replayed)
	if err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	secondRenewal := exactRenewal(t, renewal, now.Add(2*time.Minute))
	if state, err := recovered.RenewAuthenticated(secondRenewal, now.Add(2*time.Minute)); err != nil || state.RenewalCount != 2 || state.Current != secondRenewal || state.Probe != ProbeStarted {
		t.Fatalf("recovered RenewAuthenticated() = (%#v, %v), want second exact successor without a new probe start", state, err)
	}
}

func TestRenewAuthenticatedRefusesAnythingButTheExactNextAuthenticatedDeliveryTupleAndFence(t *testing.T) {
	now := time.Date(2026, time.August, 10, 13, 0, 0, 0, time.UTC)
	initial := validGrant(t, now)
	guard, err := NewGuard(initial, now)
	if err != nil {
		t.Fatalf("NewGuard() error = %v", err)
	}

	for name, mutate := range map[string]func(*firecrackerlaunchgrant.Grant){
		"stale delivery and fence": func(candidate *firecrackerlaunchgrant.Grant) {
			*candidate = initial
		},
		"forked fence": func(candidate *firecrackerlaunchgrant.Grant) {
			candidate.Envelope.FencingToken++
		},
		"skipped lease epoch": func(candidate *firecrackerlaunchgrant.Grant) {
			candidate.Envelope.LeaseEpoch++
		},
		"reused delivery ID": func(candidate *firecrackerlaunchgrant.Grant) {
			candidate.Envelope.DeliveryID = initial.Envelope.DeliveryID
		},
		"reused nonce": func(candidate *firecrackerlaunchgrant.Grant) {
			candidate.Envelope.Nonce = initial.Envelope.Nonce
		},
		"M4 fixture substitution": func(candidate *firecrackerlaunchgrant.Grant) {
			candidate.M4.FixtureDigest = testDigest('0')
		},
		"principal scope substitution": func(candidate *firecrackerlaunchgrant.Grant) {
			candidate.Envelope.Principal = "tenant_01:other-operator"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := exactRenewal(t, initial, now.Add(time.Minute))
			mutate(&candidate)
			if _, err := guard.RenewAuthenticated(candidate, now.Add(time.Minute)); !errors.Is(err, ErrRenewalRefused) {
				t.Fatalf("RenewAuthenticated() error = %v, want ErrRenewalRefused", err)
			}
		})
	}
}

func TestAdvanceTimeMakesAnExpiredLeaseCleanupPendingAndPreventsRenewalOrStart(t *testing.T) {
	now := time.Date(2026, time.August, 10, 13, 0, 0, 0, time.UTC)
	initial := validGrant(t, now)
	guard, err := NewGuard(initial, now)
	if err != nil {
		t.Fatalf("NewGuard() error = %v", err)
	}

	expired, err := guard.AdvanceTime(initial.Envelope.ExpiresAt)
	if err != nil {
		t.Fatalf("AdvanceTime() error = %v", err)
	}
	if expired.Phase != PhaseExpiredCleanupPending || !expired.CleanupPending() {
		t.Fatalf("AdvanceTime() = %#v, want expired cleanup-pending state", expired)
	}
	if next, err := guard.RenewAuthenticated(exactRenewal(t, initial, now.Add(time.Minute)), now.Add(time.Minute)); !errors.Is(err, ErrLeaseExpired) || next != expired {
		t.Fatalf("RenewAuthenticated(expired) = (%#v, %v), want unchanged state and ErrLeaseExpired", next, err)
	}
	if next, err := guard.RecordProbeStarted(now.Add(time.Minute)); !errors.Is(err, ErrLeaseExpired) || next != expired {
		t.Fatalf("RecordProbeStarted(expired) = (%#v, %v), want unchanged state and ErrLeaseExpired", next, err)
	}
}

func TestDecodeRefusesNonCanonicalOrInconsistentPersistedLeaseState(t *testing.T) {
	now := time.Date(2026, time.August, 10, 13, 0, 0, 0, time.UTC)
	guard, err := NewGuard(validGrant(t, now), now)
	if err != nil {
		t.Fatalf("NewGuard() error = %v", err)
	}
	state := guard.Snapshot()
	wire, err := Encode(state)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if _, err := Decode(append([]byte(" "), wire...)); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Decode(non-canonical) error = %v, want ErrInvalidState", err)
	}

	state.RenewalCount = 1
	inconsistent, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if _, err := Decode(inconsistent); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Decode(inconsistent) error = %v, want ErrInvalidState", err)
	}
	if bytes.Equal(wire, inconsistent) {
		t.Fatal("test fixture did not alter persisted state")
	}
}

func validGrant(t *testing.T, issuedAt time.Time) firecrackerlaunchgrant.Grant {
	t.Helper()
	grant, err := firecrackerlaunchgrant.New(firecrackerlaunchgrant.EnvelopeTuple{
		EnvelopeID:             "envelope_01",
		DeliveryID:             "delivery_01",
		Nonce:                  "MDEyMzQ1Njc4OWFiY2RlZg",
		IssuedAt:               issuedAt,
		ExpiresAt:              issuedAt.Add(2 * time.Minute),
		HostID:                 "host_01",
		HostGeneration:         7,
		AssignmentID:           "assignment_01",
		LeaseEpoch:             4,
		FencingToken:           4,
		Tenant:                 "tenant_01",
		Principal:              "tenant_01:operator_01",
		SandboxID:              "sbx_01",
		OperationID:            "operation_01",
		OperationKind:          firecrackerlaunchgrant.OperatorBootProbeOperation,
		EffectiveSpecDigest:    testDigest('a'),
		CapabilityDigest:       testDigest('b'),
		CanonicalRequestDigest: testDigest('c'),
	}, firecrackerlaunchgrant.TrustedM4Identity{
		VMID:            "sandbox-001",
		FixtureVersion:  "fixture-v1",
		PlanDigest:      testDigest('d'),
		FixtureDigest:   testDigest('e'),
		StageDigest:     testDigest('f'),
		AuthorityDigest: testDigest('1'),
	})
	if err != nil {
		t.Fatalf("firecrackerlaunchgrant.New() error = %v", err)
	}
	return grant
}

func exactRenewal(t *testing.T, previous firecrackerlaunchgrant.Grant, issuedAt time.Time) firecrackerlaunchgrant.Grant {
	t.Helper()
	next := previous
	if previous.Envelope.LeaseEpoch == 4 {
		next.Envelope.EnvelopeID = "envelope_02"
		next.Envelope.DeliveryID = "delivery_02"
		next.Envelope.Nonce = "ZmVkY2JhOTg3NjU0MzIxMA"
	} else {
		next.Envelope.EnvelopeID = "envelope_03"
		next.Envelope.DeliveryID = "delivery_03"
		next.Envelope.Nonce = "YWJjZGVmZ2hpamtsbW5vcA"
	}
	next.Envelope.IssuedAt = issuedAt
	next.Envelope.ExpiresAt = issuedAt.Add(2 * time.Minute)
	next.Envelope.LeaseEpoch++
	next.Envelope.FencingToken++
	grant, err := firecrackerlaunchgrant.New(next.Envelope, next.M4)
	if err != nil {
		t.Fatalf("firecrackerlaunchgrant.New(renewal) error = %v", err)
	}
	return grant
}

func testDigest(nibble rune) sandbox.Digest {
	return sandbox.Digest("sha256:" + string(bytes.Repeat([]byte(string(nibble)), 64)))
}
