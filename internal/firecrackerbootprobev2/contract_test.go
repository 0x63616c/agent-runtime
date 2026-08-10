package firecrackerbootprobev2

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/sandbox"
)

func TestStateAcceptsOneExactSuccessorAndClassifiesDelayedAcknowledgementAsKnownSuperseded(t *testing.T) {
	now := time.Date(2026, time.August, 10, 15, 0, 0, 0, time.UTC)
	initial := validDelivery(now)
	state, err := NewState(validBinding(), "host-session-01", initial, now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}

	successor := exactSuccessor(initial, now.Add(time.Minute))
	next, err := state.AcceptAuthenticatedSuccessor("host-session-01", successor, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("AcceptAuthenticatedSuccessor() error = %v", err)
	}
	if next.Binding != state.Binding || next.HostInstanceSessionID != state.HostInstanceSessionID || next.Current != successor || len(next.Superseded) != 1 || next.Superseded[0] != initial {
		t.Fatalf("AcceptAuthenticatedSuccessor() = %#v, want current successor and retained initial delivery", next)
	}

	classification, err := next.ClassifyAcknowledgement(Acknowledgement{HostInstanceSessionID: "host-session-01", DeliveryID: initial.DeliveryID, Nonce: initial.Nonce, LeaseEpoch: initial.LeaseEpoch, FencingToken: initial.FencingToken})
	if err != nil || classification != AcknowledgementKnownSuperseded {
		t.Fatalf("ClassifyAcknowledgement(delayed initial ACK) = (%q, %v), want (%q, nil)", classification, err, AcknowledgementKnownSuperseded)
	}
	classification, err = next.ClassifyAcknowledgement(Acknowledgement{HostInstanceSessionID: "host-session-01", DeliveryID: successor.DeliveryID, Nonce: successor.Nonce, LeaseEpoch: successor.LeaseEpoch, FencingToken: successor.FencingToken})
	if err != nil || classification != AcknowledgementCurrent {
		t.Fatalf("ClassifyAcknowledgement(current ACK) = (%q, %v), want (%q, nil)", classification, err, AcknowledgementCurrent)
	}
	classification, err = next.ClassifyAcknowledgement(Acknowledgement{HostInstanceSessionID: "host-session-02", DeliveryID: initial.DeliveryID, Nonce: initial.Nonce, LeaseEpoch: initial.LeaseEpoch, FencingToken: initial.FencingToken})
	if err != nil || classification != AcknowledgementUnknown {
		t.Fatalf("ClassifyAcknowledgement(cross-instance delayed ACK) = (%q, %v), want (%q, nil)", classification, err, AcknowledgementUnknown)
	}

	wire, err := Encode(next)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	replayed, err := Decode(wire)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if !reflect.DeepEqual(replayed, next) {
		t.Fatalf("Decode(Encode()) = %#v, want %#v", replayed, next)
	}
}

func TestStateRefusesForkedStaleOrNonExtendingSuccessorsAndCrossInstanceSessions(t *testing.T) {
	now := time.Date(2026, time.August, 10, 15, 0, 0, 0, time.UTC)
	initial := validDelivery(now)
	state, err := NewState(validBinding(), "host-session-01", initial, now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}

	for name, mutate := range map[string]func(*Delivery){
		"stale current delivery":  func(candidate *Delivery) { *candidate = initial },
		"forked epoch":            func(candidate *Delivery) { candidate.LeaseEpoch++ },
		"forked fence":            func(candidate *Delivery) { candidate.FencingToken++ },
		"non-extending issued at": func(candidate *Delivery) { candidate.IssuedAt = initial.IssuedAt },
		"non-extending expiry":    func(candidate *Delivery) { candidate.ExpiresAt = initial.ExpiresAt },
		"reused delivery ID":      func(candidate *Delivery) { candidate.DeliveryID = initial.DeliveryID },
		"reused nonce":            func(candidate *Delivery) { candidate.Nonce = initial.Nonce },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := exactSuccessor(initial, now.Add(time.Minute))
			mutate(&candidate)
			if _, err := state.AcceptAuthenticatedSuccessor("host-session-01", candidate, now.Add(time.Minute)); !errors.Is(err, ErrSuccessorRefused) {
				t.Fatalf("AcceptAuthenticatedSuccessor() error = %v, want ErrSuccessorRefused", err)
			}
		})
	}

	if _, err := state.AcceptAuthenticatedSuccessor("host-session-02", exactSuccessor(initial, now.Add(time.Minute)), now.Add(time.Minute)); !errors.Is(err, ErrSuccessorRefused) {
		t.Fatalf("AcceptAuthenticatedSuccessor(cross-instance) error = %v, want ErrSuccessorRefused", err)
	}
}

func TestStateRejectsNonCanonicalNonceAndNonCanonicalOrForkedPersistedState(t *testing.T) {
	now := time.Date(2026, time.August, 10, 15, 0, 0, 0, time.UTC)
	initial := validDelivery(now)
	initial.Nonce += "="
	if _, err := NewState(validBinding(), "host-session-01", initial, now); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("NewState(non-canonical nonce) error = %v, want ErrInvalidState", err)
	}

	state, err := NewState(validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	next, err := state.AcceptAuthenticatedSuccessor("host-session-01", exactSuccessor(state.Current, now.Add(time.Minute)), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("AcceptAuthenticatedSuccessor() error = %v", err)
	}
	wire, err := Encode(next)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if _, err := Decode(append([]byte(" "), wire...)); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Decode(non-canonical) error = %v, want ErrInvalidState", err)
	}
	broken := next
	broken.Superseded[0].FencingToken++
	if _, err := Encode(broken); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Encode(forked history) error = %v, want ErrInvalidState", err)
	}
	if bytes.Equal(wire, []byte{}) {
		t.Fatal("encoded state must not be empty")
	}
}

func TestStateRejectsNilSupersededHistorySoTheEmptyHistoryHasOneCanonicalWire(t *testing.T) {
	now := time.Date(2026, time.August, 10, 15, 0, 0, 0, time.UTC)
	state, err := NewState(validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	state.Superseded = nil
	if _, err := Encode(state); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Encode(nil superseded history) error = %v, want ErrInvalidState", err)
	}
	nonCanonical, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("json.Marshal(nil superseded history) error = %v", err)
	}
	if _, err := Decode(nonCanonical); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Decode(null superseded history) error = %v, want ErrInvalidState", err)
	}
}

func TestStateRefusesASuccessorWhenRetainingItWouldExceedTheAcknowledgementHistoryBound(t *testing.T) {
	now := time.Date(2026, time.August, 10, 15, 0, 0, 0, time.UTC)
	state, err := NewState(validBinding(), "host-session-01", validDelivery(now), now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	for sequence := 1; sequence <= maximumHistory; sequence++ {
		issuedAt := now.Add(time.Duration(sequence) * time.Second)
		state, err = state.AcceptAuthenticatedSuccessor("host-session-01", uniqueSuccessor(state.Current, sequence, issuedAt), issuedAt)
		if err != nil {
			t.Fatalf("AcceptAuthenticatedSuccessor(sequence=%d) error = %v", sequence, err)
		}
	}
	if len(state.Superseded) != maximumHistory {
		t.Fatalf("retained superseded deliveries = %d, want %d", len(state.Superseded), maximumHistory)
	}
	issuedAt := now.Add(time.Duration(maximumHistory+1) * time.Second)
	if _, err := state.AcceptAuthenticatedSuccessor("host-session-01", uniqueSuccessor(state.Current, maximumHistory+1, issuedAt), issuedAt); !errors.Is(err, ErrSuccessorRefused) {
		t.Fatalf("AcceptAuthenticatedSuccessor(over capacity) error = %v, want ErrSuccessorRefused", err)
	}
}

func TestStateEncodesTheLargestAcceptedHistoryWithMaximumLengthSafeFields(t *testing.T) {
	now := time.Date(2026, time.August, 10, 15, 0, 0, 1, time.UTC)
	state, err := NewState(maximumLengthBinding(), strings.Repeat("s", 128), maximumLengthDelivery(0, now), now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	for sequence := 1; sequence <= maximumHistory; sequence++ {
		issuedAt := now.Add(time.Duration(sequence) * time.Second)
		state, err = state.AcceptAuthenticatedSuccessor(state.HostInstanceSessionID, maximumLengthDelivery(sequence, issuedAt), issuedAt)
		if err != nil {
			t.Fatalf("AcceptAuthenticatedSuccessor(sequence=%d) error = %v", sequence, err)
		}
	}
	if _, err := Encode(state); err != nil {
		t.Fatalf("Encode(maximum accepted state) error = %v", err)
	}
}

func TestStateRefusesAnEscapedMaximumValueSuccessorBeforeItExceedsTheCanonicalWireBound(t *testing.T) {
	now := time.Date(2026, time.August, 10, 15, 0, 0, 1, time.UTC)
	state, err := NewState(maximumEscapedBinding(), strings.Repeat("\x01", 128), maximumEscapedDelivery(0, now), now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	accepted := 0
	for sequence := 1; sequence <= maximumHistory; sequence++ {
		issuedAt := now.Add(time.Duration(sequence) * time.Second)
		next, err := state.AcceptAuthenticatedSuccessor(state.HostInstanceSessionID, maximumEscapedDelivery(sequence, issuedAt), issuedAt)
		if errors.Is(err, ErrSuccessorRefused) {
			break
		}
		if err != nil {
			t.Fatalf("AcceptAuthenticatedSuccessor(sequence=%d) error = %v", sequence, err)
		}
		state, accepted = next, accepted+1
	}
	if accepted == maximumHistory {
		t.Fatalf("accepted %d successors, want a persisted-wire-bound refusal before %d", accepted, maximumHistory)
	}
	if _, err := Encode(state); err != nil {
		t.Fatalf("Encode(last accepted escaped state) error = %v", err)
	}
}

func validBinding() Binding {
	return Binding{
		HostID:                 "host_01",
		HostGeneration:         7,
		AssignmentID:           "assignment_01",
		Tenant:                 "tenant_01",
		Principal:              "tenant_01:operator_01",
		SandboxID:              "sbx_01",
		OperationID:            "operation_01",
		OperationKind:          operatorBootProbe,
		EffectiveSpecDigest:    testDigest('b'),
		CapabilityDigest:       testDigest('c'),
		CanonicalRequestDigest: testDigest('a'),
	}
}

func validDelivery(issuedAt time.Time) Delivery {
	return Delivery{
		DeliveryID:   "delivery_01",
		Nonce:        "MDEyMzQ1Njc4OWFiY2RlZg",
		IssuedAt:     issuedAt,
		ExpiresAt:    issuedAt.Add(2 * time.Minute),
		LeaseEpoch:   4,
		FencingToken: 4,
	}
}

func exactSuccessor(previous Delivery, issuedAt time.Time) Delivery {
	return Delivery{
		DeliveryID:   "delivery_02",
		Nonce:        "ZmVkY2JhOTg3NjU0MzIxMA",
		IssuedAt:     issuedAt,
		ExpiresAt:    issuedAt.Add(2 * time.Minute),
		LeaseEpoch:   previous.LeaseEpoch + 1,
		FencingToken: previous.FencingToken + 1,
	}
}

func uniqueSuccessor(previous Delivery, sequence int, issuedAt time.Time) Delivery {
	return Delivery{
		DeliveryID:   fmt.Sprintf("delivery-%03d", sequence+1),
		Nonce:        base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("nonce-value-%05d", sequence))),
		IssuedAt:     issuedAt,
		ExpiresAt:    issuedAt.Add(2 * time.Minute),
		LeaseEpoch:   previous.LeaseEpoch + 1,
		FencingToken: previous.FencingToken + 1,
	}
}

func maximumLengthBinding() Binding {
	tenant := strings.Repeat("t", 256)
	return Binding{
		HostID:                 strings.Repeat("h", 128),
		HostGeneration:         1,
		AssignmentID:           strings.Repeat("a", 128),
		Tenant:                 tenant,
		Principal:              tenant + ":" + strings.Repeat("p", 255),
		SandboxID:              strings.Repeat("s", 128),
		OperationID:            strings.Repeat("o", 128),
		OperationKind:          operatorBootProbe,
		EffectiveSpecDigest:    testDigest('a'),
		CapabilityDigest:       testDigest('b'),
		CanonicalRequestDigest: testDigest('c'),
	}
}

func maximumLengthDelivery(sequence int, issuedAt time.Time) Delivery {
	return Delivery{
		DeliveryID:   fmt.Sprintf("delivery-%0119d", sequence),
		Nonce:        base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(sequence)}, 64)),
		IssuedAt:     issuedAt,
		ExpiresAt:    issuedAt.Add(5 * time.Minute),
		LeaseEpoch:   math.MaxUint64 - maximumHistory + uint64(sequence),
		FencingToken: math.MaxUint64 - maximumHistory + uint64(sequence),
	}
}

func maximumEscapedBinding() Binding {
	tenant := strings.Repeat("\x01", 256)
	return Binding{
		HostID:                 strings.Repeat("\x01", 128),
		HostGeneration:         1,
		AssignmentID:           strings.Repeat("\x01", 128),
		Tenant:                 tenant,
		Principal:              tenant + ":" + strings.Repeat("\x01", 255),
		SandboxID:              strings.Repeat("\x01", 128),
		OperationID:            strings.Repeat("\x01", 128),
		OperationKind:          operatorBootProbe,
		EffectiveSpecDigest:    testDigest('a'),
		CapabilityDigest:       testDigest('b'),
		CanonicalRequestDigest: testDigest('c'),
	}
}

func maximumEscapedDelivery(sequence int, issuedAt time.Time) Delivery {
	return Delivery{
		DeliveryID:   strings.Repeat("\x01", 127) + string(rune(sequence+1)),
		Nonce:        base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(sequence)}, 64)),
		IssuedAt:     issuedAt,
		ExpiresAt:    issuedAt.Add(5 * time.Minute),
		LeaseEpoch:   math.MaxUint64 - maximumHistory + uint64(sequence),
		FencingToken: math.MaxUint64 - maximumHistory + uint64(sequence),
	}
}

func testDigest(nibble rune) sandbox.Digest {
	return sandbox.Digest("sha256:" + string(bytes.Repeat([]byte(string(nibble)), 64)))
}
