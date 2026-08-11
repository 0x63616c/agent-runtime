package firecrackerbootprobecomposition

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/firecracker"
	"github.com/0x63616c/agent-runtime/internal/firecrackerbootprobeprotocol"
	"github.com/0x63616c/agent-runtime/internal/firecrackerbootprobev2"
)

func TestRunRefusesAnUncompiledStageBeforeTheControlSubmitterCanRun(t *testing.T) {
	stage := &recordingStage{compileErr: errors.New("stage binding is not compiled")}
	called := false
	_, err := Run(context.Background(), Config{Stage: stage, Journal: &recordingJournal{events: &stage.events}, Snapshot: preparedSnapshot(t), GuestNonce: nonce, ObservationPrivateKey: observationKey(t), Submitter: SubmitterFunc(func(context.Context, firecrackerbootprobev2.Snapshot, firecracker.TrustedM4Identity, string, ed25519.PrivateKey) (firecrackerbootprobeprotocol.VerifiedCommand, error) {
		called = true
		return firecrackerbootprobeprotocol.VerifiedCommand{}, nil
	})})
	if err == nil || called || !reflect.DeepEqual(stage.events, []string{"compile", "cleanup"}) {
		t.Fatalf("Run() = (%v, %t, %#v), want uncompiled submit refusal and cleanup", err, called, stage.events)
	}
}

func TestRunRetriesOnlySubmissionThenJournalsConsumesAndCleansUp(t *testing.T) {
	stage := &recordingStage{identity: testIdentity()}
	attempts := 0
	result, err := Run(context.Background(), Config{Stage: stage, Journal: &recordingJournal{events: &stage.events}, Snapshot: preparedSnapshot(t), GuestNonce: func(context.Context) (string, error) {
		stage.events = append(stage.events, "nonce")
		return "YWJjZGVmZ2hpamtsbW5vcA", nil
	}, ObservationPrivateKey: func(context.Context) (ed25519.PrivateKey, error) {
		stage.events = append(stage.events, "key")
		return make(ed25519.PrivateKey, ed25519.PrivateKeySize), nil
	}, RetryAttempts: 2, Submitter: SubmitterFunc(func(context.Context, firecrackerbootprobev2.Snapshot, firecracker.TrustedM4Identity, string, ed25519.PrivateKey) (firecrackerbootprobeprotocol.VerifiedCommand, error) {
		attempts++
		stage.events = append(stage.events, "submit")
		if attempts == 1 {
			return firecrackerbootprobeprotocol.VerifiedCommand{}, errors.New("lost response")
		}
		return firecrackerbootprobeprotocol.VerifiedCommand{}, nil
	})})
	if err != nil || !result.Cleanup.Proved {
		t.Fatalf("Run() = (%#v, %v), want cleanup proof", result, err)
	}
	if got, want := stage.events, []string{"compile", "nonce", "key", "submit", "submit", "journal", "consume", "cleanup"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Run() actions = %#v, want %#v", got, want)
	}
}

func TestRunLeavesTheCommandUnconsumedAndCleansUpWhenJournalingRefuses(t *testing.T) {
	stage := &recordingStage{identity: testIdentity()}
	_, err := Run(context.Background(), Config{Stage: stage, Journal: &recordingJournal{events: &stage.events, err: errors.New("disk full")}, Snapshot: preparedSnapshot(t), GuestNonce: nonce, ObservationPrivateKey: observationKey(t), Submitter: SubmitterFunc(func(context.Context, firecrackerbootprobev2.Snapshot, firecracker.TrustedM4Identity, string, ed25519.PrivateKey) (firecrackerbootprobeprotocol.VerifiedCommand, error) {
		stage.events = append(stage.events, "submit")
		return firecrackerbootprobeprotocol.VerifiedCommand{}, nil
	})})
	if err == nil {
		t.Fatal("Run() error = nil, want journal refusal")
	}
	if got, want := stage.events, []string{"compile", "submit", "journal", "cleanup"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Run() actions = %#v, want %#v", got, want)
	}
}

type recordingStage struct {
	identity   firecracker.TrustedM4Identity
	compileErr error
	events     []string
}

func (stage *recordingStage) Compile(context.Context) (firecracker.TrustedM4Identity, error) {
	stage.events = append(stage.events, "compile")
	return stage.identity, stage.compileErr
}
func (stage *recordingStage) Consume(context.Context, firecrackerbootprobeprotocol.VerifiedCommand) error {
	stage.events = append(stage.events, "consume")
	return nil
}
func (stage *recordingStage) Cleanup(context.Context) (firecracker.CleanupProof, error) {
	stage.events = append(stage.events, "cleanup")
	return firecracker.CleanupProof{Proved: true}, nil
}

type recordingJournal struct {
	events *[]string
	err    error
}

func (j *recordingJournal) Record(context.Context, firecrackerbootprobev2.Snapshot, firecrackerbootprobeprotocol.VerifiedCommand) error {
	*j.events = append(*j.events, "journal")
	return j.err
}
func nonce(context.Context) (string, error) { return "YWJjZGVmZ2hpamtsbW5vcA", nil }
func observationKey(t *testing.T) func(context.Context) (ed25519.PrivateKey, error) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return func(context.Context) (ed25519.PrivateKey, error) { return private, nil }
}
func testIdentity() firecracker.TrustedM4Identity { return firecracker.TrustedM4Identity{} }
func preparedSnapshot(t *testing.T) firecrackerbootprobev2.Snapshot {
	t.Helper()
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	binding := firecrackerbootprobev2.Binding{HostID: "host-001", HostGeneration: 1, AssignmentID: "assignment-001", Tenant: "tenant-001", Principal: "tenant-001:runtime", SandboxID: "sandbox-001", OperationID: "operation-001", OperationKind: "firecracker-boot-probe", EffectiveSpecDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CapabilityDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", CanonicalRequestDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
	delivery := firecrackerbootprobev2.Delivery{EnvelopeID: "envelope-001", DeliveryID: "delivery-001", Nonce: "YWJjZGVmZ2hpamtsbW5vcA", LeaseEpoch: 1, FencingToken: 1, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	state, err := firecrackerbootprobev2.NewState(binding, "host-instance-001", delivery, now)
	if err != nil {
		t.Fatal(err)
	}
	session, err := firecrackerbootprobev2.NewSession(state)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := firecrackerbootprobev2.EncodeSession(session)
	if err != nil {
		t.Fatal(err)
	}
	return firecrackerbootprobev2.Snapshot{Version: 1, Session: session, Wire: wire}
}
