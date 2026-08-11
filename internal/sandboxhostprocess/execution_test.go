package sandboxhostprocess

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostjournal"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/cockroachdb/errors"
)

func TestExecuteEnvelopePersistsStartedBeforeCallingTheExecutor(t *testing.T) {
	t.Parallel()

	envelope, now := executionEnvelope()
	journal := executionJournal(t, envelope)
	startedBeforeExecute := false
	executor := executorFunc(func(context.Context, sandboxhostprotocol.Envelope) error {
		startedBeforeExecute = journal.ExecutionStarted(envelope)
		return nil
	})
	var sent [][]byte
	deadline := func(ctx context.Context, expiresAt time.Time) (context.Context, context.CancelFunc) {
		if expiresAt != envelope.ExpiresAt {
			t.Fatalf("executor deadline = %s, want envelope expiry %s", expiresAt, envelope.ExpiresAt)
		}
		return ctx, func() {}
	}
	if err := executeEnvelope(context.Background(), envelope, now, journal, executionPrivateKey(), executor, func(_ context.Context, wire []byte) error {
		sent = append(sent, append([]byte(nil), wire...))
		return nil
	}, deadline); err != nil {
		t.Fatalf("executeEnvelope: %v", err)
	}
	if !startedBeforeExecute || len(sent) != 2 || resultState(t, sent[0]) != "started" || resultState(t, sent[1]) != "succeeded" {
		t.Fatalf("execution ordering = started:%t sent:%d states:%q,%q", startedBeforeExecute, len(sent), resultState(t, sent[0]), resultState(t, sent[1]))
	}
	if len(journal.PendingResults()) != 0 || len(journal.PendingStarts()) != 0 {
		t.Fatal("execution observations remain unacknowledged after successful sends")
	}
}

func TestAuthenticatedExecutorReceivesOnlyTheExactVerifiedControlWire(t *testing.T) {
	envelope, _ := executionEnvelope()
	wire := []byte("control-signed-canonical-envelope")
	executor := &recordingAuthenticatedExecutor{}
	bound := bindAuthenticatedEnvelope(executor, wire)
	if err := bound.Execute(context.Background(), envelope); err != nil {
		t.Fatalf("bound Execute() error = %v", err)
	}
	if executor.envelope.EnvelopeID != envelope.EnvelopeID || string(executor.wire) != string(wire) {
		t.Fatalf("authenticated executor = (%#v, %q), want exact envelope and wire", executor.envelope, executor.wire)
	}
	wire[0] = 'x'
	if string(executor.wire) != "control-signed-canonical-envelope" {
		t.Fatalf("authenticated executor retained caller wire mutation = %q", executor.wire)
	}
}

func TestExecuteEnvelopeStagesAndAcknowledgesOutputBeforeTerminalResult(t *testing.T) {
	envelope, now := executionEnvelope()
	journal := executionJournal(t, envelope)
	executor := outputReportingExecutor{emit: func(ctx context.Context, emit OutputEmitter) error {
		return emit(ctx, ExecutionOutput{Stream: "stdout", Sequence: 0, Data: []byte("bounded")})
	}}
	var outputs, results [][]byte
	err := executeEnvelopeWithOutput(context.Background(), envelope, now, journal, executionPrivateKey(), executor, func(_ context.Context, wire []byte) error {
		results = append(results, append([]byte(nil), wire...))
		return nil
	}, func(_ context.Context, wire []byte) error {
		outputs = append(outputs, append([]byte(nil), wire...))
		return nil
	}, func(ctx context.Context, _ time.Time) (context.Context, context.CancelFunc) { return ctx, func() {} })
	if err != nil {
		t.Fatalf("executeEnvelopeWithOutput() error = %v", err)
	}
	if len(outputs) != 1 || len(results) != 2 || resultState(t, results[1]) != "succeeded" {
		t.Fatalf("outputs=%d results=%d terminal=%q", len(outputs), len(results), resultState(t, results[1]))
	}
	if len(journal.PendingOutputs()) != 0 || len(journal.PendingResults()) != 0 {
		t.Fatal("output or terminal acknowledgement remained pending")
	}
}

func TestExecuteEnvelopeRequiresDurablePublicDataReceiptAckBeforeSuccess(t *testing.T) {
	envelope, now := executionEnvelope()
	journal := executionJournal(t, envelope)
	receipt := []byte(`{"artifact_id":"artifact_001","version":"agent-runtime.transfer-receipt/v1"}`)
	executor := dataPlaneReceiptReportingExecutor{emit: func(ctx context.Context, emit DataPlaneReceiptEmitter) error {
		if err := journal.StageTypedTransferReceipt(envelope, "transfer", receipt); err != nil {
			return err
		}
		return emit(ctx, "transfer", receipt)
	}}
	var results, dataReceipts [][]byte
	err := executeEnvelopeWithOutputAfterTerminalSend(context.Background(), envelope, now, journal, executionPrivateKey(), executor, func(_ context.Context, wire []byte) error {
		if resultState(t, wire) == "succeeded" && len(journal.PendingTransferReceipts()) != 0 {
			t.Fatal("success was posted before the durable data-plane receipt acknowledgement")
		}
		results = append(results, append([]byte(nil), wire...))
		return nil
	}, nil, func(_ context.Context, wire []byte) error {
		dataReceipts = append(dataReceipts, append([]byte(nil), wire...))
		verified, err := sandboxhostprotocol.VerifyDataPlaneReceipt(wire, executionPrivateKey().Public().(ed25519.PublicKey))
		if err != nil || verified.AssignmentID != envelope.AssignmentID || verified.FencingToken != envelope.FencingToken || verified.ReceiptDigest != sandboxhostprotocol.Digest(receipt) {
			t.Fatalf("VerifyDataPlaneReceipt() = %#v, %v", verified, err)
		}
		return nil
	}, func(ctx context.Context, _ time.Time) (context.Context, context.CancelFunc) { return ctx, func() {} }, nil)
	if err != nil || len(dataReceipts) != 1 || len(results) != 2 || resultState(t, results[1]) != "succeeded" || len(journal.PendingTransferReceipts()) != 0 {
		t.Fatalf("receipt execution error=%v receipts=%d results=%d terminal=%q pending=%d", err, len(dataReceipts), len(results), resultState(t, results[len(results)-1]), len(journal.PendingTransferReceipts()))
	}
}

func TestExecuteEnvelopeRefusesTerminalResultWhenDataReceiptAckIsLost(t *testing.T) {
	envelope, now := executionEnvelope()
	journal := executionJournal(t, envelope)
	receipt := []byte(`{"artifact_id":"artifact_001","version":"agent-runtime.transfer-receipt/v1"}`)
	executor := dataPlaneReceiptReportingExecutor{emit: func(ctx context.Context, emit DataPlaneReceiptEmitter) error {
		if err := journal.StageTypedTransferReceipt(envelope, "transfer", receipt); err != nil {
			return err
		}
		return emit(ctx, "transfer", receipt)
	}}
	var results [][]byte
	err := executeEnvelopeWithOutputAfterTerminalSend(context.Background(), envelope, now, journal, executionPrivateKey(), executor, func(_ context.Context, wire []byte) error {
		results = append(results, append([]byte(nil), wire...))
		return nil
	}, nil, func(context.Context, []byte) error { return errors.New("control unavailable") }, func(ctx context.Context, _ time.Time) (context.Context, context.CancelFunc) { return ctx, func() {} }, nil)
	if err == nil || len(results) != 1 || resultState(t, results[0]) != "started" || len(journal.PendingTransferReceipts()) != 1 || len(journal.PendingResults()) != 0 {
		t.Fatalf("lost receipt acknowledgement error=%v results=%d state=%q pending-receipts=%d pending-results=%d", err, len(results), resultState(t, results[0]), len(journal.PendingTransferReceipts()), len(journal.PendingResults()))
	}
}

func TestPendingDataPlaneReceiptReplayPreservesItsDurableFence(t *testing.T) {
	privateKey := executionPrivateKey()
	receipt := []byte(`{"snapshot_id":"snapshot_01","version":"agent-runtime.snapshot-restore-receipt/v1"}`)
	entry := sandboxhostjournal.Entry{ReceiptKey: "host_01\x00assignment_01\x00op_01\x00sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", HostGeneration: 1, LeaseEpoch: 2, FencingToken: 3}
	wire, err := signPendingDataPlaneReceipt(entry, "snapshot-restore", receipt, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := sandboxhostprotocol.VerifyDataPlaneReceipt(wire, privateKey.Public().(ed25519.PublicKey))
	if err != nil || verified.HostGeneration != entry.HostGeneration || verified.LeaseEpoch != entry.LeaseEpoch || verified.FencingToken != entry.FencingToken || verified.Kind != "snapshot-restore" {
		t.Fatalf("replayed receipt = %#v, %v", verified, err)
	}
	entry.HostGeneration = 0
	if _, err := signPendingDataPlaneReceipt(entry, "snapshot-restore", receipt, privateKey); err == nil {
		t.Fatal("legacy receipt without host generation was replayed")
	}
}

type recordingAuthenticatedExecutor struct {
	envelope sandboxhostprotocol.Envelope
	wire     []byte
}

type recordingAuthenticatedReapingExecutor struct {
	executeEnvelope sandboxhostprotocol.Envelope
	executeWire     []byte
	reapEnvelope    sandboxhostprotocol.Envelope
	reapWire        []byte
	executeErr      error
}

type outputReportingExecutor struct {
	emit func(context.Context, OutputEmitter) error
}

type dataPlaneReceiptReportingExecutor struct {
	emit func(context.Context, DataPlaneReceiptEmitter) error
}

func (executor dataPlaneReceiptReportingExecutor) Execute(context.Context, sandboxhostprotocol.Envelope) error {
	return nil
}

func (executor dataPlaneReceiptReportingExecutor) ExecuteWithDataPlaneReceipt(ctx context.Context, _ sandboxhostprotocol.Envelope, emit DataPlaneReceiptEmitter) error {
	return executor.emit(ctx, emit)
}

func (executor outputReportingExecutor) Execute(context.Context, sandboxhostprotocol.Envelope) error {
	return nil
}
func (executor outputReportingExecutor) ExecuteWithOutput(ctx context.Context, _ sandboxhostprotocol.Envelope, emit OutputEmitter) error {
	return executor.emit(ctx, emit)
}

func (executor *recordingAuthenticatedExecutor) Execute(context.Context, sandboxhostprotocol.Envelope) error {
	return nil
}

func (executor *recordingAuthenticatedExecutor) ExecuteAuthenticated(_ context.Context, envelope sandboxhostprotocol.Envelope, wire []byte) error {
	executor.envelope = envelope
	executor.wire = append([]byte(nil), wire...)
	return nil
}

func (executor *recordingAuthenticatedReapingExecutor) Execute(context.Context, sandboxhostprotocol.Envelope) error {
	return nil
}

func (executor *recordingAuthenticatedReapingExecutor) ExecuteAuthenticated(_ context.Context, envelope sandboxhostprotocol.Envelope, wire []byte) error {
	executor.executeEnvelope = envelope
	executor.executeWire = append([]byte(nil), wire...)
	return executor.executeErr
}

func (executor *recordingAuthenticatedReapingExecutor) ReapAuthenticated(_ context.Context, envelope sandboxhostprotocol.Envelope, wire []byte) error {
	executor.reapEnvelope = envelope
	executor.reapWire = append([]byte(nil), wire...)
	return nil
}

func TestExecuteEnvelopeNeverReexecutesAfterRestartWithOnlyStartedIntent(t *testing.T) {
	t.Parallel()

	envelope, now := executionEnvelope()
	path := filepath.Join(t.TempDir(), "journal.json")
	journal, err := sandboxhostjournal.Open(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.Accept(envelope, sandboxhostprotocol.Digest([]byte("envelope"))); err != nil {
		t.Fatal(err)
	}
	started := signedExecutionResult(t, envelope, "started", now)
	if err := journal.StageStarted(envelope, started); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := sandboxhostjournal.Open(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	var sent [][]byte
	err = executeEnvelope(context.Background(), envelope, now, restarted, executionPrivateKey(), executorFunc(func(context.Context, sandboxhostprotocol.Envelope) error {
		called = true
		return nil
	}), func(_ context.Context, wire []byte) error {
		sent = append(sent, append([]byte(nil), wire...))
		return nil
	}, context.WithDeadline)
	if err != nil {
		t.Fatalf("executeEnvelope(restart): %v", err)
	}
	if called || len(sent) != 1 || resultState(t, sent[0]) != "uncertain" {
		t.Fatalf("restart execution called:%t sent:%d state:%q", called, len(sent), resultState(t, sent[0]))
	}
}

func TestExecuteEnvelopeRefusesAnExpiredLeaseBeforeExecutor(t *testing.T) {
	t.Parallel()

	envelope, now := executionEnvelope()
	envelope.ExpiresAt = now
	journal := executionJournal(t, envelope)
	called := false
	err := executeEnvelope(context.Background(), envelope, now, journal, executionPrivateKey(), executorFunc(func(context.Context, sandboxhostprotocol.Envelope) error {
		called = true
		return nil
	}), func(context.Context, []byte) error { return nil }, context.WithDeadline)
	if err == nil || called || journal.ExecutionStarted(envelope) {
		t.Fatalf("expired execution error:%v called:%t started:%t", err, called, journal.ExecutionStarted(envelope))
	}
}

func TestExecuteEnvelopeRefusesCancellationBeforeDurableIntent(t *testing.T) {
	t.Parallel()

	envelope, now := executionEnvelope()
	journal := executionJournal(t, envelope)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	err := executeEnvelope(ctx, envelope, now, journal, executionPrivateKey(), executorFunc(func(context.Context, sandboxhostprotocol.Envelope) error {
		called = true
		return nil
	}), func(context.Context, []byte) error { return nil }, context.WithDeadline)
	if !errors.Is(err, context.Canceled) || called || journal.ExecutionStarted(envelope) {
		t.Fatalf("canceled execution error:%v called:%t started:%t", err, called, journal.ExecutionStarted(envelope))
	}
}

func TestExecuteEnvelopePersistsTerminalBeforePostAndRecoversLostAcknowledgement(t *testing.T) {
	t.Parallel()

	envelope, now := executionEnvelope()
	journal := executionJournal(t, envelope)
	terminalDurableBeforePost := false
	posts := 0
	err := executeEnvelopeWithAfterTerminalSend(context.Background(), envelope, now, journal, executionPrivateKey(), executorFunc(func(context.Context, sandboxhostprotocol.Envelope) error { return nil }), func(_ context.Context, wire []byte) error {
		posts++
		if resultState(t, wire) == "succeeded" {
			terminalDurableBeforePost = len(journal.PendingResults()) == 1
		}
		return nil
	}, func(ctx context.Context, expiresAt time.Time) (context.Context, context.CancelFunc) {
		if expiresAt != envelope.ExpiresAt {
			t.Fatalf("executor deadline = %s, want envelope expiry %s", expiresAt, envelope.ExpiresAt)
		}
		return ctx, func() {}
	}, func() error { return ErrInjectedResultAcknowledgementFault })
	if !errors.Is(err, ErrInjectedResultAcknowledgementFault) || !terminalDurableBeforePost || posts != 2 || len(journal.PendingResults()) != 1 {
		t.Fatalf("lost acknowledgement error:%v durable:%t posts:%d pending:%d", err, terminalDurableBeforePost, posts, len(journal.PendingResults()))
	}
}

func TestExecuteEnvelopeDoesNotExecuteWhenStartedPostFails(t *testing.T) {
	t.Parallel()

	envelope, now := executionEnvelope()
	journal := executionJournal(t, envelope)
	called := false
	err := executeEnvelope(context.Background(), envelope, now, journal, executionPrivateKey(), executorFunc(func(context.Context, sandboxhostprotocol.Envelope) error {
		called = true
		return nil
	}), func(context.Context, []byte) error { return errors.New("control unavailable") }, context.WithDeadline)
	if err == nil || called || len(journal.PendingStarts()) != 1 || len(journal.PendingResults()) != 0 {
		t.Fatalf("started delivery failure error:%v called:%t pending-starts:%d pending-results:%d", err, called, len(journal.PendingStarts()), len(journal.PendingResults()))
	}
}

func TestExecuteEnvelopeReportsUncertainAfterExecutorFailure(t *testing.T) {
	t.Parallel()

	envelope, now := executionEnvelope()
	journal := executionJournal(t, envelope)
	var sent [][]byte
	err := executeEnvelope(context.Background(), envelope, now, journal, executionPrivateKey(), executorFunc(func(context.Context, sandboxhostprotocol.Envelope) error {
		return errors.New("executor interrupted")
	}), func(_ context.Context, wire []byte) error {
		sent = append(sent, append([]byte(nil), wire...))
		return nil
	}, context.WithDeadline)
	if err != nil || len(sent) != 2 || resultState(t, sent[1]) != "uncertain" || len(journal.PendingResults()) != 0 {
		t.Fatalf("executor failure error:%v sent:%d terminal:%q pending:%d", err, len(sent), resultState(t, sent[1]), len(journal.PendingResults()))
	}
}

func TestExecuteEnvelopeReapsTheExactAuthenticatedCommandBeforeItsUncertainTerminal(t *testing.T) {
	envelope, now := executionEnvelope()
	journal := executionJournal(t, envelope)
	wire := []byte("the-control-verified-canonical-envelope")
	executor := &recordingAuthenticatedReapingExecutor{executeErr: errors.New("guest exchange interrupted")}
	bound := bindAuthenticatedEnvelope(executor, wire)
	var sent [][]byte
	if err := executeEnvelope(context.Background(), envelope, now, journal, executionPrivateKey(), bound, func(_ context.Context, result []byte) error {
		sent = append(sent, append([]byte(nil), result...))
		return nil
	}, func(ctx context.Context, _ time.Time) (context.Context, context.CancelFunc) { return ctx, func() {} }); err != nil {
		t.Fatalf("executeEnvelope() error = %v", err)
	}
	if !reflect.DeepEqual(executor.executeEnvelope, envelope) || !reflect.DeepEqual(executor.reapEnvelope, envelope) || string(executor.executeWire) != string(wire) || string(executor.reapWire) != string(wire) || len(sent) != 2 || resultState(t, sent[1]) != "uncertain" {
		t.Fatalf("authenticated execution/reaper = %#v; terminal=%q", executor, resultState(t, sent[len(sent)-1]))
	}
	wire[0] = 'x'
	if string(executor.reapWire) != "the-control-verified-canonical-envelope" {
		t.Fatalf("reaper retained caller wire mutation = %q", executor.reapWire)
	}
}

func TestRecoverIncompleteExecutionPostsSignedUncertainWithoutExecuting(t *testing.T) {
	t.Parallel()

	envelope, now := executionEnvelope()
	journal := executionJournal(t, envelope)
	started := signedExecutionResult(t, envelope, "started", now)
	if err := journal.StageStarted(envelope, started); err != nil {
		t.Fatal(err)
	}
	var sent [][]byte
	if err := recoverIncompleteExecutions(context.Background(), now.Add(time.Second), journal, executionPrivateKey(), func(_ context.Context, wire []byte) error {
		sent = append(sent, append([]byte(nil), wire...))
		return nil
	}); err != nil {
		t.Fatalf("recoverIncompleteExecutions: %v", err)
	}
	if len(sent) != 1 || resultState(t, sent[0]) != "uncertain" || len(journal.PendingExecutions()) != 0 || len(journal.PendingResults()) != 0 {
		t.Fatalf("recovery sent:%d state:%q incomplete:%d pending:%d", len(sent), resultState(t, sent[0]), len(journal.PendingExecutions()), len(journal.PendingResults()))
	}
}

func TestRecoverIncompleteExecutionRefusesTamperedStartedObservation(t *testing.T) {
	t.Parallel()

	envelope, now := executionEnvelope()
	journal := executionJournal(t, envelope)
	if err := journal.StageStarted(envelope, []byte(`{"not":"a signed host result"}`)); err != nil {
		t.Fatal(err)
	}
	if err := recoverIncompleteExecutions(context.Background(), now.Add(time.Second), journal, executionPrivateKey(), func(context.Context, []byte) error { return nil }); err == nil {
		t.Fatal("recoverIncompleteExecutions() accepted a tampered durable started observation")
	}
	if len(journal.PendingExecutions()) != 1 {
		t.Fatal("corrupt recovery erased the durable execution intent")
	}
}

func TestSignExecutionResultBoundsResultIDForMaximumDeliveryID(t *testing.T) {
	t.Parallel()

	envelope, now := executionEnvelope()
	envelope.DeliveryID = strings.Repeat("d", 128)
	wire, err := signExecutionResult(envelope, "started", now, executionPrivateKey())
	if err != nil {
		t.Fatalf("signExecutionResult: %v", err)
	}
	result, err := sandboxhostprotocol.VerifyResult(wire, now.Add(time.Second), executionPrivateKey().Public().(ed25519.PublicKey))
	if err != nil || len(result.ResultID) > 128 {
		t.Fatalf("bounded result ID = %#v, %v", result, err)
	}
}

func TestConcurrentHostOwnersCannotExecuteOneJournalTwice(t *testing.T) {
	t.Parallel()

	envelope, now := executionEnvelope()
	path := filepath.Join(t.TempDir(), "journal.json")
	first, err := sandboxhostjournal.Open(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, _, err := first.Accept(envelope, sandboxhostprotocol.Digest([]byte("envelope"))); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	completed := make(chan error, 1)
	executions := 0
	go func() {
		completed <- executeEnvelope(context.Background(), envelope, now, first, executionPrivateKey(), executorFunc(func(context.Context, sandboxhostprotocol.Envelope) error {
			executions++
			close(entered)
			<-release
			return nil
		}), func(context.Context, []byte) error { return nil }, context.WithDeadline)
	}()
	<-entered
	second, secondErr := sandboxhostjournal.Open(path, 10)
	if second != nil || !errors.Is(secondErr, sandboxhostjournal.ErrLocked) {
		t.Fatalf("second journal owner = %#v, %v", second, secondErr)
	}
	close(release)
	if err := <-completed; err != nil || executions != 1 {
		t.Fatalf("first execution error:%v calls:%d", err, executions)
	}
}

func executionJournal(t *testing.T, envelope sandboxhostprotocol.Envelope) *sandboxhostjournal.Journal {
	t.Helper()
	journal, err := sandboxhostjournal.Open(filepath.Join(t.TempDir(), "journal.json"), 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.Accept(envelope, sandboxhostprotocol.Digest([]byte("envelope"))); err != nil {
		t.Fatal(err)
	}
	return journal
}

func executionEnvelope() (sandboxhostprotocol.Envelope, time.Time) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	return sandboxhostprotocol.Envelope{HostID: "host_01", HostGeneration: 1, AssignmentID: "assignment_01", LeaseEpoch: 1, FencingToken: 1, Principal: "tenant_01:subject_01", OperationID: "op_01", CanonicalRequestDigest: executionDigest('c'), EffectiveSpecDigest: executionDigest('a'), CapabilityDigest: executionDigest('b'), ExpiresAt: now.Add(time.Minute)}, now
}

func executionPrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
}

func signedExecutionResult(t *testing.T, envelope sandboxhostprotocol.Envelope, state string, now time.Time) []byte {
	t.Helper()
	wire, err := sandboxhostprotocol.SignResult(sandboxhostprotocol.Result{ProtocolVersion: sandboxhostprotocol.Version, ResultID: state + "_result", HostID: envelope.HostID, HostGeneration: envelope.HostGeneration, AssignmentID: envelope.AssignmentID, LeaseEpoch: envelope.LeaseEpoch, FencingToken: envelope.FencingToken, Principal: envelope.Principal, OperationID: envelope.OperationID, EffectiveSpecDigest: envelope.EffectiveSpecDigest, CapabilityDigest: envelope.CapabilityDigest, State: state, ObservedAt: now}, executionPrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func resultState(t *testing.T, wire []byte) string {
	t.Helper()
	result, err := sandboxhostprotocol.VerifyResult(wire, time.Date(2026, 8, 10, 13, 0, 0, 0, time.UTC), executionPrivateKey().Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return result.State
}

func executionDigest(value byte) string { return "sha256:" + string(bytesOf(value, 64)) }

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}
