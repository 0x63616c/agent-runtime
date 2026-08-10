package sandboxhostjournal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/cockroachdb/errors"
)

func TestJournalPersistsReceiptBeforeSingleReferenceEffect(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "receipts.json")
	journal, err := Open(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	envelope := sandboxhostprotocol.Envelope{HostID: "host_01", HostGeneration: 1, AssignmentID: "assignment_01", LeaseEpoch: 1, FencingToken: 1, OperationID: "op_01", CanonicalRequestDigest: testDigest('a')}
	first, duplicate, err := journal.Accept(envelope, testDigest('b'))
	if err != nil || duplicate || first.ExecutionCount != 1 {
		t.Fatalf("Accept(first) = %#v, %t, %v", first, duplicate, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	second, duplicate, err := restarted.Accept(envelope, testDigest('b'))
	if err != nil || !duplicate || second.ReceiptDigest != first.ReceiptDigest || second.ExecutionCount != 1 {
		t.Fatalf("Accept(after restart) = %#v, %t, %v", second, duplicate, err)
	}
	renewed := envelope
	renewed.LeaseEpoch, renewed.FencingToken = 2, 2
	renewedEntry, duplicate, err := restarted.Accept(renewed, testDigest('c'))
	if err != nil || !duplicate || renewedEntry.ReceiptDigest != first.ReceiptDigest || renewedEntry.ExecutionCount != 1 {
		t.Fatalf("Accept(renewed fence) = %#v, %t, %v", renewedEntry, duplicate, err)
	}
	if _, _, err := restarted.Accept(renewed, testDigest('d')); err == nil {
		t.Fatal("Accept() accepted altered delivery for receipt key")
	}
}

func TestJournalRefusesCorruptStartedAcknowledgementWithoutIntent(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "receipts.json")
	wire, err := json.Marshal(document{Version: "sandbox.host-journal/v1", Entries: []Entry{{ReceiptKey: "receipt_01", EnvelopeDigest: "digest", ReceiptDigest: "receipt", ExecutionCount: 1, LeaseEpoch: 1, FencingToken: 1, StartedAcknowledged: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, 100); err == nil {
		t.Fatal("Open() accepted a started acknowledgement without durable intent")
	}
}

func TestJournalReplaysLegacyV1TerminalWithoutDurableIntent(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "receipts.json")
	wire, err := json.Marshal(document{Version: "sandbox.host-journal/v1", Entries: []Entry{{ReceiptKey: "receipt_01", EnvelopeDigest: "digest", ReceiptDigest: "receipt", ExecutionCount: 1, LeaseEpoch: 1, FencingToken: 1, ResultWire: []byte(`{"state":"succeeded"}`), ResultDigest: sandboxhostprotocol.Digest([]byte(`{"state":"succeeded"}`))}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	journal, err := Open(path, 100)
	if err != nil {
		t.Fatalf("Open() refused a legacy v1 terminal journal: %v", err)
	}
	if pending := journal.PendingResults(); len(pending) != 1 || string(pending[0].Wire) != `{"state":"succeeded"}` {
		t.Fatalf("legacy PendingResults() = %#v", pending)
	}
}

func TestJournalReplaysExactUnacknowledgedResultAfterRestart(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "receipts.json")
	journal, err := Open(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	envelope := sandboxhostprotocol.Envelope{HostID: "host_01", HostGeneration: 1, AssignmentID: "assignment_01", LeaseEpoch: 1, FencingToken: 1, OperationID: "op_01", CanonicalRequestDigest: testDigest('a')}
	entry, _, err := journal.Accept(envelope, testDigest('b'))
	if err != nil {
		t.Fatal(err)
	}
	startedWire := []byte(`{"protocol_version":"sandbox.host-control/v1","result_id":"started_01","state":"started"}`)
	if err := journal.StageStarted(envelope, startedWire); err != nil {
		t.Fatal(err)
	}
	resultWire := []byte(`{"protocol_version":"sandbox.host-control/v1","result_id":"result_01"}`)
	if err := journal.StageResult(envelope, resultWire); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	pending := restarted.PendingResults()
	if len(pending) != 1 || pending[0].ReceiptKey != entry.ReceiptKey || string(pending[0].Wire) != string(resultWire) {
		t.Fatalf("PendingResults() = %#v", pending)
	}
	if err := restarted.AcknowledgeResult(entry.ReceiptKey, sandboxhostprotocol.Digest(resultWire)); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
	finished, err := Open(path, 100)
	if err != nil || len(finished.PendingResults()) != 0 {
		t.Fatalf("PendingResults(after ack) = %#v, %v", finished.PendingResults(), err)
	}
}

func TestJournalRefusesTerminalResultWithoutDurableStartedIntent(t *testing.T) {
	t.Parallel()

	journal, err := Open(filepath.Join(t.TempDir(), "receipts.json"), 100)
	if err != nil {
		t.Fatal(err)
	}
	envelope := sandboxhostprotocol.Envelope{HostID: "host_01", HostGeneration: 1, AssignmentID: "assignment_01", LeaseEpoch: 1, FencingToken: 1, OperationID: "op_01", CanonicalRequestDigest: testDigest('a')}
	if _, _, err := journal.Accept(envelope, testDigest('b')); err != nil {
		t.Fatal(err)
	}
	if err := journal.StageResult(envelope, []byte(`{"state":"succeeded"}`)); err == nil {
		t.Fatal("StageResult() accepted a terminal observation before durable started intent")
	}
}

func TestJournalFsyncsOneStableStartedIntentBeforeAnyExecution(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "receipts.json")
	journal, err := Open(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	envelope := sandboxhostprotocol.Envelope{HostID: "host_01", HostGeneration: 1, AssignmentID: "assignment_01", LeaseEpoch: 1, FencingToken: 1, OperationID: "op_01", CanonicalRequestDigest: testDigest('a')}
	entry, _, err := journal.Accept(envelope, testDigest('b'))
	if err != nil {
		t.Fatal(err)
	}
	startedWire := []byte(`{"protocol_version":"sandbox.host-control/v1","result_id":"started_01","state":"started"}`)
	if err := journal.StageStarted(envelope, startedWire); err != nil {
		t.Fatalf("StageStarted: %v", err)
	}
	if err := journal.StageStarted(envelope, []byte(`{"changed":true}`)); err == nil {
		t.Fatal("StageStarted() accepted an altered execution intent")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	pending := restarted.PendingStarts()
	if len(pending) != 1 || pending[0].ReceiptKey != entry.ReceiptKey || string(pending[0].Wire) != string(startedWire) {
		t.Fatalf("PendingStarts() = %#v", pending)
	}
	if !restarted.ExecutionStarted(envelope) {
		t.Fatal("ExecutionStarted() = false after durable intent")
	}
	if err := restarted.AcknowledgeStarted(entry.ReceiptKey, sandboxhostprotocol.Digest(startedWire)); err != nil {
		t.Fatalf("AcknowledgeStarted: %v", err)
	}
}

func TestJournalExclusivelyLocksOneHostInstance(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "receipts.json")
	first, err := Open(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, 100); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Open() error = %v, want ErrLocked", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(path, 100)
	if err != nil {
		t.Fatalf("Open() after release: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestJournalFindsIncompleteStartedExecutionAndStagesItsRecoveryResult(t *testing.T) {
	t.Parallel()

	journal, err := Open(filepath.Join(t.TempDir(), "receipts.json"), 100)
	if err != nil {
		t.Fatal(err)
	}
	envelope := sandboxhostprotocol.Envelope{HostID: "host_01", HostGeneration: 1, AssignmentID: "assignment_01", LeaseEpoch: 1, FencingToken: 1, OperationID: "op_01", CanonicalRequestDigest: testDigest('a')}
	entry, _, err := journal.Accept(envelope, testDigest('b'))
	if err != nil {
		t.Fatal(err)
	}
	started := []byte(`{"protocol_version":"sandbox.host-control/v1","result_id":"started_01","state":"started"}`)
	if err := journal.StageStarted(envelope, started); err != nil {
		t.Fatal(err)
	}
	pending := journal.PendingExecutions()
	if len(pending) != 1 || pending[0].ReceiptKey != entry.ReceiptKey || string(pending[0].Wire) != string(started) {
		t.Fatalf("PendingExecutions() = %#v", pending)
	}
	uncertain := []byte(`{"protocol_version":"sandbox.host-control/v1","result_id":"uncertain_01","state":"uncertain"}`)
	if err := journal.StageRecoveryResult(entry.ReceiptKey, uncertain); err != nil {
		t.Fatalf("StageRecoveryResult: %v", err)
	}
	if pending = journal.PendingExecutions(); len(pending) != 0 {
		t.Fatalf("PendingExecutions(after terminal) = %#v", pending)
	}
}

func testDigest(character byte) string { return "sha256:" + string(makeBytes(character, 64)) }

func makeBytes(character byte, count int) []byte {
	value := make([]byte, count)
	for index := range value {
		value[index] = character
	}
	return value
}
