package sandboxhostjournal

import (
	"path/filepath"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
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
	resultWire := []byte(`{"protocol_version":"sandbox.host-control/v1","result_id":"result_01"}`)
	if err := journal.StageResult(envelope, resultWire); err != nil {
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
	finished, err := Open(path, 100)
	if err != nil || len(finished.PendingResults()) != 0 {
		t.Fatalf("PendingResults(after ack) = %#v, %v", finished.PendingResults(), err)
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
