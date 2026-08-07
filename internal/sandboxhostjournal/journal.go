// Package sandboxhostjournal persists the reference host's receipt journal
// before any fake effect. It is local host state, never control-plane authority.
package sandboxhostjournal

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/cockroachdb/errors"
)

// Entry is one immutable accepted receipt key and reference execution marker.
type Entry struct {
	ReceiptKey         string `json:"receipt_key"`
	EnvelopeDigest     string `json:"envelope_digest"`
	ReceiptDigest      string `json:"receipt_digest"`
	ExecutionCount     uint64 `json:"execution_count"`
	LeaseEpoch         uint64 `json:"lease_epoch"`
	FencingToken       uint64 `json:"fencing_token"`
	ResultWire         []byte `json:"result_wire"`
	ResultDigest       string `json:"result_digest"`
	ResultAcknowledged bool   `json:"result_acknowledged"`
}

// PendingResult is one exact signed result awaiting control acknowledgement.
type PendingResult struct {
	ReceiptKey string
	Wire       []byte
}

type document struct {
	Version string  `json:"version"`
	Entries []Entry `json:"entries"`
}

// Journal is a bounded fsync-and-rename receipt journal.
type Journal struct {
	mu      sync.Mutex
	path    string
	maximum int
	entries map[string]Entry
}

// Open loads an existing canonical journal or initializes an empty one. Its
// parent directory must already exist and the path must be absolute.
func Open(path string, maximum int) (*Journal, error) {
	if !filepath.IsAbs(path) || maximum <= 0 || maximum > 100000 {
		return nil, errors.New("open sandbox host journal: absolute path and finite maximum are required")
	}
	journal := &Journal{path: path, maximum: maximum, entries: make(map[string]Entry)}
	wire, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return journal, nil
	}
	if err != nil {
		return nil, errors.Wrap(err, "read sandbox host journal")
	}
	if len(wire) == 0 || len(wire) > 16<<20 {
		return nil, errors.New("open sandbox host journal: invalid bounded document")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var decoded document
	if err := decoder.Decode(&decoded); err != nil {
		return nil, errors.Wrap(err, "decode sandbox host journal")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || decoded.Version != "sandbox.host-journal/v1" || len(decoded.Entries) > maximum {
		return nil, errors.New("open sandbox host journal: invalid canonical document")
	}
	canonical, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, errors.New("open sandbox host journal: non-canonical document")
	}
	prior := ""
	for _, entry := range decoded.Entries {
		if entry.ReceiptKey == "" || entry.ReceiptKey <= prior || entry.EnvelopeDigest == "" || entry.ReceiptDigest == "" || entry.ExecutionCount != 1 || entry.LeaseEpoch == 0 || entry.FencingToken == 0 || !validResultState(entry) {
			return nil, errors.New("open sandbox host journal: invalid receipt entry")
		}
		journal.entries[entry.ReceiptKey] = entry
		prior = entry.ReceiptKey
	}
	return journal, nil
}

// StageResult fsyncs the exact signed result before its first transport
// attempt. An altered result for the same durable receipt is refused.
func (journal *Journal) StageResult(envelope sandboxhostprotocol.Envelope, wire []byte) error {
	if journal == nil || len(wire) == 0 || len(wire) > 1<<20 {
		return errors.New("stage sandbox host result: bounded result is required")
	}
	key := receiptKey(envelope)
	journal.mu.Lock()
	defer journal.mu.Unlock()
	entry, exists := journal.entries[key]
	if !exists {
		return errors.New("stage sandbox host result: durable receipt is required")
	}
	digest := sandboxhostprotocol.Digest(wire)
	if entry.ResultDigest != "" {
		if entry.ResultDigest != digest || !bytes.Equal(entry.ResultWire, wire) {
			return errors.New("stage sandbox host result: altered result refused")
		}
		return nil
	}
	entry.ResultWire = append([]byte(nil), wire...)
	entry.ResultDigest = digest
	journal.entries[key] = entry
	if err := journal.persistLocked(); err != nil {
		entry.ResultWire, entry.ResultDigest = nil, ""
		journal.entries[key] = entry
		return err
	}
	return nil
}

// PendingResults returns stable receipt-key order and cloned signed bytes.
func (journal *Journal) PendingResults() []PendingResult {
	if journal == nil {
		return nil
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	results := make([]PendingResult, 0)
	for _, entry := range journal.entries {
		if entry.ResultDigest != "" && !entry.ResultAcknowledged {
			results = append(results, PendingResult{ReceiptKey: entry.ReceiptKey, Wire: append([]byte(nil), entry.ResultWire...)})
		}
	}
	sort.Slice(results, func(left, right int) bool { return results[left].ReceiptKey < results[right].ReceiptKey })
	return results
}

// AcknowledgeResult durably marks only the exact staged result as complete.
func (journal *Journal) AcknowledgeResult(receiptKey, resultDigest string) error {
	if journal == nil || receiptKey == "" || resultDigest == "" {
		return errors.New("acknowledge sandbox host result: receipt and result are required")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	entry, exists := journal.entries[receiptKey]
	if !exists || entry.ResultDigest != resultDigest {
		return errors.New("acknowledge sandbox host result: altered or absent result refused")
	}
	if entry.ResultAcknowledged {
		return nil
	}
	entry.ResultAcknowledged = true
	journal.entries[receiptKey] = entry
	if err := journal.persistLocked(); err != nil {
		entry.ResultAcknowledged = false
		journal.entries[receiptKey] = entry
		return err
	}
	return nil
}

// Accept persists a first receipt before returning it. Byte-identical or
// intentional lost-ack delivery retries return the prior receipt; changed
// envelope identity for the receipt key fails closed.
func (journal *Journal) Accept(envelope sandboxhostprotocol.Envelope, envelopeDigest string) (Entry, bool, error) {
	if journal == nil || envelopeDigest == "" {
		return Entry{}, false, errors.New("accept sandbox host receipt: journal and envelope digest are required")
	}
	key := receiptKey(envelope)
	if key == "" {
		return Entry{}, false, errors.New("accept sandbox host receipt: invalid envelope binding")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if prior, exists := journal.entries[key]; exists {
		if prior.EnvelopeDigest == envelopeDigest && prior.LeaseEpoch == envelope.LeaseEpoch && prior.FencingToken == envelope.FencingToken {
			return prior, true, nil
		}
		if envelope.LeaseEpoch <= prior.LeaseEpoch || envelope.FencingToken <= prior.FencingToken || prior.ResultDigest != "" {
			return Entry{}, false, errors.New("accept sandbox host receipt: altered delivery refused")
		}
		original := prior
		prior.EnvelopeDigest, prior.LeaseEpoch, prior.FencingToken = envelopeDigest, envelope.LeaseEpoch, envelope.FencingToken
		journal.entries[key] = prior
		if err := journal.persistLocked(); err != nil {
			journal.entries[key] = original
			return Entry{}, false, err
		}
		return prior, true, nil
	}
	if len(journal.entries) >= journal.maximum {
		return Entry{}, false, errors.New("accept sandbox host receipt: finite journal limit reached")
	}
	entry := Entry{ReceiptKey: key, EnvelopeDigest: envelopeDigest, ReceiptDigest: sandboxhostprotocol.Digest([]byte(key)), ExecutionCount: 1, LeaseEpoch: envelope.LeaseEpoch, FencingToken: envelope.FencingToken}
	journal.entries[key] = entry
	if err := journal.persistLocked(); err != nil {
		delete(journal.entries, key)
		return Entry{}, false, err
	}
	return entry, false, nil
}

func (journal *Journal) persistLocked() error {
	entries := make([]Entry, 0, len(journal.entries))
	for _, entry := range journal.entries {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].ReceiptKey < entries[right].ReceiptKey })
	wire, err := json.Marshal(document{Version: "sandbox.host-journal/v1", Entries: entries})
	if err != nil {
		return errors.Wrap(err, "encode sandbox host journal")
	}
	if len(wire) > 16<<20 {
		return errors.New("encode sandbox host journal: finite document limit reached")
	}
	temporary, err := os.CreateTemp(filepath.Dir(journal.path), ".sandbox-host-journal-*")
	if err != nil {
		return errors.Wrap(err, "create sandbox host journal temporary file")
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return errors.Wrap(err, "protect sandbox host journal temporary file")
	}
	if _, err := temporary.Write(wire); err != nil {
		_ = temporary.Close()
		return errors.Wrap(err, "write sandbox host journal")
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return errors.Wrap(err, "sync sandbox host journal")
	}
	if err := temporary.Close(); err != nil {
		return errors.Wrap(err, "close sandbox host journal")
	}
	if err := os.Rename(temporaryPath, journal.path); err != nil {
		return errors.Wrap(err, "replace sandbox host journal")
	}
	removeTemporary = false
	directory, err := os.Open(filepath.Dir(journal.path))
	if err != nil {
		return errors.Wrap(err, "open sandbox host journal directory")
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return errors.Wrap(err, "sync sandbox host journal directory")
	}
	return errors.Wrap(directory.Close(), "close sandbox host journal directory")
}

func validResultState(entry Entry) bool {
	if entry.ResultDigest == "" {
		return len(entry.ResultWire) == 0 && !entry.ResultAcknowledged
	}
	return len(entry.ResultWire) > 0 && len(entry.ResultWire) <= 1<<20 && sandboxhostprotocol.Digest(entry.ResultWire) == entry.ResultDigest
}

func receiptKey(envelope sandboxhostprotocol.Envelope) string {
	if envelope.HostID == "" || envelope.HostGeneration == 0 || envelope.AssignmentID == "" || envelope.LeaseEpoch == 0 || envelope.FencingToken == 0 || envelope.OperationID == "" || envelope.CanonicalRequestDigest == "" {
		return ""
	}
	return envelope.HostID + "\x00" + envelope.AssignmentID + "\x00" + envelope.OperationID + "\x00" + envelope.CanonicalRequestDigest
}
