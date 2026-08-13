package sandboxcontrol

import (
	"context"
	"sort"
	"strconv"

	"github.com/0x63616c/agent-runtime/sandbox"
	"github.com/cockroachdb/errors"
)

// ReplayOutput returns the retained, signed host chunks owned by principal.
// A header-only legacy output record deliberately produces no event: it was
// created before the durable-byte protocol and must not be misrepresented as
// replayable content.
func (ledger *MemoryLedger) ReplayOutput(ctx context.Context, principal string, processID sandbox.ProcessID, after sandbox.OutputCursor) ([]sandbox.OutputEvent, error) {
	if err := validateProjectionInput(ctx, principal, string(processID)); err != nil {
		return nil, err
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	type item struct{ fields hostOutputFields }
	items := make([]item, 0)
	for _, fields := range ledger.hostOutput {
		if len(fields.Chunk) == 0 {
			continue
		}
		for _, operation := range ledger.operations {
			if operation.Principal == principal && operation.TargetKind == "process" && operation.TargetID == string(processID) && operation.Assignment.AssignmentID == fields.AssignmentID {
				items = append(items, item{fields: fields})
				break
			}
		}
	}
	sort.Slice(items, func(left, right int) bool {
		if items[left].fields.ObservedAt.Equal(items[right].fields.ObservedAt) {
			if items[left].fields.Stream == items[right].fields.Stream {
				return items[left].fields.Sequence < items[right].fields.Sequence
			}
			return items[left].fields.Stream < items[right].fields.Stream
		}
		return items[left].fields.ObservedAt.Before(items[right].fields.ObservedAt)
	})
	events := make([]sandbox.OutputEvent, 0, len(items))
	for _, item := range items {
		cursor := sandbox.OutputCursor("output:" + item.fields.AssignmentID + ":" + item.fields.Stream + ":" + strconv.FormatUint(item.fields.Sequence, 10))
		events = append(events, sandbox.OutputEvent{Kind: sandbox.OutputEventChunk, Cursor: cursor, Stream: sandbox.OutputKind(item.fields.Stream), Chunk: &sandbox.OutputChunk{Bytes: append([]byte(nil), item.fields.Chunk...), Redacted: item.fields.Redacted}})
	}
	return replayAfter(events, after)
}

// ReplayOutput reads the retained redacted chunks after authenticating the
// caller by the principal-scoped process target. The operation join means an
// assignment identifier never becomes an output-read capability.
func (ledger *PostgresLedger) ReplayOutput(ctx context.Context, principal string, processID sandbox.ProcessID, after sandbox.OutputCursor) ([]sandbox.OutputEvent, error) {
	if err := validateProjectionInput(ctx, principal, string(processID)); err != nil {
		return nil, err
	}
	rows, err := ledger.pool.Query(ctx, `
		SELECT h.assignment_id, h.stream, h.sequence, c.chunk, c.redacted
		FROM runtime.sandbox_host_outputs h
		JOIN runtime.sandbox_host_output_chunks c USING (assignment_id, stream, sequence)
		JOIN runtime.sandbox_operations o ON o.assignment_id=h.assignment_id
		WHERE o.principal=$1 AND o.target_kind='process' AND o.target_id=$2
		ORDER BY h.observed_at, h.stream, h.sequence`, principal, string(processID))
	if err != nil {
		return nil, errors.Wrap(err, "read retained sandbox output")
	}
	defer rows.Close()
	events := make([]sandbox.OutputEvent, 0)
	for rows.Next() {
		var assignmentID, stream string
		var sequence int64
		var chunk []byte
		var redacted bool
		if err := rows.Scan(&assignmentID, &stream, &sequence, &chunk, &redacted); err != nil {
			return nil, errors.Wrap(err, "scan retained sandbox output")
		}
		if sequence < 1 {
			return nil, errors.New("read retained sandbox output: invalid sequence")
		}
		cursor := sandbox.OutputCursor("output:" + assignmentID + ":" + stream + ":" + strconv.FormatInt(sequence, 10))
		events = append(events, sandbox.OutputEvent{Kind: sandbox.OutputEventChunk, Cursor: cursor, Stream: sandbox.OutputKind(stream), Chunk: &sandbox.OutputChunk{Bytes: append([]byte(nil), chunk...), Redacted: redacted}})
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "read retained sandbox output")
	}
	return replayAfter(events, after)
}

func replayAfter(events []sandbox.OutputEvent, after sandbox.OutputCursor) ([]sandbox.OutputEvent, error) {
	if after == "" || after == "0" {
		return events, nil
	}
	for index, event := range events {
		if event.Cursor == after {
			return events[index+1:], nil
		}
	}
	return nil, errors.New("sandbox output cursor is outside retained history")
}
