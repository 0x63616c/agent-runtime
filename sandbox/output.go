package sandbox

import (
	"bytes"
	"sort"
	"sync"
)

type literalRedactor struct {
	patterns [][]byte
	pending  []byte
}

func newLiteralRedactor(patterns []string) (*literalRedactor, error) {
	value := &literalRedactor{}
	total := 0
	for _, pattern := range patterns {
		if pattern == "" {
			return nil, newFailure(FailureInvalidArgument, "redaction pattern cannot be empty", RetryNever)
		}
		total += len(pattern)
		if total > 64*1024 || len(value.patterns) >= 128 {
			return nil, newFailure(FailureResourceLimitExceeded, "redaction patterns exceed the finite limit", RetryNever)
		}
		value.patterns = append(value.patterns, []byte(pattern))
	}
	// Longest then binding order is the specified overlap rule.
	sort.SliceStable(value.patterns, func(left, right int) bool { return len(value.patterns[left]) > len(value.patterns[right]) })
	return value, nil
}

func (redactor *literalRedactor) Write(chunk []byte) ([]byte, bool) {
	redactor.pending = append(redactor.pending, chunk...)
	if len(redactor.patterns) == 0 {
		ready := append([]byte(nil), redactor.pending...)
		redactor.pending = nil
		return ready, false
	}
	limit := len(redactor.pending) - (redactor.longestPattern() - 1)
	if limit <= 0 {
		return nil, false
	}
	// A pattern may begin before the usual look-behind boundary and end after
	// it. Keep from the beginning of that pattern so it cannot leak in two
	// chunks. Recalculate because multiple patterns can overlap the boundary.
	for {
		changed := false
		for _, pattern := range redactor.patterns {
			for offset := 0; ; {
				index := bytes.Index(redactor.pending[offset:], pattern)
				if index < 0 {
					break
				}
				index += offset
				if index < limit && index+len(pattern) > limit {
					limit = index
					changed = true
				}
				offset = index + 1
				if offset >= len(redactor.pending) {
					break
				}
			}
		}
		if !changed {
			break
		}
	}
	if limit <= 0 {
		return nil, false
	}
	ready := append([]byte(nil), redactor.pending[:limit]...)
	redactor.pending = append([]byte(nil), redactor.pending[limit:]...)
	return redactor.replace(ready)
}

func (redactor *literalRedactor) Flush() ([]byte, bool) {
	ready := redactor.pending
	redactor.pending = nil
	return redactor.replace(ready)
}

func (redactor *literalRedactor) longestPattern() int {
	longest := 0
	for _, pattern := range redactor.patterns {
		if len(pattern) > longest {
			longest = len(pattern)
		}
	}
	return longest
}

func (redactor *literalRedactor) replace(value []byte) ([]byte, bool) {
	changed := false
	for _, pattern := range redactor.patterns {
		if bytes.Contains(value, pattern) {
			changed = true
			value = bytes.ReplaceAll(value, pattern, []byte("[REDACTED]"))
		}
	}
	return append([]byte(nil), value...), changed
}

// processOutputSpool owns one process-scoped produced-output budget and an
// independent retained-output tail for each source stream. It stores redacted
// bytes once in control-plane order; stdout and stderr share the produced limit
// while retaining their declared tails independently.
type processOutputSpool struct {
	mu            sync.Mutex
	producedLimit uint64
	retainedLimit uint64
	produced      uint64
	nextCursor    uint64
	closed        bool
	events        []OutputEvent
	redactors     map[OutputKind]*literalRedactor
	retentions    map[OutputKind]OutputRetention
	streamCursors map[OutputKind][]OutputCursor
}

func newProcessOutputSpool(producedLimit, retainedLimit uint64, patterns []string) (*processOutputSpool, error) {
	if producedLimit == 0 || retainedLimit == 0 || retainedLimit > producedLimit*16 {
		return nil, newFailure(FailureInvalidArgument, "output limits must be finite", RetryNever)
	}
	stdout, err := newLiteralRedactor(patterns)
	if err != nil {
		return nil, err
	}
	stderr, err := newLiteralRedactor(patterns)
	if err != nil {
		return nil, err
	}
	return &processOutputSpool{
		producedLimit: producedLimit,
		retainedLimit: retainedLimit,
		redactors:     map[OutputKind]*literalRedactor{OutputStdout: stdout, OutputStderr: stderr},
		retentions:    map[OutputKind]OutputRetention{OutputStdout: {}, OutputStderr: {}},
		streamCursors: map[OutputKind][]OutputCursor{OutputStdout: {}, OutputStderr: {}},
	}, nil
}

func (spool *processOutputSpool) Write(stream OutputKind, chunk []byte) error {
	spool.mu.Lock()
	defer spool.mu.Unlock()
	return spool.writeLocked(stream, chunk)
}

func (spool *processOutputSpool) writeLocked(stream OutputKind, chunk []byte) error {
	if spool.closed {
		return newFailure(FailureAlreadyTerminal, "output stream is finalized", RetryNever)
	}
	redactor, found := spool.redactors[stream]
	if !found {
		return newFailure(FailureInvalidArgument, "output stream is invalid", RetryNever)
	}
	if spool.produced+uint64(len(chunk)) > spool.producedLimit {
		return newFailure(FailureResourceLimitExceeded, "produced output limit was exceeded", RetryNever)
	}
	spool.produced += uint64(len(chunk))
	redacted, changed := redactor.Write(chunk)
	spool.retain(stream, redacted, changed)
	return nil
}

func (spool *processOutputSpool) Close(result ProcessResult) {
	spool.mu.Lock()
	defer spool.mu.Unlock()
	if spool.closed {
		return
	}
	for _, stream := range []OutputKind{OutputStdout, OutputStderr} {
		redacted, changed := spool.redactors[stream].Flush()
		spool.retain(stream, redacted, changed)
	}
	for _, stream := range []OutputKind{OutputStdout, OutputStderr} {
		retention := spool.retentions[stream]
		if retention.Truncated {
			spool.appendEvent(OutputEvent{Kind: OutputEventGap, Stream: stream, Gap: &OutputGap{EarliestRetained: retention.EarliestCursor, Reason: "retained output limit exceeded"}})
		}
		spool.appendEvent(OutputEvent{Kind: OutputEventFinal, Stream: stream, Final: &OutputFinal{Result: copyProcessResult(result)}})
	}
	spool.closed = true
}

func (spool *processOutputSpool) retain(stream OutputKind, chunk []byte, redacted bool) {
	if len(chunk) == 0 {
		return
	}
	retention := spool.retentions[stream]
	if uint64(len(chunk)) > spool.retainedLimit {
		chunk = append([]byte(nil), chunk[uint64(len(chunk))-spool.retainedLimit:]...)
		retention.Truncated = true
		spool.retentions[stream] = retention
	}
	for spool.retentions[stream].RetainedBytes+uint64(len(chunk)) > spool.retainedLimit {
		if !spool.evictOldestChunk(stream) {
			break
		}
	}
	spool.appendEvent(OutputEvent{Kind: OutputEventChunk, Stream: stream, Chunk: &OutputChunk{Bytes: append([]byte(nil), chunk...), Redacted: redacted}})
	spool.streamCursors[stream] = append(spool.streamCursors[stream], spool.events[len(spool.events)-1].Cursor)
	retention = spool.retentions[stream]
	retention.RetainedBytes += uint64(len(chunk))
	if retention.EarliestCursor == "" {
		retention.EarliestCursor = spool.events[len(spool.events)-1].Cursor
	}
	spool.retentions[stream] = retention
}

func (spool *processOutputSpool) evictOldestChunk(stream OutputKind) bool {
	index := -1
	for candidate, event := range spool.events {
		if event.Kind == OutputEventChunk && event.Stream == stream && event.Chunk != nil {
			index = candidate
			break
		}
	}
	if index < 0 {
		return false
	}
	event := spool.events[index]
	spool.events = append(spool.events[:index], spool.events[index+1:]...)
	retention := spool.retentions[event.Stream]
	retention.RetainedBytes -= uint64(len(event.Chunk.Bytes))
	retention.Truncated = true
	cursors := spool.streamCursors[event.Stream]
	if len(cursors) == 0 || cursors[0] != event.Cursor {
		panic("sandbox: output cursor index is inconsistent")
	}
	cursors = cursors[1:]
	spool.streamCursors[event.Stream] = cursors
	retention.EarliestCursor = ""
	if len(cursors) > 0 {
		retention.EarliestCursor = cursors[0]
	}
	spool.retentions[event.Stream] = retention
	return true
}

func (spool *processOutputSpool) appendEvent(event OutputEvent) {
	spool.nextCursor++
	event.Cursor = outputCursor("output", spool.nextCursor)
	spool.events = append(spool.events, event)
}

func (spool *processOutputSpool) Events() []OutputEvent {
	spool.mu.Lock()
	defer spool.mu.Unlock()
	events := make([]OutputEvent, len(spool.events))
	for index, event := range spool.events {
		events[index] = copyOutputEvent(event)
	}
	return events
}

func (spool *processOutputSpool) Retention(stream OutputKind) OutputRetention {
	spool.mu.Lock()
	defer spool.mu.Unlock()
	return spool.retentions[stream]
}
