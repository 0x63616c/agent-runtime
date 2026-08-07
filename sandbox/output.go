package sandbox

import (
	"bytes"
	"sort"
)

// outputSpool is the core-owned bounded, redacted per-stream replay buffer.
// It has no reader dependency: a slow or absent consumer cannot backpressure
// the process-side tee represented by this deterministic fixture.
type outputSpool struct {
	stream        OutputKind
	producedLimit uint64
	retainedLimit uint64
	produced      uint64
	retainedBytes uint64
	truncated     bool
	closed        bool
	nextCursor    uint64
	firstCursor   OutputCursor
	events        []OutputEvent
	evicted       []OutputCursor
	redactor      *literalRedactor
}

func newOutputSpool(stream OutputKind, producedLimit, retainedLimit uint64, patterns []string) (*outputSpool, error) {
	if producedLimit == 0 || retainedLimit == 0 || retainedLimit > producedLimit*16 {
		return nil, newFailure(FailureInvalidArgument, "output limits must be finite", RetryNever)
	}
	redactor, err := newLiteralRedactor(patterns)
	if err != nil {
		return nil, err
	}
	return &outputSpool{stream: stream, producedLimit: producedLimit, retainedLimit: retainedLimit, redactor: redactor}, nil
}

func (spool *outputSpool) Write(chunk []byte) error {
	if spool.closed {
		return newFailure(FailureAlreadyTerminal, "output stream is finalized", RetryNever)
	}
	if spool.produced+uint64(len(chunk)) > spool.producedLimit {
		return newFailure(FailureResourceLimitExceeded, "produced output limit was exceeded", RetryNever)
	}
	spool.produced += uint64(len(chunk))
	redacted, changed := spool.redactor.Write(chunk)
	spool.retain(redacted, changed)
	return nil
}

func (spool *outputSpool) retain(chunk []byte, redacted bool) {
	if len(chunk) == 0 {
		return
	}
	if uint64(len(chunk)) > spool.retainedLimit {
		chunk = append([]byte(nil), chunk[uint64(len(chunk))-spool.retainedLimit:]...)
		spool.truncated = true
	}
	for spool.retainedBytes+uint64(len(chunk)) > spool.retainedLimit {
		if !spool.evictOldestChunk() {
			break
		}
	}
	spool.nextCursor++
	cursor := outputCursor(spool.stream, spool.nextCursor)
	if spool.firstCursor == "" {
		spool.firstCursor = cursor
	}
	spool.retainedBytes += uint64(len(chunk))
	spool.events = append(spool.events, OutputEvent{Kind: OutputEventChunk, Cursor: cursor, Stream: spool.stream, Chunk: &OutputChunk{Bytes: append([]byte(nil), chunk...), Redacted: redacted}})
}

func (spool *outputSpool) evictOldestChunk() bool {
	for index, event := range spool.events {
		if event.Kind != OutputEventChunk || event.Chunk == nil {
			continue
		}
		spool.retainedBytes -= uint64(len(event.Chunk.Bytes))
		spool.evicted = append(spool.evicted, event.Cursor)
		spool.events = append(spool.events[:index], spool.events[index+1:]...)
		spool.firstCursor = ""
		for _, retained := range spool.events {
			if retained.Kind == OutputEventChunk {
				spool.firstCursor = retained.Cursor
				break
			}
		}
		spool.truncated = true
		return true
	}
	return false
}

func (spool *outputSpool) takeEvicted() []OutputCursor {
	evicted := append([]OutputCursor(nil), spool.evicted...)
	spool.evicted = spool.evicted[:0]
	return evicted
}

func (spool *outputSpool) Close(result ProcessResult) []OutputEvent {
	if spool.closed {
		return spool.Events()
	}
	redacted, changed := spool.redactor.Flush()
	spool.retain(redacted, changed)
	if spool.truncated {
		spool.nextCursor++
		earliest := spool.firstCursor
		if earliest == "" {
			earliest = outputCursor(spool.stream, spool.nextCursor)
		}
		spool.events = append(spool.events, OutputEvent{Kind: OutputEventGap, Cursor: outputCursor(spool.stream, spool.nextCursor), Stream: spool.stream, Gap: &OutputGap{EarliestRetained: earliest, Reason: "retained output limit exceeded"}})
	}
	spool.nextCursor++
	spool.events = append(spool.events, OutputEvent{Kind: OutputEventFinal, Cursor: outputCursor(spool.stream, spool.nextCursor), Stream: spool.stream, Final: &OutputFinal{Result: copyProcessResult(result)}})
	spool.closed = true
	return spool.Events()
}

func (spool *outputSpool) Events() []OutputEvent {
	events := make([]OutputEvent, len(spool.events))
	for index, event := range spool.events {
		events[index] = copyOutputEvent(event)
	}
	return events
}

func (spool *outputSpool) Retention() OutputRetention {
	return OutputRetention{EarliestCursor: spool.firstCursor, RetainedBytes: spool.retainedBytes, Truncated: spool.truncated}
}

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
