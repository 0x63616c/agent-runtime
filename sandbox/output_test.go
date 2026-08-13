package sandbox

import (
	"bytes"
	"sync"
	"testing"
)

func TestProcessOutputSpoolRedactsAcrossChunks(t *testing.T) {
	spool, err := newProcessOutputSpool(10, 64, []string{"secret"})
	if err != nil {
		t.Fatalf("newOutputSpool() error = %v", err)
	}
	if err := spool.Write(OutputStdout, []byte("a sec")); err != nil {
		t.Fatalf("first Write() error = %v", err)
	}
	if err := spool.Write(OutputStdout, []byte("ret z")); err != nil {
		t.Fatalf("second Write() error = %v", err)
	}
	spool.Close(ProcessResult{Reason: TerminationExited})
	events := spool.Events()
	if len(events) != 4 {
		t.Fatalf("events = %#v, want two chunks and one final per stream", events)
	}
	if events[0].Kind != OutputEventChunk || events[1].Kind != OutputEventChunk || string(events[0].Chunk.Bytes)+string(events[1].Chunk.Bytes) != "a [REDACTED] z" || !events[1].Chunk.Redacted {
		t.Errorf("chunks = %#v", events[:2])
	}
	if events[2].Kind != OutputEventFinal || events[3].Kind != OutputEventFinal {
		t.Errorf("final events = %#v, want a final per stream", events[2:])
	}
}

func TestProcessOutputSpoolStopsAtProducedLimit(t *testing.T) {
	spool, err := newProcessOutputSpool(4, 64, nil)
	if err != nil {
		t.Fatalf("newOutputSpool() error = %v", err)
	}
	if err := spool.Write(OutputStderr, []byte("1234")); err != nil {
		t.Fatalf("first Write() error = %v", err)
	}
	if err := spool.Write(OutputStdout, []byte("5")); err == nil {
		t.Fatal("second Write() error = nil, want output limit")
	}
}

func TestProcessOutputSpoolMarksOnlyChunksWhoseBytesWereRedacted(t *testing.T) {
	spool, err := newProcessOutputSpool(64, 64, []string{"secret"})
	if err != nil {
		t.Fatalf("newOutputSpool() error = %v", err)
	}
	if err := spool.Write(OutputStdout, []byte("secret")); err != nil {
		t.Fatalf("first Write() error = %v", err)
	}
	if err := spool.Write(OutputStdout, []byte(" ordinary")); err != nil {
		t.Fatalf("second Write() error = %v", err)
	}
	spool.Close(ProcessResult{Reason: TerminationCancelled})
	events := spool.Events()
	if len(events) < 2 || !events[0].Chunk.Redacted {
		t.Fatalf("first output event = %#v, want redacted chunk", events[0])
	}
	if events[1].Chunk.Redacted {
		t.Fatalf("ordinary output event = %#v, must not inherit a prior chunk's redaction flag", events[1])
	}
}

func TestProcessOutputSpoolRetainsEachStreamIndependently(t *testing.T) {
	spool, err := newProcessOutputSpool(64, 4, nil)
	if err != nil {
		t.Fatalf("newProcessOutputSpool() error = %v", err)
	}
	if err := spool.Write(OutputStderr, []byte("err!")); err != nil {
		t.Fatalf("stderr Write() error = %v", err)
	}
	if err := spool.Write(OutputStdout, []byte("out!")); err != nil {
		t.Fatalf("stdout Write() error = %v", err)
	}
	spool.Close(ProcessResult{Reason: TerminationCancelled})
	var stderr string
	for _, event := range spool.Events() {
		if event.Kind == OutputEventChunk && event.Stream == OutputStderr {
			stderr += string(event.Chunk.Bytes)
		}
	}
	if stderr != "err!" {
		t.Fatalf("stderr retained bytes = %q, want independent tail", stderr)
	}
	if spool.Retention(OutputStderr).Truncated {
		t.Fatalf("stderr retention = %#v, must not be truncated by stdout", spool.Retention(OutputStderr))
	}
}

func TestProcessOutputSpoolRedactsBinaryOverlapsAcrossEveryChunkBoundary(t *testing.T) {
	spool, err := newProcessOutputSpool(128, 128, []string{"token", "token-value", "\x00secret\x00"})
	if err != nil {
		t.Fatalf("newProcessOutputSpool() error = %v", err)
	}
	for _, chunk := range [][]byte{
		[]byte("before to"),
		[]byte("ken-va"),
		[]byte("lue after "),
		{'\x00', 's', 'e'},
		{'c', 'r', 'e', 't', '\x00'},
	} {
		if err := spool.Write(OutputStdout, chunk); err != nil {
			t.Fatalf("Write(%q) error = %v", chunk, err)
		}
	}
	spool.Close(ProcessResult{Reason: TerminationExited})

	var got []byte
	for _, event := range spool.Events() {
		if event.Kind == OutputEventChunk {
			got = append(got, event.Chunk.Bytes...)
		}
	}
	for _, forbidden := range [][]byte{[]byte("token"), []byte("token-value"), {'\x00', 's', 'e', 'c', 'r', 'e', 't', '\x00'}} {
		if bytes.Contains(got, forbidden) {
			t.Fatalf("retained output leaked %q: %q", forbidden, got)
		}
	}
	if want := []byte("before [REDACTED] after [REDACTED]"); !bytes.Equal(got, want) {
		t.Fatalf("redacted output = %q, want %q", got, want)
	}
}

func TestProcessOutputSpoolSerializesConcurrentSourcesAndDefensivelyCopiesEvents(t *testing.T) {
	spool, err := newProcessOutputSpool(1024, 1024, []string{"secret"})
	if err != nil {
		t.Fatalf("newProcessOutputSpool() error = %v", err)
	}
	const writers = 32
	var group sync.WaitGroup
	for writer := 0; writer < writers; writer++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			stream := OutputStdout
			if index%2 != 0 {
				stream = OutputStderr
			}
			if err := spool.Write(stream, []byte("secret")); err != nil {
				t.Errorf("Write(%d) error = %v", index, err)
			}
		}(writer)
	}
	group.Wait()
	spool.Close(ProcessResult{Reason: TerminationExited})

	events := spool.Events()
	chunks := 0
	for _, event := range events {
		if event.Kind != OutputEventChunk {
			continue
		}
		chunks++
		if bytes.Contains(event.Chunk.Bytes, []byte("secret")) {
			t.Fatalf("raw secret in retained event: %#v", event)
		}
	}
	if chunks != writers {
		t.Fatalf("retained chunk count = %d, want %d", chunks, writers)
	}
	for index := range events {
		if events[index].Chunk != nil && len(events[index].Chunk.Bytes) != 0 {
			events[index].Chunk.Bytes[0] = 'x'
			break
		}
	}
	for _, event := range spool.Events() {
		if event.Chunk != nil && len(event.Chunk.Bytes) != 0 && event.Chunk.Bytes[0] == 'x' {
			t.Fatal("Events() exposed spool-owned output bytes")
		}
	}
}
