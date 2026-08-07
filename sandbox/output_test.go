package sandbox

import "testing"

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
