package sandbox

import "testing"

func TestOutputSpoolRedactsAcrossChunksAndReportsRetentionGap(t *testing.T) {
	spool, err := newOutputSpool(OutputStdout, 10, 64, []string{"secret"})
	if err != nil {
		t.Fatalf("newOutputSpool() error = %v", err)
	}
	if err := spool.Write([]byte("a sec")); err != nil {
		t.Fatalf("first Write() error = %v", err)
	}
	if err := spool.Write([]byte("ret z")); err != nil {
		t.Fatalf("second Write() error = %v", err)
	}
	events := spool.Close(ProcessResult{Reason: TerminationExited})
	if len(events) != 3 {
		t.Fatalf("events = %#v, want two chunks and final", events)
	}
	if events[0].Kind != OutputEventChunk || events[1].Kind != OutputEventChunk || string(events[0].Chunk.Bytes)+string(events[1].Chunk.Bytes) != "a [REDACTED] z" || !events[1].Chunk.Redacted {
		t.Errorf("chunks = %#v", events[:2])
	}
	if events[2].Kind != OutputEventFinal {
		t.Errorf("final event = %#v, want final", events[2])
	}
}

func TestOutputSpoolStopsAtProducedLimit(t *testing.T) {
	spool, err := newOutputSpool(OutputStderr, 4, 64, nil)
	if err != nil {
		t.Fatalf("newOutputSpool() error = %v", err)
	}
	if err := spool.Write([]byte("1234")); err != nil {
		t.Fatalf("first Write() error = %v", err)
	}
	if err := spool.Write([]byte("5")); err == nil {
		t.Fatal("second Write() error = nil, want output limit")
	}
}
