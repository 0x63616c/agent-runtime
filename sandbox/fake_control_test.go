package sandbox

import (
	"context"
	"testing"
	"time"
)

func TestFakeControlClientAdvancesOnlyItsInjectedClockAndReplaysScriptedStatesAndGap(t *testing.T) {
	clock, err := NewFakeClock(time.Date(2026, 8, 10, 14, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("NewFakeClock() error = %v", err)
	}
	client, err := NewFakeControlClient(FakeControlConfig{
		Principal:       "orchestration-test",
		Clock:           clock,
		AdmissionPolicy: operationAdmissionPolicyForTest(testLimitPolicy()),
		Scripts: map[OperationID]FakeOperationScript{
			"op_fake_lifecycle": {
				Steps: []FakeOperationStep{
					{At: time.Minute, State: OperationQueued},
					{At: 2 * time.Minute, State: OperationStarted, Gap: &OperationGap{EarliestRetained: "operation:1", Reason: "scripted durable stream gap"}},
					{At: 3 * time.Minute, State: OperationSucceeded},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewFakeControlClient() error = %v", err)
	}
	request := validCreateRequest("op_fake_lifecycle")
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	operation, err := client.GetOperation(context.Background(), request.ID)
	if err != nil {
		t.Fatalf("GetOperation() error = %v", err)
	}
	if got, want := operation.State, OperationAccepted; got != want {
		t.Fatalf("initial fake state = %q, want %q", got, want)
	}
	if err := client.Advance(time.Minute); err != nil {
		t.Fatalf("Advance() error = %v", err)
	}
	operation, err = client.GetOperation(context.Background(), request.ID)
	if err != nil {
		t.Fatalf("GetOperation() after advance error = %v", err)
	}
	if got, want := operation.State, OperationQueued; got != want {
		t.Fatalf("state after logical minute = %q, want %q", got, want)
	}
	if err := client.Advance(2 * time.Minute); err != nil {
		t.Fatalf("Advance() terminal error = %v", err)
	}
	terminal, err := client.WaitOperation(context.Background(), request.ID)
	if err != nil {
		t.Fatalf("WaitOperation() error = %v", err)
	}
	if got, want := terminal.State, OperationSucceeded; got != want {
		t.Fatalf("terminal state = %q, want %q", got, want)
	}

	stream, err := client.WatchOperation(context.Background(), request.ID, "0")
	if err != nil {
		t.Fatalf("WatchOperation() error = %v", err)
	}
	defer stream.Close()
	var kinds []OperationEventKind
	for {
		event, nextErr := stream.Next(context.Background())
		if failure, ok := AsFailure(nextErr); ok && failure.Code == FailureCursorExpired {
			break
		}
		if nextErr != nil {
			t.Fatalf("stream Next() error = %v", nextErr)
		}
		kinds = append(kinds, event.Kind)
	}
	if got, want := len(kinds), 5; got != want || kinds[0] != OperationEventUpdate || kinds[1] != OperationEventUpdate || kinds[2] != OperationEventUpdate || kinds[3] != OperationEventGap || kinds[4] != OperationEventUpdate {
		t.Fatalf("scripted stream kinds = %#v, want accepted/queued/started/gap/succeeded", kinds)
	}
}

func TestFakeControlClientAppliesScriptedProcessResultAndFailureWithoutExecutingACommand(t *testing.T) {
	clock, err := NewFakeClock(time.Date(2026, 8, 10, 15, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("NewFakeClock() error = %v", err)
	}
	exitCode := 0
	client, err := NewFakeControlClient(FakeControlConfig{
		Principal:       "orchestration-test",
		Clock:           clock,
		AdmissionPolicy: operationAdmissionPolicyForTest(testLimitPolicy()),
		Scripts: map[OperationID]FakeOperationScript{
			"op_fake_process": {Steps: []FakeOperationStep{{At: time.Second, State: OperationSucceeded, ProcessResult: &ProcessResult{StartedAt: clock.Now(), FinishedAt: clock.Now().Add(time.Second), ExitCode: &exitCode, Reason: TerminationExited, Cleanup: TreeCleanupNotRequired}}}},
			"op_fake_failure": {Steps: []FakeOperationStep{{At: 0, State: OperationFailed, Failure: &Failure{Code: FailureUnavailable, Message: "scripted backend loss", Retry: RetryAfterReconcile}}}},
		},
	})
	if err != nil {
		t.Fatalf("NewFakeControlClient() error = %v", err)
	}
	processRequest := OperationRequest{ID: "op_fake_process", Kind: OperationExecProcess, ExecProcess: &ExecProcessRequest{SandboxID: "sbx_01", Command: Command{Executable: "/bin/echo", Argv: []string{"echo", "not-executed"}, WorkDir: "/work"}}}
	if _, err := client.Submit(context.Background(), processRequest); err != nil {
		t.Fatalf("Submit(process) error = %v", err)
	}
	if err := client.Advance(time.Second); err != nil {
		t.Fatalf("Advance() error = %v", err)
	}
	process, err := client.GetProcess(context.Background(), "prc_fake_process")
	if err != nil {
		t.Fatalf("GetProcess() error = %v", err)
	}
	if process.State != ProcessTerminal || process.Result == nil || process.Result.ExitCode == nil || *process.Result.ExitCode != 0 {
		t.Fatalf("scripted process = %#v, want terminal exit 0", process)
	}

	failureRequest := validCreateRequest("op_fake_failure")
	if _, err := client.Submit(context.Background(), failureRequest); err != nil {
		t.Fatalf("Submit(failure) error = %v", err)
	}
	failure, err := client.GetOperation(context.Background(), failureRequest.ID)
	if err != nil {
		t.Fatalf("GetOperation(failure) error = %v", err)
	}
	if failure.State != OperationFailed || failure.Failure == nil || failure.Failure.Code != FailureUnavailable {
		t.Fatalf("scripted failure = %#v, want unavailable terminal operation", failure)
	}
}
