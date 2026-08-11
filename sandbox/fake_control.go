package sandbox

import (
	"context"
	"sort"
	"strconv"
	"sync"
	"time"
)

// FakeClock is a manually advanced UTC clock for deterministic sandbox
// orchestration tests. It never reads wall time or sleeps.
type FakeClock struct {
	mu  sync.RWMutex
	now time.Time
}

// NewFakeClock constructs a deterministic clock at a non-zero instant.
func NewFakeClock(now time.Time) (*FakeClock, error) {
	if now.IsZero() {
		return nil, newFailure(FailureInvalidArgument, "fake clock requires a non-zero instant", RetryNever)
	}
	return &FakeClock{now: now.UTC()}, nil
}

// Now returns the fake clock's current UTC instant.
func (clock *FakeClock) Now() time.Time {
	if clock == nil {
		return time.Time{}
	}
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.now
}

// Advance moves the fake clock without waiting on wall time.
func (clock *FakeClock) Advance(delta time.Duration) error {
	if clock == nil || delta < 0 {
		return newFailure(FailureInvalidArgument, "fake clock advance must be finite and non-negative", RetryNever)
	}
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(delta)
	return nil
}

// FakeControlConfig declares a deterministic no-execution control adapter.
// Scripts are keyed by the immutable operation ID that they will control.
type FakeControlConfig struct {
	Principal       string
	Clock           *FakeClock
	AdmissionPolicy OperationAdmissionPolicy
	Scripts         map[OperationID]FakeOperationScript
}

// FakeOperationScript is a deterministic operation timeline. Steps are
// applied only when the owning FakeControlClient advances its FakeClock.
type FakeOperationScript struct {
	Steps []FakeOperationStep
}

// FakeOperationStep records a fake durable transition without starting an OS
// process. A ProcessResult is permitted only for an exec operation. Gap, if
// set, is emitted immediately after this transition.
type FakeOperationStep struct {
	At            time.Duration
	State         OperationState
	Failure       *Failure
	ProcessResult *ProcessResult
	Gap           *OperationGap
}

// FakeControlClient is a deterministic Client implementation for unit and
// orchestration tests. It records scripted state only and never executes a
// command, opens a network connection, or touches a filesystem.
type FakeControlClient struct {
	*coreClient
	clock   *FakeClock
	mu      sync.Mutex
	scripts map[OperationID]FakeOperationScript
	states  map[OperationID]*fakeOperationState
}

type fakeOperationState struct {
	acceptedAt time.Time
	script     FakeOperationScript
	next       int
	events     []OperationEvent
}

// NewFakeControlClient constructs a deterministic no-execution control client.
func NewFakeControlClient(config FakeControlConfig) (*FakeControlClient, error) {
	if config.Principal == "" || config.Clock == nil {
		return nil, newFailure(FailureInvalidArgument, "fake control client requires principal and fake clock", RetryNever)
	}
	if err := validateFakeScripts(config.Scripts); err != nil {
		return nil, err
	}
	client, err := newCoreClientWithPolicy(config.Principal, config.Clock.Now(), limitPolicyFromAdmission(config.AdmissionPolicy))
	if err != nil {
		return nil, err
	}
	scripts := make(map[OperationID]FakeOperationScript, len(config.Scripts))
	for id, script := range config.Scripts {
		scripts[id] = copyFakeOperationScript(script)
	}
	return &FakeControlClient{coreClient: client, clock: config.Clock, scripts: scripts, states: make(map[OperationID]*fakeOperationState)}, nil
}

// Advance moves logical time and applies every due scripted transition. It is
// the only way a FakeControlClient changes a non-terminal scripted operation.
func (client *FakeControlClient) Advance(delta time.Duration) error {
	if client == nil {
		return newFailure(FailureUnavailable, "fake control client is unavailable", RetryNever)
	}
	if err := client.clock.Advance(delta); err != nil {
		return err
	}
	client.applyDueTransitions()
	return nil
}

// Submit validates and persists an operation through the normal control seam,
// then associates an optional immutable fake script with its opaque ID.
func (client *FakeControlClient) Submit(ctx context.Context, request OperationRequest) (OperationRef, error) {
	if client == nil {
		return OperationRef{}, newFailure(FailureUnavailable, "fake control client is unavailable", RetryNever)
	}
	ref, err := client.coreClient.Submit(ctx, request)
	if err != nil {
		return OperationRef{}, err
	}
	client.mu.Lock()
	if client.states[ref.ID] == nil {
		state := &fakeOperationState{acceptedAt: ref.AcceptedAt, script: copyFakeOperationScript(client.scripts[ref.ID])}
		state.events = []OperationEvent{client.currentOperationEvent(ref.ID, 1)}
		client.states[ref.ID] = state
	}
	client.mu.Unlock()
	client.applyDueTransitions()
	return ref, nil
}

// GetOperation observes the current scripted durable state.
func (client *FakeControlClient) GetOperation(ctx context.Context, id OperationID) (Operation, error) {
	client.applyDueTransitions()
	return client.coreClient.GetOperation(ctx, id)
}

// WaitOperation waits for a terminal scripted state or caller cancellation.
func (client *FakeControlClient) WaitOperation(ctx context.Context, id OperationID) (Operation, error) {
	client.applyDueTransitions()
	return client.coreClient.WaitOperation(ctx, id)
}

// WatchOperation replays the deterministic scripted transition history.
func (client *FakeControlClient) WatchOperation(ctx context.Context, id OperationID, from OperationCursor) (OperationStream, error) {
	if err := contextFailure(ctx); err != nil {
		return nil, err
	}
	client.applyDueTransitions()
	client.mu.Lock()
	state := client.states[id]
	if state == nil {
		client.mu.Unlock()
		return nil, newFailure(FailureNotFoundOrDenied, "operation was not found", RetryNever)
	}
	events, err := fakeEventsAfter(state.events, from)
	client.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &sliceOperationStream{events: events}, nil
}

// GetSandbox observes sandbox information after applying due fake transitions.
func (client *FakeControlClient) GetSandbox(ctx context.Context, id SandboxID) (SandboxInfo, error) {
	client.applyDueTransitions()
	return client.coreClient.GetSandbox(ctx, id)
}

// GetProcess observes a scripted process result without any process execution.
func (client *FakeControlClient) GetProcess(ctx context.Context, id ProcessID) (ProcessInfo, error) {
	client.applyDueTransitions()
	return client.coreClient.GetProcess(ctx, id)
}

// ReplayOutput observes the normal bounded fake output spool.
func (client *FakeControlClient) ReplayOutput(ctx context.Context, id ProcessID, from OutputCursor) (OutputStream, error) {
	client.applyDueTransitions()
	return client.coreClient.ReplayOutput(ctx, id, from)
}

func (client *FakeControlClient) applyDueTransitions() {
	if client == nil {
		return
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	now := client.clock.Now()
	ids := make([]string, 0, len(client.states))
	for id := range client.states {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)
	for _, rawID := range ids {
		id := OperationID(rawID)
		state := client.states[id]
		for state.next < len(state.script.Steps) && !state.acceptedAt.Add(state.script.Steps[state.next].At).After(now) {
			client.applyStepLocked(id, state, state.script.Steps[state.next])
			state.next++
		}
	}
}

func (client *FakeControlClient) applyStepLocked(id OperationID, state *fakeOperationState, step FakeOperationStep) {
	client.ledger.mu.Lock()
	defer client.ledger.mu.Unlock()
	ledger := client.ledger.principals[client.principal]
	if ledger == nil || ledger.operations[id] == nil {
		return
	}
	entry := ledger.operations[id]
	if isTerminalOperation(entry.value.State) {
		return
	}
	entry.value.State = step.State
	entry.value.Failure = copyFailure(step.Failure)
	if step.ProcessResult != nil {
		processID := processIDFor(id)
		record := ledger.processes[processID]
		if record != nil {
			client.completeProcessLocked(ledger, record, *step.ProcessResult)
			entry.value.Result = &OperationResult{Kind: ResultProcess, Process: ptrProcessResult(*step.ProcessResult)}
		}
	}
	cursor := OperationCursor("operation:" + strconvFormatUint(uint64(len(state.events)+1)))
	entry.value.LatestCursor = cursor
	state.events = append(state.events, OperationEvent{Kind: OperationEventUpdate, Cursor: cursor, Update: ptrOperation(copyOperation(entry.value))})
	if step.Gap != nil {
		gapCursor := OperationCursor("operation:" + strconvFormatUint(uint64(len(state.events)+1)))
		state.events = append(state.events, OperationEvent{Kind: OperationEventGap, Cursor: gapCursor, Gap: copyOperationGap(step.Gap)})
		entry.value.LatestCursor = gapCursor
	}
	if isTerminalOperation(entry.value.State) {
		entry.once.Do(func() { close(entry.done) })
	}
}

func (client *FakeControlClient) currentOperationEvent(id OperationID, sequence uint64) OperationEvent {
	client.ledger.mu.Lock()
	defer client.ledger.mu.Unlock()
	ledger := client.ledger.principals[client.principal]
	entry := ledger.operations[id]
	cursor := OperationCursor("operation:" + strconvFormatUint(sequence))
	entry.value.LatestCursor = cursor
	return OperationEvent{Kind: OperationEventUpdate, Cursor: cursor, Update: ptrOperation(copyOperation(entry.value))}
}

func validateFakeScripts(scripts map[OperationID]FakeOperationScript) error {
	for id, script := range scripts {
		if !validOperationID(id) {
			return newFailure(FailureInvalidArgument, "fake script operation ID is invalid", RetryNever)
		}
		var previous time.Duration
		for index, step := range script.Steps {
			if step.At < 0 || (index > 0 && step.At <= previous) || !validOperationState(step.State) || (step.Failure != nil && !validWireFailure(*step.Failure)) || (step.Gap != nil && (!validOperationCursor(step.Gap.EarliestRetained) || step.Gap.Reason == "" || len(step.Gap.Reason) > 256)) {
				return newFailure(FailureInvalidArgument, "fake operation script is invalid", RetryNever)
			}
			if index > 0 && isTerminalOperation(script.Steps[index-1].State) {
				return newFailure(FailureInvalidArgument, "fake operation script continues after terminal state", RetryNever)
			}
			previous = step.At
		}
	}
	return nil
}

func fakeEventsAfter(events []OperationEvent, from OperationCursor) ([]OperationEvent, error) {
	if from == "" || from == "0" {
		return copyOperationEvents(events), nil
	}
	for index, event := range events {
		if event.Cursor == from {
			return copyOperationEvents(events[index+1:]), nil
		}
	}
	return nil, newFailure(FailureCursorExpired, "operation cursor is outside retained fake history", RetryNever)
}

func copyOperationEvents(events []OperationEvent) []OperationEvent {
	copied := make([]OperationEvent, len(events))
	for index, event := range events {
		copied[index] = event
		if event.Update != nil {
			copied[index].Update = ptrOperation(copyOperation(*event.Update))
		}
		copied[index].Gap = copyOperationGap(event.Gap)
	}
	return copied
}

func copyOperationGap(value *OperationGap) *OperationGap {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func copyFakeOperationScript(value FakeOperationScript) FakeOperationScript {
	copied := FakeOperationScript{Steps: make([]FakeOperationStep, len(value.Steps))}
	for index, step := range value.Steps {
		copied.Steps[index] = step
		copied.Steps[index].Failure = copyFailure(step.Failure)
		copied.Steps[index].Gap = copyOperationGap(step.Gap)
		if step.ProcessResult != nil {
			result := copyProcessResult(*step.ProcessResult)
			copied.Steps[index].ProcessResult = &result
		}
	}
	return copied
}

func validOperationCursor(cursor OperationCursor) bool {
	_, ok := operationCursorVersion(cursor)
	return ok
}

func strconvFormatUint(value uint64) string {
	return strconv.FormatUint(value, 10)
}

var _ Client = (*FakeControlClient)(nil)
