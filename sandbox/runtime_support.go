package sandbox

import (
	"context"
	"sort"
	"strconv"
)

func sandboxIDFor(operationID OperationID) SandboxID {
	return SandboxID("sbx_" + string(operationID)[3:])
}

func processIDFor(operationID OperationID) ProcessID {
	return ProcessID("prc_" + string(operationID)[3:])
}

func digestCanonical(value string) Digest {
	// canonicalRequestDigest owns the exact hash primitive. A synthetic
	// operation lets Effective Spec version facts use the same unambiguous
	// framing without making a second hash implementation.
	return canonicalDigestBytes([]byte(value))
}

func ptrOperation(value Operation) *Operation             { return &value }
func ptrProcessResult(value ProcessResult) *ProcessResult { return &value }

func isTerminalOperation(state OperationState) bool {
	switch state {
	case OperationSucceeded, OperationFailed, OperationCancelled, OperationUncertain, OperationExpired, OperationTombstoned:
		return true
	default:
		return false
	}
}

func validateProcessResult(result ProcessResult) error {
	if result.Reason == "" {
		return newFailure(FailureInvalidArgument, "process result requires a termination reason", RetryNever)
	}
	switch result.Reason {
	case TerminationExited, TerminationSignaled, TerminationTimedOut, TerminationOOMKilled, TerminationOutputLimit, TerminationCancelled, TerminationKilledByCaller, TerminationSandboxClosed, TerminationSandboxLost, TerminationStartupFailed, TerminationInfrastructureFailed, TerminationOutcomeUncertain:
	default:
		return newFailure(FailureInvalidArgument, "process termination reason is invalid", RetryNever)
	}
	if result.Reason == TerminationOutcomeUncertain && (result.ExitCode != nil || result.Signal != nil) {
		return newFailure(FailureInvalidArgument, "uncertain process outcome cannot invent exit status", RetryNever)
	}
	if result.Reason == TerminationExited && result.ExitCode == nil {
		return newFailure(FailureInvalidArgument, "exited process result requires an exit code", RetryNever)
	}
	if result.Reason == TerminationSignaled && result.Signal == nil {
		return newFailure(FailureInvalidArgument, "signaled process result requires a signal", RetryNever)
	}
	return nil
}

func copyFailure(value *Failure) *Failure {
	if value == nil {
		return nil
	}
	copied := *value
	copied.Details = append([]FailureDetail(nil), value.Details...)
	return &copied
}

func copyProcessResult(value ProcessResult) ProcessResult {
	copied := value
	if value.ExitCode != nil {
		exitCode := *value.ExitCode
		copied.ExitCode = &exitCode
	}
	if value.Signal != nil {
		signal := *value.Signal
		copied.Signal = &signal
	}
	return copied
}

func copyOperationResult(value *OperationResult) *OperationResult {
	if value == nil {
		return nil
	}
	copied := *value
	if value.Sandbox != nil {
		payload := *value.Sandbox
		copied.Sandbox = &payload
	}
	if value.Process != nil {
		payload := copyProcessResult(*value.Process)
		copied.Process = &payload
	}
	if value.Artifact != nil {
		payload := *value.Artifact
		copied.Artifact = &payload
	}
	if value.Volume != nil {
		payload := *value.Volume
		if payload.Attachment != nil {
			attachment := *payload.Attachment
			payload.Attachment = &attachment
		}
		copied.Volume = &payload
	}
	if value.Snapshot != nil {
		payload := *value.Snapshot
		copied.Snapshot = &payload
	}
	if value.Control != nil {
		payload := *value.Control
		copied.Control = &payload
	}
	return &copied
}

func copyCapabilitySnapshot(value CapabilitySnapshot) CapabilitySnapshot {
	copied := value
	copied.Signals = append([]Signal(nil), value.Signals...)
	copied.Isolation.LimitPrecision = append([]string(nil), value.Isolation.LimitPrecision...)
	copied.Resources.LimitPrecision = append([]string(nil), value.Resources.LimitPrecision...)
	copied.Output.LimitPrecision = append([]string(nil), value.Output.LimitPrecision...)
	return copied
}

func copyEffectiveSpec(value effectiveSpec) effectiveSpec {
	copied := value
	copied.request = copyRequest(value.request)
	copied.capabilities = copyCapabilitySnapshot(value.capabilities)
	copied.image.Identity.Groups = append([]uint32(nil), value.image.Identity.Groups...)
	return copied
}

func copySandboxInfo(value SandboxInfo) SandboxInfo {
	copied := value
	copied.Image.Identity.Groups = append([]uint32(nil), value.Image.Identity.Groups...)
	copied.Capabilities = copyCapabilitySnapshot(value.Capabilities)
	copied.Failure = copyFailure(value.Failure)
	return copied
}

func copyProcessInfo(value ProcessInfo) ProcessInfo {
	copied := value
	if value.Result != nil {
		result := copyProcessResult(*value.Result)
		copied.Result = &result
	}
	return copied
}

func copyVolumeInfo(value VolumeInfo) VolumeInfo {
	copied := value
	if value.Attachment != nil {
		attachment := *value.Attachment
		copied.Attachment = &attachment
	}
	return copied
}

func copySnapshotInfo(value SnapshotInfo) SnapshotInfo { return value }

func pageVolumes(values map[VolumeID]VolumeInfo, page Page) VolumePage {
	ids := make([]string, 0, len(values))
	for id := range values {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)
	start := cursorStart(page.Cursor, ids)
	end := start + int(page.Limit)
	if end > len(ids) {
		end = len(ids)
	}
	result := VolumePage{Items: make([]VolumeInfo, 0, end-start)}
	for _, id := range ids[start:end] {
		result.Items = append(result.Items, copyVolumeInfo(values[VolumeID(id)]))
	}
	if end < len(ids) {
		result.Next = PageCursor(ids[end-1])
	}
	return result
}

func pageSnapshots(values map[SnapshotID]SnapshotInfo, page Page) SnapshotPage {
	ids := make([]string, 0, len(values))
	for id := range values {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)
	start := cursorStart(page.Cursor, ids)
	end := start + int(page.Limit)
	if end > len(ids) {
		end = len(ids)
	}
	result := SnapshotPage{Items: make([]SnapshotInfo, 0, end-start)}
	for _, id := range ids[start:end] {
		result.Items = append(result.Items, copySnapshotInfo(values[SnapshotID(id)]))
	}
	if end < len(ids) {
		result.Next = PageCursor(ids[end-1])
	}
	return result
}

func cursorStart(cursor PageCursor, values []string) int {
	if cursor == "" {
		return 0
	}
	for index, value := range values {
		if value > string(cursor) {
			return index
		}
	}
	return len(values)
}

type sliceOperationStream struct {
	events []OperationEvent
	index  int
	closed bool
}

func (stream *sliceOperationStream) Next(ctx context.Context) (OperationEvent, error) {
	if err := contextFailure(ctx); err != nil {
		return OperationEvent{}, err
	}
	if stream.closed || stream.index >= len(stream.events) {
		return OperationEvent{}, newFailure(FailureCursorExpired, "operation stream is complete", RetryNever)
	}
	value := stream.events[stream.index]
	stream.index++
	if value.Update != nil {
		value.Update = ptrOperation(copyOperation(*value.Update))
	}
	return value, nil
}

func (stream *sliceOperationStream) Close() error {
	stream.closed = true
	return nil
}

type sliceOutputStream struct {
	events []OutputEvent
	index  int
	closed bool
}

func newSliceOutputStream(events []OutputEvent, from OutputCursor) (OutputStream, error) {
	start := 0
	if from != "" && from != "0" {
		seen := false
		for index, event := range events {
			if event.Cursor == from {
				start = index + 1
				seen = true
				break
			}
		}
		if !seen {
			return nil, newFailure(FailureOutputGap, "output cursor is outside retained history", RetryNever)
		}
	}
	copied := make([]OutputEvent, len(events)-start)
	for index, event := range events[start:] {
		copied[index] = copyOutputEvent(event)
	}
	return &sliceOutputStream{events: copied}, nil
}

func (stream *sliceOutputStream) Next(ctx context.Context) (OutputEvent, error) {
	if err := contextFailure(ctx); err != nil {
		return OutputEvent{}, err
	}
	if stream.closed || stream.index >= len(stream.events) {
		return OutputEvent{}, newFailure(FailureCursorExpired, "output stream is complete", RetryNever)
	}
	value := copyOutputEvent(stream.events[stream.index])
	stream.index++
	return value, nil
}

func (stream *sliceOutputStream) Close() error {
	stream.closed = true
	return nil
}

func copyOutputEvent(value OutputEvent) OutputEvent {
	copied := value
	if value.Chunk != nil {
		chunk := *value.Chunk
		chunk.Bytes = append([]byte(nil), value.Chunk.Bytes...)
		copied.Chunk = &chunk
	}
	if value.Gap != nil {
		gap := *value.Gap
		copied.Gap = &gap
	}
	if value.Final != nil {
		final := *value.Final
		final.Result = copyProcessResult(value.Final.Result)
		copied.Final = &final
	}
	return copied
}

func outputCursor(number uint64) OutputCursor { return OutputCursor(strconv.FormatUint(number, 10)) }

var _ OperationStream = (*sliceOperationStream)(nil)
var _ OutputStream = (*sliceOutputStream)(nil)
var _ = context.Background
