package sandbox

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

const operationRequestKind = "operation-request"

const (
	operationResponseKind    = "operation-response"
	operationEventsKind      = "operation-events"
	capabilitiesResponseKind = "capabilities-response"
	outputEventsResponseKind = "output-events"
	processResponseKind      = "process-response"
	volumeResponseKind       = "volume-response"
	volumePageResponseKind   = "volume-page-response"
	failureResponseKind      = "failure-response"
)

const (
	maxControlV1Bytes      = 1 << 20
	maxControlV1Nesting    = 64
	maxControlV1Collection = 4096
)

type operationRequestEnvelope struct {
	Version string           `json:"version"`
	Kind    string           `json:"kind"`
	Request OperationRequest `json:"request"`
}

type operationResponseEnvelope struct {
	Version   string    `json:"version"`
	Kind      string    `json:"kind"`
	Operation Operation `json:"operation"`
}

type operationEventsEnvelope struct {
	Version string           `json:"version"`
	Kind    string           `json:"kind"`
	Events  []OperationEvent `json:"events"`
}

type capabilitiesResponseEnvelope struct {
	Version      string             `json:"version"`
	Kind         string             `json:"kind"`
	Capabilities CapabilitySnapshot `json:"capabilities"`
}

type outputEventsResponseEnvelope struct {
	Version string        `json:"version"`
	Kind    string        `json:"kind"`
	Events  []OutputEvent `json:"events"`
}

type processResponseEnvelope struct {
	Version string      `json:"version"`
	Kind    string      `json:"kind"`
	Process ProcessInfo `json:"process"`
}

type volumeResponseEnvelope struct {
	Version string     `json:"version"`
	Kind    string     `json:"kind"`
	Volume  VolumeInfo `json:"volume"`
}

type volumePageResponseEnvelope struct {
	Version string     `json:"version"`
	Kind    string     `json:"kind"`
	Page    VolumePage `json:"page"`
}

type failureResponseEnvelope struct {
	Version string  `json:"version"`
	Kind    string  `json:"kind"`
	Failure Failure `json:"failure"`
}

func encodeOperationRequestV1(request OperationRequest) ([]byte, error) {
	if err := validateCanonicalStrings(reflect.ValueOf(request)); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(operationRequestEnvelope{Version: controlV1, Kind: operationRequestKind, Request: copyRequest(request)})
	if err != nil {
		return nil, newFailure(FailureInvalidArgument, "operation request cannot be encoded", RetryNever)
	}
	if len(encoded) > maxControlV1Bytes {
		return nil, newFailure(FailureResourceLimitExceeded, "operation request exceeds the finite wire limit", RetryNever)
	}
	return encoded, nil
}

func decodeOperationRequestV1(data []byte) (OperationRequest, error) {
	if err := validateStrictJSON(data); err != nil {
		return OperationRequest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var envelope operationRequestEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return OperationRequest{}, newFailure(FailureInvalidArgument, "operation request is invalid", RetryNever)
	}
	if envelope.Version != controlV1 || envelope.Kind != operationRequestKind {
		return OperationRequest{}, newFailure(FailureInvalidArgument, "operation request violates sandbox.control/v1", RetryNever)
	}
	canonical, err := encodeOperationRequestV1(envelope.Request)
	if err != nil || !bytes.Equal(canonical, data) {
		return OperationRequest{}, newFailure(FailureInvalidArgument, "operation request is not canonical sandbox.control/v1", RetryNever)
	}
	return copyRequest(envelope.Request), nil
}

func encodeOperationResponseV1(operation Operation) ([]byte, error) {
	return encodeControlV1(operationResponseEnvelope{Version: controlV1, Kind: operationResponseKind, Operation: copyOperation(operation)})
}

func decodeOperationResponseV1(data []byte) (Operation, error) {
	var envelope operationResponseEnvelope
	if err := decodeControlV1(data, operationResponseKind, &envelope); err != nil {
		return Operation{}, err
	}
	if !validWireOperation(envelope.Operation) {
		return Operation{}, newFailure(FailureInvalidArgument, "operation response violates sandbox.control/v1", RetryNever)
	}
	return copyOperation(envelope.Operation), nil
}

func decodeOperationEventsV1(data []byte) ([]OperationEvent, error) {
	var envelope operationEventsEnvelope
	if err := decodeControlV1(data, operationEventsKind, &envelope); err != nil {
		return nil, err
	}
	if len(envelope.Events) == 0 || len(envelope.Events) > maxControlV1Collection {
		return nil, newFailure(FailureInvalidArgument, "operation events violate sandbox.control/v1", RetryNever)
	}
	var prior uint64
	for _, event := range envelope.Events {
		cursor, ok := operationCursorVersion(event.Cursor)
		if !ok || cursor <= prior || (event.Kind == OperationEventUpdate) == (event.Update == nil) || (event.Kind == OperationEventGap) == (event.Gap == nil) {
			return nil, newFailure(FailureInvalidArgument, "operation events violate sandbox.control/v1", RetryNever)
		}
		prior = cursor
		if event.Update != nil {
			encoded, err := encodeOperationResponseV1(*event.Update)
			if err != nil {
				return nil, err
			}
			if _, err := decodeOperationResponseV1(encoded); err != nil {
				return nil, err
			}
			if event.Update.LatestCursor != event.Cursor {
				return nil, newFailure(FailureInvalidArgument, "operation event cursor does not match its update", RetryNever)
			}
		}
		if event.Gap != nil {
			if _, ok := operationCursorVersion(event.Gap.EarliestRetained); !ok || event.Gap.Reason == "" || len(event.Gap.Reason) > 256 {
				return nil, newFailure(FailureInvalidArgument, "operation gap violates sandbox.control/v1", RetryNever)
			}
		}
	}
	return envelope.Events, nil
}

func decodeCapabilitiesResponseV1(data []byte) (CapabilitySnapshot, error) {
	var envelope capabilitiesResponseEnvelope
	if err := decodeControlV1(data, capabilitiesResponseKind, &envelope); err != nil {
		return CapabilitySnapshot{}, err
	}
	if !validCapabilitySnapshot(envelope.Capabilities) {
		return CapabilitySnapshot{}, newFailure(FailureInvalidArgument, "capabilities response violates sandbox.control/v1", RetryNever)
	}
	return copyCapabilitySnapshot(envelope.Capabilities), nil
}

func decodeOutputEventsV1(data []byte) ([]OutputEvent, error) {
	var envelope outputEventsResponseEnvelope
	if err := decodeControlV1(data, outputEventsResponseKind, &envelope); err != nil {
		return nil, err
	}
	if len(envelope.Events) == 0 || len(envelope.Events) > maxControlV1Collection {
		return nil, newFailure(FailureInvalidArgument, "output events violate sandbox.control/v1", RetryNever)
	}
	seen := make(map[OutputCursor]struct{}, len(envelope.Events))
	for _, event := range envelope.Events {
		if event.Kind != OutputEventChunk || event.Cursor == "" || len(event.Cursor) > 128 || event.Stream != OutputStdout && event.Stream != OutputStderr || event.Chunk == nil || event.Gap != nil || event.Final != nil || len(event.Chunk.Bytes) == 0 || len(event.Chunk.Bytes) > maximumOutputChunkBytes {
			return nil, newFailure(FailureInvalidArgument, "output events violate sandbox.control/v1", RetryNever)
		}
		if _, duplicate := seen[event.Cursor]; duplicate {
			return nil, newFailure(FailureInvalidArgument, "output events violate sandbox.control/v1", RetryNever)
		}
		seen[event.Cursor] = struct{}{}
	}
	return copyOutputEvents(envelope.Events), nil
}

func decodeProcessResponseV1(data []byte) (ProcessInfo, error) {
	var envelope processResponseEnvelope
	if err := decodeControlV1(data, processResponseKind, &envelope); err != nil {
		return ProcessInfo{}, err
	}
	if !validProcessID(envelope.Process.ID) || !validSandboxID(envelope.Process.SandboxID) {
		return ProcessInfo{}, newFailure(FailureInvalidArgument, "process response violates sandbox.control/v1", RetryNever)
	}
	return copyProcessInfo(envelope.Process), nil
}

func decodeVolumeResponseV1(data []byte) (VolumeInfo, error) {
	var envelope volumeResponseEnvelope
	if err := decodeControlV1(data, volumeResponseKind, &envelope); err != nil {
		return VolumeInfo{}, err
	}
	if !validVolumeID(envelope.Volume.ID) {
		return VolumeInfo{}, newFailure(FailureInvalidArgument, "volume response violates sandbox.control/v1", RetryNever)
	}
	return copyVolumeInfo(envelope.Volume), nil
}

func decodeVolumePageResponseV1(data []byte) (VolumePage, error) {
	var envelope volumePageResponseEnvelope
	if err := decodeControlV1(data, volumePageResponseKind, &envelope); err != nil {
		return VolumePage{}, err
	}
	if len(envelope.Page.Items) > 100 || (envelope.Page.Next != "" && !validVolumeID(VolumeID(envelope.Page.Next))) {
		return VolumePage{}, newFailure(FailureInvalidArgument, "volume page response violates sandbox.control/v1", RetryNever)
	}
	previous := ""
	for _, volume := range envelope.Page.Items {
		if !validVolumeID(volume.ID) || string(volume.ID) <= previous {
			return VolumePage{}, newFailure(FailureInvalidArgument, "volume page response violates sandbox.control/v1", RetryNever)
		}
		previous = string(volume.ID)
	}
	page := VolumePage{Next: envelope.Page.Next, Items: make([]VolumeInfo, len(envelope.Page.Items))}
	for index, volume := range envelope.Page.Items {
		page.Items[index] = copyVolumeInfo(volume)
	}
	return page, nil
}

func copyOutputEvents(events []OutputEvent) []OutputEvent {
	copied := make([]OutputEvent, len(events))
	for index, event := range events {
		copied[index] = copyOutputEvent(event)
	}
	return copied
}

func decodeFailureResponseV1(data []byte) (Failure, error) {
	var envelope failureResponseEnvelope
	if err := decodeControlV1(data, failureResponseKind, &envelope); err != nil || !validWireFailure(envelope.Failure) {
		return Failure{}, newFailure(FailureInvalidArgument, "failure response violates sandbox.control/v1", RetryNever)
	}
	return *copyFailure(&envelope.Failure), nil
}

func encodeControlV1(envelope any) ([]byte, error) {
	if err := validateCanonicalStrings(reflect.ValueOf(envelope)); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(envelope)
	if err != nil || len(encoded) > maxControlV1Bytes {
		return nil, newFailure(FailureResourceLimitExceeded, "sandbox.control/v1 response exceeds the finite wire limit", RetryNever)
	}
	return encoded, nil
}

func decodeControlV1(data []byte, kind string, envelope any) error {
	if err := validateStrictJSON(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(envelope); err != nil {
		return newFailure(FailureInvalidArgument, "sandbox.control/v1 response is invalid", RetryNever)
	}
	encoded, err := encodeControlV1(envelope)
	if err != nil || !bytes.Equal(encoded, data) {
		return newFailure(FailureInvalidArgument, "sandbox.control/v1 response is not canonical", RetryNever)
	}
	value := reflect.ValueOf(envelope)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return newFailure(FailureInvalidArgument, "sandbox.control/v1 response is invalid", RetryNever)
	}
	value = value.Elem()
	version := value.FieldByName("Version")
	kindField := value.FieldByName("Kind")
	if !version.IsValid() || !kindField.IsValid() || version.String() != controlV1 || kindField.String() != kind {
		return newFailure(FailureInvalidArgument, "sandbox.control/v1 response has invalid version or kind", RetryNever)
	}
	return nil
}

func validWireFailure(failure Failure) bool {
	if failure.Message == "" || len(failure.Message) > 512 || (failure.Retry != RetryNever && failure.Retry != RetryAfterReconcile && failure.Retry != RetryCallerControlled) || len(failure.Details) > 16 {
		return false
	}
	switch failure.Code {
	case FailureInvalidArgument, FailureNotFoundOrDenied, FailureOperationConflict, FailureAlreadyTerminal, FailureCursorExpired, FailureOutputGap, FailureGrantWideningDenied, FailureNetworkGrantInvalid, FailureCapabilityUnavailable, FailureCapabilityRegressed, FailureResourceLimitExceeded, FailureControlQuotaExceeded, FailureIncompatiblePersistedPolicy, FailureOutcomeUncertain, FailureCancelled, FailureDeadlineExceeded, FailureUnavailable:
	default:
		return false
	}
	keys := make([]string, len(failure.Details))
	for index, detail := range failure.Details {
		switch detail.Key {
		case DetailField, DetailLimit, DetailResource, DetailCapability, DetailPolicyVersion, DetailEarliestCursor, DetailOperationState, DetailRetryAfterMillis:
		default:
			return false
		}
		if detail.Value == "" || len(detail.Value) > 256 {
			return false
		}
		keys[index] = string(detail.Key)
	}
	if !sort.StringsAreSorted(keys) {
		return false
	}
	for index := 1; index < len(keys); index++ {
		if keys[index] == keys[index-1] {
			return false
		}
	}
	return true
}

func validWireOperation(operation Operation) bool {
	if !validOperationID(operation.Ref.ID) || operation.Ref.AcceptedAt.IsZero() || operation.Ref.AcceptedAt.Location() != time.UTC || operation.RetentionExpiresAt.Location() != time.UTC || !operation.RetentionExpiresAt.After(operation.Ref.AcceptedAt) || !validOperationKind(operation.Kind) || !validOperationState(operation.State) || !validOperationTarget(operation.Target) || !validDigest(operation.CanonicalDigest) || !validDigest(operation.EffectiveSpecDigest) || !validDigest(operation.CapabilityDigest) {
		return false
	}
	if _, ok := operationCursorVersion(operation.LatestCursor); !ok {
		return false
	}
	return operation.Failure == nil || validWireFailure(*operation.Failure)
}

func validOperationKind(kind OperationKind) bool {
	switch kind {
	case OperationCreateSandbox, OperationRestoreSandbox, OperationExecProcess, OperationSignalProcess, OperationKillProcess, OperationCopyIn, OperationCopyOut, OperationSnapshotSandbox, OperationCloseSandbox, OperationReconcileSandbox, OperationCreateVolume, OperationAttachVolume, OperationDetachVolume, OperationDeleteVolume, OperationDeleteSnapshot, OperationApproveSensitive:
		return true
	default:
		return false
	}
}

func validOperationState(state OperationState) bool {
	switch state {
	case OperationAccepted, OperationQueued, OperationDispatched, OperationStarted, OperationSucceeded, OperationFailed, OperationCancelled, OperationUncertain, OperationCleanupPending, OperationCleanupConfirmed, OperationExpired, OperationTombstoned:
		return true
	default:
		return false
	}
}

func validOperationTarget(target OperationTarget) bool {
	switch target.Kind {
	case TargetSandbox:
		return validSandboxID(target.SandboxID) && target.ProcessID == "" && target.VolumeID == "" && target.SnapshotID == "" && target.OperationID == ""
	case TargetProcess:
		return validProcessID(target.ProcessID) && target.SandboxID == "" && target.VolumeID == "" && target.SnapshotID == "" && target.OperationID == ""
	case TargetVolume:
		return validVolumeID(target.VolumeID) && (target.SandboxID == "" || validSandboxID(target.SandboxID)) && target.ProcessID == "" && target.SnapshotID == "" && target.OperationID == ""
	case TargetSnapshot:
		return validSnapshotID(target.SnapshotID) && target.SandboxID == "" && target.ProcessID == "" && target.VolumeID == "" && target.OperationID == ""
	case TargetOperation:
		return validOperationID(target.OperationID) && target.SandboxID == "" && target.ProcessID == "" && target.VolumeID == "" && target.SnapshotID == ""
	case TargetNone:
		return target.SandboxID == "" && target.ProcessID == "" && target.VolumeID == "" && target.SnapshotID == "" && target.OperationID == ""
	default:
		return false
	}
}

func operationCursorVersion(cursor OperationCursor) (uint64, bool) {
	const prefix = "operation:"
	if !strings.HasPrefix(string(cursor), prefix) {
		return 0, false
	}
	version, err := strconv.ParseUint(string(cursor)[len(prefix):], 10, 64)
	return version, err == nil && version > 0
}

// validateStrictJSON rejects every form that encoding/json would otherwise
// quietly normalize: duplicate keys, trailing values, float/exponent numbers,
// and aliases that do not round-trip to canonical bytes.
func validateStrictJSON(data []byte) error {
	if len(data) == 0 || len(data) > maxControlV1Bytes {
		return newFailure(FailureResourceLimitExceeded, "sandbox.control/v1 exceeds the finite wire limit", RetryNever)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return newFailure(FailureInvalidArgument, "sandbox.control/v1 has trailing JSON data", RetryNever)
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth >= maxControlV1Nesting {
		return newFailure(FailureResourceLimitExceeded, "sandbox.control/v1 nesting exceeds the finite limit", RetryNever)
	}
	token, err := decoder.Token()
	if err != nil {
		return newFailure(FailureInvalidArgument, "sandbox.control/v1 contains invalid JSON", RetryNever)
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			seen := make(map[string]struct{})
			entries := 0
			for decoder.More() {
				entries++
				if entries > maxControlV1Collection {
					return newFailure(FailureResourceLimitExceeded, "sandbox.control/v1 object exceeds the finite entry limit", RetryNever)
				}
				key, err := decoder.Token()
				if err != nil {
					return newFailure(FailureInvalidArgument, "sandbox.control/v1 object key is invalid", RetryNever)
				}
				name, ok := key.(string)
				if !ok || name == "" {
					return newFailure(FailureInvalidArgument, "sandbox.control/v1 object key is invalid", RetryNever)
				}
				if _, duplicate := seen[name]; duplicate {
					return newFailure(FailureInvalidArgument, "sandbox.control/v1 contains a duplicate key", RetryNever)
				}
				seen[name] = struct{}{}
				if err := scanJSONValue(decoder, depth+1); err != nil {
					return err
				}
			}
			if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
				return newFailure(FailureInvalidArgument, "sandbox.control/v1 object is incomplete", RetryNever)
			}
		case '[':
			entries := 0
			for decoder.More() {
				entries++
				if entries > maxControlV1Collection {
					return newFailure(FailureResourceLimitExceeded, "sandbox.control/v1 array exceeds the finite entry limit", RetryNever)
				}
				if err := scanJSONValue(decoder, depth+1); err != nil {
					return err
				}
			}
			if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
				return newFailure(FailureInvalidArgument, "sandbox.control/v1 array is incomplete", RetryNever)
			}
		default:
			return newFailure(FailureInvalidArgument, "sandbox.control/v1 delimiter is invalid", RetryNever)
		}
	case json.Number:
		text := value.String()
		if strings.ContainsAny(text, ".eE") || strings.HasPrefix(text, "+") || (len(text) > 1 && text[0] == '0') || strings.HasPrefix(text, "-0") {
			return newFailure(FailureInvalidArgument, "sandbox.control/v1 number is not a canonical integer", RetryNever)
		}
	}
	return nil
}
