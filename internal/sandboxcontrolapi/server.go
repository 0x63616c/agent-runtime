// Package sandboxcontrolapi serves the private sandbox.control/v1 control
// process without exposing persistence, authentication, or transport types in
// the public sandbox SDK.
package sandboxcontrolapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/sandboxcontrol"
	"github.com/0x63616c/agent-runtime/sandbox"
	"github.com/cockroachdb/errors"
)

const (
	controlVersion        = "sandbox.control/v1"
	bindPath              = "/sandbox.control/v1/bind"
	operationsPath        = "/sandbox.control/v1/operations"
	capabilitiesPath      = "/sandbox.control/v1/capabilities"
	processOutputPath     = "/sandbox.control/v1/processes/{id}/output"
	volumesPath           = "/sandbox.control/v1/volumes"
	bindingHeader         = "Sandbox-Binding"
	maxRequestBytes       = 1 << 20
	maxAssertionBytes     = 2048
	maxOperationEventPage = 1000
)

var canonicalBindRequest = []byte(`{"version":"sandbox.control/v1","kind":"bind-request"}`)

// Identity is the complete authenticated authority bound to one private
// assertion. Principal is the durable ledger scope; Authority, Tenant and
// Subject prevent a credential from matching only by display name.
type Identity struct {
	Authority string
	Tenant    string
	Subject   string
	Principal string
}

// Authenticator verifies a fresh request credential without retaining it.
type Authenticator interface {
	Authenticate(context.Context, string) (Identity, error)
}

// Config contains explicit control-process authority and finite policy.
type Config struct {
	Store           sandboxcontrol.DurableStore
	Authenticator   Authenticator
	AssertionKey    []byte
	Entropy         io.Reader
	Clock           clock.Clock
	BindingLifetime time.Duration
	Retention       time.Duration
	WaitInterval    time.Duration
	// Wait is the injected cancellation-aware scheduling seam used between
	// durable reads. Production composition supplies a bounded context wait;
	// deterministic tests can advance without wall-clock sleeps.
	Wait      func(context.Context, time.Duration) error
	Admission sandbox.OperationAdmissionPolicy
}

// NewHandler constructs a strict, bounded sandbox.control/v1 handler. It does
// not open a listener, create schema, load credentials, or dispatch a host.
func NewHandler(config Config) (http.Handler, error) {
	if config.Store == nil || config.Authenticator == nil || config.Entropy == nil || config.Clock == nil || config.Wait == nil || len(config.AssertionKey) < 32 || len(config.AssertionKey) > 128 || config.BindingLifetime <= 0 || config.BindingLifetime > time.Hour || config.Retention <= 0 || config.WaitInterval <= 0 || config.WaitInterval > time.Second {
		return nil, errors.New("construct sandbox control handler: explicit bounded dependencies are required")
	}
	replay, ok := config.Store.(sandboxcontrol.OutputReplayStore)
	if !ok {
		return nil, errors.New("construct sandbox control handler: durable output replay store is required")
	}
	server := &server{config: config, assertionKey: append([]byte(nil), config.AssertionKey...), replay: replay}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+bindPath, server.bind)
	mux.HandleFunc("POST "+operationsPath, server.submit)
	mux.HandleFunc("GET "+operationsPath+"/{id}", server.get)
	mux.HandleFunc("GET "+operationsPath+"/{id}/wait", server.wait)
	mux.HandleFunc("GET "+operationsPath+"/{id}/events", server.watch)
	mux.HandleFunc("GET "+capabilitiesPath, server.capabilities)
	mux.HandleFunc("GET "+processOutputPath, server.replayOutput)
	if _, ok := config.Store.(sandboxcontrol.VolumeReadModel); ok {
		mux.HandleFunc("GET "+volumesPath, server.listVolumes)
		mux.HandleFunc("GET "+volumesPath+"/{id}", server.getVolume)
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(writer, request)
	}), nil
}

type server struct {
	config       Config
	assertionKey []byte
	replay       sandboxcontrol.OutputReplayStore
}

type assertionPayload struct {
	Version   string `json:"version"`
	Authority string `json:"authority"`
	Tenant    string `json:"tenant"`
	Subject   string `json:"subject"`
	Principal string `json:"principal"`
	ExpiresAt int64  `json:"expires_at"`
	Nonce     string `json:"nonce"`
}

type bindResponse struct {
	Version   string    `json:"version"`
	Kind      string    `json:"kind"`
	Assertion string    `json:"assertion"`
	ExpiresAt time.Time `json:"expires_at"`
}

type operationResponse struct {
	Version   string            `json:"version"`
	Kind      string            `json:"kind"`
	Operation sandbox.Operation `json:"operation"`
}

type operationEventsResponse struct {
	Version string                   `json:"version"`
	Kind    string                   `json:"kind"`
	Events  []sandbox.OperationEvent `json:"events"`
}

type capabilitiesResponse struct {
	Version      string                     `json:"version"`
	Kind         string                     `json:"kind"`
	Capabilities sandbox.CapabilitySnapshot `json:"capabilities"`
}

type outputEventsResponse struct {
	Version string                `json:"version"`
	Kind    string                `json:"kind"`
	Events  []sandbox.OutputEvent `json:"events"`
}

type volumeResponse struct {
	Version string             `json:"version"`
	Kind    string             `json:"kind"`
	Volume  sandbox.VolumeInfo `json:"volume"`
}

type volumePageResponse struct {
	Version string             `json:"version"`
	Kind    string             `json:"kind"`
	Page    sandbox.VolumePage `json:"page"`
}

type failureResponse struct {
	Version string          `json:"version"`
	Kind    string          `json:"kind"`
	Failure sandbox.Failure `json:"failure"`
}

func (server *server) bind(writer http.ResponseWriter, request *http.Request) {
	body, ok := readCanonicalBody(writer, request)
	if !ok {
		return
	}
	if string(body) != string(canonicalBindRequest) {
		writeFailure(writer, http.StatusBadRequest, sandbox.Failure{Code: sandbox.FailureInvalidArgument, Message: "bind request violates sandbox.control/v1", Retry: sandbox.RetryNever})
		return
	}
	identity, err := server.config.Authenticator.Authenticate(request.Context(), request.Header.Get("Authorization"))
	request.Header.Del("Authorization")
	if err != nil || !validIdentity(identity) {
		writeDenied(writer)
		return
	}
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(server.config.Entropy, nonce); err != nil {
		writeUnavailable(writer)
		return
	}
	expiresAt := server.config.Clock.Now().UTC().Add(server.config.BindingLifetime)
	payload := assertionPayload{Version: controlVersion, Authority: identity.Authority, Tenant: identity.Tenant, Subject: identity.Subject, Principal: identity.Principal, ExpiresAt: expiresAt.Unix(), Nonce: base64.RawURLEncoding.EncodeToString(nonce)}
	assertion, err := server.signAssertion(payload)
	if err != nil {
		writeUnavailable(writer)
		return
	}
	writeJSON(writer, http.StatusOK, bindResponse{Version: controlVersion, Kind: "bind-response", Assertion: assertion, ExpiresAt: expiresAt})
}

func (server *server) capabilities(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.authenticateBound(writer, request); !ok {
		return
	}
	capabilities, err := sandbox.AdmissionCapabilities(server.config.Admission)
	if err != nil {
		writeUnavailable(writer)
		return
	}
	writeJSON(writer, http.StatusOK, capabilitiesResponse{Version: controlVersion, Kind: "capabilities-response", Capabilities: capabilities})
}

func (server *server) replayOutput(writer http.ResponseWriter, request *http.Request) {
	identity, ok := server.authenticateBound(writer, request)
	if !ok {
		return
	}
	processID := sandbox.ProcessID(request.PathValue("id"))
	after := sandbox.OutputCursor(request.URL.Query().Get("after"))
	if processID == "" || len(processID) > 128 || len(after) > 128 {
		writeFailure(writer, http.StatusBadRequest, sandbox.Failure{Code: sandbox.FailureInvalidArgument, Message: "output replay request is invalid", Retry: sandbox.RetryNever})
		return
	}
	events, err := server.replay.ReplayOutput(request.Context(), identity.Principal, processID, after)
	if err != nil {
		if strings.Contains(err.Error(), "cursor") {
			writeFailure(writer, http.StatusConflict, sandbox.Failure{Code: sandbox.FailureOutputGap, Message: "output cursor is outside retained history", Retry: sandbox.RetryCallerControlled})
			return
		}
		writeStoreError(writer, err)
		return
	}
	if len(events) == 0 {
		writeFailure(writer, http.StatusConflict, sandbox.Failure{Code: sandbox.FailureCursorExpired, Message: "no retained output is available", Retry: sandbox.RetryNever})
		return
	}
	writeJSON(writer, http.StatusOK, outputEventsResponse{Version: controlVersion, Kind: "output-events", Events: events})
}

func (server *server) getVolume(writer http.ResponseWriter, request *http.Request) {
	identity, ok := server.authenticateBound(writer, request)
	if !ok {
		return
	}
	model, ok := server.config.Store.(sandboxcontrol.VolumeReadModel)
	if !ok {
		writeUnavailable(writer)
		return
	}
	id := sandbox.VolumeID(request.PathValue("id"))
	if id == "" || len(id) > 128 {
		writeFailure(writer, http.StatusBadRequest, sandbox.Failure{Code: sandbox.FailureInvalidArgument, Message: "volume identifier is invalid", Retry: sandbox.RetryNever})
		return
	}
	volume, err := model.GetVolume(request.Context(), identity.Principal, id)
	if err != nil {
		writeStoreError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, volumeResponse{Version: controlVersion, Kind: "volume-response", Volume: volume})
}

func (server *server) listVolumes(writer http.ResponseWriter, request *http.Request) {
	identity, ok := server.authenticateBound(writer, request)
	if !ok {
		return
	}
	model, ok := server.config.Store.(sandboxcontrol.VolumeReadModel)
	if !ok {
		writeUnavailable(writer)
		return
	}
	limit, err := strconv.ParseUint(request.URL.Query().Get("limit"), 10, 32)
	if err != nil || limit == 0 || limit > 100 {
		writeFailure(writer, http.StatusBadRequest, sandbox.Failure{Code: sandbox.FailureInvalidArgument, Message: "volume page limit is invalid", Retry: sandbox.RetryNever})
		return
	}
	after := sandbox.PageCursor(request.URL.Query().Get("after"))
	if len(after) > 128 {
		writeFailure(writer, http.StatusBadRequest, sandbox.Failure{Code: sandbox.FailureInvalidArgument, Message: "volume page cursor is invalid", Retry: sandbox.RetryNever})
		return
	}
	page, err := model.ListVolumes(request.Context(), identity.Principal, sandbox.Page{Cursor: after, Limit: uint32(limit)})
	if err != nil {
		writeStoreError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, volumePageResponse{Version: controlVersion, Kind: "volume-page-response", Page: page})
}

func (server *server) submit(writer http.ResponseWriter, request *http.Request) {
	identity, ok := server.authenticateBound(writer, request)
	if !ok {
		return
	}
	body, ok := readCanonicalBody(writer, request)
	if !ok {
		return
	}
	acceptedAt := server.config.Clock.Now().UTC()
	resolved, err := sandbox.ResolveControlOperationRequest(body, acceptedAt, acceptedAt.Add(server.config.Retention), server.config.Admission)
	if err != nil {
		writeError(writer, err)
		return
	}
	dispatchBody, encodeErr := sandbox.EncodeControlOperationRequest(resolved.Request)
	if encodeErr != nil {
		writeUnavailable(writer)
		return
	}
	operation := toRecord(identity.Tenant, identity.Principal, dispatchBody, resolved)
	var stored sandboxcontrol.Operation
	if resolved.Operation.Kind == sandbox.OperationCreateVolume {
		resourceStore, ok := server.config.Store.(sandboxcontrol.ResourceAdmissionStore)
		if !ok {
			writeUnavailable(writer)
			return
		}
		admitted, decodeErr := sandbox.DecodeControlOperationRequest(body)
		if decodeErr != nil || admitted.CreateVolume == nil {
			writeUnavailable(writer)
			return
		}
		volumeID := server.volumeID(identity.Principal, resolved.Operation.Ref.ID)
		value := sandbox.VolumeInfo{ID: volumeID, SizeBytes: admitted.CreateVolume.Spec.SizeBytes, Inodes: admitted.CreateVolume.Spec.Inodes, RetentionExpiresAt: resolved.Operation.RetentionExpiresAt}
		binding, bindErr := sandboxcontrol.NewResourceProjectionBinding(request.Context(), identity.Principal, sandboxcontrol.ResourceProjectionVolume, string(volumeID), value)
		if bindErr != nil {
			writeUnavailable(writer)
			return
		}
		operation.TargetKind, operation.TargetID, operation.ResourceProjectionBinding = string(sandbox.TargetVolume), string(volumeID), &binding
		stored, _, err = resourceStore.AcceptVolume(request.Context(), operation, value)
	} else {
		stored, _, err = server.config.Store.Accept(request.Context(), operation)
	}
	if err != nil {
		writeStoreError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, operationResponse{Version: controlVersion, Kind: "operation-response", Operation: fromRecord(stored)})
}

// volumeID is control-sourced, opaque and stable for a principal/operation
// retry. The caller's operation ID never becomes the resource ID directly.
func (server *server) volumeID(principal string, operationID sandbox.OperationID) sandbox.VolumeID {
	mac := hmac.New(sha256.New, server.assertionKey)
	_, _ = mac.Write([]byte("sandbox.volume/v1\x00" + principal + "\x00" + string(operationID)))
	return sandbox.VolumeID("vol_" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:18]))
}

func (server *server) get(writer http.ResponseWriter, request *http.Request) {
	identity, ok := server.authenticateBound(writer, request)
	if !ok {
		return
	}
	operation, err := server.config.Store.Get(request.Context(), identity.Principal, request.PathValue("id"))
	if err != nil {
		writeStoreError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, operationResponse{Version: controlVersion, Kind: "operation-response", Operation: fromRecord(operation)})
}

func (server *server) wait(writer http.ResponseWriter, request *http.Request) {
	identity, ok := server.authenticateBound(writer, request)
	if !ok {
		return
	}
	for {
		operation, err := server.config.Store.Get(request.Context(), identity.Principal, request.PathValue("id"))
		if err != nil {
			writeStoreError(writer, err)
			return
		}
		if terminal(operation.State) {
			writeJSON(writer, http.StatusOK, operationResponse{Version: controlVersion, Kind: "operation-response", Operation: fromRecord(operation)})
			return
		}
		if err := server.config.Wait(request.Context(), server.config.WaitInterval); err != nil {
			return
		}
	}
}

func (server *server) watch(writer http.ResponseWriter, request *http.Request) {
	identity, ok := server.authenticateBound(writer, request)
	if !ok {
		return
	}
	after, err := parseOperationCursor(request.URL.Query().Get("after"))
	if err != nil {
		writeFailure(writer, http.StatusBadRequest, sandbox.Failure{Code: sandbox.FailureInvalidArgument, Message: "operation cursor is invalid", Retry: sandbox.RetryNever})
		return
	}
	id := request.PathValue("id")
	records, err := server.config.Store.ReadOperationOutbox(request.Context(), identity.Principal, id, after, maxOperationEventPage)
	if err != nil {
		writeStoreError(writer, err)
		return
	}
	current, err := server.config.Store.Get(request.Context(), identity.Principal, id)
	if err != nil {
		writeStoreError(writer, err)
		return
	}
	events := make([]sandbox.OperationEvent, 0, len(records))
	for _, record := range records {
		operation := fromRecord(current)
		operation.State = publicState(record.State)
		operation.LatestCursor = operationCursor(record.OperationVersion)
		events = append(events, sandbox.OperationEvent{Kind: sandbox.OperationEventUpdate, Cursor: operation.LatestCursor, Update: &operation})
	}
	if len(events) == 0 {
		writeFailure(writer, http.StatusConflict, sandbox.Failure{Code: sandbox.FailureCursorExpired, Message: "no newer operation observation is available", Retry: sandbox.RetryCallerControlled})
		return
	}
	writeJSON(writer, http.StatusOK, operationEventsResponse{Version: controlVersion, Kind: "operation-events", Events: events})
}

func (server *server) authenticateBound(writer http.ResponseWriter, request *http.Request) (Identity, bool) {
	authorization := request.Header.Get("Authorization")
	assertion := request.Header.Get(bindingHeader)
	request.Header.Del("Authorization")
	request.Header.Del(bindingHeader)
	if len(assertion) == 0 || len(assertion) > maxAssertionBytes {
		writeDenied(writer)
		return Identity{}, false
	}
	identity, err := server.config.Authenticator.Authenticate(request.Context(), authorization)
	if err != nil || !validIdentity(identity) {
		writeDenied(writer)
		return Identity{}, false
	}
	payload, err := server.verifyAssertion(assertion)
	if err != nil || payload.ExpiresAt <= server.config.Clock.Now().UTC().Unix() || payload.Authority != identity.Authority || payload.Tenant != identity.Tenant || payload.Subject != identity.Subject || payload.Principal != identity.Principal {
		writeDenied(writer)
		return Identity{}, false
	}
	return identity, true
}

func (server *server) signAssertion(payload assertionPayload) (string, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", errors.Wrap(err, "encode sandbox binding assertion")
	}
	mac := hmac.New(sha256.New, server.assertionKey)
	_, _ = mac.Write(encoded)
	return base64.RawURLEncoding.EncodeToString(encoded) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (server *server) verifyAssertion(assertion string) (assertionPayload, error) {
	parts := strings.Split(assertion, ".")
	if len(parts) != 2 {
		return assertionPayload{}, errors.New("verify sandbox binding assertion: invalid framing")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payloadBytes) > 1024 {
		return assertionPayload{}, errors.New("verify sandbox binding assertion: invalid payload")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return assertionPayload{}, errors.New("verify sandbox binding assertion: invalid signature")
	}
	mac := hmac.New(sha256.New, server.assertionKey)
	_, _ = mac.Write(payloadBytes)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return assertionPayload{}, errors.New("verify sandbox binding assertion: signature mismatch")
	}
	decoder := json.NewDecoder(strings.NewReader(string(payloadBytes)))
	decoder.DisallowUnknownFields()
	var payload assertionPayload
	if err := decoder.Decode(&payload); err != nil || payload.Version != controlVersion || payload.Nonce == "" || !validIdentity(Identity{Authority: payload.Authority, Tenant: payload.Tenant, Subject: payload.Subject, Principal: payload.Principal}) {
		return assertionPayload{}, errors.New("verify sandbox binding assertion: invalid identity")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return assertionPayload{}, errors.New("verify sandbox binding assertion: trailing data")
	}
	return payload, nil
}

func readCanonicalBody(writer http.ResponseWriter, request *http.Request) ([]byte, bool) {
	if request.Header.Get("Content-Type") != "application/json" || request.ContentLength > maxRequestBytes {
		writeFailure(writer, http.StatusBadRequest, sandbox.Failure{Code: sandbox.FailureInvalidArgument, Message: "sandbox control request content is invalid", Retry: sandbox.RetryNever})
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxRequestBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxRequestBytes {
		writeFailure(writer, http.StatusRequestEntityTooLarge, sandbox.Failure{Code: sandbox.FailureResourceLimitExceeded, Message: "sandbox control request exceeds its finite limit", Retry: sandbox.RetryNever})
		return nil, false
	}
	return body, true
}

func validIdentity(identity Identity) bool {
	return bounded(identity.Authority, 256) && bounded(identity.Tenant, 256) && bounded(identity.Subject, 256) && bounded(identity.Principal, 512) && strings.HasPrefix(identity.Principal, identity.Tenant+":")
}

func bounded(value string, limit int) bool {
	return value != "" && len(value) <= limit && !strings.ContainsAny(value, "\x00\r\n")
}

func toRecord(tenant, principal string, dispatchBody []byte, resolved sandbox.ResolvedOperation) sandboxcontrol.Operation {
	operation := resolved.Operation
	targetKind, targetID := flattenTarget(operation.Target)
	return sandboxcontrol.Operation{Principal: principal, Tenant: tenant, ID: string(operation.Ref.ID), Kind: string(operation.Kind), TargetKind: targetKind, TargetID: targetID, InputDigest: string(resolved.InputDigest), CanonicalDigest: string(operation.CanonicalDigest), EffectiveSpecDigest: string(operation.EffectiveSpecDigest), CapabilityDigest: string(operation.CapabilityDigest), DispatchBody: string(dispatchBody), AcceptedAt: operation.Ref.AcceptedAt, RetentionExpiresAt: operation.RetentionExpiresAt, CleanupRequired: resolved.CleanupRequired, RetainedOutputBytes: resolved.ResourceLimits.RetainedOutputBytes}
}

func fromRecord(record sandboxcontrol.Operation) sandbox.Operation {
	return sandbox.Operation{Ref: sandbox.OperationRef{ID: sandbox.OperationID(record.ID), AcceptedAt: record.AcceptedAt}, Kind: sandbox.OperationKind(record.Kind), State: publicState(record.State), Target: expandTarget(record.TargetKind, record.TargetID), CanonicalDigest: sandbox.Digest(record.CanonicalDigest), EffectiveSpecDigest: sandbox.Digest(record.EffectiveSpecDigest), CapabilityDigest: sandbox.Digest(record.CapabilityDigest), RetentionExpiresAt: record.RetentionExpiresAt, LatestCursor: operationCursor(record.Version)}
}

func flattenTarget(target sandbox.OperationTarget) (string, string) {
	switch target.Kind {
	case sandbox.TargetSandbox:
		return string(target.Kind), string(target.SandboxID)
	case sandbox.TargetProcess:
		return string(target.Kind), string(target.ProcessID)
	case sandbox.TargetVolume:
		return string(target.Kind), string(target.VolumeID)
	case sandbox.TargetSnapshot:
		return string(target.Kind), string(target.SnapshotID)
	case sandbox.TargetOperation:
		return string(target.Kind), string(target.OperationID)
	default:
		return string(target.Kind), ""
	}
}

func expandTarget(kind, id string) sandbox.OperationTarget {
	target := sandbox.OperationTarget{Kind: sandbox.OperationTargetKind(kind)}
	switch target.Kind {
	case sandbox.TargetSandbox:
		target.SandboxID = sandbox.SandboxID(id)
	case sandbox.TargetProcess:
		target.ProcessID = sandbox.ProcessID(id)
	case sandbox.TargetVolume:
		target.VolumeID = sandbox.VolumeID(id)
	case sandbox.TargetSnapshot:
		target.SnapshotID = sandbox.SnapshotID(id)
	case sandbox.TargetOperation:
		target.OperationID = sandbox.OperationID(id)
	}
	return target
}

func publicState(state sandboxcontrol.State) sandbox.OperationState {
	return sandbox.OperationState(state)
}

func terminal(state sandboxcontrol.State) bool {
	switch state {
	case sandboxcontrol.StateSucceeded, sandboxcontrol.StateFailed, sandboxcontrol.StateCancelled, sandboxcontrol.StateUncertain, sandboxcontrol.StateExpired, sandboxcontrol.StateTombstoned:
		return true
	default:
		return false
	}
}

func operationCursor(version uint64) sandbox.OperationCursor {
	return sandbox.OperationCursor("operation:" + strconv.FormatUint(version, 10))
}

func parseOperationCursor(cursor string) (uint64, error) {
	if cursor == "" {
		return 0, nil
	}
	if !strings.HasPrefix(cursor, "operation:") {
		return 0, errors.New("parse operation cursor: prefix is invalid")
	}
	version, err := strconv.ParseUint(strings.TrimPrefix(cursor, "operation:"), 10, 64)
	if err != nil || version == 0 {
		return 0, errors.New("parse operation cursor: sequence is invalid")
	}
	return version, nil
}

func writeStoreError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sandboxcontrol.ErrNotFoundOrDenied), errors.Is(err, sandboxcontrol.ErrOperationIDExpired):
		writeDenied(writer)
	case errors.Is(err, sandboxcontrol.ErrConflict):
		writeFailure(writer, http.StatusConflict, sandbox.Failure{Code: sandbox.FailureOperationConflict, Message: "operation ID has different immutable input", Retry: sandbox.RetryNever})
	default:
		writeUnavailable(writer)
	}
}

func writeError(writer http.ResponseWriter, err error) {
	if failure, ok := sandbox.AsFailure(err); ok {
		writeFailure(writer, http.StatusBadRequest, failure)
		return
	}
	writeUnavailable(writer)
}

func writeDenied(writer http.ResponseWriter) {
	writeFailure(writer, http.StatusForbidden, sandbox.Failure{Code: sandbox.FailureNotFoundOrDenied, Message: "sandbox operation was not found or denied", Retry: sandbox.RetryNever})
}

func writeUnavailable(writer http.ResponseWriter) {
	writeFailure(writer, http.StatusServiceUnavailable, sandbox.Failure{Code: sandbox.FailureUnavailable, Message: "sandbox control service is unavailable", Retry: sandbox.RetryAfterReconcile})
}

func writeFailure(writer http.ResponseWriter, status int, failure sandbox.Failure) {
	writeJSON(writer, status, failureResponse{Version: controlVersion, Kind: "failure-response", Failure: failure})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > maxRequestBytes {
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}
