// Package runtimeapi exposes the public, Temporal-free HTTP boundary of Agent Runtime.
package runtimeapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/cockroachdb/errors"
)

const minimumRequestBytes int64 = 3 << 20

// Identity is the authenticated tenant and principal boundary for one request.
type Identity struct {
	Tenant    string
	Principal string
	Admin     bool
}

// Authenticator turns one bearer credential into a bounded caller identity.
type Authenticator interface {
	Authenticate(context.Context, string) (Identity, error)
}

// Config declares every dependency and finite request bound used by the API.
type Config struct {
	Runtime         Runtime
	Authenticator   Authenticator
	RequestIDs      agentruntime.RequestIDSource
	MaxRequestBytes int64
	Observability   Observability
}

// NewHandler constructs the versioned public HTTP API without starting a listener.
func NewHandler(config Config) (http.Handler, error) {
	if runtimeMissing(config.Runtime) || config.Authenticator == nil || config.RequestIDs == nil {
		return nil, errors.New("create runtime API: runtime, authenticator, and request ID source are required")
	}
	observability, err := newRequestObservability(config.Observability)
	if err != nil {
		return nil, err
	}
	limit := config.MaxRequestBytes
	if limit == 0 {
		limit = minimumRequestBytes
	}
	if limit < minimumRequestBytes || limit > 16<<20 {
		return nil, errors.New("create runtime API: request limit must be between 3 MiB and 16 MiB")
	}
	emergencyRequestID, err := config.RequestIDs.NextRequestID()
	if err != nil {
		return nil, errors.Wrap(err, "create runtime API: allocate emergency request ID")
	}
	if _, err := agentruntime.ParseRequestID(emergencyRequestID.String()); err != nil {
		return nil, errors.New("create runtime API: request ID source returned an invalid ID")
	}
	server := &server{runtime: config.Runtime, authenticator: config.Authenticator, requestIDs: config.RequestIDs, emergencyRequestID: emergencyRequestID, maxRequestBytes: limit, observability: observability}
	mux := http.NewServeMux()
	mux.HandleFunc(openAPIMethodCreateAgent+" "+openAPIPathCreateAgent, server.createAgent)
	mux.HandleFunc(openAPIMethodReviseAgent+" "+openAPIPathReviseAgent, server.reviseAgent)
	mux.HandleFunc(openAPIMethodGetAgentRevision+" "+openAPIPathGetAgentRevision, server.getAgentRevision)
	mux.HandleFunc(openAPIMethodCreateSession+" "+openAPIPathCreateSession, server.createSession)
	mux.HandleFunc(openAPIMethodSendInput+" "+openAPIPathSendInput, server.sendInput)
	mux.HandleFunc(openAPIMethodInspectSession+" "+openAPIPathInspectSession, server.inspectSession)
	mux.HandleFunc(openAPIMethodInspectTurn+" "+openAPIPathInspectTurn, server.inspectTurn)
	mux.HandleFunc(openAPIMethodListEvents+" "+openAPIPathListEvents, server.events)
	mux.HandleFunc(openAPIMethodCancelTurn+" "+openAPIPathCancelTurn, server.cancelTurn)
	mux.HandleFunc(openAPIMethodCloseSession+" "+openAPIPathCloseSession, server.closeSession)
	mux.HandleFunc("/", server.notFound)
	server.next = mux
	return server, nil
}

func runtimeMissing(runtime Runtime) bool {
	return dependencyMissing(runtime)
}

func dependencyMissing(dependency any) bool {
	if dependency == nil {
		return true
	}
	value := reflect.ValueOf(dependency)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (server *server) notFound(writer http.ResponseWriter, request *http.Request) {
	contextValue := request.Context().Value(requestContextKey{}).(requestContext)
	server.writeFailure(writer, contextValue.requestID, http.StatusNotFound, agentruntime.Failure{Code: agentruntime.FailureNotFound, Message: "resource not found"})
}

type server struct {
	runtime            Runtime
	authenticator      Authenticator
	requestIDs         agentruntime.RequestIDSource
	emergencyRequestID agentruntime.RequestID
	maxRequestBytes    int64
	observability      requestObservability
	next               http.Handler
}

type requestContext struct {
	requestID agentruntime.RequestID
	identity  Identity
}

func (server *server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	observedWriter := &responseStatusWriter{ResponseWriter: writer}
	operation := canonicalOperation(request.Method, request.URL.Path)
	var requestID agentruntime.RequestID
	var identity *Identity
	var started time.Time
	if server.observability.enabled() {
		started = server.observability.clock.Now().UTC()
		defer func() {
			server.observability.complete(request, operation, requestID, identity, observedWriter.statusCode(), started)
		}()
	}
	writer = observedWriter
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	requestIDValues := request.Header.Values("X-Request-ID")
	var err error
	if len(requestIDValues) == 1 {
		requestID, err = agentruntime.ParseRequestID(requestIDValues[0])
	} else {
		err = errors.New("request ID header is not singular")
	}
	if err != nil {
		requestID, err = server.requestIDs.NextRequestID()
		if err != nil {
			server.writeFailure(writer, server.emergencyRequestID, http.StatusInternalServerError, agentruntime.Failure{Code: agentruntime.FailureInternal, Message: "request failed"})
			return
		}
		if _, err := agentruntime.ParseRequestID(requestID.String()); err != nil {
			writer.Header().Set("X-Request-ID", server.emergencyRequestID.String())
			server.writeFailure(writer, server.emergencyRequestID, http.StatusInternalServerError, agentruntime.Failure{Code: agentruntime.FailureInternal, Message: "request failed"})
			return
		}
		writer.Header().Set("X-Request-ID", requestID.String())
		server.writeInvalid(writer, requestID)
		return
	}
	writer.Header().Set("X-Request-ID", requestID.String())
	authorization := request.Header.Values("Authorization")
	credential := ""
	if len(authorization) == 1 && strings.HasPrefix(authorization[0], "Bearer ") {
		credential = strings.TrimPrefix(authorization[0], "Bearer ")
	}
	request.Header.Del("Authorization")
	authenticated, authErr := server.authenticator.Authenticate(request.Context(), credential)
	if authErr != nil || !validBearerCredential(credential) || !validIdentity(authenticated) {
		server.writeFailure(writer, requestID, http.StatusUnauthorized, agentruntime.Failure{Code: agentruntime.FailureNotFound, Message: "resource not found"})
		return
	}
	identity = &authenticated
	contextValue := requestContext{requestID: requestID, identity: authenticated}
	if !validQuery(request) {
		server.writeInvalid(writer, requestID)
		return
	}
	server.next.ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), requestContextKey{}, contextValue)))
}

type requestContextKey struct{}

func (server *server) createAgent(writer http.ResponseWriter, request *http.Request) {
	contextValue := request.Context().Value(requestContextKey{}).(requestContext)
	if !contextValue.identity.Admin {
		server.writeFailure(writer, contextValue.requestID, http.StatusNotFound, agentruntime.Failure{Code: agentruntime.FailureNotFound, Message: "resource not found"})
		return
	}
	var body struct {
		Name         string                        `json:"name"`
		ModelProfile string                        `json:"model_profile"`
		Instructions string                        `json:"instructions"`
		Tools        []agentruntime.ToolDefinition `json:"tools"`
	}
	if !server.decodeMutation(writer, request, contextValue.requestID, &body) {
		return
	}
	result, err := server.runtime.CreateAgent(request.Context(), contextValue.identity, agentruntime.CreateAgentRequest{IdempotencyKey: request.Header.Get("Idempotency-Key"), Name: body.Name, ModelProfile: body.ModelProfile, Instructions: body.Instructions, Tools: body.Tools})
	server.writeResult(writer, contextValue.requestID, http.StatusCreated, result, err)
}

func (server *server) reviseAgent(writer http.ResponseWriter, request *http.Request) {
	contextValue := request.Context().Value(requestContextKey{}).(requestContext)
	if !contextValue.identity.Admin {
		server.writeFailure(writer, contextValue.requestID, http.StatusNotFound, agentruntime.Failure{Code: agentruntime.FailureNotFound, Message: "resource not found"})
		return
	}
	agentID, err := agentruntime.ParseAgentID(request.PathValue("agent_id"))
	var body struct {
		ModelProfile string                        `json:"model_profile"`
		Instructions string                        `json:"instructions"`
		Tools        []agentruntime.ToolDefinition `json:"tools"`
	}
	if err != nil || !server.decodeMutation(writer, request, contextValue.requestID, &body) {
		if err != nil {
			server.writeInvalid(writer, contextValue.requestID)
		}
		return
	}
	result, callErr := server.runtime.ReviseAgent(request.Context(), contextValue.identity, agentruntime.ReviseAgentRequest{AgentID: agentID, IdempotencyKey: request.Header.Get("Idempotency-Key"), ModelProfile: body.ModelProfile, Instructions: body.Instructions, Tools: body.Tools})
	server.writeResult(writer, contextValue.requestID, http.StatusCreated, result, callErr)
}

func (server *server) getAgentRevision(writer http.ResponseWriter, request *http.Request) {
	contextValue := request.Context().Value(requestContextKey{}).(requestContext)
	if !contextValue.identity.Admin {
		server.writeFailure(writer, contextValue.requestID, http.StatusNotFound, agentruntime.Failure{Code: agentruntime.FailureNotFound, Message: "resource not found"})
		return
	}
	agentID, first := agentruntime.ParseAgentID(request.PathValue("agent_id"))
	revisionID, second := agentruntime.ParseAgentRevisionID(request.PathValue("revision_id"))
	if first != nil || second != nil {
		server.writeInvalid(writer, contextValue.requestID)
		return
	}
	result, err := server.runtime.GetAgentRevision(request.Context(), contextValue.identity, agentID, revisionID)
	server.writeResult(writer, contextValue.requestID, http.StatusOK, result, err)
}

func (server *server) createSession(writer http.ResponseWriter, request *http.Request) {
	contextValue := request.Context().Value(requestContextKey{}).(requestContext)
	var body struct {
		AgentRevision agentruntime.AgentRevisionID `json:"agent_revision_id"`
	}
	if !server.decodeMutation(writer, request, contextValue.requestID, &body) {
		return
	}
	result, err := server.runtime.CreateSession(request.Context(), contextValue.identity, agentruntime.CreateSessionRequest{IdempotencyKey: request.Header.Get("Idempotency-Key"), AgentRevision: body.AgentRevision})
	server.writeResult(writer, contextValue.requestID, http.StatusCreated, result, err)
}

func (server *server) sendInput(writer http.ResponseWriter, request *http.Request) {
	contextValue := request.Context().Value(requestContextKey{}).(requestContext)
	sessionID, err := agentruntime.ParseSessionID(request.PathValue("session_id"))
	var body struct {
		Parts []agentruntime.ContentPart `json:"parts"`
	}
	if err != nil || !server.decodeMutation(writer, request, contextValue.requestID, &body) {
		if err != nil {
			server.writeInvalid(writer, contextValue.requestID)
		}
		return
	}
	result, callErr := server.runtime.SendInput(request.Context(), contextValue.identity, agentruntime.SendInputRequest{SessionID: sessionID, IdempotencyKey: request.Header.Get("Idempotency-Key"), Parts: body.Parts})
	server.writeResult(writer, contextValue.requestID, http.StatusAccepted, result, callErr)
}

func (server *server) inspectSession(writer http.ResponseWriter, request *http.Request) {
	contextValue := request.Context().Value(requestContextKey{}).(requestContext)
	sessionID, err := agentruntime.ParseSessionID(request.PathValue("session_id"))
	if err != nil {
		server.writeInvalid(writer, contextValue.requestID)
		return
	}
	result, err := server.runtime.InspectSession(request.Context(), contextValue.identity, sessionID)
	server.writeResult(writer, contextValue.requestID, http.StatusOK, result, err)
}

func (server *server) inspectTurn(writer http.ResponseWriter, request *http.Request) {
	contextValue := request.Context().Value(requestContextKey{}).(requestContext)
	sessionID, first := agentruntime.ParseSessionID(request.PathValue("session_id"))
	turnID, second := agentruntime.ParseTurnID(request.PathValue("turn_id"))
	if first != nil || second != nil {
		server.writeInvalid(writer, contextValue.requestID)
		return
	}
	result, err := server.runtime.InspectTurn(request.Context(), contextValue.identity, sessionID, turnID)
	server.writeResult(writer, contextValue.requestID, http.StatusOK, result, err)
}

func (server *server) events(writer http.ResponseWriter, request *http.Request) {
	contextValue := request.Context().Value(requestContextKey{}).(requestContext)
	sessionID, err := agentruntime.ParseSessionID(request.PathValue("session_id"))
	if err != nil {
		server.writeInvalid(writer, contextValue.requestID)
		return
	}
	var after agentruntime.Cursor
	if raw := request.URL.Query().Get("after"); raw != "" {
		after, err = agentruntime.ParseCursor(raw)
		if err != nil {
			server.writeInvalid(writer, contextValue.requestID)
			return
		}
	}
	limit, err := strconv.Atoi(request.URL.Query().Get("limit"))
	if err != nil {
		server.writeInvalid(writer, contextValue.requestID)
		return
	}
	result, err := server.runtime.Events(request.Context(), contextValue.identity, sessionID, after, limit)
	server.writeResult(writer, contextValue.requestID, http.StatusOK, result, err)
}

func (server *server) cancelTurn(writer http.ResponseWriter, request *http.Request) {
	contextValue := request.Context().Value(requestContextKey{}).(requestContext)
	sessionID, first := agentruntime.ParseSessionID(request.PathValue("session_id"))
	turnID, second := agentruntime.ParseTurnID(request.PathValue("turn_id"))
	var body struct{}
	if first != nil || second != nil || !server.decodeMutation(writer, request, contextValue.requestID, &body) {
		if first != nil || second != nil {
			server.writeInvalid(writer, contextValue.requestID)
		}
		return
	}
	result, err := server.runtime.CancelTurn(request.Context(), contextValue.identity, agentruntime.CancelTurnRequest{SessionID: sessionID, TurnID: turnID, IdempotencyKey: request.Header.Get("Idempotency-Key")})
	server.writeResult(writer, contextValue.requestID, http.StatusOK, result, err)
}

func (server *server) closeSession(writer http.ResponseWriter, request *http.Request) {
	contextValue := request.Context().Value(requestContextKey{}).(requestContext)
	sessionID, err := agentruntime.ParseSessionID(request.PathValue("session_id"))
	var body struct{}
	if err != nil || !server.decodeMutation(writer, request, contextValue.requestID, &body) {
		if err != nil {
			server.writeInvalid(writer, contextValue.requestID)
		}
		return
	}
	result, callErr := server.runtime.CloseSession(request.Context(), contextValue.identity, agentruntime.CloseSessionRequest{SessionID: sessionID, IdempotencyKey: request.Header.Get("Idempotency-Key")})
	server.writeResult(writer, contextValue.requestID, http.StatusOK, result, callErr)
}

func (server *server) decodeMutation(writer http.ResponseWriter, request *http.Request, requestID agentruntime.RequestID, target any) bool {
	idempotencyKeys := request.Header.Values("Idempotency-Key")
	if len(idempotencyKeys) != 1 || idempotencyKeys[0] == "" {
		server.writeInvalid(writer, requestID)
		return false
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		server.writeInvalid(writer, requestID)
		return false
	}
	reader := http.MaxBytesReader(writer, request.Body, server.maxRequestBytes)
	data, err := io.ReadAll(reader)
	if err != nil || int64(len(data)) > server.maxRequestBytes {
		server.writeInvalid(writer, requestID)
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		server.writeInvalid(writer, requestID)
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		server.writeInvalid(writer, requestID)
		return false
	}
	return true
}

func (server *server) writeResult(writer http.ResponseWriter, requestID agentruntime.RequestID, status int, result any, err error) {
	if err != nil {
		var runtimeError *agentruntime.Error
		if !errors.As(err, &runtimeError) {
			server.writeFailure(writer, requestID, http.StatusInternalServerError, agentruntime.Failure{Code: agentruntime.FailureInternal, Message: "request failed"})
			return
		}
		code := map[agentruntime.FailureCode]int{agentruntime.FailureInvalidInput: http.StatusBadRequest, agentruntime.FailureConflict: http.StatusConflict, agentruntime.FailureNotFound: http.StatusNotFound, agentruntime.FailureUnavailable: http.StatusServiceUnavailable, agentruntime.FailureInternal: http.StatusInternalServerError}[runtimeError.Failure.Code]
		if code == 0 {
			code = http.StatusInternalServerError
		}
		server.writeFailure(writer, requestID, code, *runtimeError.Failure.Clone())
		return
	}
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(result)
}

func (server *server) writeInvalid(writer http.ResponseWriter, requestID agentruntime.RequestID) {
	server.writeFailure(writer, requestID, http.StatusBadRequest, agentruntime.Failure{Code: agentruntime.FailureInvalidInput, Message: "invalid request"})
}

func (server *server) writeFailure(writer http.ResponseWriter, requestID agentruntime.RequestID, status int, failure agentruntime.Failure) {
	writer.Header().Set("X-Request-ID", requestID.String())
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(struct {
		RequestID agentruntime.RequestID `json:"request_id"`
		Error     agentruntime.Failure   `json:"error"`
	}{requestID, failure})
}

func validIdentity(identity Identity) bool {
	return identity.Tenant != "" && len(identity.Tenant) <= 128 && identity.Principal != "" && len(identity.Principal) <= 128
}

func validBearerCredential(token string) bool {
	if len(token) < 16 || len(token) > 4096 {
		return false
	}
	for _, character := range token {
		alphaNumeric := (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9')
		if !alphaNumeric && !strings.ContainsRune("-._~+/=", character) {
			return false
		}
	}
	return true
}

func validQuery(request *http.Request) bool {
	if !strings.HasSuffix(request.URL.Path, "/events") {
		return request.URL.RawQuery == ""
	}
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		return false
	}
	for key, values := range query {
		if (key != "after" && key != "limit") || len(values) != 1 {
			return false
		}
	}
	return len(query["limit"]) == 1
}
