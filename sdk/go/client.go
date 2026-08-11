package agentruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cockroachdb/errors"
)

const defaultMaxResponseBytes int64 = 2 << 20

// RuntimeClient is the Temporal-free application contract for durable Agent Runtime commands.
type RuntimeClient interface {
	// CreateAgent creates the first immutable Agent revision through the admin surface.
	CreateAgent(context.Context, CreateAgentRequest) (AgentSpecification, error)
	// ReviseAgent creates another immutable Agent revision through the admin surface.
	ReviseAgent(context.Context, ReviseAgentRequest) (AgentSpecification, error)
	// GetAgentRevision reads one immutable Agent revision through the admin surface.
	GetAgentRevision(context.Context, AgentID, AgentRevisionID) (AgentSpecification, error)
	// CreatePolicy creates the first immutable revision of a tenant Policy.
	CreatePolicy(context.Context, CreatePolicyRequest) (Policy, error)
	// RevisePolicy creates the next immutable revision of a tenant Policy.
	RevisePolicy(context.Context, RevisePolicyRequest) (Policy, error)
	// GetPolicy reads one immutable Policy revision through the admin surface.
	GetPolicy(context.Context, string, uint64) (Policy, error)
	// ReadArtifact downloads one caller-authorized immutable artifact.
	ReadArtifact(context.Context, ArtifactID) (ArtifactDownload, error)
	// InspectApproval returns the caller-authorized state of one Approval.
	InspectApproval(context.Context, ApprovalID) (Approval, error)
	// DecideApproval records one idempotent owner decision for a pending Approval.
	DecideApproval(context.Context, DecideApprovalRequest) (Approval, error)
	// IdempotencyStatus reads one retained receipt without re-executing work.
	IdempotencyStatus(context.Context, string) (IdempotencyStatus, error)
	// CreateSession creates a principal-owned Session pinned to one Agent revision.
	CreateSession(context.Context, CreateSessionRequest) (Session, error)
	// SendInput idempotently admits bounded Input into a Session.
	SendInput(context.Context, SendInputRequest) (SendInputResult, error)
	// InspectSession returns caller-safe Session state without backend identifiers.
	InspectSession(context.Context, SessionID) (SessionView, error)
	// InspectTurn returns one caller-safe Turn snapshot.
	InspectTurn(context.Context, SessionID, TurnID) (Turn, error)
	// Events resumes bounded Product-event observation after an opaque Cursor.
	Events(context.Context, SessionID, Cursor, int) (EventPage, error)
	// CancelTurn explicitly requests durable Turn cancellation.
	CancelTurn(context.Context, CancelTurnRequest) (Turn, error)
	// CloseSession closes Input admission and drains accepted work.
	CloseSession(context.Context, CloseSessionRequest) (Session, error)
}

// RequestIDSource creates a fresh opaque correlation ID for each HTTP attempt.
type RequestIDSource interface {
	// NextRequestID creates one fresh opaque correlation ID.
	NextRequestID() (RequestID, error)
}

// AuthorizationSink accepts one request-scoped bearer credential.
type AuthorizationSink interface {
	// SetBearerToken accepts one request-scoped bearer credential.
	SetBearerToken(string) error
}

// CredentialSource authorizes one request without exposing credential bytes to Client diagnostics.
type CredentialSource interface {
	// Authorize applies one request-scoped credential without exposing it to Client diagnostics.
	Authorize(context.Context, AuthorizationSink) error
}

// StaticBearerCredential is a redacted in-memory credential adapter for explicitly supplied tokens.
type StaticBearerCredential struct{ token string }

// NewStaticBearerCredential validates and owns a copy of one bearer token.
func NewStaticBearerCredential(token string) (*StaticBearerCredential, error) {
	if !validBearerToken(token) {
		return nil, errors.New("create static Agent Runtime credential: invalid bearer token")
	}
	return &StaticBearerCredential{token: token}, nil
}

// Authorize applies the credential to one request-scoped sink.
func (credential *StaticBearerCredential) Authorize(ctx context.Context, sink AuthorizationSink) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if credential == nil || !validBearerToken(credential.token) || sink == nil {
		return errors.New("authorize Agent Runtime request: credential is unavailable")
	}
	return sink.SetBearerToken(credential.token)
}

// String returns a secret-safe credential diagnostic.
func (credential *StaticBearerCredential) String() string {
	if credential == nil || credential.token == "" {
		return "StaticBearerCredential{Token:[NOT CONFIGURED]}"
	}
	return "StaticBearerCredential{Token:[REDACTED]}"
}

// GoString keeps detailed formatter diagnostics secret-safe.
func (credential *StaticBearerCredential) GoString() string { return credential.String() }

// ClientConfig contains every dependency and finite bound required by Client.
type ClientConfig struct {
	BaseURL          string
	HTTPClient       *http.Client
	Credentials      CredentialSource
	RequestIDs       RequestIDSource
	MaxResponseBytes int64
}

// Client is the concrete HTTP implementation of RuntimeClient.
type Client struct {
	baseURL          *url.URL
	httpClient       *http.Client
	credentials      CredentialSource
	requestIDs       RequestIDSource
	maxResponseBytes int64
}

// NewClient validates a bounded, explicit public HTTP client configuration.
func NewClient(config ClientConfig) (*Client, error) {
	if config.HTTPClient == nil || config.Credentials == nil || config.RequestIDs == nil {
		return nil, errors.New("create Agent Runtime client: HTTP client, credentials, and request ID source are required")
	}
	baseURL, err := url.Parse(config.BaseURL)
	if err != nil {
		return nil, errors.New("create Agent Runtime client: base URL must be an explicit HTTPS origin or loopback HTTP origin")
	}
	protectedTransport := baseURL.Scheme == "https" || (baseURL.Scheme == "http" && loopbackHost(baseURL.Hostname()))
	if baseURL.User != nil || baseURL.RawQuery != "" || baseURL.ForceQuery || baseURL.Fragment != "" || !protectedTransport || baseURL.Hostname() == "" || (baseURL.Path != "" && baseURL.Path != "/") {
		return nil, errors.New("create Agent Runtime client: base URL must be an explicit HTTPS origin or loopback HTTP origin")
	}
	maximum := config.MaxResponseBytes
	if maximum == 0 {
		maximum = defaultMaxResponseBytes
	}
	if maximum < 1024 || maximum > 16<<20 {
		return nil, errors.New("create Agent Runtime client: response limit must be between 1 KiB and 16 MiB")
	}
	baseURL.Path = ""
	httpClient := *config.HTTPClient
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{baseURL: baseURL, httpClient: &httpClient, credentials: config.Credentials, requestIDs: config.RequestIDs, maxResponseBytes: maximum}, nil
}

// CreateAgent creates the first immutable Agent revision through the admin surface.
func (client *Client) CreateAgent(ctx context.Context, request CreateAgentRequest) (AgentSpecification, error) {
	body := struct {
		Name         string           `json:"name"`
		ModelProfile string           `json:"model_profile"`
		Instructions string           `json:"instructions"`
		Tools        []ToolDefinition `json:"tools,omitempty"`
	}{Name: request.Name, ModelProfile: request.ModelProfile, Instructions: request.Instructions, Tools: request.Tools}
	return doJSON[AgentSpecification](client, ctx, openAPIMethodCreateAgent, openAPIPathCreateAgent, request.IdempotencyKey, body)
}

// ReviseAgent creates another immutable Agent revision through the admin surface.
func (client *Client) ReviseAgent(ctx context.Context, request ReviseAgentRequest) (AgentSpecification, error) {
	body := struct {
		ModelProfile string           `json:"model_profile"`
		Instructions string           `json:"instructions"`
		Tools        []ToolDefinition `json:"tools,omitempty"`
	}{ModelProfile: request.ModelProfile, Instructions: request.Instructions, Tools: request.Tools}
	path := replacePath(openAPIPathReviseAgent, "agent_id", request.AgentID.String())
	return doJSON[AgentSpecification](client, ctx, openAPIMethodReviseAgent, path, request.IdempotencyKey, body)
}

// GetAgentRevision reads one immutable Agent revision through the admin surface.
func (client *Client) GetAgentRevision(ctx context.Context, agentID AgentID, revisionID AgentRevisionID) (AgentSpecification, error) {
	path := replacePath(replacePath(openAPIPathGetAgentRevision, "agent_id", agentID.String()), "revision_id", revisionID.String())
	return doJSON[AgentSpecification](client, ctx, openAPIMethodGetAgentRevision, path, "", nil)
}

// CreatePolicy creates the first immutable revision of a tenant Policy.
func (client *Client) CreatePolicy(ctx context.Context, request CreatePolicyRequest) (Policy, error) {
	body := struct {
		Name  string       `json:"name"`
		Rules []PolicyRule `json:"rules"`
	}{Name: request.Name, Rules: request.Rules}
	return doJSON[Policy](client, ctx, openAPIMethodCreatePolicy, openAPIPathCreatePolicy, request.IdempotencyKey, body)
}

// RevisePolicy creates the next immutable revision of a tenant Policy.
func (client *Client) RevisePolicy(ctx context.Context, request RevisePolicyRequest) (Policy, error) {
	body := struct {
		ExpectedRevision uint64       `json:"expected_revision"`
		Rules            []PolicyRule `json:"rules"`
	}{ExpectedRevision: request.ExpectedRevision, Rules: request.Rules}
	path := replacePath(openAPIPathRevisePolicy, "policy_name", request.Name)
	return doJSON[Policy](client, ctx, openAPIMethodRevisePolicy, path, request.IdempotencyKey, body)
}

// GetPolicy reads one immutable Policy revision through the admin surface.
func (client *Client) GetPolicy(ctx context.Context, name string, revision uint64) (Policy, error) {
	path := replacePath(replacePath(openAPIPathGetPolicy, "policy_name", name), "revision", strconv.FormatUint(revision, 10))
	return doJSON[Policy](client, ctx, openAPIMethodGetPolicy, path, "", nil)
}

// ReadArtifact downloads bounded immutable content only after the server has
// authorized the exact tenant/principal/artifact tuple.
func (client *Client) ReadArtifact(ctx context.Context, artifactID ArtifactID) (ArtifactDownload, error) {
	if _, err := ParseArtifactID(artifactID.String()); err != nil {
		return ArtifactDownload{}, errors.New("read Artifact: invalid artifact ID")
	}
	return doArtifact(client, ctx, replacePath(openAPIPathReadArtifact, "artifact_id", artifactID.String()), artifactID)
}

// InspectApproval returns the caller-authorized state of one Approval.
func (client *Client) InspectApproval(ctx context.Context, approvalID ApprovalID) (Approval, error) {
	if _, err := ParseApprovalID(approvalID.String()); err != nil {
		return Approval{}, errors.New("inspect Approval: invalid approval ID")
	}
	return doJSON[Approval](client, ctx, openAPIMethodInspectApproval, replacePath(openAPIPathInspectApproval, "approval_id", approvalID.String()), "", nil)
}

// DecideApproval records one idempotent owner decision for a pending Approval.
func (client *Client) DecideApproval(ctx context.Context, request DecideApprovalRequest) (Approval, error) {
	if _, err := ParseApprovalID(request.ApprovalID.String()); err != nil || (request.Decision != ApprovalApproved && request.Decision != ApprovalDenied) {
		return Approval{}, errors.New("decide Approval: request is invalid")
	}
	path := replacePath(openAPIPathDecideApproval, "approval_id", request.ApprovalID.String())
	return doJSON[Approval](client, ctx, openAPIMethodDecideApproval, path, request.IdempotencyKey, struct {
		Decision ApprovalState `json:"decision"`
	}{Decision: request.Decision})
}

// IdempotencyStatus reads the caller-scoped durable status of one mutation key.
func (client *Client) IdempotencyStatus(ctx context.Context, key string) (IdempotencyStatus, error) {
	if key == "" || len(key) > MaxIdempotencyKeyBytes {
		return IdempotencyStatus{}, errors.New("read idempotency status: invalid idempotency key")
	}
	return doJSON[IdempotencyStatus](client, ctx, openAPIMethodIdempotencyStatus, openAPIPathIdempotencyStatus, key, nil)
}

// CreateSession creates a principal-owned Session pinned to one Agent revision.
func (client *Client) CreateSession(ctx context.Context, request CreateSessionRequest) (Session, error) {
	body := struct {
		AgentRevision AgentRevisionID `json:"agent_revision_id"`
	}{AgentRevision: request.AgentRevision}
	return doJSON[Session](client, ctx, openAPIMethodCreateSession, openAPIPathCreateSession, request.IdempotencyKey, body)
}

// SendInput idempotently admits bounded Input into a Session.
func (client *Client) SendInput(ctx context.Context, request SendInputRequest) (SendInputResult, error) {
	body := struct {
		Parts []ContentPart `json:"parts"`
	}{Parts: request.Parts}
	path := replacePath(openAPIPathSendInput, "session_id", request.SessionID.String())
	return doJSON[SendInputResult](client, ctx, openAPIMethodSendInput, path, request.IdempotencyKey, body)
}

// InspectSession returns caller-safe Session state without backend identifiers.
func (client *Client) InspectSession(ctx context.Context, sessionID SessionID) (SessionView, error) {
	path := replacePath(openAPIPathInspectSession, "session_id", sessionID.String())
	return doJSON[SessionView](client, ctx, openAPIMethodInspectSession, path, "", nil)
}

// InspectTurn returns one caller-safe Turn snapshot.
func (client *Client) InspectTurn(ctx context.Context, sessionID SessionID, turnID TurnID) (Turn, error) {
	path := replacePath(replacePath(openAPIPathInspectTurn, "session_id", sessionID.String()), "turn_id", turnID.String())
	return doJSON[Turn](client, ctx, openAPIMethodInspectTurn, path, "", nil)
}

// Events resumes bounded Product-event observation after an opaque Cursor.
func (client *Client) Events(ctx context.Context, sessionID SessionID, after Cursor, limit int) (EventPage, error) {
	path := replacePath(openAPIPathListEvents, "session_id", sessionID.String())
	query := url.Values{"limit": []string{strconv.Itoa(limit)}}
	if after != "" {
		query.Set("after", after.String())
	}
	return doJSON[EventPage](client, ctx, openAPIMethodListEvents, path+"?"+query.Encode(), "", nil)
}

// CancelTurn explicitly requests durable Turn cancellation.
func (client *Client) CancelTurn(ctx context.Context, request CancelTurnRequest) (Turn, error) {
	path := replacePath(replacePath(openAPIPathCancelTurn, "session_id", request.SessionID.String()), "turn_id", request.TurnID.String())
	return doJSON[Turn](client, ctx, openAPIMethodCancelTurn, path, request.IdempotencyKey, struct{}{})
}

// CloseSession closes Input admission and drains accepted work.
func (client *Client) CloseSession(ctx context.Context, request CloseSessionRequest) (Session, error) {
	path := replacePath(openAPIPathCloseSession, "session_id", request.SessionID.String())
	return doJSON[Session](client, ctx, openAPIMethodCloseSession, path, request.IdempotencyKey, struct{}{})
}

func doJSON[Response any](client *Client, ctx context.Context, method, path, idempotencyKey string, body any) (Response, error) {
	var zero Response
	if client == nil {
		return zero, errors.New("send Agent Runtime request: client is nil")
	}
	if err := contextError(ctx); err != nil {
		return zero, err
	}
	requestID, err := client.requestIDs.NextRequestID()
	if err != nil {
		return zero, errors.Wrap(err, "send Agent Runtime request: allocate request ID")
	}
	if _, err := ParseRequestID(requestID.String()); err != nil {
		return zero, errors.New("send Agent Runtime request: request ID source returned an invalid ID")
	}
	var encoded io.Reader
	if body != nil {
		data, encodeErr := json.Marshal(body)
		if encodeErr != nil {
			return zero, errors.Wrap(encodeErr, "send Agent Runtime request: encode body")
		}
		encoded = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, client.baseURL.String()+path, encoded)
	if err != nil {
		return zero, errors.Wrap(err, "send Agent Runtime request: construct HTTP request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Request-ID", requestID.String())
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	sink := &requestAuthorizationSink{header: request.Header}
	if err := client.credentials.Authorize(ctx, sink); err != nil {
		return zero, errors.Wrap(err, "send Agent Runtime request: authorize")
	}
	response, err := client.httpClient.Do(request)
	request.Header.Del("Authorization")
	if err != nil {
		return zero, errors.Wrap(err, "send Agent Runtime request")
	}
	if response == nil {
		return zero, errors.New("send Agent Runtime request: transport returned no response")
	}
	defer func() { _ = response.Body.Close() }()
	if response.Header.Get("X-Request-ID") != requestID.String() {
		return zero, errors.New("read Agent Runtime response: request ID mismatch")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return zero, errors.New("read Agent Runtime response: content type is not application/json")
	}
	limited := io.LimitReader(response.Body, client.maxResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return zero, errors.Wrap(err, "read Agent Runtime response")
	}
	if int64(len(data)) > client.maxResponseBytes {
		return zero, errors.New("read Agent Runtime response: body exceeds configured limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var envelope struct {
			RequestID RequestID `json:"request_id"`
			Error     Failure   `json:"error"`
		}
		if decodeStrict(data, &envelope) != nil || envelope.RequestID != requestID || !validSafeFailure(envelope.Error) {
			return zero, errors.New("read Agent Runtime response: invalid safe failure envelope")
		}
		return zero, &Error{Failure: *envelope.Error.Clone()}
	}
	if err := decodeStrict(data, &zero); err != nil {
		return zero, errors.Wrap(err, "read Agent Runtime response: decode body")
	}
	return zero, nil
}

func doArtifact(client *Client, ctx context.Context, path string, artifactID ArtifactID) (ArtifactDownload, error) {
	if client == nil {
		return ArtifactDownload{}, errors.New("read Artifact: client is nil")
	}
	if err := contextError(ctx); err != nil {
		return ArtifactDownload{}, err
	}
	requestID, err := client.requestIDs.NextRequestID()
	if err != nil {
		return ArtifactDownload{}, errors.Wrap(err, "read Artifact: allocate request ID")
	}
	request, err := http.NewRequestWithContext(ctx, openAPIMethodReadArtifact, client.baseURL.String()+path, nil)
	if err != nil {
		return ArtifactDownload{}, errors.Wrap(err, "read Artifact: construct request")
	}
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("X-Request-ID", requestID.String())
	sink := &requestAuthorizationSink{header: request.Header}
	if err := client.credentials.Authorize(ctx, sink); err != nil {
		return ArtifactDownload{}, errors.Wrap(err, "read Artifact: authorize")
	}
	response, err := client.httpClient.Do(request)
	request.Header.Del("Authorization")
	if err != nil || response == nil {
		if err != nil {
			return ArtifactDownload{}, errors.Wrap(err, "read Artifact")
		}
		return ArtifactDownload{}, errors.New("read Artifact: transport returned no response")
	}
	defer func() { _ = response.Body.Close() }()
	if response.Header.Get("X-Request-ID") != requestID.String() {
		return ArtifactDownload{}, errors.New("read Artifact: request ID mismatch")
	}
	limited := io.LimitReader(response.Body, client.maxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return ArtifactDownload{}, errors.Wrap(err, "read Artifact")
	}
	if int64(len(body)) > client.maxResponseBytes {
		return ArtifactDownload{}, errors.New("read Artifact: body exceeds configured limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var envelope struct {
			RequestID RequestID `json:"request_id"`
			Error     Failure   `json:"error"`
		}
		if decodeStrict(body, &envelope) != nil || envelope.RequestID != requestID || !validSafeFailure(envelope.Error) {
			return ArtifactDownload{}, errors.New("read Artifact: invalid safe failure envelope")
		}
		return ArtifactDownload{}, &Error{Failure: *envelope.Error.Clone()}
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType == "application/json" || mediaType == "" {
		return ArtifactDownload{}, errors.New("read Artifact: invalid media type")
	}
	size, err := strconv.ParseInt(response.Header.Get("Content-Length"), 10, 64)
	if err != nil || size != int64(len(body)) {
		return ArtifactDownload{}, errors.New("read Artifact: invalid content length")
	}
	digest := response.Header.Get("Digest")
	if !strings.HasPrefix(digest, "sha-256=") || len(strings.TrimPrefix(digest, "sha-256=")) != 64 {
		return ArtifactDownload{}, errors.New("read Artifact: invalid digest")
	}
	return ArtifactDownload{Artifact: ArtifactReference{ID: artifactID, MediaType: mediaType, SizeBytes: size, SHA256: strings.TrimPrefix(digest, "sha-256=")}, Body: body}, nil
}

func validSafeFailure(failure Failure) bool {
	switch failure.Code {
	case FailureInvalidInput, FailureConflict, FailureNotFound, FailureUnavailable, FailureInternal:
	default:
		return false
	}
	if failure.Message == "" || len(failure.Message) > 1024 || !utf8.ValidString(failure.Message) || len(failure.Details) > 16 {
		return false
	}
	for key, value := range failure.Details {
		if len(key) == 0 || len(key) > 128 || len(value) > 1024 || !utf8.ValidString(value) {
			return false
		}
		for _, character := range key {
			if !asciiAlphaNumeric(character) && character != '-' && character != '_' && character != '.' {
				return false
			}
		}
	}
	return true
}

type requestAuthorizationSink struct{ header http.Header }

func (sink *requestAuthorizationSink) SetBearerToken(token string) error {
	if !validBearerToken(token) {
		return errors.New("apply Agent Runtime authorization: invalid bearer credential")
	}
	sink.header.Set("Authorization", "Bearer "+token)
	return nil
}

func validBearerToken(token string) bool {
	if len(token) < 16 || len(token) > 4096 {
		return false
	}
	for _, character := range token {
		if !asciiAlphaNumeric(character) && !strings.ContainsRune("-._~+/=", character) {
			return false
		}
	}
	return true
}

func replacePath(path, parameter, value string) string {
	return strings.ReplaceAll(path, "{"+parameter+"}", url.PathEscape(value))
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("response contains trailing JSON")
	}
	return nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("Agent Runtime context is required")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}
