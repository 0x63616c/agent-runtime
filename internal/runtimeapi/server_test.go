package runtimeapi_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtime/kernel"
	"github.com/0x63616c/agent-runtime/internal/runtimeapi"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/cockroachdb/errors"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Public runtime HTTP boundary", func() {
	var (
		service *kernel.Kernel
		server  *httptest.Server
		ids     *requestIDs
	)

	BeforeEach(func() {
		fakeClock, err := clock.NewFake(time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC))
		Expect(err).NotTo(HaveOccurred())
		service, err = kernel.New(fakeClock, &kernelIDs{}, kernel.NewMemoryRepository(), []string{"balanced"})
		Expect(err).NotTo(HaveOccurred())
		runtime, err := runtimeapi.NewKernelRuntime(service)
		Expect(err).NotTo(HaveOccurred())
		ids = &requestIDs{}
		handler, err := runtimeapi.NewHandler(runtimeapi.Config{
			Runtime: runtime,
			Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{
				"admin-token-000000": {Tenant: "tenant-a", Principal: "admin", Admin: true},
				"alice-token-000000": {Tenant: "tenant-a", Principal: "alice"},
				"bob-token-00000000": {Tenant: "tenant-a", Principal: "bob"},
				"other-admin-00000":  {Tenant: "tenant-b", Principal: "admin", Admin: true},
				"other-user-000000":  {Tenant: "tenant-b", Principal: "user"},
			}},
			RequestIDs: ids,
		})
		Expect(err).NotTo(HaveOccurred())
		server = httptest.NewServer(handler)
	})

	AfterEach(func() { server.Close() })

	It("serves the complete public path with tenant catalog and principal isolation", func(ctx SpecContext) {
		admin := newClient(server.URL, "admin-token-000000", ids)
		alice := newClient(server.URL, "alice-token-000000", ids)
		bob := newClient(server.URL, "bob-token-00000000", ids)

		agent, err := admin.CreateAgent(ctx, agentruntime.CreateAgentRequest{IdempotencyKey: "create-agent", Name: "assistant", ModelProfile: "balanced", Instructions: "Help safely."})
		Expect(err).NotTo(HaveOccurred())
		Expect(agent.Revision).To(Equal(uint64(1)))
		read, err := admin.GetAgentRevision(ctx, agent.ID, agent.RevisionID)
		Expect(err).NotTo(HaveOccurred())
		Expect(read).To(Equal(agent))
		revised, err := admin.ReviseAgent(ctx, agentruntime.ReviseAgentRequest{AgentID: agent.ID, IdempotencyKey: "revise-agent", ModelProfile: "balanced", Instructions: "Help with stronger safety."})
		Expect(err).NotTo(HaveOccurred())
		Expect(revised.Revision).To(Equal(uint64(2)))
		replayedRevision, err := admin.ReviseAgent(ctx, agentruntime.ReviseAgentRequest{AgentID: agent.ID, IdempotencyKey: "revise-agent", ModelProfile: "balanced", Instructions: "Help with stronger safety."})
		Expect(err).NotTo(HaveOccurred())
		Expect(replayedRevision).To(Equal(revised))
		_, err = admin.ReviseAgent(ctx, agentruntime.ReviseAgentRequest{AgentID: agent.ID, IdempotencyKey: "revise-agent", ModelProfile: "balanced", Instructions: "Different content."})
		var runtimeError *agentruntime.Error
		Expect(errors.As(err, &runtimeError)).To(BeTrue())
		Expect(runtimeError.Failure.Code).To(Equal(agentruntime.FailureConflict))

		session, err := alice.CreateSession(ctx, agentruntime.CreateSessionRequest{IdempotencyKey: "create-session", AgentRevision: agent.RevisionID})
		Expect(err).NotTo(HaveOccurred())
		accepted, err := alice.SendInput(ctx, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "send-one", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "hello"}}})
		Expect(err).NotTo(HaveOccurred())
		replayed, err := alice.SendInput(ctx, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "send-one", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "hello"}}})
		Expect(err).NotTo(HaveOccurred())
		Expect(replayed).To(Equal(accepted))

		turn, err := alice.InspectTurn(ctx, session.ID, accepted.Turn.ID)
		Expect(err).NotTo(HaveOccurred())
		Expect(turn.State).To(Equal(agentruntime.TurnRunning))
		firstPage, err := alice.Events(ctx, session.ID, "", 2)
		Expect(err).NotTo(HaveOccurred())
		Expect(firstPage.Events).To(HaveLen(2))
		secondPage, err := alice.Events(ctx, session.ID, firstPage.NextCursor, 20)
		Expect(err).NotTo(HaveOccurred())
		Expect(secondPage.Events).NotTo(BeEmpty())
		Expect(service.CompactEvents(ctx, principalScope("tenant-a", "alice"), session.ID, 1)).To(Succeed())
		gap, err := alice.Events(ctx, session.ID, firstPage.Events[0].Cursor, 20)
		Expect(err).NotTo(HaveOccurred())
		Expect(gap.Gap).NotTo(BeNil())
		Expect(gap.Gap.InspectSession).To(BeTrue())

		cancelled, err := alice.CancelTurn(ctx, agentruntime.CancelTurnRequest{SessionID: session.ID, TurnID: accepted.Turn.ID, IdempotencyKey: "cancel-one"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cancelled.State).To(Equal(agentruntime.TurnCancelled))
		closed, err := alice.CloseSession(ctx, agentruntime.CloseSessionRequest{SessionID: session.ID, IdempotencyKey: "close-one"})
		Expect(err).NotTo(HaveOccurred())
		Expect(closed.State).To(Equal(agentruntime.SessionCompleted))

		_, err = bob.InspectSession(ctx, session.ID)
		runtimeError = nil
		Expect(errors.As(err, &runtimeError)).To(BeTrue())
		Expect(runtimeError.Failure.Code).To(Equal(agentruntime.FailureNotFound))
		otherAdmin := newClient(server.URL, "other-admin-00000", ids)
		_, err = otherAdmin.GetAgentRevision(ctx, agent.ID, agent.RevisionID)
		Expect(errors.As(err, &runtimeError)).To(BeTrue())
		Expect(runtimeError.Failure.Code).To(Equal(agentruntime.FailureNotFound))
		otherUser := newClient(server.URL, "other-user-000000", ids)
		_, err = otherUser.CreateSession(ctx, agentruntime.CreateSessionRequest{IdempotencyKey: "cross-tenant", AgentRevision: agent.RevisionID})
		Expect(errors.As(err, &runtimeError)).To(BeTrue())
		Expect(runtimeError.Failure.Code).To(Equal(agentruntime.FailureNotFound))
	})

	It("rejects unknown JSON fields before invoking the kernel", func() {
		request, err := http.NewRequest(http.MethodPost, server.URL+"/v1/admin/agents", strings.NewReader(`{"name":"assistant","model_profile":"balanced","instructions":"safe","unknown":true}`))
		Expect(err).NotTo(HaveOccurred())
		request.Header.Set("Authorization", "Bearer admin-token-000000")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "unknown-field")
		request.Header.Set("X-Request-ID", "req_0000000000000001")
		response, err := http.DefaultClient.Do(request)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(response.Body.Close)
		Expect(response.StatusCode).To(Equal(http.StatusBadRequest))
	})

	It("rejects ambiguous headers and query parameters", func() {
		mutation, err := http.NewRequest(http.MethodPost, server.URL+"/v1/admin/agents", strings.NewReader(`{"name":"assistant","model_profile":"balanced","instructions":"safe"}`))
		Expect(err).NotTo(HaveOccurred())
		mutation.Header.Set("Authorization", "Bearer admin-token-000000")
		mutation.Header.Set("Content-Type", "application/json")
		mutation.Header.Add("Idempotency-Key", "first")
		mutation.Header.Add("Idempotency-Key", "second")
		mutation.Header.Set("X-Request-ID", "req_0000000000000001")
		response, err := http.DefaultClient.Do(mutation)
		Expect(err).NotTo(HaveOccurred())
		Expect(response.Body.Close()).To(Succeed())
		Expect(response.StatusCode).To(Equal(http.StatusBadRequest))

		query, err := http.NewRequest(http.MethodGet, server.URL+"/v1/sessions/sess_1234567890ABCDEF/events?limit=1&limit=2", nil)
		Expect(err).NotTo(HaveOccurred())
		query.Header.Set("Authorization", "Bearer alice-token-000000")
		query.Header.Set("X-Request-ID", "req_0000000000000002")
		response, err = http.DefaultClient.Do(query)
		Expect(err).NotTo(HaveOccurred())
		Expect(response.Body.Close()).To(Succeed())
		Expect(response.StatusCode).To(Equal(http.StatusBadRequest))
	})

	It("returns a non-enumerating failure to a non-admin caller", func(ctx SpecContext) {
		alice := newClient(server.URL, "alice-token-000000", ids)
		_, err := alice.CreateAgent(ctx, agentruntime.CreateAgentRequest{IdempotencyKey: "forbidden", Name: "x", ModelProfile: "balanced", Instructions: "x"})
		var runtimeError *agentruntime.Error
		Expect(errors.As(err, &runtimeError)).To(BeTrue())
		Expect(runtimeError.Failure.Code).To(Equal(agentruntime.FailureNotFound))
	})

	It("rejects a missing request ID with a fresh bounded correlation ID", func() {
		request, err := http.NewRequest(http.MethodGet, server.URL+"/v1/unknown", nil)
		Expect(err).NotTo(HaveOccurred())
		request.Header.Set("Authorization", "Bearer alice-token-000000")
		response, err := http.DefaultClient.Do(request)
		Expect(err).NotTo(HaveOccurred())
		Expect(response.Body.Close()).To(Succeed())
		Expect(response.StatusCode).To(Equal(http.StatusBadRequest))
		_, err = agentruntime.ParseRequestID(response.Header.Get("X-Request-ID"))
		Expect(err).NotTo(HaveOccurred())
	})

	It("keeps allocator failure inside the safe error contract", func() {
		source := &failingRequestIDs{}
		runtime, err := runtimeapi.NewKernelRuntime(service)
		Expect(err).NotTo(HaveOccurred())
		handler, err := runtimeapi.NewHandler(runtimeapi.Config{Runtime: runtime, Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{"alice-token-000000": {Tenant: "tenant-a", Principal: "alice"}}}, RequestIDs: source})
		Expect(err).NotTo(HaveOccurred())
		failureServer := httptest.NewServer(handler)
		DeferCleanup(failureServer.Close)
		request, err := http.NewRequest(http.MethodGet, failureServer.URL+"/v1/unknown", nil)
		Expect(err).NotTo(HaveOccurred())
		request.Header.Set("Authorization", "Bearer alice-token-000000")
		response, err := http.DefaultClient.Do(request)
		Expect(err).NotTo(HaveOccurred())
		body, readErr := io.ReadAll(response.Body)
		Expect(response.Body.Close()).To(Succeed())
		Expect(readErr).NotTo(HaveOccurred())
		Expect(response.StatusCode).To(Equal(http.StatusInternalServerError))
		Expect(response.Header.Get("Content-Type")).To(Equal("application/json"))
		Expect(body).To(MatchJSON(`{"request_id":"req_9999999999999999","error":{"code":"internal","message":"request failed","retryable":false}}`))
	})

	It("returns the same bounded JSON failure for unknown routes and methods", func() {
		for _, target := range []struct{ method, path string }{{http.MethodGet, "/v1/unknown"}, {http.MethodDelete, "/v1/sessions/sess_1234567890ABCDEF"}} {
			request, err := http.NewRequest(target.method, server.URL+target.path, nil)
			Expect(err).NotTo(HaveOccurred())
			request.Header.Set("Authorization", "Bearer alice-token-000000")
			request.Header.Set("X-Request-ID", "req_0000000000000001")
			response, err := http.DefaultClient.Do(request)
			Expect(err).NotTo(HaveOccurred())
			body, readErr := io.ReadAll(response.Body)
			Expect(response.Body.Close()).To(Succeed())
			Expect(readErr).NotTo(HaveOccurred())
			Expect(response.StatusCode).To(Equal(http.StatusNotFound))
			Expect(body).To(MatchJSON(`{"request_id":"req_0000000000000001","error":{"code":"not_found","message":"resource not found","retryable":false}}`))
		}
	})

	It("keeps accepted work when observation disconnects and replays it idempotently", func(ctx SpecContext) {
		admin := newClient(server.URL, "admin-token-000000", ids)
		alice := newClient(server.URL, "alice-token-000000", ids)
		agent, err := admin.CreateAgent(ctx, agentruntime.CreateAgentRequest{IdempotencyKey: "disconnect-agent", Name: "assistant", ModelProfile: "balanced", Instructions: "safe"})
		Expect(err).NotTo(HaveOccurred())
		session, err := alice.CreateSession(ctx, agentruntime.CreateSessionRequest{IdempotencyKey: "disconnect-session", AgentRevision: agent.RevisionID})
		Expect(err).NotTo(HaveOccurred())
		request := agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "disconnect-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "accepted once"}}}
		disconnected := newClientWithHTTPClient(server.URL, "alice-token-000000", ids, &http.Client{Transport: &dropResponseOnce{next: http.DefaultTransport}})
		_, err = disconnected.SendInput(ctx, request)
		Expect(err).To(MatchError(ContainSubstring("observation connection lost")))
		replayed, err := alice.SendInput(ctx, request)
		Expect(err).NotTo(HaveOccurred())
		page, err := alice.Events(ctx, session.ID, "", 20)
		Expect(err).NotTo(HaveOccurred())
		acceptedEvents := 0
		for _, event := range page.Events {
			if event.Kind == agentruntime.EventInputAccepted {
				acceptedEvents++
			}
		}
		Expect(acceptedEvents).To(Equal(1))
		turn, err := alice.InspectTurn(ctx, session.ID, replayed.Turn.ID)
		Expect(err).NotTo(HaveOccurred())
		Expect(turn.State).To(Equal(agentruntime.TurnRunning))
	})

	It("serializes bounded Session inspection with explicit omitted-Turn metadata", func(ctx SpecContext) {
		admin := newClient(server.URL, "admin-token-000000", ids)
		alice := newClient(server.URL, "alice-token-000000", ids)
		agent, err := admin.CreateAgent(ctx, agentruntime.CreateAgentRequest{IdempotencyKey: "bounded-agent", Name: "assistant", ModelProfile: "balanced", Instructions: "safe"})
		Expect(err).NotTo(HaveOccurred())
		session, err := alice.CreateSession(ctx, agentruntime.CreateSessionRequest{IdempotencyKey: "bounded-session", AgentRevision: agent.RevisionID})
		Expect(err).NotTo(HaveOccurred())
		for index := 0; index < agentruntime.MaxSessionViewQueuedTurns+6; index++ {
			_, err := alice.SendInput(ctx, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: fmt.Sprintf("bounded-%d", index), Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "bounded"}}})
			Expect(err).NotTo(HaveOccurred())
		}
		view, err := alice.InspectSession(ctx, session.ID)
		Expect(err).NotTo(HaveOccurred())
		Expect(view.QueuedTurns).To(HaveLen(agentruntime.MaxSessionViewQueuedTurns))
		Expect(view.QueuedTurnCount).To(Equal(uint64(agentruntime.MaxSessionViewQueuedTurns + 5)))
		Expect(view.QueuedTurnsTruncated).To(BeTrue())
	})

	It("passes exact authenticated identity and request context to the runtime", func() {
		runtime := &recordingRuntime{}
		handler, err := runtimeapi.NewHandler(runtimeapi.Config{
			Runtime:       runtime,
			Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{"admin-token-000000": {Tenant: "tenant-a", Principal: "admin", Admin: true}}},
			RequestIDs:    &requestIDs{},
		})
		Expect(err).NotTo(HaveOccurred())
		marker := struct{ name string }{"request-context"}
		request := httptest.NewRequest(http.MethodPost, "/v1/admin/agents", strings.NewReader(`{"name":"assistant","model_profile":"balanced","instructions":"safe"}`)).WithContext(context.WithValue(context.Background(), marker, "preserved"))
		request.Header.Set("Authorization", "Bearer admin-token-000000")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "create-agent")
		request.Header.Set("X-Request-ID", "req_0000000000000001")
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		Expect(response.Code).To(Equal(http.StatusCreated))
		Expect(runtime.createAgentIdentity).To(Equal(runtimeapi.Identity{Tenant: "tenant-a", Principal: "admin", Admin: true}))
		Expect(runtime.createAgentContext.Value(marker)).To(Equal("preserved"))
	})

	It("requires an explicit runtime without a memory fallback", func() {
		_, err := runtimeapi.NewHandler(runtimeapi.Config{
			Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{"alice-token-000000": {Tenant: "tenant-a", Principal: "alice"}}},
			RequestIDs:    &requestIDs{},
		})
		Expect(err).To(MatchError(ContainSubstring("runtime")))
		var typedNil *recordingRuntime
		_, err = runtimeapi.NewHandler(runtimeapi.Config{
			Runtime:       typedNil,
			Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{"alice-token-000000": {Tenant: "tenant-a", Principal: "alice"}}},
			RequestIDs:    &requestIDs{},
		})
		Expect(err).To(MatchError(ContainSubstring("runtime")))
	})

	It("preserves caller cancellation through the runtime and maps its failure", func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancelled := make(chan struct{})
		runtime := &recordingRuntime{
			onCreateAgent: func(ctx context.Context) {
				cancel()
				<-ctx.Done()
				close(cancelled)
			},
			createAgentErr: &agentruntime.Error{Failure: agentruntime.Failure{Code: agentruntime.FailureUnavailable, Message: "runtime unavailable", Retryable: true}},
		}
		handler, err := runtimeapi.NewHandler(runtimeapi.Config{
			Runtime:       runtime,
			Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{"admin-token-000000": {Tenant: "tenant-a", Principal: "admin", Admin: true}}},
			RequestIDs:    &requestIDs{},
		})
		Expect(err).NotTo(HaveOccurred())
		request := httptest.NewRequest(http.MethodPost, "/v1/admin/agents", strings.NewReader(`{"name":"assistant","model_profile":"balanced","instructions":"safe"}`)).WithContext(ctx)
		request.Header.Set("Authorization", "Bearer admin-token-000000")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "cancelled-runtime")
		request.Header.Set("X-Request-ID", "req_0000000000000001")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		Expect(cancelled).To(BeClosed())
		Expect(response.Code).To(Equal(http.StatusServiceUnavailable))
	})

	It("denies an admin route before invoking the runtime", func() {
		runtime := &recordingRuntime{}
		handler, err := runtimeapi.NewHandler(runtimeapi.Config{
			Runtime:       runtime,
			Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{"alice-token-000000": {Tenant: "tenant-a", Principal: "alice"}}},
			RequestIDs:    &requestIDs{},
		})
		Expect(err).NotTo(HaveOccurred())
		request := httptest.NewRequest(http.MethodPost, "/v1/admin/agents", strings.NewReader(`{"name":"assistant","model_profile":"balanced","instructions":"safe"}`))
		request.Header.Set("Authorization", "Bearer alice-token-000000")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "forbidden")
		request.Header.Set("X-Request-ID", "req_0000000000000001")
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		Expect(response.Code).To(Equal(http.StatusNotFound))
		Expect(runtime.createAgentCalls).To(BeZero())
	})

	It("returns durable unavailability without a memory fallback", func() {
		runtime := &recordingRuntime{createSessionErr: &agentruntime.Error{Failure: agentruntime.Failure{Code: agentruntime.FailureUnavailable, Message: "durable runtime is not configured", Retryable: true}}}
		handler, err := runtimeapi.NewHandler(runtimeapi.Config{
			Runtime:       runtime,
			Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{"alice-token-000000": {Tenant: "tenant-a", Principal: "alice"}}},
			RequestIDs:    &requestIDs{},
		})
		Expect(err).NotTo(HaveOccurred())
		request := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(`{"agent_revision_id":"arev_1234567890ABCDEF"}`))
		request.Header.Set("Authorization", "Bearer alice-token-000000")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "create-session")
		request.Header.Set("X-Request-ID", "req_0000000000000001")
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		Expect(response.Code).To(Equal(http.StatusServiceUnavailable))
		Expect(runtime.createSessionCalls).To(Equal(1))
	})
})

type staticAuth struct {
	identities map[string]runtimeapi.Identity
}

type recordingRuntime struct {
	createAgentCalls    int
	createAgentContext  context.Context
	createAgentIdentity runtimeapi.Identity
	createAgentErr      error
	onCreateAgent       func(context.Context)
	createSessionCalls  int
	createSessionErr    error
}

func (runtime *recordingRuntime) CreateAgent(ctx context.Context, identity runtimeapi.Identity, _ agentruntime.CreateAgentRequest) (agentruntime.AgentSpecification, error) {
	runtime.createAgentCalls++
	runtime.createAgentContext = ctx
	runtime.createAgentIdentity = identity
	if runtime.onCreateAgent != nil {
		runtime.onCreateAgent(ctx)
	}
	return agentruntime.AgentSpecification{}, runtime.createAgentErr
}

func (runtime *recordingRuntime) ReviseAgent(context.Context, runtimeapi.Identity, agentruntime.ReviseAgentRequest) (agentruntime.AgentSpecification, error) {
	return agentruntime.AgentSpecification{}, nil
}

func (runtime *recordingRuntime) GetAgentRevision(context.Context, runtimeapi.Identity, agentruntime.AgentID, agentruntime.AgentRevisionID) (agentruntime.AgentSpecification, error) {
	return agentruntime.AgentSpecification{}, nil
}

func (runtime *recordingRuntime) CreateSession(_ context.Context, _ runtimeapi.Identity, _ agentruntime.CreateSessionRequest) (agentruntime.Session, error) {
	runtime.createSessionCalls++
	return agentruntime.Session{}, runtime.createSessionErr
}

func (runtime *recordingRuntime) SendInput(context.Context, runtimeapi.Identity, agentruntime.SendInputRequest) (agentruntime.SendInputResult, error) {
	return agentruntime.SendInputResult{}, nil
}

func (runtime *recordingRuntime) InspectSession(context.Context, runtimeapi.Identity, agentruntime.SessionID) (agentruntime.SessionView, error) {
	return agentruntime.SessionView{}, nil
}

func (runtime *recordingRuntime) InspectTurn(context.Context, runtimeapi.Identity, agentruntime.SessionID, agentruntime.TurnID) (agentruntime.Turn, error) {
	return agentruntime.Turn{}, nil
}

func (runtime *recordingRuntime) Events(context.Context, runtimeapi.Identity, agentruntime.SessionID, agentruntime.Cursor, int) (agentruntime.EventPage, error) {
	return agentruntime.EventPage{}, nil
}

func (runtime *recordingRuntime) CancelTurn(context.Context, runtimeapi.Identity, agentruntime.CancelTurnRequest) (agentruntime.Turn, error) {
	return agentruntime.Turn{}, nil
}

func (runtime *recordingRuntime) CloseSession(context.Context, runtimeapi.Identity, agentruntime.CloseSessionRequest) (agentruntime.Session, error) {
	return agentruntime.Session{}, nil
}

func (auth staticAuth) Authenticate(ctx context.Context, token string) (runtimeapi.Identity, error) {
	if err := ctx.Err(); err != nil {
		return runtimeapi.Identity{}, err
	}
	identity, ok := auth.identities[token]
	if !ok {
		return runtimeapi.Identity{}, errors.New("invalid credential")
	}
	return identity, nil
}

type kernelIDs struct {
	mu   sync.Mutex
	next uint64
}

func (source *kernelIDs) Next() (string, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.next++
	return fmt.Sprintf("%016d", source.next), nil
}

type requestIDs struct {
	mu   sync.Mutex
	next uint64
}

type failingRequestIDs struct{ called bool }

func (source *failingRequestIDs) NextRequestID() (agentruntime.RequestID, error) {
	if !source.called {
		source.called = true
		return agentruntime.ParseRequestID("req_9999999999999999")
	}
	return "", errors.New("entropy unavailable")
}

func (source *requestIDs) NextRequestID() (agentruntime.RequestID, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.next++
	return agentruntime.ParseRequestID(fmt.Sprintf("req_%016d", source.next))
}

func newClient(baseURL, token string, ids agentruntime.RequestIDSource) *agentruntime.Client {
	return newClientWithHTTPClient(baseURL, token, ids, http.DefaultClient)
}

func newClientWithHTTPClient(baseURL, token string, ids agentruntime.RequestIDSource, httpClient *http.Client) *agentruntime.Client {
	credential, err := agentruntime.NewStaticBearerCredential(token)
	Expect(err).NotTo(HaveOccurred())
	client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: baseURL, HTTPClient: httpClient, Credentials: credential, RequestIDs: ids})
	Expect(err).NotTo(HaveOccurred())
	return client
}

func principalScope(tenant, principal string) kernel.Scope {
	digest := sha256.Sum256([]byte("principal\x00" + tenant + "\x00" + principal))
	parsed, err := kernel.ParseScope("principal_" + hex.EncodeToString(digest[:16]))
	Expect(err).NotTo(HaveOccurred())
	return parsed
}

type dropResponseOnce struct {
	next    http.RoundTripper
	dropped bool
}

func (doer *dropResponseOnce) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := doer.next.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if !doer.dropped {
		doer.dropped = true
		_ = response.Body.Close()
		return nil, errors.New("observation connection lost")
	}
	return response, nil
}
