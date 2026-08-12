package runtimeapi_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimeapi"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Runtime request observations", func() {
	var (
		observations *recordingRequestObserver
		fakeClock    *clock.Fake
		correlator   runtimeapi.IdentityCorrelator
	)

	BeforeEach(func() {
		var err error
		fakeClock, err = clock.NewFake(time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC))
		Expect(err).NotTo(HaveOccurred())
		correlator, err = runtimeapi.NewHMACIdentityCorrelator([]byte("0123456789abcdef0123456789abcdef"))
		Expect(err).NotTo(HaveOccurred())
		observations = &recordingRequestObserver{}
	})

	It("records one deterministic redacted completion for an authenticated route", func() {
		runtime := &recordingRuntime{onCreateAgent: func(context.Context) {
			Expect(fakeClock.Advance(17 * time.Millisecond)).To(Succeed())
		}}
		handler := observedHandler(runtime, fakeClock, observations, correlator)
		request := httptest.NewRequest(http.MethodPost, "/v1/admin/agents", strings.NewReader(`{"name":"assistant","model_profile":"balanced","instructions":"raw prompt must not be observed"}`))
		request.Header.Set("Authorization", "Bearer admin-token-000000")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "idempotency-key-must-not-be-observed")
		request.Header.Set("X-Request-ID", "req_0000000000000001")
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		Expect(response.Code).To(Equal(http.StatusCreated))
		recorded := observations.only()
		Expect(recorded.Operation).To(Equal("create_agent"))
		Expect(recorded.RequestID).To(Equal(agentruntime.RequestID("req_0000000000000001")))
		Expect(recorded.Status).To(Equal(http.StatusCreated))
		Expect(recorded.Outcome).To(Equal(runtimeapi.RequestOutcomeSucceeded))
		Expect(recorded.FailureCode).To(BeEmpty())
		Expect(recorded.Duration).To(Equal(17 * time.Millisecond))
		Expect(recorded.TenantCorrelation).NotTo(BeEmpty())
		Expect(recorded.PrincipalCorrelation).NotTo(BeEmpty())
		Expect(fmt.Sprintf("%#v", recorded)).NotTo(ContainSubstring("tenant-a"))
		Expect(fmt.Sprintf("%#v", recorded)).NotTo(ContainSubstring("admin"))
		Expect(fmt.Sprintf("%#v", recorded)).NotTo(ContainSubstring("raw prompt"))
		Expect(fmt.Sprintf("%#v", recorded)).NotTo(ContainSubstring("idempotency-key"))
		Expect(fmt.Sprintf("%#v", recorded)).NotTo(ContainSubstring("admin-token"))
		Expect(fmt.Sprintf("%#v", recorded)).NotTo(ContainSubstring("/v1/"))
	})

	It("records malformed unauthenticated and cancelled requests exactly once", func() {
		cases := []struct {
			name        string
			context     context.Context
			requestID   string
			token       string
			wantStatus  int
			wantOutcome runtimeapi.RequestOutcome
			wantFailure agentruntime.FailureCode
		}{
			{name: "malformed", context: context.Background(), requestID: "invalid", token: "admin-token-000000", wantStatus: http.StatusBadRequest, wantOutcome: runtimeapi.RequestOutcomeFailed, wantFailure: agentruntime.FailureInvalidInput},
			{name: "unauthenticated", context: context.Background(), requestID: "req_0000000000000002", token: "unknown-token-00000", wantStatus: http.StatusUnauthorized, wantOutcome: runtimeapi.RequestOutcomeFailed, wantFailure: agentruntime.FailureNotFound},
			{name: "cancelled", context: cancelledContext(), requestID: "req_0000000000000003", token: "admin-token-000000", wantStatus: http.StatusUnauthorized, wantOutcome: runtimeapi.RequestOutcomeCancelled, wantFailure: agentruntime.FailureNotFound},
		}
		for _, test := range cases {
			By(test.name)
			observations = &recordingRequestObserver{}
			handler := observedHandler(&recordingRuntime{}, fakeClock, observations, correlator)
			request := httptest.NewRequest(http.MethodGet, "/v1/unknown/with/raw/path", nil).WithContext(test.context)
			request.Header.Set("Authorization", "Bearer "+test.token)
			request.Header.Set("X-Request-ID", test.requestID)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			Expect(response.Code).To(Equal(test.wantStatus))
			recorded := observations.only()
			Expect(recorded.Operation).To(Equal("unknown"))
			Expect(recorded.Outcome).To(Equal(test.wantOutcome))
			Expect(recorded.Status).To(Equal(test.wantStatus))
			Expect(recorded.FailureCode).To(Equal(test.wantFailure))
			Expect(recorded.TenantCorrelation).To(BeEmpty())
			Expect(recorded.PrincipalCorrelation).To(BeEmpty())
			Expect(fmt.Sprintf("%#v", recorded)).NotTo(ContainSubstring(test.token))
			Expect(fmt.Sprintf("%#v", recorded)).NotTo(ContainSubstring("/v1/"))
		}
	})

	It("uses a canonical operation vocabulary before route dispatch", func() {
		for _, test := range []struct {
			method, path, want string
		}{
			{http.MethodPost, "/v1/admin/agents", "create_agent"},
			{http.MethodPost, "/v1/admin/agents/agent_1234567890ABCDEF/revisions", "revise_agent"},
			{http.MethodGet, "/v1/admin/agents/agent_1234567890ABCDEF/revisions/arev_1234567890ABCDEF", "get_agent_revision"},
			{http.MethodPost, "/v1/sessions", "create_session"},
			{http.MethodPost, "/v1/sessions/sess_1234567890ABCDEF/inputs", "send_input"},
			{http.MethodGet, "/v1/sessions/sess_1234567890ABCDEF", "inspect_session"},
			{http.MethodGet, "/v1/sessions/sess_1234567890ABCDEF/turns/turn_1234567890ABCDEF", "inspect_turn"},
			{http.MethodGet, "/v1/sessions/sess_1234567890ABCDEF/events", "list_events"},
			{http.MethodPost, "/v1/sessions/sess_1234567890ABCDEF/turns/turn_1234567890ABCDEF/cancel", "cancel_turn"},
			{http.MethodPost, "/v1/sessions/sess_1234567890ABCDEF/close", "close_session"},
			{http.MethodPost, "/v1/sessions/sess_1234567890ABCDEF/cancel", "cancel_session"},
			{http.MethodGet, "/v1/unknown", "unknown"},
		} {
			By(test.method + " " + test.path)
			observations = &recordingRequestObserver{}
			handler := observedHandler(&recordingRuntime{}, fakeClock, observations, correlator)
			request := httptest.NewRequest(test.method, test.path, nil)
			request.Header.Set("Authorization", "Bearer unknown-token-00000")
			request.Header.Set("X-Request-ID", "req_0000000000000004")

			handler.ServeHTTP(httptest.NewRecorder(), request)

			Expect(observations.only().Operation).To(Equal(test.want))
		}
	})

	It("refuses incomplete observability dependencies", func() {
		var typedNil *recordingRequestObserver
		_, err := runtimeapi.NewHandler(runtimeapi.Config{
			Runtime:       &recordingRuntime{},
			Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{"admin-token-000000": {Tenant: "tenant-a", Principal: "admin", Admin: true}}},
			RequestIDs:    &requestIDs{},
			Observability: runtimeapi.Observability{Clock: fakeClock, Observer: typedNil, IdentityCorrelator: correlator},
		})
		Expect(err).To(MatchError(ContainSubstring("observability")))
	})
})

func observedHandler(runtime runtimeapi.Runtime, source runtimeapi.Clock, observer runtimeapi.RequestObserver, correlator runtimeapi.IdentityCorrelator) http.Handler {
	handler, err := runtimeapi.NewHandler(runtimeapi.Config{
		Runtime:       runtime,
		Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{"admin-token-000000": {Tenant: "tenant-a", Principal: "admin", Admin: true}}},
		RequestIDs:    &requestIDs{},
		Observability: runtimeapi.Observability{Clock: source, Observer: observer, IdentityCorrelator: correlator},
	})
	Expect(err).NotTo(HaveOccurred())
	return handler
}

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

type recordingRequestObserver struct {
	mu     sync.Mutex
	values []runtimeapi.RequestObservation
}

func (observer *recordingRequestObserver) ObserveRequest(observation runtimeapi.RequestObservation) {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	observer.values = append(observer.values, observation)
}

func (observer *recordingRequestObserver) only() runtimeapi.RequestObservation {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	Expect(observer.values).To(HaveLen(1))
	return observer.values[0]
}
