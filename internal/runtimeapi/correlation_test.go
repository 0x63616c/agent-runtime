package runtimeapi

import (
	"context"
	"net/http"
	"testing"
	"time"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestRequestRouteCorrelationRetainsOnlyValidatedOpaqueRouteReferences(t *testing.T) {
	t.Parallel()
	envelope := requestRouteCorrelation("/v1/sessions/sess_1234567890ABCDEF/turns/turn_1234567890ABCDEF/tools")
	values := envelope.Values()
	if values.SessionID != "sess_1234567890ABCDEF" || values.TurnID != "turn_1234567890ABCDEF" {
		t.Fatalf("route correlation = %#v", values)
	}
	if requestRouteCorrelation("/v1/sessions/raw secret/turns/turn_1234567890ABCDEF").Values().SessionID != "" {
		t.Fatal("unsafe route value entered correlation envelope")
	}
}

func TestCorrelationEnvelopeRejectsUnsafeValuesAndComposesWithoutOverridingRoute(t *testing.T) {
	t.Parallel()
	if _, err := NewCorrelationEnvelope(CorrelationValues{ToolCallID: "unsafe value"}); err == nil {
		t.Fatal("NewCorrelationEnvelope accepted unsafe value")
	}
	route, err := NewCorrelationEnvelope(CorrelationValues{SessionID: "sess_1234567890ABCDEF"})
	if err != nil {
		t.Fatalf("route envelope: %v", err)
	}
	provider, err := NewCorrelationEnvelope(CorrelationValues{SessionID: "sess_other_ignored", InvocationID: "invocation_123"})
	if err != nil {
		t.Fatalf("provider envelope: %v", err)
	}
	values := route.merge(provider).Values()
	if values.SessionID != "sess_1234567890ABCDEF" || values.InvocationID != "invocation_123" {
		t.Fatalf("merged envelope = %#v", values)
	}
}

func TestRequestObservabilityPassesOnlyRedactedObservationToCorrelationProvider(t *testing.T) {
	t.Parallel()
	clock := fixedClock{}
	observer := &captureObserver{}
	provider := &correlationProvider{envelope: mustCorrelationEnvelope(t, CorrelationValues{OperationID: "operation_123"})}
	configured, err := newRequestObservability(Observability{
		Clock: clock, Observer: observer, IdentityCorrelator: &HMACIdentityCorrelator{key: []byte("0123456789abcdef0123456789abcdef")}, CorrelationProvider: provider,
	})
	if err != nil {
		t.Fatalf("newRequestObservability: %v", err)
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://runtime.invalid/v1/sessions/sess_1234567890ABCDEF", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	configured.complete(request, "inspect_session", agentruntime.RequestID("req_0000000000000001"), &Identity{Tenant: "tenant-a", Principal: "alice"}, 200, clock.Now())
	if provider.observed.TenantCorrelation == "" || provider.observed.Correlation.Values().SessionID != "sess_1234567890ABCDEF" {
		t.Fatalf("provider observation = %#v", provider.observed)
	}
	if provider.observed.Correlation.Values().OperationID != "" || observer.observed.Correlation.Values().OperationID != "operation_123" {
		t.Fatalf("provider must receive pre-provider observation: provider=%#v final=%#v", provider.observed, observer.observed)
	}
}

type correlationProvider struct {
	envelope CorrelationEnvelope
	observed RequestObservation
}

func (provider *correlationProvider) CorrelateRequest(_ context.Context, observation RequestObservation) CorrelationEnvelope {
	provider.observed = observation
	return provider.envelope
}

type captureObserver struct{ observed RequestObservation }

func (observer *captureObserver) ObserveRequest(_ context.Context, observation RequestObservation) {
	observer.observed = observation
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC) }
func mustCorrelationEnvelope(t *testing.T, values CorrelationValues) CorrelationEnvelope {
	t.Helper()
	envelope, err := NewCorrelationEnvelope(values)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}
