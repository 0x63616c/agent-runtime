package runtimeapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"regexp"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/cockroachdb/errors"
)

// Clock supplies the request-duration clock when observability is enabled.
type Clock = clock.Clock

// RequestOutcome classifies one bounded HTTP completion without exposing request data.
type RequestOutcome string

const (
	// RequestOutcomeSucceeded reports a completed non-error HTTP request.
	RequestOutcomeSucceeded RequestOutcome = "succeeded"
	// RequestOutcomeFailed reports a completed HTTP request with a safe failure status.
	RequestOutcomeFailed RequestOutcome = "failed"
	// RequestOutcomeCancelled reports a request whose caller context ended before completion.
	RequestOutcomeCancelled RequestOutcome = "cancelled"
)

// RequestObservation contains the bounded, application-safe outcome of one HTTP request.
type RequestObservation struct {
	RequestID            agentruntime.RequestID
	Operation            string
	Status               int
	Outcome              RequestOutcome
	FailureCode          agentruntime.FailureCode
	Duration             time.Duration
	TenantCorrelation    string
	PrincipalCorrelation string
}

// RequestObserver receives exactly one completed request observation.
type RequestObserver interface {
	ObserveRequest(RequestObservation)
}

// IdentityCorrelation contains non-reversible operator correlation references.
type IdentityCorrelation struct {
	Tenant    string
	Principal string
}

// IdentityCorrelator derives safe operator correlations without returning a raw identity.
type IdentityCorrelator interface {
	Correlate(Identity) IdentityCorrelation
}

// Observability declares every dependency required to observe public HTTP requests.
// Its zero value deliberately disables observations for the local memory-unsafe role.
type Observability struct {
	Clock              Clock
	Observer           RequestObserver
	IdentityCorrelator IdentityCorrelator
}

// HMACIdentityCorrelator derives stable, keyed, bounded identity correlations.
type HMACIdentityCorrelator struct{ key []byte }

// NewHMACIdentityCorrelator constructs an identity correlator from an explicit secret key.
func NewHMACIdentityCorrelator(key []byte) (*HMACIdentityCorrelator, error) {
	if len(key) < 32 || len(key) > 4096 {
		return nil, errors.New("create request identity correlator: key must be between 32 and 4096 bytes")
	}
	return &HMACIdentityCorrelator{key: append([]byte(nil), key...)}, nil
}

// Correlate returns tenant and principal references that cannot be reversed without the configured key.
func (correlator *HMACIdentityCorrelator) Correlate(identity Identity) IdentityCorrelation {
	if correlator == nil || len(correlator.key) == 0 {
		return IdentityCorrelation{}
	}
	return IdentityCorrelation{
		Tenant:    correlateIdentity(correlator.key, "tenant", identity.Tenant),
		Principal: correlateIdentity(correlator.key, "principal", identity.Tenant+"\x00"+identity.Principal),
	}
}

func correlateIdentity(key []byte, kind, value string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(kind + "\x00" + value))
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil)[:16])
}

type requestObservability struct {
	clock      Clock
	observer   RequestObserver
	correlator IdentityCorrelator
}

func newRequestObservability(config Observability) (requestObservability, error) {
	if dependencyMissing(config.Clock) && dependencyMissing(config.Observer) && dependencyMissing(config.IdentityCorrelator) {
		return requestObservability{}, nil
	}
	if dependencyMissing(config.Clock) || dependencyMissing(config.Observer) || dependencyMissing(config.IdentityCorrelator) {
		return requestObservability{}, errors.New("create runtime API: observability clock, observer, and identity correlator are required together")
	}
	return requestObservability{clock: config.Clock, observer: config.Observer, correlator: config.IdentityCorrelator}, nil
}

func (observability requestObservability) enabled() bool { return observability.observer != nil }

func (observability requestObservability) complete(request *http.Request, operation string, requestID agentruntime.RequestID, identity *Identity, status int, started time.Time) {
	if !observability.enabled() {
		return
	}
	duration := observability.clock.Now().UTC().Sub(started)
	if duration < 0 {
		duration = 0
	}
	outcome := RequestOutcomeSucceeded
	if status >= http.StatusBadRequest {
		outcome = RequestOutcomeFailed
	}
	if request.Context().Err() != nil {
		outcome = RequestOutcomeCancelled
	}
	observation := RequestObservation{RequestID: requestID, Operation: operation, Status: status, Outcome: outcome, Duration: duration, FailureCode: failureCodeForStatus(status)}
	if identity != nil {
		correlation := observability.correlator.Correlate(*identity)
		observation.TenantCorrelation = correlation.Tenant
		observation.PrincipalCorrelation = correlation.Principal
	}
	observability.observer.ObserveRequest(observation)
}

func failureCodeForStatus(status int) agentruntime.FailureCode {
	switch status {
	case http.StatusBadRequest:
		return agentruntime.FailureInvalidInput
	case http.StatusConflict:
		return agentruntime.FailureConflict
	case http.StatusUnauthorized, http.StatusNotFound:
		return agentruntime.FailureNotFound
	case http.StatusServiceUnavailable:
		return agentruntime.FailureUnavailable
	default:
		if status >= http.StatusBadRequest {
			return agentruntime.FailureInternal
		}
		return ""
	}
}

type responseStatusWriter struct {
	http.ResponseWriter
	status int
}

func (writer *responseStatusWriter) WriteHeader(status int) {
	if writer.status != 0 {
		return
	}
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *responseStatusWriter) Write(value []byte) (int, error) {
	if writer.status == 0 {
		writer.WriteHeader(http.StatusOK)
	}
	return writer.ResponseWriter.Write(value)
}

func (writer *responseStatusWriter) statusCode() int {
	if writer.status == 0 {
		return http.StatusOK
	}
	return writer.status
}

var requestOperations = []struct {
	method    string
	path      *regexp.Regexp
	operation string
}{
	{method: http.MethodPost, path: regexp.MustCompile(`^/v1/admin/agents$`), operation: "create_agent"},
	{method: http.MethodPost, path: regexp.MustCompile(`^/v1/admin/agents/[^/]+/revisions$`), operation: "revise_agent"},
	{method: http.MethodGet, path: regexp.MustCompile(`^/v1/admin/agents/[^/]+/revisions/[^/]+$`), operation: "get_agent_revision"},
	{method: http.MethodPost, path: regexp.MustCompile(`^/v1/sessions$`), operation: "create_session"},
	{method: http.MethodPost, path: regexp.MustCompile(`^/v1/sessions/[^/]+/inputs$`), operation: "send_input"},
	{method: http.MethodGet, path: regexp.MustCompile(`^/v1/sessions/[^/]+$`), operation: "inspect_session"},
	{method: http.MethodGet, path: regexp.MustCompile(`^/v1/sessions/[^/]+/turns/[^/]+$`), operation: "inspect_turn"},
	{method: http.MethodGet, path: regexp.MustCompile(`^/v1/sessions/[^/]+/events$`), operation: "list_events"},
	{method: http.MethodPost, path: regexp.MustCompile(`^/v1/sessions/[^/]+/turns/[^/]+/cancel$`), operation: "cancel_turn"},
	{method: http.MethodPost, path: regexp.MustCompile(`^/v1/sessions/[^/]+/close$`), operation: "close_session"},
}

func canonicalOperation(method, path string) string {
	for _, candidate := range requestOperations {
		if candidate.method == method && candidate.path.MatchString(path) {
			return candidate.operation
		}
	}
	return "unknown"
}
