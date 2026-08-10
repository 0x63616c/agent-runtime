package runtimeapiprocess

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimeapi"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestRequestObservabilityIsInertUntilExplicitlyConfigured(t *testing.T) {
	t.Parallel()
	configured, err := requestObservability(Config{}, func(string) (string, bool) { return "", false }, slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)))
	if err != nil {
		t.Fatalf("requestObservability(unconfigured): %v", err)
	}
	if configured.Clock != nil || configured.Observer != nil || configured.IdentityCorrelator != nil {
		t.Fatalf("requestObservability(unconfigured) = %#v, want inert zero value", configured)
	}
}

func TestRequestObservabilityUsesOnlyBoundedRedactedCompletionFields(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	configured, err := requestObservability(Config{observabilityKeyEnvironment: "OBSERVABILITY_CORRELATION_KEY"}, func(name string) (string, bool) {
		if name != "OBSERVABILITY_CORRELATION_KEY" {
			t.Fatalf("lookup(%q)", name)
		}
		return "0123456789abcdef0123456789abcdef", true
	}, slog.New(slog.NewJSONHandler(&output, nil)))
	if err != nil {
		t.Fatalf("requestObservability(configured): %v", err)
	}
	correlation := configured.IdentityCorrelator.Correlate(runtimeapi.Identity{Tenant: "tenant-a", Principal: "alice"})
	configured.Observer.ObserveRequest(runtimeapi.RequestObservation{
		RequestID:            agentruntime.RequestID("req_0000000000000001"),
		Operation:            "create_session",
		Status:               201,
		Outcome:              runtimeapi.RequestOutcomeSucceeded,
		Duration:             17 * time.Millisecond,
		TenantCorrelation:    correlation.Tenant,
		PrincipalCorrelation: correlation.Principal,
	})
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode slog JSON: %v (%q)", err, output.String())
	}
	for _, key := range []string{"msg", "request_id", "operation", "status", "outcome", "duration_ms", "tenant_correlation", "principal_correlation"} {
		if _, found := record[key]; !found {
			t.Fatalf("slog record missing %q: %#v", key, record)
		}
	}
	encoded := output.String()
	for _, forbidden := range []string{"tenant-a", "alice", "OBSERVABILITY_CORRELATION_KEY", "0123456789abcdef0123456789abcdef"} {
		if bytes.Contains(output.Bytes(), []byte(forbidden)) {
			t.Fatalf("slog record contains %q: %s", forbidden, encoded)
		}
	}
}

func TestRequestObservabilityRefusesMissingOrWeakConfiguredKey(t *testing.T) {
	t.Parallel()
	for _, value := range []struct {
		name  string
		found bool
		key   string
	}{
		{name: "missing", found: false},
		{name: "weak", found: true, key: "too-short"},
	} {
		t.Run(value.name, func(t *testing.T) {
			_, err := requestObservability(Config{observabilityKeyEnvironment: "OBSERVABILITY_CORRELATION_KEY"}, func(string) (string, bool) { return value.key, value.found }, slog.Default())
			if err == nil {
				t.Fatal("requestObservability() error = nil")
			}
		})
	}
}
