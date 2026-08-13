package runtimeapiprocess

import (
	"context"
	"strings"
	"testing"
)

func TestObservabilityOTLPGRPCEndpointIsStrictlyInClusterAndCredentialFree(t *testing.T) {
	for _, endpoint := range []string{"", "otel-collector:4317", "otel-collector.runtime.svc:4317"} {
		if !validOTLPGRPCEndpoint(endpoint) {
			t.Fatalf("validOTLPGRPCEndpoint(%q) = false", endpoint)
		}
	}
	for _, endpoint := range []string{"http://otel-collector:4317", "otel-collector:4318", "user@otel-collector:4317", "otel-collector:4317/path", "127.0.0.1:4317", "collector.example.com:4317"} {
		if validOTLPGRPCEndpoint(endpoint) {
			t.Fatalf("validOTLPGRPCEndpoint(%q) = true", endpoint)
		}
	}
}

func TestExportingTelemetryRefusesMissingOrUnsafeEndpointBeforeNetworkUse(t *testing.T) {
	for _, endpoint := range []string{"", "http://otel-collector:4317", "collector.example.com:4317"} {
		telemetry, err := NewExportingTelemetry(context.Background(), endpoint)
		if telemetry != nil || err == nil || !strings.Contains(err.Error(), "valid in-cluster") {
			t.Fatalf("NewExportingTelemetry(%q) = (%#v, %v), want local validation failure", endpoint, telemetry, err)
		}
	}
}
