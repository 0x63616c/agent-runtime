package runtimeapiprocess

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// This exercises the actual public HTTP process seam rather than calling the
// request observer directly. It is deliberately memory-only: exporter
// delivery and a deployed collector remain a separate environment proof.
func TestRuntimeAPIProcessExportsBoundedRequestTelemetry(t *testing.T) {
	config, err := Parse(strings.NewReader(`{"version":1,"listen_address":"127.0.0.1:0","storage":{"mode":"memory-unsafe"},"model_profiles":["balanced"],"max_request_bytes":4194304,"observability":{"identity_correlation_key_environment":"OBSERVABILITY_CORRELATION_KEY"},"principals":[{"tenant":"telemetry-e2e","principal":"alice","admin":false,"bearer_token_environment":"ALICE_TOKEN"}]}`))
	if err != nil {
		t.Fatalf("parse process configuration: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	reader := metric.NewManualReader()
	meterProvider := metric.NewMeterProvider(metric.WithReader(reader))
	defer func() { _ = meterProvider.Shutdown(context.Background()) }()
	exporter := tracetest.NewInMemoryExporter()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tracerProvider.Shutdown(context.Background()) }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- ServeWithTelemetry(ctx, config, telemetryProcessSecrets, TelemetryProviders{
			MeterProvider: meterProvider, TracerProvider: tracerProvider,
		}, listener)
	}()
	baseURL := "http://" + listener.Addr().String()
	awaitTelemetryHealth(t, baseURL)

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/v1/sessions/sess_1234567890ABCDEF", nil)
	if err != nil {
		t.Fatalf("create public request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer alice-token-000000")
	request.Header.Set("X-Request-ID", "req_0000000000000001")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("perform public request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("public request status = %d, want %d", response.StatusCode, http.StatusNotFound)
	}

	var collected metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &collected); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}
	assertProcessRequestMetricData(t, collected)
	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("exported spans = %d, want 1", len(spans))
	}
	span := spans[0]
	if span.Name != "runtime.api.request" {
		t.Fatalf("span name = %q", span.Name)
	}
	for _, key := range []string{"runtime.request.id", "runtime.tenant.correlation", "runtime.principal.correlation", "runtime.session.id", "runtime.operation", "runtime.failure_code"} {
		if !spanHasAttribute(span.Attributes, key) {
			t.Fatalf("public request span attributes = %#v, missing %q", span.Attributes, key)
		}
	}
	if spanHasAttributeValue(span.Attributes, "runtime.tenant.correlation", "telemetry-e2e") || spanHasAttributeValue(span.Attributes, "runtime.principal.correlation", "alice") {
		t.Fatalf("public request span exposes raw identity: %#v", span.Attributes)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stop runtime API process: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out stopping runtime API process")
	}
}

func telemetryProcessSecrets(name string) (string, bool) {
	values := map[string]string{
		"ALICE_TOKEN":                   "alice-token-000000",
		"OBSERVABILITY_CORRELATION_KEY": "0123456789abcdef0123456789abcdef",
	}
	value, found := values[name]
	return value, found
}

func awaitTelemetryHealth(t *testing.T, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get(baseURL + "/healthz")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("runtime API process did not become healthy")
}

func assertProcessRequestMetricData(t *testing.T, collected metricdata.ResourceMetrics) {
	t.Helper()
	seen := make(map[string]metricdata.Metrics)
	for _, scope := range collected.ScopeMetrics {
		for _, instrument := range scope.Metrics {
			seen[instrument.Name] = instrument
		}
	}
	for _, name := range []string{"runtime.api.request.completed", "runtime.api.request.duration"} {
		instrument, found := seen[name]
		if !found {
			t.Fatalf("metrics missing %q: %#v", name, seen)
		}
		if !metricHasOnlySafeDimensions(instrument) {
			t.Fatalf("metric %q exposes unbounded request or identity data: %#v", name, instrument)
		}
	}
}

func spanHasAttributeValue(attributes []attribute.KeyValue, key, value string) bool {
	for _, attribute := range attributes {
		if string(attribute.Key) == key && attribute.Value.AsString() == value {
			return true
		}
	}
	return false
}
