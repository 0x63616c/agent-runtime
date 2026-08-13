package runtimeapiprocess

import (
	"context"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimeapi"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestOTelRequestObserverEmitsSafeBoundedMetricsAndCorrelatedTrace(t *testing.T) {
	t.Parallel()
	reader := metric.NewManualReader()
	meterProvider := metric.NewMeterProvider(metric.WithReader(reader))
	defer func() { _ = meterProvider.Shutdown(context.Background()) }()
	exporter := tracetest.NewInMemoryExporter()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tracerProvider.Shutdown(context.Background()) }()
	observer, err := newOTelRequestObserver(
		meterProvider.Meter(runtimeAPIInstrumentationScope),
		tracerProvider.Tracer(runtimeAPIInstrumentationScope),
	)
	if err != nil {
		t.Fatalf("newOTelRequestObserver(): %v", err)
	}

	requestContext, parent := tracerProvider.Tracer(runtimeAPIInstrumentationScope).Start(context.Background(), "ingress")
	observer.ObserveRequest(requestContext, runtimeapi.RequestObservation{
		RequestID:            agentruntime.RequestID("req_0000000000000001"),
		Operation:            "create_session",
		Status:               201,
		Outcome:              runtimeapi.RequestOutcomeSucceeded,
		StartedAt:            time.Date(2026, 8, 12, 18, 0, 0, 0, time.UTC),
		Duration:             17*time.Millisecond + 500*time.Microsecond,
		TenantCorrelation:    "hmac-sha256:tenant-correlation",
		PrincipalCorrelation: "hmac-sha256:principal-correlation",
	})
	parent.End()

	var collected metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &collected); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}
	assertRequestMetricData(t, collected)
	spans := exporter.GetSpans()
	if len(spans) != 2 {
		t.Fatalf("traces = %d, want 2", len(spans))
	}
	span := spans[0]
	if span.Name == "ingress" {
		span = spans[1]
	}
	if span.Name != "runtime.api.request" {
		t.Fatalf("span name = %q", span.Name)
	}
	if !span.Parent.IsValid() {
		t.Fatal("request completion span is not correlated to the ingress trace")
	}
	if span.EndTime.Sub(span.StartTime) != 17*time.Millisecond+500*time.Microsecond {
		t.Fatalf("span duration = %s", span.EndTime.Sub(span.StartTime))
	}
	for _, want := range []string{"runtime.request.id", "runtime.tenant.correlation", "runtime.principal.correlation", "runtime.operation"} {
		if !spanHasAttribute(span.Attributes, want) {
			t.Fatalf("span attributes = %#v, missing %q", span.Attributes, want)
		}
	}
}

func TestOTelRequestObserverRejectsMissingDependencies(t *testing.T) {
	t.Parallel()
	if _, err := newOTelRequestObserver(nil, nil); err == nil {
		t.Fatal("newOTelRequestObserver(nil, nil) error = nil")
	}
}

func assertRequestMetricData(t *testing.T, collected metricdata.ResourceMetrics) {
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
			t.Fatalf("metric %q exposes an unbounded or identity dimension: %#v", name, instrument)
		}
		if name == "runtime.api.request.duration" && !metricRecordsDuration(instrument, 17.5) {
			t.Fatalf("metric %q does not preserve the sub-millisecond completion duration: %#v", name, instrument)
		}
	}
}

func metricRecordsDuration(instrument metricdata.Metrics, want float64) bool {
	histogram, ok := instrument.Data.(metricdata.Histogram[float64])
	if !ok || len(histogram.DataPoints) != 1 {
		return false
	}
	return histogram.DataPoints[0].Sum == want
}

func metricHasOnlySafeDimensions(instrument metricdata.Metrics) bool {
	allowed := map[string]bool{
		"runtime.operation": true, "http.response.status_code": true, "runtime.outcome": true, "runtime.failure_code": true,
	}
	attributes := metricAttributes(instrument.Data)
	for _, attribute := range attributes.ToSlice() {
		if !allowed[string(attribute.Key)] {
			return false
		}
	}
	return true
}

func metricAttributes(data metricdata.Aggregation) attributeSet {
	switch value := data.(type) {
	case metricdata.Sum[int64]:
		return attributeSet{set: value.DataPoints[0].Attributes}
	case metricdata.Histogram[float64]:
		return attributeSet{set: value.DataPoints[0].Attributes}
	default:
		panic("unexpected request metric aggregation")
	}
}

type attributeSet struct{ set attribute.Set }

func (set attributeSet) ToSlice() []attribute.KeyValue { return set.set.ToSlice() }

func spanHasAttribute(attributes []attribute.KeyValue, key string) bool {
	for _, attribute := range attributes {
		if string(attribute.Key) == key {
			return true
		}
	}
	return false
}
