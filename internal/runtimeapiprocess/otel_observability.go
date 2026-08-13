package runtimeapiprocess

import (
	"context"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimeapi"
	"github.com/cockroachdb/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

const runtimeAPIInstrumentationScope = "github.com/0x63616c/agent-runtime/runtimeapi"

// newOTelRequestObserver exposes the existing safe request completion boundary
// to an operator-provided OpenTelemetry meter and tracer. Request-scoped and
// tenant-correlated values are trace-only: metric labels are deliberately
// bounded to avoid a cardinality-based telemetry denial of service.
func newOTelRequestObserver(meter metric.Meter, tracer trace.Tracer) (runtimeapi.RequestObserver, error) {
	if meter == nil || tracer == nil {
		return nil, errors.New("create OpenTelemetry request observer: meter and tracer are required")
	}
	completed, err := meter.Int64Counter(
		"runtime.api.request.completed",
		metric.WithDescription("Completed public API requests by bounded outcome."),
	)
	if err != nil {
		return nil, errors.Wrap(err, "create OpenTelemetry request observer: completed counter")
	}
	duration, err := meter.Float64Histogram(
		"runtime.api.request.duration",
		metric.WithUnit("ms"),
		metric.WithDescription("Public API request completion duration in milliseconds."),
	)
	if err != nil {
		return nil, errors.Wrap(err, "create OpenTelemetry request observer: duration histogram")
	}
	return otelRequestObserver{completed: completed, duration: duration, tracer: tracer}, nil
}

type otelRequestObserver struct {
	completed metric.Int64Counter
	duration  metric.Float64Histogram
	tracer    trace.Tracer
}

func (observer otelRequestObserver) ObserveRequest(ctx context.Context, observation runtimeapi.RequestObservation) {
	if ctx == nil {
		ctx = context.Background()
	}
	metricAttributes := requestMetricAttributes(observation)
	observer.completed.Add(ctx, 1, metric.WithAttributes(metricAttributes...))
	observer.duration.Record(ctx, float64(observation.Duration)/float64(time.Millisecond), metric.WithAttributes(metricAttributes...))
	options := []trace.SpanStartOption{trace.WithAttributes(requestTraceAttributes(observation)...)}
	if !observation.StartedAt.IsZero() {
		options = append(options, trace.WithTimestamp(observation.StartedAt))
	}
	_, span := observer.tracer.Start(ctx, "runtime.api.request", options...)
	if observation.StartedAt.IsZero() {
		span.End()
		return
	}
	span.End(trace.WithTimestamp(observation.StartedAt.Add(observation.Duration)))
}

func requestMetricAttributes(observation runtimeapi.RequestObservation) []attribute.KeyValue {
	attributes := []attribute.KeyValue{
		attribute.String("runtime.operation", observation.Operation),
		attribute.Int("http.response.status_code", observation.Status),
		attribute.String("runtime.outcome", string(observation.Outcome)),
	}
	if observation.FailureCode != "" {
		attributes = append(attributes, attribute.String("runtime.failure_code", string(observation.FailureCode)))
	}
	return attributes
}

func requestTraceAttributes(observation runtimeapi.RequestObservation) []attribute.KeyValue {
	attributes := requestMetricAttributes(observation)
	attributes = append(attributes, attribute.String("runtime.request.id", observation.RequestID.String()))
	if observation.TenantCorrelation != "" {
		attributes = append(attributes, attribute.String("runtime.tenant.correlation", observation.TenantCorrelation))
	}
	if observation.PrincipalCorrelation != "" {
		attributes = append(attributes, attribute.String("runtime.principal.correlation", observation.PrincipalCorrelation))
	}
	correlation := observation.Correlation.Values()
	for _, field := range []struct{ key, value string }{
		{"runtime.agent.id", correlation.AgentID},
		{"runtime.agent.revision.id", correlation.AgentRevisionID},
		{"runtime.session.id", correlation.SessionID},
		{"runtime.turn.id", correlation.TurnID},
		{"runtime.invocation.id", correlation.InvocationID},
		{"runtime.tool.call.id", correlation.ToolCallID},
		{"runtime.tool.execution.id", correlation.ToolExecutionID},
		{"runtime.approval.id", correlation.ApprovalID},
		{"runtime.sandbox.id", correlation.SandboxID},
		{"runtime.process.id", correlation.ProcessID},
		{"runtime.operation.id", correlation.OperationID},
	} {
		if field.value != "" {
			attributes = append(attributes, attribute.String(field.key, field.value))
		}
	}
	return attributes
}
