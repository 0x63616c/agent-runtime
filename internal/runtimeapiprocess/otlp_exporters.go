package runtimeapiprocess

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// ExportingTelemetry owns paired OTLP providers for one API process. It uses
// an explicit in-cluster gRPC target, no ambient exporter environment, no
// headers, and no credential configuration.
type ExportingTelemetry struct {
	Providers TelemetryProviders
	meter     *metric.MeterProvider
	tracer    *sdktrace.TracerProvider
}

// NewExportingTelemetry creates the paired OTLP trace and metric exporters.
// Call Shutdown after RunWithTelemetry returns so both pipelines flush their
// bounded pending batches before the process exits.
func NewExportingTelemetry(ctx context.Context, endpoint string) (*ExportingTelemetry, error) {
	if ctx == nil || endpoint == "" || !validOTLPGRPCEndpoint(endpoint) {
		return nil, errors.New("create exporting telemetry: a valid in-cluster OTLP gRPC endpoint is required")
	}
	metricExporter, err := otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithEndpoint(endpoint), otlpmetricgrpc.WithInsecure(), otlpmetricgrpc.WithTimeout(5*time.Second))
	if err != nil {
		return nil, errors.New("create exporting telemetry: OTLP metric exporter is unavailable")
	}
	traceExporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithEndpoint(endpoint), otlptracegrpc.WithInsecure(), otlptracegrpc.WithTimeout(5*time.Second))
	if err != nil {
		_ = metricExporter.Shutdown(context.Background())
		return nil, errors.New("create exporting telemetry: OTLP trace exporter is unavailable")
	}
	meter := metric.NewMeterProvider(metric.WithReader(metric.NewPeriodicReader(metricExporter, metric.WithInterval(15*time.Second))))
	tracer := sdktrace.NewTracerProvider(sdktrace.WithBatcher(traceExporter, sdktrace.WithBatchTimeout(time.Second), sdktrace.WithExportTimeout(5*time.Second)))
	return &ExportingTelemetry{Providers: TelemetryProviders{MeterProvider: meter, TracerProvider: tracer}, meter: meter, tracer: tracer}, nil
}

// Shutdown flushes traces then metrics without exposing transport failures or
// endpoint data through logs. The first failure is returned only to the local
// process supervisor.
func (telemetry *ExportingTelemetry) Shutdown(ctx context.Context) error {
	if telemetry == nil || telemetry.meter == nil || telemetry.tracer == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	traceErr := telemetry.tracer.Shutdown(ctx)
	metricErr := telemetry.meter.Shutdown(ctx)
	return errors.Join(traceErr, metricErr)
}
