package runtimeapiprocess

import (
	"context"
	"log/slog"

	"github.com/0x63616c/agent-runtime/internal/runtimeapi"
	"github.com/cockroachdb/errors"
	"go.opentelemetry.io/otel"
)

func requestObservability(config Config, lookup SecretLookup, logger *slog.Logger) (runtimeapi.Observability, error) {
	if config.observabilityKeyEnvironment == "" {
		return runtimeapi.Observability{}, nil
	}
	if lookup == nil || logger == nil {
		return runtimeapi.Observability{}, errors.New("configure runtime API request observability: secret lookup and JSON logger are required")
	}
	key, found := lookup(config.observabilityKeyEnvironment)
	if !found {
		return runtimeapi.Observability{}, errors.New("configure runtime API request observability: identity correlation key is unavailable")
	}
	correlator, err := runtimeapi.NewHMACIdentityCorrelator([]byte(key))
	if err != nil {
		return runtimeapi.Observability{}, errors.Wrap(err, "configure runtime API request observability")
	}
	otelObserver, err := newOTelRequestObserver(
		otel.GetMeterProvider().Meter(runtimeAPIInstrumentationScope),
		otel.GetTracerProvider().Tracer(runtimeAPIInstrumentationScope),
	)
	if err != nil {
		return runtimeapi.Observability{}, errors.Wrap(err, "configure runtime API request observability")
	}
	return runtimeapi.Observability{
		Clock:              systemClock{},
		Observer:           requestObservers{slogRequestObserver{logger: logger}, otelObserver},
		IdentityCorrelator: correlator,
	}, nil
}

type requestObservers []runtimeapi.RequestObserver

func (observers requestObservers) ObserveRequest(ctx context.Context, observation runtimeapi.RequestObservation) {
	for _, observer := range observers {
		observer.ObserveRequest(ctx, observation)
	}
}

type slogRequestObserver struct{ logger *slog.Logger }

func (observer slogRequestObserver) ObserveRequest(_ context.Context, observation runtimeapi.RequestObservation) {
	attributes := []any{
		"request_id", observation.RequestID,
		"operation", observation.Operation,
		"status", observation.Status,
		"outcome", observation.Outcome,
		"duration_ms", observation.Duration.Milliseconds(),
	}
	if observation.FailureCode != "" {
		attributes = append(attributes, "failure_code", observation.FailureCode)
	}
	if observation.TenantCorrelation != "" {
		attributes = append(attributes, "tenant_correlation", observation.TenantCorrelation)
	}
	if observation.PrincipalCorrelation != "" {
		attributes = append(attributes, "principal_correlation", observation.PrincipalCorrelation)
	}
	observer.logger.Info("runtime request completed", attributes...)
}
