package observability

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.opentelemetry.io/otel/trace"

	platformconfig "github.com/owndock/owndock/internal/platform/config"
)

type Tracing struct {
	serviceName  string
	provider     trace.TracerProvider
	propagator   propagation.TextMapPropagator
	shutdown     func(context.Context) error
	shutdownErr  error
	shutdownOnce sync.Once
}

func NewTracing(
	ctx context.Context,
	cfg platformconfig.Tracing,
	serviceName string,
	version string,
	instanceID string,
) (*Tracing, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate tracing config: %w", err)
	}
	propagator := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
	if !cfg.Enabled {
		return &Tracing{
			serviceName: serviceName,
			provider:    trace.NewNoopTracerProvider(),
			propagator:  propagator,
			shutdown:    func(context.Context) error { return nil },
		}, nil
	}

	exporterOptions := []otlptracehttp.Option{otlptracehttp.WithEndpoint(cfg.Endpoint)}
	if cfg.Insecure {
		exporterOptions = append(exporterOptions, otlptracehttp.WithInsecure())
	}
	exporter, err := otlptracehttp.New(ctx, exporterOptions...)
	if err != nil {
		return nil, fmt.Errorf("create OTLP trace exporter: %w", err)
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.EffectiveSampleRatio()))),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(version),
			semconv.ServiceInstanceID(instanceID),
		)),
	)
	return &Tracing{
		serviceName: serviceName,
		provider:    provider,
		propagator:  propagator,
		shutdown:    provider.Shutdown,
	}, nil
}

func (t *Tracing) Instrument(next http.Handler) http.Handler {
	return otelhttp.NewHandler(
		next,
		t.serviceName+".http.request",
		otelhttp.WithTracerProvider(t.provider),
		otelhttp.WithPropagators(t.propagator),
		otelhttp.WithSpanNameFormatter(func(operation string, r *http.Request) string {
			return r.Method + " " + operation
		}),
	)
}

func (t *Tracing) Shutdown(ctx context.Context) error {
	if t == nil || t.shutdown == nil {
		return nil
	}
	t.shutdownOnce.Do(func() {
		t.shutdownErr = t.shutdown(ctx)
	})
	return t.shutdownErr
}
