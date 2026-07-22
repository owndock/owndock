package observability

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	registry *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	inFlight prometheus.Gauge
}

func NewMetrics() *Metrics {
	registry := prometheus.NewRegistry()
	metrics := &Metrics{
		registry: registry,
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "owndock",
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "Total number of HTTP requests by method and status code.",
		}, []string{"code", "method"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "owndock",
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "HTTP request duration in seconds by method.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"method"}),
		inFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "owndock",
			Subsystem: "http",
			Name:      "requests_in_flight",
			Help:      "Current number of HTTP requests being served.",
		}),
	}
	registry.MustRegister(
		metrics.requests,
		metrics.duration,
		metrics.inFlight,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return metrics
}

func (m *Metrics) Instrument(next http.Handler) http.Handler {
	return promhttp.InstrumentHandlerInFlight(
		m.inFlight,
		promhttp.InstrumentHandlerDuration(
			m.duration,
			promhttp.InstrumentHandlerCounter(m.requests, next),
		),
	)
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}
