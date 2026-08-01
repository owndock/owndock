package observability

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	registry        *prometheus.Registry
	requests        *prometheus.CounterVec
	duration        *prometheus.HistogramVec
	inFlight        prometheus.Gauge
	buildOperations *prometheus.CounterVec
	buildDuration   *prometheus.HistogramVec
	buildLogWrites  *prometheus.CounterVec
	buildLogBytes   *prometheus.CounterVec
	workerPolls     *prometheus.CounterVec
	workerPollTime  *prometheus.HistogramVec
	workerLastOK    *prometheus.GaugeVec
	workerLastError *prometheus.GaugeVec
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
		buildOperations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "owndock", Subsystem: "build_worker", Name: "operations_total",
			Help: "Total claimed Build operations by safe result.",
		}, []string{"result"}),
		buildDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "owndock", Subsystem: "build_worker", Name: "operation_duration_seconds",
			Help: "Claimed Build operation duration by safe result.", Buckets: prometheus.DefBuckets,
		}, []string{"result"}),
		buildLogWrites: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "owndock", Subsystem: "build_worker", Name: "log_writes_total",
			Help: "Build log persistence attempts by stage and safe result.",
		}, []string{"stage", "result"}),
		buildLogBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "owndock", Subsystem: "build_worker", Name: "log_bytes_total",
			Help: "Redacted Build log bytes submitted for persistence by stage.",
		}, []string{"stage"}),
		workerPolls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "owndock", Subsystem: "worker", Name: "polls_total",
			Help: "Worker polling iterations by bounded worker name and safe result.",
		}, []string{"worker", "result"}),
		workerPollTime: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "owndock", Subsystem: "worker", Name: "poll_duration_seconds",
			Help:    "Worker polling iteration duration by bounded worker name and safe result.",
			Buckets: prometheus.DefBuckets,
		}, []string{"worker", "result"}),
		workerLastOK: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "owndock", Subsystem: "worker", Name: "last_success_unixtime",
			Help: "Unix timestamp of the most recent successful worker polling iteration.",
		}, []string{"worker"}),
		workerLastError: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "owndock", Subsystem: "worker", Name: "last_error_unixtime",
			Help: "Unix timestamp of the most recent failed or timed-out worker polling iteration.",
		}, []string{"worker"}),
	}
	registry.MustRegister(
		metrics.requests,
		metrics.duration,
		metrics.inFlight,
		metrics.buildOperations,
		metrics.buildDuration,
		metrics.buildLogWrites,
		metrics.buildLogBytes,
		metrics.workerPolls,
		metrics.workerPollTime,
		metrics.workerLastOK,
		metrics.workerLastError,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return metrics
}

func (m *Metrics) RecordWorkerPoll(worker, result string, duration time.Duration) {
	worker = safeWorkerName(worker)
	result = safeWorkerResult(result)
	m.workerPolls.WithLabelValues(worker, result).Inc()
	m.workerPollTime.WithLabelValues(worker, result).Observe(max(duration.Seconds(), 0))
	now := float64(time.Now().Unix())
	if result == "success" {
		m.workerLastOK.WithLabelValues(worker).Set(now)
	}
	if result == "error" || result == "timeout" {
		m.workerLastError.WithLabelValues(worker).Set(now)
	}
}

func safeWorkerName(value string) string {
	switch value {
	case "build", "deployment", "runtime_inventory", "runtime_inventory_events":
		return value
	default:
		return "unknown"
	}
}

func safeWorkerResult(value string) string {
	switch value {
	case "success", "error", "timeout", "canceled":
		return value
	default:
		return "error"
	}
}

func (m *Metrics) RecordBuildOperation(result string, duration time.Duration) {
	if result != "success" {
		result = "error"
	}
	m.buildOperations.WithLabelValues(result).Inc()
	m.buildDuration.WithLabelValues(result).Observe(duration.Seconds())
}

func (m *Metrics) RecordBuildLog(stage string, bytes int, err error) {
	result := "success"
	if err != nil {
		result = "error"
	}
	m.buildLogWrites.WithLabelValues(stage, result).Inc()
	if bytes > 0 {
		m.buildLogBytes.WithLabelValues(stage).Add(float64(bytes))
	}
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
