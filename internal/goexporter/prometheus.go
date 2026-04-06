package goexporter

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

type PrometheusExporter struct {
	registry *prometheus.Registry
	server   *http.Server
	listener net.Listener

	accessOps     *prometheus.CounterVec
	accessLatency *prometheus.HistogramVec
	dataBytes     *prometheus.CounterVec
	rpcWaitOps    *prometheus.CounterVec
	rpcWaitLat    *prometheus.HistogramVec
	inflight      *prometheus.GaugeVec
}

func NewPrometheusExporter(listenAddress string, telemetryPath string) (*PrometheusExporter, error) {
	registry := prometheus.NewRegistry()
	exporter := &PrometheusExporter{
		registry: registry,
		accessOps: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "lustre_client_access_operations_total", Help: "Aggregated llite access operation count"},
			[]string{"fs", "mount", "access_class", "op", "uid", "process", "actor_type"},
		),
		accessLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{Name: "lustre_client_access_duration_seconds", Help: "Aggregated llite access latency in seconds", Buckets: PrometheusLatencyBucketsSeconds},
			[]string{"fs", "mount", "access_class", "op", "uid", "process", "actor_type"},
		),
		dataBytes: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "lustre_client_data_bytes_total", Help: "Aggregated llite data volume in bytes"},
			[]string{"fs", "mount", "access_class", "op", "uid", "process", "actor_type"},
		),
		rpcWaitOps: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "lustre_client_rpc_wait_operations_total", Help: "Aggregated ptlrpc queue wait count"},
			[]string{"fs", "mount", "op", "uid", "process", "actor_type"},
		),
		rpcWaitLat: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{Name: "lustre_client_rpc_wait_duration_seconds", Help: "Aggregated ptlrpc queue wait latency in seconds", Buckets: PrometheusLatencyBucketsSeconds},
			[]string{"fs", "mount", "op", "uid", "process", "actor_type"},
		),
		inflight: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "lustre_client_inflight_requests", Help: "Net tracked ptlrpc requests"},
			[]string{"fs", "mount", "uid", "process", "actor_type"},
		),
	}
	registry.MustRegister(
		exporter.accessOps, exporter.accessLatency, exporter.dataBytes,
		exporter.rpcWaitOps, exporter.rpcWaitLat, exporter.inflight,
	)

	mux := http.NewServeMux()
	mux.Handle(telemetryPath, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return nil, err
	}
	exporter.listener = listener
	exporter.server = &http.Server{Handler: mux}
	go func() {
		_ = exporter.server.Serve(listener)
	}()
	return exporter, nil
}

func (e *PrometheusExporter) Export(metrics []AggregatedMetric) {
	for _, metric := range metrics {
		switch metric.Name {
		case "lustre.client.access.operations":
			e.accessOps.With(e.labels(metric)).Add(metric.Value)
		case "lustre.client.access.duration":
			observer := e.accessLatency.With(e.labels(metric))
			for _, value := range metric.Histogram {
				observer.Observe(value / 1_000_000.0)
			}
		case "lustre.client.data.bytes":
			e.dataBytes.With(e.labels(metric)).Add(metric.Value)
		case "lustre.client.rpc.wait.operations":
			e.rpcWaitOps.With(e.labels(metric)).Add(metric.Value)
		case "lustre.client.rpc.wait.duration":
			observer := e.rpcWaitLat.With(e.labels(metric))
			for _, value := range metric.Histogram {
				observer.Observe(value / 1_000_000.0)
			}
		case "lustre.client.inflight.requests":
			e.inflight.With(e.labels(metric)).Set(metric.Value)
		}
	}
}

func (e *PrometheusExporter) Shutdown(ctx context.Context) error {
	if e.server == nil {
		return nil
	}
	return e.server.Shutdown(ctx)
}

func (e *PrometheusExporter) RenderText() (string, error) {
	metrics, err := e.registry.Gather()
	if err != nil {
		return "", err
	}
	return gatherToText(metrics)
}

func (e *PrometheusExporter) labels(metric AggregatedMetric) prometheus.Labels {
	labels := prometheus.Labels{
		"fs":         metric.Attributes["lustre.fs.name"],
		"mount":      metric.Attributes["lustre.mount.path"],
		"uid":        metric.Attributes["user.id"],
		"process":    metric.Attributes["process.name"],
		"actor_type": metric.Attributes["lustre.actor.type"],
	}
	if accessClass, ok := metric.Attributes["lustre.access.class"]; ok {
		labels["access_class"] = accessClass
	}
	if op, ok := metric.Attributes["lustre.access.op"]; ok {
		labels["op"] = op
	}
	return labels
}

func gatherToText(families []*dto.MetricFamily) (string, error) {
	var out strings.Builder
	enc := expfmt.NewEncoder(&out, expfmt.FmtText)
	for _, family := range families {
		if err := enc.Encode(family); err != nil {
			return "", fmt.Errorf("encode metric family %s: %w", family.GetName(), err)
		}
	}
	return out.String(), nil
}
