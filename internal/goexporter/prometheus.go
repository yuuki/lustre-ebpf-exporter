package goexporter

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

var (
	baseLabels   = []string{"fs", "mount", "uid", "username", "process", "actor_type"}
	ptlrpcLabels = []string{"fs", "mount", "op", "uid", "username", "process", "actor_type"}
	lliteLabels  = []string{"fs", "mount", "access_intent", "op", "uid", "username", "process", "actor_type"}
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
			lliteLabels,
		),
		accessLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{Name: "lustre_client_access_duration_seconds", Help: "Aggregated llite access latency in seconds", Buckets: PrometheusLatencyBucketsSeconds},
			lliteLabels,
		),
		dataBytes: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "lustre_client_data_bytes_total", Help: "Aggregated llite data volume in bytes"},
			lliteLabels,
		),
		rpcWaitOps: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "lustre_client_rpc_wait_operations_total", Help: "Aggregated ptlrpc queue wait count"},
			ptlrpcLabels,
		),
		rpcWaitLat: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{Name: "lustre_client_rpc_wait_duration_seconds", Help: "Aggregated ptlrpc queue wait latency in seconds", Buckets: PrometheusLatencyBucketsSeconds},
			ptlrpcLabels,
		),
		inflight: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "lustre_client_inflight_requests", Help: "Net tracked ptlrpc requests"},
			baseLabels,
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
	log.Printf("Listening on %s, metrics at %s", listener.Addr(), telemetryPath)
	return exporter, nil
}

func (e *PrometheusExporter) Export(metrics []AggregatedMetric) {
	for _, metric := range metrics {
		switch metric.Name {
		case MetricAccessOps:
			e.accessOps.With(e.labels(metric)).Add(metric.Value)
		case MetricAccessDuration:
			observer := e.accessLatency.With(e.labels(metric))
			for _, value := range metric.Histogram {
				observer.Observe(value / 1_000_000.0)
			}
		case MetricDataBytes:
			e.dataBytes.With(e.labels(metric)).Add(metric.Value)
		case MetricRPCWaitOps:
			e.rpcWaitOps.With(e.labels(metric)).Add(metric.Value)
		case MetricRPCWaitDuration:
			observer := e.rpcWaitLat.With(e.labels(metric))
			for _, value := range metric.Histogram {
				observer.Observe(value / 1_000_000.0)
			}
		case MetricInflight:
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
		"fs":         metric.Attributes[AttrFSName],
		"mount":      metric.Attributes[AttrMountPath],
		"uid":        metric.Attributes[AttrUserID],
		"username":   metric.Attributes[AttrUserName],
		"process":    metric.Attributes[AttrProcessName],
		"actor_type": metric.Attributes[AttrActorType],
	}
	if accessIntent, ok := metric.Attributes[AttrAccessIntent]; ok {
		labels["access_intent"] = accessIntent
	}
	if op, ok := metric.Attributes[AttrAccessOp]; ok {
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
