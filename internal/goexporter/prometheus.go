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

// Label schemas are composed from three positional groups:
//
//  1. A kind-specific prefix (e.g. "fs", "mount", "access_intent", "op").
//  2. Optional per-UID identity ("uid", "username") when uidEnabled is true.
//  3. The common "process", "actor_type" pair, optionally followed by
//     "slurm_job_id" when slurmEnabled is true, and a kind-specific trailing
//     slot (e.g. "errno_class").
//
// Each metric family has a dedicated builder so call sites read naturally
// and the schema-shaping logic is centralized.
func appendUIDLabels(dst []string, uidEnabled bool) []string {
	if uidEnabled {
		return append(dst, "uid", "username")
	}
	return dst
}

func appendSlurmLabel(dst []string, slurmEnabled bool) []string {
	if slurmEnabled {
		return append(dst, "slurm_job_id")
	}
	return dst
}

func buildBaseLabels(slurmEnabled, uidEnabled bool) []string {
	labels := []string{"fs", "mount"}
	labels = appendUIDLabels(labels, uidEnabled)
	labels = append(labels, "process", "actor_type")
	return appendSlurmLabel(labels, slurmEnabled)
}

func buildPtlrpcLabels(slurmEnabled, uidEnabled bool) []string {
	labels := []string{"fs", "mount", "op"}
	labels = appendUIDLabels(labels, uidEnabled)
	labels = append(labels, "process", "actor_type")
	return appendSlurmLabel(labels, slurmEnabled)
}

func buildLliteLabels(slurmEnabled, uidEnabled bool) []string {
	labels := []string{"fs", "mount", "access_intent", "op"}
	labels = appendUIDLabels(labels, uidEnabled)
	labels = append(labels, "process", "actor_type")
	return appendSlurmLabel(labels, slurmEnabled)
}

func buildLliteErrLabels(slurmEnabled, uidEnabled bool) []string {
	labels := buildLliteLabels(slurmEnabled, uidEnabled)
	return append(labels, "errno_class")
}

func buildRPCErrorLabels(slurmEnabled, uidEnabled bool) []string {
	labels := []string{"fs", "mount", "event"}
	labels = appendUIDLabels(labels, uidEnabled)
	labels = append(labels, "process", "actor_type")
	return appendSlurmLabel(labels, slurmEnabled)
}

func buildPCCAttachLabels(slurmEnabled, uidEnabled bool) []string {
	labels := []string{"fs", "mount", "mode", "trigger"}
	labels = appendUIDLabels(labels, uidEnabled)
	labels = append(labels, "process", "actor_type")
	return appendSlurmLabel(labels, slurmEnabled)
}

func buildWorkloadAccessLabels(slurmEnabled, uidEnabled bool) []string {
	labels := []string{"fs", "mount", "access_intent"}
	labels = appendUIDLabels(labels, uidEnabled)
	labels = append(labels, "process", "actor_type")
	labels = appendSlurmLabel(labels, slurmEnabled)
	return append(labels, "aggregation")
}

func buildWorkloadRPCWaitLabels(slurmEnabled, uidEnabled bool) []string {
	labels := []string{"fs", "mount"}
	labels = appendUIDLabels(labels, uidEnabled)
	labels = append(labels, "process", "actor_type")
	labels = appendSlurmLabel(labels, slurmEnabled)
	return append(labels, "aggregation")
}

// PrometheusExporter serves Prometheus metrics via HTTP.
// Histograms and gauges are updated directly; counters are provided
// by the BPFCounterCollector custom Collector.
type PrometheusExporter struct {
	registry *prometheus.Registry
	server   *http.Server
	listener net.Listener

	PCCEnabled   bool
	SlurmEnabled bool
	UIDEnabled   bool

	Inflight          *prometheus.GaugeVec
	RequestsStarted   *prometheus.CounterVec
	RequestsCompleted *prometheus.CounterVec
	WorkloadCollector *WorkloadWindowCollector

	// PCC metrics (nil when PCCEnabled is false)
	PCCLatency             *prometheus.HistogramVec
	PCCAttachTotal         *prometheus.CounterVec
	PCCAttachFailuresTotal *prometheus.CounterVec
	PCCDetachTotal         *prometheus.CounterVec
	PCCInvalidationsTotal  *prometheus.CounterVec
}

func NewPrometheusExporter(listenAddress string, telemetryPath string, counterCollector *BPFCounterCollector, pccEnabled bool, slurmEnabled bool, uidEnabled bool) (*PrometheusExporter, error) {
	registry := prometheus.NewRegistry()
	workloadCollector := NewWorkloadWindowCollector(DefaultWorkloadFilterConfig(), nil, slurmEnabled, uidEnabled)
	exporter := &PrometheusExporter{
		registry:     registry,
		PCCEnabled:   pccEnabled,
		SlurmEnabled: slurmEnabled,
		UIDEnabled:   uidEnabled,
		Inflight: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "lustre_client_inflight_requests", Help: "Net tracked ptlrpc requests"},
			buildBaseLabels(slurmEnabled, uidEnabled),
		),
		RequestsStarted: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "lustre_client_ptlrpc_requests_started_total",
				Help: "Total ptlrpc requests sent (ptlrpc_send_new_req events)",
			},
			buildBaseLabels(slurmEnabled, uidEnabled),
		),
		RequestsCompleted: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "lustre_client_ptlrpc_requests_completed_total",
				Help: "Total ptlrpc requests freed (__ptlrpc_free_req events)",
			},
			buildBaseLabels(slurmEnabled, uidEnabled),
		),
		WorkloadCollector: workloadCollector,
	}

	collectors := []prometheus.Collector{
		exporter.WorkloadCollector, exporter.Inflight,
		exporter.RequestsStarted, exporter.RequestsCompleted,
	}

	if pccEnabled {
		exporter.PCCLatency = prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "lustre_client_pcc_operation_duration_seconds",
				Help:    "PCC I/O operation latency in seconds",
				Buckets: PrometheusLatencyBucketsSeconds,
			},
			buildLliteLabels(slurmEnabled, uidEnabled),
		)
		exporter.PCCAttachTotal = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "lustre_client_pcc_attach_total",
				Help: "Total PCC attach attempts",
			},
			buildPCCAttachLabels(slurmEnabled, uidEnabled),
		)
		exporter.PCCAttachFailuresTotal = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "lustre_client_pcc_attach_failures_total",
				Help: "Total PCC attach failures",
			},
			buildPCCAttachLabels(slurmEnabled, uidEnabled),
		)
		exporter.PCCDetachTotal = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "lustre_client_pcc_detach_total",
				Help: "Total PCC detach operations",
			},
			buildBaseLabels(slurmEnabled, uidEnabled),
		)
		exporter.PCCInvalidationsTotal = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "lustre_client_pcc_layout_invalidations_total",
				Help: "Total PCC layout invalidation events",
			},
			buildBaseLabels(slurmEnabled, uidEnabled),
		)
		collectors = append(collectors,
			exporter.PCCLatency,
			exporter.PCCAttachTotal, exporter.PCCAttachFailuresTotal,
			exporter.PCCDetachTotal, exporter.PCCInvalidationsTotal,
		)
	}
	if counterCollector != nil {
		collectors = append(collectors, counterCollector)
	}
	for _, c := range collectors {
		registry.MustRegister(c)
	}

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

func (e *PrometheusExporter) SetProcessFilter(filter *ProcessFilter) {
	if e.WorkloadCollector != nil {
		e.WorkloadCollector.SetProcessFilter(filter)
	}
}

func (e *PrometheusExporter) FlushWorkloadWindow() {
	if e.WorkloadCollector != nil {
		e.WorkloadCollector.RotateWindow()
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

func gatherToText(families []*dto.MetricFamily) (string, error) {
	var out strings.Builder
	enc := expfmt.NewEncoder(&out, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, family := range families {
		if err := enc.Encode(family); err != nil {
			return "", fmt.Errorf("encode metric family %s: %w", family.GetName(), err)
		}
	}
	return out.String(), nil
}
