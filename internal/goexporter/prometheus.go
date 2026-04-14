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
	baseLabels      = []string{"fs", "mount", "uid", "username", "process", "actor_type", "slurm_job_id"}
	ptlrpcLabels    = []string{"fs", "mount", "op", "uid", "username", "process", "actor_type", "slurm_job_id"}
	lliteLabels     = []string{"fs", "mount", "access_intent", "op", "uid", "username", "process", "actor_type", "slurm_job_id"}
	lliteErrLabels  = []string{"fs", "mount", "access_intent", "op", "uid", "username", "process", "actor_type", "slurm_job_id", "errno_class"}
	rpcErrorLabels  = []string{"fs", "mount", "event", "uid", "username", "process", "actor_type", "slurm_job_id"}
	pccAttachLabels = []string{"fs", "mount", "mode", "trigger", "uid", "username", "process", "actor_type", "slurm_job_id"}

	baseLabelsNoSlurm      = []string{"fs", "mount", "uid", "username", "process", "actor_type"}
	ptlrpcLabelsNoSlurm    = []string{"fs", "mount", "op", "uid", "username", "process", "actor_type"}
	lliteLabelsNoSlurm     = []string{"fs", "mount", "access_intent", "op", "uid", "username", "process", "actor_type"}
	lliteErrLabelsNoSlurm  = []string{"fs", "mount", "access_intent", "op", "uid", "username", "process", "actor_type", "errno_class"}
	rpcErrorLabelsNoSlurm  = []string{"fs", "mount", "event", "uid", "username", "process", "actor_type"}
	pccAttachLabelsNoSlurm = []string{"fs", "mount", "mode", "trigger", "uid", "username", "process", "actor_type"}
)

// pickLabels returns with if slurmEnabled, otherwise without.
func pickLabels(slurmEnabled bool, with, without []string) []string {
	if slurmEnabled {
		return with
	}
	return without
}

// PrometheusExporter serves Prometheus metrics via HTTP.
// Histograms and gauges are updated directly; counters are provided
// by the BPFCounterCollector custom Collector.
type PrometheusExporter struct {
	registry *prometheus.Registry
	server   *http.Server
	listener net.Listener

	PCCEnabled  bool
	SlurmEnabled bool

	AccessLatency     *prometheus.HistogramVec
	RPCWaitLat        *prometheus.HistogramVec
	Inflight          *prometheus.GaugeVec
	RequestsStarted   *prometheus.CounterVec
	RequestsCompleted *prometheus.CounterVec

	// PCC metrics (nil when PCCEnabled is false)
	PCCLatency             *prometheus.HistogramVec
	PCCAttachTotal         *prometheus.CounterVec
	PCCAttachFailuresTotal *prometheus.CounterVec
	PCCDetachTotal         *prometheus.CounterVec
	PCCInvalidationsTotal  *prometheus.CounterVec
}

func NewPrometheusExporter(listenAddress string, telemetryPath string, counterCollector *BPFCounterCollector, pccEnabled bool, slurmEnabled bool) (*PrometheusExporter, error) {
	registry := prometheus.NewRegistry()
	exporter := &PrometheusExporter{
		registry:     registry,
		PCCEnabled:   pccEnabled,
		SlurmEnabled: slurmEnabled,
		AccessLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{Name: "lustre_client_access_duration_seconds", Help: "Aggregated llite access latency in seconds", Buckets: PrometheusLatencyBucketsSeconds},
			pickLabels(slurmEnabled,lliteLabels, lliteLabelsNoSlurm),
		),
		RPCWaitLat: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{Name: "lustre_client_rpc_wait_duration_seconds", Help: "Aggregated ptlrpc queue wait latency in seconds", Buckets: PrometheusLatencyBucketsSeconds},
			pickLabels(slurmEnabled,ptlrpcLabels, ptlrpcLabelsNoSlurm),
		),
		Inflight: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "lustre_client_inflight_requests", Help: "Net tracked ptlrpc requests"},
			pickLabels(slurmEnabled,baseLabels, baseLabelsNoSlurm),
		),
		RequestsStarted: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "lustre_client_ptlrpc_requests_started_total",
				Help: "Total ptlrpc requests sent (ptlrpc_send_new_req events)",
			},
			pickLabels(slurmEnabled,baseLabels, baseLabelsNoSlurm),
		),
		RequestsCompleted: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "lustre_client_ptlrpc_requests_completed_total",
				Help: "Total ptlrpc requests freed (__ptlrpc_free_req events)",
			},
			pickLabels(slurmEnabled,baseLabels, baseLabelsNoSlurm),
		),
	}

	collectors := []prometheus.Collector{
		exporter.AccessLatency, exporter.RPCWaitLat, exporter.Inflight,
		exporter.RequestsStarted, exporter.RequestsCompleted,
	}

	if pccEnabled {
		exporter.PCCLatency = prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "lustre_client_pcc_operation_duration_seconds",
				Help:    "PCC I/O operation latency in seconds",
				Buckets: PrometheusLatencyBucketsSeconds,
			},
			pickLabels(slurmEnabled,lliteLabels, lliteLabelsNoSlurm),
		)
		exporter.PCCAttachTotal = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "lustre_client_pcc_attach_total",
				Help: "Total PCC attach attempts",
			},
			pickLabels(slurmEnabled,pccAttachLabels, pccAttachLabelsNoSlurm),
		)
		exporter.PCCAttachFailuresTotal = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "lustre_client_pcc_attach_failures_total",
				Help: "Total PCC attach failures",
			},
			pickLabels(slurmEnabled,pccAttachLabels, pccAttachLabelsNoSlurm),
		)
		exporter.PCCDetachTotal = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "lustre_client_pcc_detach_total",
				Help: "Total PCC detach operations",
			},
			pickLabels(slurmEnabled,baseLabels, baseLabelsNoSlurm),
		)
		exporter.PCCInvalidationsTotal = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "lustre_client_pcc_layout_invalidations_total",
				Help: "Total PCC layout invalidation events",
			},
			pickLabels(slurmEnabled,baseLabels, baseLabelsNoSlurm),
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
