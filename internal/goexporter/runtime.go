package goexporter

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/yuuki/otel-lustre-tracer/internal/goexporter/slurm"
)

type EventSource interface {
	Events() <-chan Event
	CounterMaps() (llite, rpc *ebpf.Map)
	ErrorCounterMaps() (lliteErrors, rpcErrors *ebpf.Map)
	PccCounterMaps() (pcc, pccErrors *ebpf.Map)
	Close() error
}

func Run(ctx context.Context, cfg Config) error {
	if len(cfg.MountPaths) > MaxMountPoints {
		return fmt.Errorf("too many mount paths (%d); maximum is %d", len(cfg.MountPaths), MaxMountPoints)
	}
	var mountInfos []MountInfo
	for _, mp := range cfg.MountPaths {
		mi, err := ResolveMountInfo(mp)
		if err != nil {
			return err
		}
		mountInfos = append(mountInfos, mi)
	}

	source, err := newEventSource(ctx, cfg, mountInfos)
	if err != nil {
		return err
	}
	defer source.Close()

	resolver := NewUsernameResolver()
	slurmResolver := newSlurmResolverFromConfig(cfg)
	procNameResolver := NewProcNameResolver()

	lliteMap, rpcMap := source.CounterMaps()
	lliteErrorMap, rpcErrorMap := source.ErrorCounterMaps()
	var pccMap, pccErrorMap *ebpf.Map
	if cfg.PCCEnabled {
		pccMap, pccErrorMap = source.PccCounterMaps()
	}
	counterCollector := NewBPFCounterCollector(lliteMap, rpcMap, lliteErrorMap, rpcErrorMap, pccMap, pccErrorMap, mountInfos, resolver, slurmResolver)
	counterCollector.StartDrain(ctx, cfg.DrainInterval)

	exporter, err := NewPrometheusExporter(cfg.WebListenAddress, cfg.WebTelemetryPath, counterCollector, cfg.PCCEnabled)
	if err != nil {
		return err
	}
	defer exporter.Shutdown(context.Background())

	inflightTracker := NewInflightTracker(exporter.Inflight, resolver, slurmResolver)

	debugEnabled := os.Getenv("LUSTRE_OBSERVER_DEBUG") == "1"

	var durationTimer <-chan time.Time
	if cfg.Duration > 0 {
		timer := time.NewTimer(cfg.Duration)
		defer timer.Stop()
		durationTimer = timer.C
	}

	var onceTimer <-chan time.Time
	if cfg.Once {
		t := time.NewTimer(cfg.DrainInterval)
		defer t.Stop()
		onceTimer = t.C
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-durationTimer:
			return nil
		case <-onceTimer:
			counterCollector.DrainOnce()
			return nil
		case event, ok := <-source.Events():
			if !ok {
				return nil
			}
			if int(event.MountIdx) < len(mountInfos) {
				mi := mountInfos[event.MountIdx]
				event.MountPath = mi.Path
				event.FSName = mi.FSName
			} else {
				log.Printf("warning: event has unknown mount index %d", event.MountIdx)
			}
			event.Comm = procNameResolver.Resolve(event.PID, event.Comm)
			if debugEnabled {
				log.Printf("debug: event plane=%s op=%s uid=%d pid=%d mount=%s comm=%s dur_us=%d bytes=%d req=%d", event.Plane, event.Op, event.UID, event.PID, event.MountPath, event.Comm, event.DurationUS, event.SizeBytes, event.RequestPtr)
			}
			processEvent(event, exporter, inflightTracker, resolver, slurmResolver)
		}
	}
}

func processEvent(event Event, exporter *PrometheusExporter, inflight *InflightTracker, resolver *UsernameResolver, slurmResolver *slurm.Resolver) {
	if event.Plane == PlaneLLite {
		intent := AccessIntentForOp(event.Op)
		if intent == "" || event.DurationUS == 0 {
			return
		}
		uid, username, actorType, slurmJobID := resolveEventIdentity(event, resolver, slurmResolver)
		// Positional order must match lliteLabels in prometheus.go.
		exporter.AccessLatency.WithLabelValues(
			event.FSName, event.MountPath, intent, event.Op,
			uid, username, event.Comm, actorType, slurmJobID,
		).Observe(float64(event.DurationUS) / 1_000_000.0)
		return
	}

	if event.Plane == PlanePCC {
		if !exporter.PCCEnabled {
			return
		}
		processPCCEvent(event, exporter, resolver, slurmResolver)
		return
	}

	if event.Plane != PlanePtlRPC {
		return
	}

	if event.Op == OpQueueWait {
		if event.DurationUS > 0 {
			uid, username, actorType, slurmJobID := resolveEventIdentity(event, resolver, slurmResolver)
			// Positional order must match ptlrpcLabels in prometheus.go.
			exporter.RPCWaitLat.WithLabelValues(
				event.FSName, event.MountPath, event.Op,
				uid, username, event.Comm, actorType, slurmJobID,
			).Observe(float64(event.DurationUS) / 1_000_000.0)
		}
		return
	}

	var counter *prometheus.CounterVec
	var delta float64
	switch event.Op {
	case OpSendNewReq:
		counter, delta = exporter.RequestsStarted, 1
	case OpFreeReq:
		counter, delta = exporter.RequestsCompleted, -1
	default:
		return
	}
	uid, username, actorType, slurmJobID := resolveEventIdentity(event, resolver, slurmResolver)
	labels := baseLabelValues(event, uid, username, actorType, slurmJobID)
	counter.WithLabelValues(labels...).Inc()
	inflight.Update(delta, event, uid, username, actorType, slurmJobID)
}

func processPCCEvent(event Event, exporter *PrometheusExporter, resolver *UsernameResolver, slurmResolver *slurm.Resolver) {
	uid, username, actorType, slurmJobID := resolveEventIdentity(event, resolver, slurmResolver)

	switch event.Op {
	case OpRead, OpWrite, OpOpen, OpLookup, OpFsync:
		// Phase 1: PCC I/O histogram.
		intent := AccessIntentForOp(event.Op)
		if intent == "" || event.DurationUS == 0 {
			return
		}
		exporter.PCCLatency.WithLabelValues(
			event.FSName, event.MountPath, intent, event.Op,
			uid, username, event.Comm, actorType, slurmJobID,
		).Observe(float64(event.DurationUS) / 1_000_000.0)

	case OpPCCAttach:
		// Phase 2: attach counter.
		mode, trigger := DecodePCCAttachInfo(event.RequestPtr)
		exporter.PCCAttachTotal.WithLabelValues(
			event.FSName, event.MountPath, mode, trigger,
			uid, username, event.Comm, actorType, slurmJobID,
		).Inc()
		if event.ErrnoClass != "" {
			exporter.PCCAttachFailuresTotal.WithLabelValues(
				event.FSName, event.MountPath, mode, trigger,
				uid, username, event.Comm, actorType, slurmJobID,
			).Inc()
		}

	case OpPCCDetach:
		labels := baseLabelValues(event, uid, username, actorType, slurmJobID)
		exporter.PCCDetachTotal.WithLabelValues(labels...).Inc()

	case OpPCCInvalidate:
		labels := baseLabelValues(event, uid, username, actorType, slurmJobID)
		exporter.PCCInvalidationsTotal.WithLabelValues(labels...).Inc()
	}
}

func resolveEventIdentity(event Event, resolver *UsernameResolver, slurmResolver *slurm.Resolver) (uid, username, actorType, slurmJobID string) {
	uid = strconv.FormatUint(uint64(event.UID), 10)
	username = resolver.Resolve(event.UID)
	actorType = ClassifyActorType(event.Comm)
	slurmJobID = slurmResolver.Resolve(event.PID).JobID
	return
}

// newSlurmResolverFromConfig constructs a slurm.Resolver from the exporter
// Config. It wires the default /proc-backed readers on Linux builds and
// stubs them out on other platforms.
func newSlurmResolverFromConfig(cfg Config) *slurm.Resolver {
	return slurm.NewDefault(slurm.Options{
		Enabled:     cfg.SlurmJobIDEnabled,
		TTL:         cfg.SlurmJobIDTTL,
		NegativeTTL: cfg.SlurmJobIDNegativeTTL,
		VerifyTTL:   cfg.SlurmJobIDVerifyTTL,
		MaxEntries:  cfg.SlurmJobIDCacheSize,
	})
}
