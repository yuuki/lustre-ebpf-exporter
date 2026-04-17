package goexporter

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/cilium/ebpf"

	"github.com/yuuki/lustre-ebpf-exporter/internal/goexporter/slurm"
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
	processFilter := NewProcessFilter(cfg.ProcessAllowlist, cfg.ProcessNameStripSuffix)

	lliteMap, rpcMap := source.CounterMaps()
	lliteErrorMap, rpcErrorMap := source.ErrorCounterMaps()
	var pccMap, pccErrorMap *ebpf.Map
	if cfg.PCCEnabled {
		pccMap, pccErrorMap = source.PccCounterMaps()
	}
	counterCollector := NewBPFCounterCollector(lliteMap, rpcMap, lliteErrorMap, rpcErrorMap, pccMap, pccErrorMap, mountInfos, resolver, slurmResolver, processFilter, cfg.SlurmJobIDEnabled, cfg.UIDLabelsEnabled)
	counterCollector.StartDrain(ctx, cfg.DrainInterval)

	exporter, err := NewPrometheusExporter(cfg.WebListenAddress, cfg.WebTelemetryPath, counterCollector, cfg.PCCEnabled, cfg.SlurmJobIDEnabled, cfg.UIDLabelsEnabled)
	if err != nil {
		return err
	}
	defer exporter.Shutdown(context.Background())
	exporter.SetProcessFilter(processFilter)

	inflightTracker := NewInflightTracker(exporter.Inflight, cfg.SlurmJobIDEnabled, cfg.UIDLabelsEnabled)

	debugEnabled := os.Getenv("LUSTRE_OBSERVER_DEBUG") == "1"

	var durationTimer <-chan time.Time
	if cfg.Duration > 0 {
		timer := time.NewTimer(cfg.Duration)
		defer timer.Stop()
		durationTimer = timer.C
	}

	windowInterval := cfg.WorkloadWindowInterval
	if windowInterval <= 0 {
		windowInterval = 30 * time.Second
	}
	windowTicker := time.NewTicker(windowInterval)
	defer windowTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			counterCollector.DrainOnce()
			exporter.FlushWorkloadWindow()
			return nil
		case <-durationTimer:
			counterCollector.DrainOnce()
			exporter.FlushWorkloadWindow()
			return nil
		case <-windowTicker.C:
			counterCollector.DrainOnce()
			exporter.FlushWorkloadWindow()
			if cfg.Once {
				return nil
			}
		case event, ok := <-source.Events():
			if !ok {
				counterCollector.DrainOnce()
				exporter.FlushWorkloadWindow()
				return nil
			}
			if int(event.MountIdx) < len(mountInfos) {
				mi := mountInfos[event.MountIdx]
				event.MountPath = mi.Path
				event.FSName = mi.FSName
			} else {
				log.Printf("warning: event has unknown mount index %d", event.MountIdx)
			}
			bpfComm := event.Comm
			rawComm := procNameResolver.Resolve(event.PID, bpfComm)
			event.Comm = processFilter.Normalize(rawComm, bpfComm)
			if debugEnabled {
				log.Printf("debug: event plane=%s op=%s uid=%d pid=%d mount=%s comm=%s dur_us=%d bytes=%d req=%d", event.Plane, event.Op, event.UID, event.PID, event.MountPath, event.Comm, event.DurationUS, event.SizeBytes, event.RequestPtr)
			}
			processEvent(event, rawComm, exporter, inflightTracker, resolver, slurmResolver)
		}
	}
}

func processEvent(event Event, rawComm string, exporter *PrometheusExporter, inflight *InflightTracker, resolver *UsernameResolver, slurmResolver *slurm.Resolver) {
	if event.Plane == PlaneLLite {
		intent := AccessIntentForOp(event.Op)
		if intent == "" {
			return
		}
		uid, username, actorType, slurmJobID := resolveEventIdentity(event, rawComm, resolver, slurmResolver, exporter.UIDEnabled)
		if event.DurationUS > 0 {
			exporter.AccessLatency.WithLabelValues(
				lliteLabelValues(event.FSName, event.MountPath, intent, event.Op, uid, username, event.Comm, actorType, slurmJobID, exporter.SlurmEnabled, exporter.UIDEnabled)...,
			).Observe(float64(event.DurationUS) / 1_000_000.0)
		}
		exporter.WorkloadCollector.ObserveAccess(event, uid, username, actorType, slurmJobID)
		return
	}

	if event.Plane == PlanePCC {
		if !exporter.PCCEnabled {
			return
		}
		processPCCEvent(event, rawComm, exporter, resolver, slurmResolver)
		return
	}

	if event.Plane != PlanePtlRPC {
		return
	}

	if event.Op == OpQueueWait {
		uid, username, actorType, slurmJobID := resolveEventIdentity(event, rawComm, resolver, slurmResolver, exporter.UIDEnabled)
		if event.DurationUS > 0 {
			exporter.RPCWaitLat.WithLabelValues(
				ptlrpcLabelValues(event.FSName, event.MountPath, event.Op, uid, username, event.Comm, actorType, slurmJobID, exporter.SlurmEnabled, exporter.UIDEnabled)...,
			).Observe(float64(event.DurationUS) / 1_000_000.0)
		}
		exporter.WorkloadCollector.ObserveRPCWait(event, uid, username, actorType, slurmJobID)
		return
	}

	var delta float64
	switch event.Op {
	case OpSendNewReq:
		delta = 1
	case OpFreeReq:
		delta = -1
	default:
		return
	}
	uid, username, actorType, slurmJobID := resolveEventIdentity(event, rawComm, resolver, slurmResolver, exporter.UIDEnabled)
	labels := baseLabelValues(event, uid, username, actorType, slurmJobID, exporter.SlurmEnabled, exporter.UIDEnabled)
	switch event.Op {
	case OpSendNewReq:
		exporter.RequestsStarted.WithLabelValues(labels...).Inc()
	case OpFreeReq:
		exporter.RequestsCompleted.WithLabelValues(labels...).Inc()
	}
	inflight.Update(delta, event, uid, username, actorType, slurmJobID)
}

func processPCCEvent(event Event, rawComm string, exporter *PrometheusExporter, resolver *UsernameResolver, slurmResolver *slurm.Resolver) {
	uid, username, actorType, slurmJobID := resolveEventIdentity(event, rawComm, resolver, slurmResolver, exporter.UIDEnabled)

	switch event.Op {
	case OpRead, OpWrite, OpOpen, OpLookup, OpFsync:
		// Phase 1: PCC I/O histogram.
		intent := AccessIntentForOp(event.Op)
		if intent == "" || event.DurationUS == 0 {
			return
		}
		exporter.PCCLatency.WithLabelValues(
			lliteLabelValues(event.FSName, event.MountPath, intent, event.Op, uid, username, event.Comm, actorType, slurmJobID, exporter.SlurmEnabled, exporter.UIDEnabled)...,
		).Observe(float64(event.DurationUS) / 1_000_000.0)

	case OpPCCAttach:
		mode, trigger := DecodePCCAttachInfo(event.RequestPtr)
		attachVals := pccAttachLabelValues(event.FSName, event.MountPath, mode, trigger, uid, username, event.Comm, actorType, slurmJobID, exporter.SlurmEnabled, exporter.UIDEnabled)
		exporter.PCCAttachTotal.WithLabelValues(attachVals...).Inc()
		if event.ErrnoClass != "" {
			exporter.PCCAttachFailuresTotal.WithLabelValues(attachVals...).Inc()
		}

	case OpPCCDetach:
		labels := baseLabelValues(event, uid, username, actorType, slurmJobID, exporter.SlurmEnabled, exporter.UIDEnabled)
		exporter.PCCDetachTotal.WithLabelValues(labels...).Inc()

	case OpPCCInvalidate:
		labels := baseLabelValues(event, uid, username, actorType, slurmJobID, exporter.SlurmEnabled, exporter.UIDEnabled)
		exporter.PCCInvalidationsTotal.WithLabelValues(labels...).Inc()
	}
}

// resolveEventIdentity resolves identity labels for an event. rawComm is
// the original process name before normalization; it is used for actor-type
// classification so that processes collapsed to "other" by the process
// filter retain their correct actor type. When uidEnabled is false the
// kernel already zeroes event.UID and we skip the UsernameResolver lookup
// so the hot path avoids touching the getpwuid cache entirely.
func resolveEventIdentity(event Event, rawComm string, resolver *UsernameResolver, slurmResolver *slurm.Resolver, uidEnabled bool) (uid, username, actorType, slurmJobID string) {
	if uidEnabled {
		uid = strconv.FormatUint(uint64(event.UID), 10)
		username = resolver.Resolve(event.UID)
	}
	actorType = ClassifyActorType(rawComm)
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
