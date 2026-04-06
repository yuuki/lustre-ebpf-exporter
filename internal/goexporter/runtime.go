package goexporter

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf"
)

type EventSource interface {
	Events() <-chan Event
	CounterMaps() (llite, rpc *ebpf.Map)
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

	exporter, err := NewPrometheusExporter(cfg.WebListenAddress, cfg.WebTelemetryPath)
	if err != nil {
		return err
	}
	defer exporter.Shutdown(context.Background())

	source, err := newEventSource(ctx, cfg, mountInfos)
	if err != nil {
		return err
	}
	defer source.Close()

	resolver := NewUsernameResolver()
	aggregator := NewAggregator(resolver)

	lliteMap, rpcMap := source.CounterMaps()
	counterReader := NewCounterReader(lliteMap, rpcMap, mountInfos, resolver)

	ticker := time.NewTicker(cfg.Window)
	defer ticker.Stop()
	debugEnabled := os.Getenv("LUSTRE_OBSERVER_DEBUG") == "1"

	flush := func(reason string) {
		counterMetrics := counterReader.Read()
		histMetrics := aggregator.Collect()
		metrics := append(counterMetrics, histMetrics...)
		if debugEnabled {
			log.Printf("debug: flushing %d metrics (%d counters, %d hist/inflight) on %s",
				len(metrics), len(counterMetrics), len(histMetrics), reason)
		}
		exporter.Export(metrics)
	}

	var durationTimer <-chan time.Time
	if cfg.Duration > 0 {
		timer := time.NewTimer(cfg.Duration)
		defer timer.Stop()
		durationTimer = timer.C
	}

	for {
		select {
		case <-ctx.Done():
			flush("context cancellation")
			return nil
		case <-durationTimer:
			flush("duration timeout")
			return nil
		case <-ticker.C:
			flush("ticker")
			if cfg.Once {
				return nil
			}
		case event, ok := <-source.Events():
			if !ok {
				flush("source close")
				return nil
			}
			if int(event.MountIdx) < len(mountInfos) {
				mi := mountInfos[event.MountIdx]
				event.MountPath = mi.Path
				event.FSName = mi.FSName
			} else {
				log.Printf("warning: event has unknown mount index %d", event.MountIdx)
			}
			if debugEnabled {
				log.Printf("debug: event plane=%s op=%s uid=%d pid=%d mount=%s comm=%s dur_us=%d bytes=%d req=%d", event.Plane, event.Op, event.UID, event.PID, event.MountPath, event.Comm, event.DurationUS, event.SizeBytes, event.RequestPtr)
			}
			aggregator.Consume(event)
		}
	}
}
