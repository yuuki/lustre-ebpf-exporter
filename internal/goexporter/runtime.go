package goexporter

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"
)

type EventSource interface {
	Events() <-chan Event
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

	aggregator := NewAggregator()
	ticker := time.NewTicker(cfg.Window)
	defer ticker.Stop()
	debugEnabled := os.Getenv("LUSTRE_OBSERVER_DEBUG") == "1"

	flush := func(reason string) {
		metrics := aggregator.Collect()
		if debugEnabled {
			log.Printf("debug: flushing %d metrics on %s", len(metrics), reason)
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
