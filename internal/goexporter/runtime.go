package goexporter

import (
	"context"
	"log"
	"os"
	"time"
)

type EventSource interface {
	Events() <-chan Event
	Close() error
}

func Run(ctx context.Context, cfg Config) error {
	mountInfo, err := ResolveMountInfo(cfg.MountPath)
	if err != nil {
		return err
	}

	exporter, err := NewPrometheusExporter(mountInfo, cfg.WebListenAddress, cfg.WebTelemetryPath)
	if err != nil {
		return err
	}
	defer exporter.Shutdown(context.Background())

	source, err := newEventSource(ctx, cfg, mountInfo)
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
			if debugEnabled {
				log.Printf("debug: event plane=%s op=%s uid=%d pid=%d comm=%s dur_us=%d bytes=%d req=%d", event.Plane, event.Op, event.UID, event.PID, event.Comm, event.DurationUS, event.SizeBytes, event.RequestPtr)
			}
			aggregator.Consume(event)
		}
	}
}
