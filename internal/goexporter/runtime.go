package goexporter

import (
	"context"
	"log"
	"os"
	"os/signal"
	"time"
)

type EventSource interface {
	Events() <-chan Event
	Close() error
}

func NotifyContext(parent context.Context, signals ...os.Signal) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, signals...)
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

	var durationTimer <-chan time.Time
	if cfg.Duration > 0 {
		timer := time.NewTimer(cfg.Duration)
		defer timer.Stop()
		durationTimer = timer.C
	}

	for {
		select {
		case <-ctx.Done():
			metrics := aggregator.Collect()
			if debugEnabled {
				log.Printf("debug: flushing %d metrics on context cancellation", len(metrics))
			}
			exporter.Export(metrics)
			return nil
		case <-durationTimer:
			metrics := aggregator.Collect()
			if debugEnabled {
				log.Printf("debug: flushing %d metrics on duration timeout", len(metrics))
			}
			exporter.Export(metrics)
			return nil
		case <-ticker.C:
			metrics := aggregator.Collect()
			if debugEnabled {
				log.Printf("debug: flushing %d metrics on ticker", len(metrics))
			}
			exporter.Export(metrics)
			if cfg.Once {
				return nil
			}
		case event, ok := <-source.Events():
			if !ok {
				metrics := aggregator.Collect()
				if debugEnabled {
					log.Printf("debug: flushing %d metrics on source close", len(metrics))
				}
				exporter.Export(metrics)
				return nil
			}
			if debugEnabled {
				log.Printf("debug: event plane=%s op=%s uid=%d pid=%d comm=%s dur_us=%d bytes=%d req=%d", event.Plane, event.Op, event.UID, event.PID, event.Comm, event.DurationUS, event.SizeBytes, event.RequestPtr)
			}
			aggregator.Consume(event)
		}
	}
}
