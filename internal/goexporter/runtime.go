package goexporter

import (
	"context"
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

	var durationTimer <-chan time.Time
	if cfg.Duration > 0 {
		timer := time.NewTimer(cfg.Duration)
		defer timer.Stop()
		durationTimer = timer.C
	}

	for {
		select {
		case <-ctx.Done():
			exporter.Export(aggregator.Collect())
			return nil
		case <-durationTimer:
			exporter.Export(aggregator.Collect())
			return nil
		case <-ticker.C:
			exporter.Export(aggregator.Collect())
			if cfg.Once {
				return nil
			}
		case event, ok := <-source.Events():
			if !ok {
				exporter.Export(aggregator.Collect())
				return nil
			}
			aggregator.Consume(event)
		}
	}
}
