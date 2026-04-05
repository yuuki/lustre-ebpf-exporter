package main

import (
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/yuuki/otel-lustre-tracer/internal/goexporter"
)

func main() {
	cfg := goexporter.Config{}

	flag.StringVar(&cfg.MountPath, "mount", "/mnt/lustre", "Lustre client mount path")
	flag.DurationVar(&cfg.Window, "window-seconds", 10*time.Second, "Aggregation window size")
	flag.DurationVar(&cfg.Duration, "duration", 0, "Stop after the given duration; 0 means run until interrupted")
	flag.BoolVar(&cfg.Once, "once", false, "Flush one aggregation window and exit")
	flag.StringVar(&cfg.BPFObjectPath, "bpf-object", defaultBPFObjectPath(), "Path to the CO-RE BPF object")
	flag.BoolVar(
		&cfg.LegacySymbolAllowMissing,
		"legacy-symbol-allow-missing",
		false,
		"Degrade gracefully when Lustre probe symbols are missing",
	)
	flag.StringVar(&cfg.WebListenAddress, "web.listen-address", ":9108", "Address to listen on for web interface and telemetry")
	flag.StringVar(&cfg.WebTelemetryPath, "web.telemetry-path", "/metrics", "Path under which to expose metrics")
	flag.Parse()

	if cfg.Window <= 0 {
		log.Fatal("--window-seconds must be greater than zero")
	}

	ctx, stop := goexporter.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := goexporter.Run(ctx, cfg); err != nil {
		log.Fatal(err)
	}
}

func defaultBPFObjectPath() string {
	exePath, err := os.Executable()
	if err != nil {
		return "lustre_client_observer.bpf.o"
	}
	return filepath.Join(filepath.Dir(exePath), "lustre_client_observer.bpf.o")
}
