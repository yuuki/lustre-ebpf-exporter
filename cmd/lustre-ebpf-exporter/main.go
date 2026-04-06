package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/yuuki/otel-lustre-tracer/internal/goexporter"
)

func main() {
	cfg := goexporter.Config{}
	var windowSeconds int
	var durationSeconds int

	flag.StringVar(&cfg.MountPath, "mount", "/mnt/lustre", "Lustre client mount path")
	flag.IntVar(&windowSeconds, "window-seconds", 10, "Aggregation window size in seconds")
	flag.IntVar(&durationSeconds, "duration", 0, "Stop after the given duration in seconds; 0 means run until interrupted")
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

	if windowSeconds <= 0 {
		log.Fatal("--window-seconds must be greater than zero")
	}
	if durationSeconds < 0 {
		log.Fatal("--duration must be greater than or equal to zero")
	}
	cfg.Window = time.Duration(windowSeconds) * time.Second
	cfg.Duration = time.Duration(durationSeconds) * time.Second

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := goexporter.Run(ctx, cfg); err != nil {
		log.Fatal(err)
	}
}

func defaultBPFObjectPath() string {
	exePath, err := os.Executable()
	if err != nil {
		return "lustre_ebpf_exporter.bpf.o"
	}
	return filepath.Join(filepath.Dir(exePath), "lustre_ebpf_exporter.bpf.o")
}
