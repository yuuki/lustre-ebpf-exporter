package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yuuki/otel-lustre-tracer/internal/goexporter"
)

var (
	version = "dev"
	commit  = "unknown"
)

type mountPathsFlag []string

func (m *mountPathsFlag) String() string { return strings.Join(*m, ",") }
func (m *mountPathsFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func main() {
	cfg := goexporter.Config{}
	var drainIntervalSeconds int
	var durationSeconds int
	var mounts mountPathsFlag

	flag.Var(&mounts, "mount", "Lustre client mount path (can be specified multiple times)")
	flag.IntVar(&drainIntervalSeconds, "drain-interval", 5, "BPF counter map drain interval in seconds")
	flag.IntVar(&durationSeconds, "duration", 0, "Stop after the given duration in seconds; 0 means run until interrupted")
	flag.BoolVar(&cfg.Once, "once", false, "Drain counters once and exit")
	flag.BoolVar(
		&cfg.LegacySymbolAllowMissing,
		"legacy-symbol-allow-missing",
		false,
		"Degrade gracefully when Lustre probe symbols are missing",
	)
	flag.StringVar(&cfg.WebListenAddress, "web.listen-address", ":9108", "Address to listen on for web interface and telemetry")
	flag.StringVar(&cfg.WebTelemetryPath, "web.telemetry-path", "/metrics", "Path under which to expose metrics")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("lustre-ebpf-exporter %s (commit: %s)\n", version, commit)
		os.Exit(0)
	}

	if len(mounts) == 0 {
		detected, err := goexporter.DetectLustreMounts()
		if err != nil {
			log.Printf("Warning: failed to auto-detect Lustre mounts: %v; falling back to /mnt/lustre", err)
			mounts = mountPathsFlag{"/mnt/lustre"}
		} else if len(detected) == 0 {
			log.Fatal("No Lustre mounts detected. Specify mount paths with -mount or ensure Lustre filesystems are mounted.")
		} else {
			mounts = detected
			log.Printf("Auto-detected %d Lustre mount(s)", len(mounts))
		}
	}
	cfg.MountPaths = mounts

	if drainIntervalSeconds <= 0 {
		log.Fatal("--drain-interval must be greater than zero")
	}
	if durationSeconds < 0 {
		log.Fatal("--duration must be greater than or equal to zero")
	}
	cfg.DrainInterval = time.Duration(drainIntervalSeconds) * time.Second
	cfg.Duration = time.Duration(durationSeconds) * time.Second

	log.Printf("Starting lustre-ebpf-exporter")
	log.Printf("Mount paths: %s", strings.Join(cfg.MountPaths, ", "))
	log.Printf("BPF counter drain interval: %s", cfg.DrainInterval)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := goexporter.Run(ctx, cfg); err != nil {
		log.Fatal(err)
	}
}
