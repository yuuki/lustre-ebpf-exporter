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
	var slurmTTLSeconds int
	var slurmNegativeTTLSeconds int
	var slurmVerifyTTLSeconds int
	var processAllowlist string

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
	flag.BoolVar(
		&cfg.SlurmJobIDEnabled,
		"slurm-jobid",
		false,
		"Resolve Slurm job id per pid via /proc/<pid>/environ and cgroup (label always present; empty when disabled or unresolved)",
	)
	flag.IntVar(&slurmTTLSeconds, "slurm-jobid-ttl", 30, "Cache TTL in seconds for a resolved Slurm job id")
	flag.IntVar(&slurmNegativeTTLSeconds, "slurm-jobid-negative-ttl", 5, "Cache TTL in seconds for a negative (unresolved) Slurm job id lookup")
	flag.IntVar(&slurmVerifyTTLSeconds, "slurm-jobid-verify-ttl", 1, "Grace period in seconds before re-checking /proc/<pid>/stat for pid reuse")
	flag.IntVar(&cfg.SlurmJobIDCacheSize, "slurm-jobid-cache-size", 8192, "Maximum number of cached pid entries for Slurm job id resolution")
	flag.StringVar(&processAllowlist, "process-allowlist", "", "Comma-separated list of process names to track individually; all others become \"other\". Takes priority over --process-tail-trim-percent")
	flag.Float64Var(&cfg.ProcessTailTrimPercent, "process-tail-trim-percent", 0, "Dynamically trim the bottom N% of processes by operation count each drain interval (0 to disable)")
	flag.IntVar(&cfg.ProcessTailTrimHysteresis, "process-tail-trim-hysteresis", 1, "Consecutive drain cycles a process must be in the trim set before actually trimming")
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

	if slurmTTLSeconds <= 0 {
		log.Fatal("--slurm-jobid-ttl must be greater than zero")
	}
	if slurmNegativeTTLSeconds < 0 {
		log.Fatal("--slurm-jobid-negative-ttl must be greater than or equal to zero")
	}
	if slurmVerifyTTLSeconds < 0 {
		log.Fatal("--slurm-jobid-verify-ttl must be greater than or equal to zero")
	}
	if cfg.SlurmJobIDCacheSize <= 0 {
		log.Fatal("--slurm-jobid-cache-size must be greater than zero")
	}
	cfg.SlurmJobIDTTL = time.Duration(slurmTTLSeconds) * time.Second
	cfg.SlurmJobIDNegativeTTL = time.Duration(slurmNegativeTTLSeconds) * time.Second
	cfg.SlurmJobIDVerifyTTL = time.Duration(slurmVerifyTTLSeconds) * time.Second

	if processAllowlist != "" {
		for _, name := range strings.Split(processAllowlist, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				cfg.ProcessAllowlist = append(cfg.ProcessAllowlist, name)
			}
		}
	}
	if cfg.ProcessTailTrimPercent < 0 || cfg.ProcessTailTrimPercent > 100 {
		log.Fatal("--process-tail-trim-percent must be between 0 and 100")
	}
	if cfg.ProcessTailTrimHysteresis < 1 {
		log.Fatal("--process-tail-trim-hysteresis must be at least 1")
	}

	log.Printf("Starting lustre-ebpf-exporter")
	log.Printf("Mount paths: %s", strings.Join(cfg.MountPaths, ", "))
	log.Printf("BPF counter drain interval: %s", cfg.DrainInterval)
	if cfg.SlurmJobIDEnabled {
		log.Printf("Slurm job id resolution: enabled (ttl=%s negative_ttl=%s verify_ttl=%s cache_size=%d)",
			cfg.SlurmJobIDTTL, cfg.SlurmJobIDNegativeTTL, cfg.SlurmJobIDVerifyTTL, cfg.SlurmJobIDCacheSize)
	} else {
		log.Printf("Slurm job id resolution: disabled (label emitted as empty string)")
	}
	if len(cfg.ProcessAllowlist) > 0 {
		log.Printf("Process allowlist: %s (all others become \"other\")", strings.Join(cfg.ProcessAllowlist, ", "))
	} else if cfg.ProcessTailTrimPercent > 0 {
		log.Printf("Process tail-trim: bottom %.0f%% by ops (hysteresis=%d cycles)", cfg.ProcessTailTrimPercent, cfg.ProcessTailTrimHysteresis)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := goexporter.Run(ctx, cfg); err != nil {
		log.Fatal(err)
	}
}
