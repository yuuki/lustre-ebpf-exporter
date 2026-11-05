package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yuuki/lustre-ebpf-exporter/internal/goexporter"
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
	flag.BoolVar(&cfg.UIDLabelsEnabled, "uid-labels", true, "Emit uid/username labels and key BPF counter maps per-UID; set to false to drop both labels and skip kernel-side bpf_get_current_uid_gid collection so PERCPU_HASH rows fold across users")
	flag.BoolVar(&cfg.HistogramProcessLabelsEnabled, "histogram-process-labels", false, "Emit process label on histogram metric families; default false drops it from histogram bucket/sum/count series to reduce cardinality while keeping process-labeled counters/gauges such as operation totals")
	flag.StringVar(&processAllowlist, "process-allowlist", "", "Comma-separated list of process names to track individually; all others become \"other\"")
	flag.BoolVar(&cfg.ProcessNameStripSuffix, "process-name-strip-suffix", false, "Normalize process-name instance variants (e.g. \"Bun Pool 1\" → \"Bun Pool\") to reduce label cardinality")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("lustre-ebpf-exporter %s (commit: %s)\n", version, commit)
		os.Exit(0)
	}

	mountPaths, err := resolveMountPaths(mounts, goexporter.DetectLustreMounts)
	if err != nil {
		log.Fatal(err)
	}
	cfg.MountPaths = mountPaths

	if err := applyIntervalFlags(&cfg, drainIntervalSeconds, durationSeconds); err != nil {
		log.Fatal(err)
	}
	if err := applySlurmJobIDFlags(&cfg, slurmTTLSeconds, slurmNegativeTTLSeconds, slurmVerifyTTLSeconds); err != nil {
		log.Fatal(err)
	}
	cfg.ProcessAllowlist = parseProcessAllowlist(processAllowlist)
	logStartupConfig(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := goexporter.Run(ctx, cfg); err != nil {
		log.Fatal(err)
	}
}

// errNoLustreMounts is printed verbatim when no -mount is given and no Lustre
// filesystem is mounted.
var errNoLustreMounts = errors.New("No Lustre mounts detected. Specify mount paths with -mount or ensure Lustre filesystems are mounted.")

// resolveMountPaths returns the -mount paths or, when there are none, the
// Lustre mounts found by detect. It falls back to /mnt/lustre when detection
// fails.
func resolveMountPaths(mounts []string, detect func() ([]string, error)) ([]string, error) {
	if len(mounts) > 0 {
		return mounts, nil
	}
	detected, err := detect()
	if err != nil {
		log.Printf("Warning: failed to auto-detect Lustre mounts: %v; falling back to /mnt/lustre", err)
		return []string{"/mnt/lustre"}, nil
	}
	if len(detected) == 0 {
		return nil, errNoLustreMounts
	}
	log.Printf("Auto-detected %d Lustre mount(s)", len(detected))
	return detected, nil
}

// applyIntervalFlags validates --drain-interval and --duration and stores them
// in cfg.
func applyIntervalFlags(cfg *goexporter.Config, drainIntervalSeconds, durationSeconds int) error {
	if drainIntervalSeconds <= 0 {
		return errors.New("--drain-interval must be greater than zero")
	}
	if durationSeconds < 0 {
		return errors.New("--duration must be greater than or equal to zero")
	}
	cfg.DrainInterval = time.Duration(drainIntervalSeconds) * time.Second
	cfg.Duration = time.Duration(durationSeconds) * time.Second
	return nil
}

// applySlurmJobIDFlags validates the Slurm job id cache flags, including the
// cache size already parsed into cfg, and stores the TTLs in cfg.
func applySlurmJobIDFlags(cfg *goexporter.Config, ttlSeconds, negativeTTLSeconds, verifyTTLSeconds int) error {
	if ttlSeconds <= 0 {
		return errors.New("--slurm-jobid-ttl must be greater than zero")
	}
	if negativeTTLSeconds < 0 {
		return errors.New("--slurm-jobid-negative-ttl must be greater than or equal to zero")
	}
	if verifyTTLSeconds < 0 {
		return errors.New("--slurm-jobid-verify-ttl must be greater than or equal to zero")
	}
	if cfg.SlurmJobIDCacheSize <= 0 {
		return errors.New("--slurm-jobid-cache-size must be greater than zero")
	}
	cfg.SlurmJobIDTTL = time.Duration(ttlSeconds) * time.Second
	cfg.SlurmJobIDNegativeTTL = time.Duration(negativeTTLSeconds) * time.Second
	cfg.SlurmJobIDVerifyTTL = time.Duration(verifyTTLSeconds) * time.Second
	return nil
}

// parseProcessAllowlist splits the comma-separated --process-allowlist value,
// trimming spaces and dropping empty names. It returns nil when no name is left.
func parseProcessAllowlist(value string) []string {
	if value == "" {
		return nil
	}
	var names []string
	for _, name := range strings.Split(value, ",") {
		name = strings.TrimSpace(name)
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

// logStartupConfig logs the effective configuration before the exporter starts.
func logStartupConfig(cfg goexporter.Config) {
	log.Printf("Starting lustre-ebpf-exporter")
	log.Printf("Mount paths: %s", strings.Join(cfg.MountPaths, ", "))
	log.Printf("BPF counter drain interval: %s", cfg.DrainInterval)
	if cfg.SlurmJobIDEnabled {
		log.Printf("Slurm job id resolution: enabled (ttl=%s negative_ttl=%s verify_ttl=%s cache_size=%d)",
			cfg.SlurmJobIDTTL, cfg.SlurmJobIDNegativeTTL, cfg.SlurmJobIDVerifyTTL, cfg.SlurmJobIDCacheSize)
	} else {
		log.Printf("Slurm job id resolution: disabled (label emitted as empty string)")
	}
	if cfg.UIDLabelsEnabled {
		log.Printf("UID labels: enabled")
	} else {
		log.Printf("UID labels: disabled (kernel-side uid collection bypassed)")
	}
	if cfg.HistogramProcessLabelsEnabled {
		log.Printf("Histogram process labels: enabled")
	} else {
		log.Printf("Histogram process labels: disabled")
	}
	if cfg.ProcessNameStripSuffix {
		log.Printf("Process name instance variant normalization: enabled")
	}
	if len(cfg.ProcessAllowlist) > 0 {
		log.Printf("Process allowlist: %s (all others become \"other\")", strings.Join(cfg.ProcessAllowlist, ", "))
	}
}
