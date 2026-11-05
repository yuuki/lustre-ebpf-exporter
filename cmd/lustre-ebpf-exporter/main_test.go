package main

import (
	"bytes"
	"errors"
	"log"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yuuki/lustre-ebpf-exporter/internal/goexporter"
)

// captureLog redirects the standard logger, without timestamps, for the rest
// of the test. Tests using it must not run in parallel.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	flags, out := log.Flags(), log.Writer()
	log.SetFlags(0)
	log.SetOutput(&buf)
	t.Cleanup(func() {
		log.SetFlags(flags)
		log.SetOutput(out)
	})
	return &buf
}

func TestResolveMountPaths(t *testing.T) {
	detectErr := errors.New("open /proc/mounts: permission denied")
	tests := []struct {
		name     string
		mounts   []string
		detected []string
		err      error
		want     []string
		wantErr  error
		wantLog  string
	}{
		{
			name:     "explicit mounts skip detection",
			mounts:   []string{"/a", "/b"},
			detected: []string{"/detected"},
			want:     []string{"/a", "/b"},
		},
		{
			name:     "auto-detected",
			detected: []string{"/mnt/lfs", "/mnt/lfs2"},
			want:     []string{"/mnt/lfs", "/mnt/lfs2"},
			wantLog:  "Auto-detected 2 Lustre mount(s)\n",
		},
		{
			name:    "detection failure falls back to /mnt/lustre",
			err:     detectErr,
			want:    []string{"/mnt/lustre"},
			wantLog: "Warning: failed to auto-detect Lustre mounts: open /proc/mounts: permission denied; falling back to /mnt/lustre\n",
		},
		{
			name:    "no Lustre mount",
			wantErr: errNoLustreMounts,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLog(t)
			detect := func() ([]string, error) {
				if len(tt.mounts) > 0 {
					t.Fatal("detection must not run when -mount is given")
				}
				return tt.detected, tt.err
			}
			got, err := resolveMountPaths(tt.mounts, detect)
			if err != tt.wantErr {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("mounts = %v, want %v", got, tt.want)
			}
			if logs.String() != tt.wantLog {
				t.Fatalf("log = %q, want %q", logs.String(), tt.wantLog)
			}
		})
	}
	if got := errNoLustreMounts.Error(); got != "No Lustre mounts detected. Specify mount paths with -mount or ensure Lustre filesystems are mounted." {
		t.Fatalf("errNoLustreMounts = %q", got)
	}
}

func TestApplyIntervalFlags(t *testing.T) {
	tests := []struct {
		drain, duration int
		wantErr         string
	}{
		{0, 0, "--drain-interval must be greater than zero"},
		{-1, -1, "--drain-interval must be greater than zero"},
		{1, -1, "--duration must be greater than or equal to zero"},
		{5, 0, ""},
		{2, 30, ""},
	}
	for _, tt := range tests {
		var cfg goexporter.Config
		err := applyIntervalFlags(&cfg, tt.drain, tt.duration)
		if tt.wantErr != "" {
			if err == nil || err.Error() != tt.wantErr {
				t.Errorf("applyIntervalFlags(%d, %d) err = %v, want %q", tt.drain, tt.duration, err, tt.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("applyIntervalFlags(%d, %d) err = %v", tt.drain, tt.duration, err)
			continue
		}
		if cfg.DrainInterval != time.Duration(tt.drain)*time.Second || cfg.Duration != time.Duration(tt.duration)*time.Second {
			t.Errorf("applyIntervalFlags(%d, %d) set drain=%s duration=%s", tt.drain, tt.duration, cfg.DrainInterval, cfg.Duration)
		}
	}
}

func TestApplySlurmJobIDFlags(t *testing.T) {
	tests := []struct {
		ttl, negative, verify, cacheSize int
		wantErr                          string
	}{
		{0, 5, 1, 8192, "--slurm-jobid-ttl must be greater than zero"},
		{0, -1, -1, 0, "--slurm-jobid-ttl must be greater than zero"},
		{30, -1, -1, 0, "--slurm-jobid-negative-ttl must be greater than or equal to zero"},
		{30, 5, -1, 0, "--slurm-jobid-verify-ttl must be greater than or equal to zero"},
		{30, 5, 1, 0, "--slurm-jobid-cache-size must be greater than zero"},
		{30, 5, 1, 8192, ""},
		{7, 0, 0, 3, ""},
	}
	for _, tt := range tests {
		cfg := goexporter.Config{SlurmJobIDCacheSize: tt.cacheSize}
		err := applySlurmJobIDFlags(&cfg, tt.ttl, tt.negative, tt.verify)
		if tt.wantErr != "" {
			if err == nil || err.Error() != tt.wantErr {
				t.Errorf("%+v: err = %v, want %q", tt, err, tt.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%+v: err = %v", tt, err)
			continue
		}
		if cfg.SlurmJobIDTTL != time.Duration(tt.ttl)*time.Second ||
			cfg.SlurmJobIDNegativeTTL != time.Duration(tt.negative)*time.Second ||
			cfg.SlurmJobIDVerifyTTL != time.Duration(tt.verify)*time.Second {
			t.Errorf("%+v: set ttl=%s negative=%s verify=%s", tt, cfg.SlurmJobIDTTL, cfg.SlurmJobIDNegativeTTL, cfg.SlurmJobIDVerifyTTL)
		}
	}
}

func TestParseProcessAllowlist(t *testing.T) {
	tests := []struct {
		value string
		want  []string
	}{
		{"", nil},
		{" , ,", nil},
		{"python", []string{"python"}},
		{"python, dd ,,  ,rsync", []string{"python", "dd", "rsync"}},
	}
	for _, tt := range tests {
		if got := parseProcessAllowlist(tt.value); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("parseProcessAllowlist(%q) = %#v, want %#v", tt.value, got, tt.want)
		}
	}
}

func TestLogStartupConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  goexporter.Config
		want []string
	}{
		{
			name: "defaults",
			cfg: goexporter.Config{
				MountPaths:       []string{"/mnt/lustre"},
				DrainInterval:    5 * time.Second,
				UIDLabelsEnabled: true,
			},
			want: []string{
				"Starting lustre-ebpf-exporter",
				"Mount paths: /mnt/lustre",
				"BPF counter drain interval: 5s",
				"Slurm job id resolution: disabled (label emitted as empty string)",
				"UID labels: enabled",
				"Histogram process labels: disabled",
			},
		},
		{
			name: "everything enabled",
			cfg: goexporter.Config{
				MountPaths:                    []string{"/a", "/b"},
				DrainInterval:                 2 * time.Second,
				SlurmJobIDEnabled:             true,
				SlurmJobIDTTL:                 30 * time.Second,
				SlurmJobIDNegativeTTL:         5 * time.Second,
				SlurmJobIDVerifyTTL:           time.Second,
				SlurmJobIDCacheSize:           8192,
				HistogramProcessLabelsEnabled: true,
				ProcessNameStripSuffix:        true,
				ProcessAllowlist:              []string{"python", "dd"},
			},
			want: []string{
				"Starting lustre-ebpf-exporter",
				"Mount paths: /a, /b",
				"BPF counter drain interval: 2s",
				"Slurm job id resolution: enabled (ttl=30s negative_ttl=5s verify_ttl=1s cache_size=8192)",
				"UID labels: disabled (kernel-side uid collection bypassed)",
				"Histogram process labels: enabled",
				"Process name instance variant normalization: enabled",
				`Process allowlist: python, dd (all others become "other")`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLog(t)
			logStartupConfig(tt.cfg)
			if got, want := logs.String(), strings.Join(tt.want, "\n")+"\n"; got != want {
				t.Fatalf("log mismatch\n got:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}
