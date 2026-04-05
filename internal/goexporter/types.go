package goexporter

import (
	"strings"
	"time"
)

const (
	PlaneLLite  = "llite"
	PlanePtlRPC = "ptlrpc"
)

const (
	OpLookup     = "lookup"
	OpOpen       = "open"
	OpRead       = "read"
	OpWrite      = "write"
	OpFsync      = "fsync"
	OpQueueWait  = "queue_wait"
	OpSendNewReq = "send_new_req"
	OpFreeReq    = "free_req"
	OpRename     = "rename"
	OpUnlink     = "unlink"
	OpMkdir      = "mkdir"
	OpRmdir      = "rmdir"
)

var (
	LLiteMetadataOps = map[string]struct{}{
		OpLookup: {}, OpOpen: {}, OpRename: {}, OpUnlink: {}, OpMkdir: {}, OpRmdir: {},
	}
	LLiteDataOps = map[string]struct{}{
		OpRead: {}, OpWrite: {}, OpFsync: {},
	}
	DaemonNames = map[string]struct{}{
		"node_exporter":   {},
		"sshd":            {},
		"systemd":         {},
		"systemd-journal": {},
		"dbus-daemon":     {},
		"cron":            {},
		"crond":           {},
	}
	PrometheusLatencyBucketsSeconds = []float64{
		5e-6, 1e-5, 2.5e-5, 5e-5, 1e-4, 2.5e-4, 5e-4, 1e-3, 2.5e-3, 5e-3,
		1e-2, 2.5e-2, 5e-2, 1e-1, 2.5e-1, 5e-1, 1.0,
	}
)

type Config struct {
	MountPath                string
	Window                   time.Duration
	Duration                 time.Duration
	Once                     bool
	BPFObjectPath            string
	LegacySymbolAllowMissing bool
	WebListenAddress         string
	WebTelemetryPath         string
}

type Event struct {
	Plane      string
	Op         string
	UID        uint32
	PID        uint32
	Comm       string
	DurationUS uint64
	SizeBytes  uint64
	RequestPtr uint64
}

type AggregatedMetric struct {
	Name       string
	Type       string
	Unit       string
	Value      float64
	Histogram  []float64
	Attributes map[string]string
}

type MountInfo struct {
	Source string
	Path   string
	FSName string
	Major  uint32
	Minor  uint32
}

func sanitizeComm(raw []byte) string {
	return strings.Trim(string(raw), "\x00")
}
