package goexporter

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

const (
	PlaneLLite  = "llite"
	PlanePtlRPC = "ptlrpc"
)

const (
	rawPlaneLLite   uint8 = 1
	rawPlanePtlRPC  uint8 = 2
	rawOpLookup     uint8 = 1
	rawOpOpen       uint8 = 2
	rawOpRead       uint8 = 3
	rawOpWrite      uint8 = 4
	rawOpFsync      uint8 = 5
	rawOpQueueWait  uint8 = 6
	rawOpSendNewReq uint8 = 7
	rawOpFreeReq    uint8 = 8
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
	IntentForOp = map[string]string{
		OpLookup: "namespace_read", OpOpen: "namespace_read",
		OpRename: "namespace_mutation", OpUnlink: "namespace_mutation",
		OpMkdir: "namespace_mutation", OpRmdir: "namespace_mutation",
		OpRead: "data_read", OpWrite: "data_write",
		OpFsync: "sync",
	}
	BatchJobPrefixes = []string{"slurm", "pbs_", "sge_", "lsf_"}
	DaemonNames = map[string]struct{}{
		"node_exporter":   {},
		"sshd":            {},
		"systemd":         {},
		"systemd-journal": {},
		"dbus-daemon":     {},
		"cron":            {},
		"crond":           {},
	}
	MaxMountPoints                  = 16
	PrometheusLatencyBucketsSeconds = []float64{
		5e-6, 1e-5, 2.5e-5, 5e-5, 1e-4, 2.5e-4, 5e-4, 1e-3, 2.5e-3, 5e-3,
		1e-2, 2.5e-2, 5e-2, 1e-1, 2.5e-1, 5e-1, 1.0,
	}
)

type Config struct {
	MountPaths               []string
	Window                   time.Duration
	Duration                 time.Duration
	Once                     bool
	LegacySymbolAllowMissing bool
	WebListenAddress         string
	WebTelemetryPath         string
}

type Event struct {
	Plane      string
	Op         string
	UID        uint32
	PID        uint32
	MountIdx   uint32
	Comm       string
	DurationUS uint64
	SizeBytes  uint64
	RequestPtr uint64
	MountPath  string
	FSName     string
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
	raw = bytes.TrimLeft(raw, "\x00")
	end := bytes.IndexByte(raw, 0)
	if end >= 0 {
		raw = raw[:end]
	}
	return string(raw)
}

func parseObserverEvent(sample []byte) (Event, error) {
	if len(sample) < 64 {
		return Event{}, fmt.Errorf("short raw event: got %d bytes", len(sample))
	}
	plane, err := planeName(sample[0])
	if err != nil {
		return Event{}, err
	}
	op, err := opName(sample[1])
	if err != nil {
		return Event{}, err
	}
	return Event{
		Plane:      plane,
		Op:         op,
		UID:        binary.LittleEndian.Uint32(sample[8:12]),
		PID:        binary.LittleEndian.Uint32(sample[12:16]),
		MountIdx:   binary.LittleEndian.Uint32(sample[16:20]),
		DurationUS: binary.LittleEndian.Uint64(sample[24:32]),
		SizeBytes:  binary.LittleEndian.Uint64(sample[32:40]),
		RequestPtr: binary.LittleEndian.Uint64(sample[40:48]),
		Comm:       sanitizeComm(sample[48:64]),
	}, nil
}

func planeName(raw uint8) (string, error) {
	switch raw {
	case rawPlaneLLite:
		return PlaneLLite, nil
	case rawPlanePtlRPC:
		return PlanePtlRPC, nil
	default:
		return "", fmt.Errorf("unknown plane code: %d", raw)
	}
}

func opName(raw uint8) (string, error) {
	switch raw {
	case rawOpLookup:
		return OpLookup, nil
	case rawOpOpen:
		return OpOpen, nil
	case rawOpRead:
		return OpRead, nil
	case rawOpWrite:
		return OpWrite, nil
	case rawOpFsync:
		return OpFsync, nil
	case rawOpQueueWait:
		return OpQueueWait, nil
	case rawOpSendNewReq:
		return OpSendNewReq, nil
	case rawOpFreeReq:
		return OpFreeReq, nil
	default:
		return "", fmt.Errorf("unknown op code: %d", raw)
	}
}
