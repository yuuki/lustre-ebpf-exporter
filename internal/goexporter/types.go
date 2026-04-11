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
	PlanePCC    = "pcc"
)

const (
	rawPlaneLLite   uint8 = 1
	rawPlanePtlRPC  uint8 = 2
	rawPlanePCC     uint8 = 3
	rawOpLookup     uint8 = 1
	rawOpOpen       uint8 = 2
	rawOpRead       uint8 = 3
	rawOpWrite      uint8 = 4
	rawOpFsync      uint8 = 5
	rawOpQueueWait  uint8 = 6
	rawOpSendNewReq uint8 = 7
	rawOpFreeReq    uint8 = 8
	rawOpClose      uint8 = 9
	rawOpGetattr    uint8 = 10
	rawOpGetxattr   uint8 = 11
	rawOpMkdir      uint8 = 12
	rawOpMknod      uint8 = 13
	rawOpRename     uint8 = 14
	rawOpRmdir      uint8 = 15
	rawOpSetattr    uint8 = 16
	rawOpSetxattr   uint8 = 17
	rawOpStatfs     uint8 = 18

	// PCC-specific op codes (19-26). I/O ops map to the same Go-side op
	// strings as their llite counterparts; the plane label discriminates.
	rawOpPCCAttach     uint8 = 19
	rawOpPCCDetach     uint8 = 20
	rawOpPCCInvalidate uint8 = 21
	rawOpPCCRead       uint8 = 22
	rawOpPCCWrite      uint8 = 23
	rawOpPCCOpen       uint8 = 24
	rawOpPCCLookup     uint8 = 25
	rawOpPCCFsync      uint8 = 26
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
	OpClose      = "close"
	OpGetattr    = "getattr"
	OpGetxattr   = "getxattr"
	OpMknod      = "mknod"
	OpSetattr    = "setattr"
	OpSetxattr   = "setxattr"
	OpStatfs     = "statfs"

	// PCC lifecycle ops (no llite equivalent).
	OpPCCAttach     = "pcc_attach"
	OpPCCDetach     = "pcc_detach"
	OpPCCInvalidate = "pcc_invalidate"

	// PCC attach mode / trigger labels.
	PCCModeRO        = "ro"
	PCCModeRW        = "rw"
	PCCTriggerManual = "manual"
	PCCTriggerAuto   = "auto"

	// Raw PCC mode/trigger values packed by BPF into request_ptr.
	// Must match PCC_MODE_* / PCC_TRIGGER_* in lustre_ebpf_exporter.bpf.c.
	rawPCCModeRO        uint8 = 1
	rawPCCModeRW        uint8 = 2
	rawPCCTriggerManual uint8 = 1
	rawPCCTriggerAuto   uint8 = 2
)

const (
	ActorUser         = "user"
	ActorClientWorker = "client_worker"
	ActorBatchJob     = "batch_job"
	ActorSystemDaemon = "system_daemon"

	IntentNamespaceRead     = "namespace_read"
	IntentNamespaceMutation = "namespace_mutation"
	IntentDataRead          = "data_read"
	IntentDataWrite         = "data_write"
	IntentSync              = "sync"
)

const (
	ErrnoClassTimeout  = "timeout"
	ErrnoClassNotconn  = "notconn"
	ErrnoClassPerm     = "perm"
	ErrnoClassNotfound = "notfound"
	ErrnoClassIO       = "io"
	ErrnoClassAgain    = "again"
	ErrnoClassOther    = "other"
)

const (
	rawErrnoClassNone     uint8 = 0
	rawErrnoClassTimeout  uint8 = 1
	rawErrnoClassNotconn  uint8 = 2
	rawErrnoClassPerm     uint8 = 3
	rawErrnoClassNotfound uint8 = 4
	rawErrnoClassIO       uint8 = 5
	rawErrnoClassAgain    uint8 = 6
	rawErrnoClassOther    uint8 = 7
)

func errnoClassName(raw uint8) string {
	switch raw {
	case rawErrnoClassNone:
		return ""
	case rawErrnoClassTimeout:
		return ErrnoClassTimeout
	case rawErrnoClassNotconn:
		return ErrnoClassNotconn
	case rawErrnoClassPerm:
		return ErrnoClassPerm
	case rawErrnoClassNotfound:
		return ErrnoClassNotfound
	case rawErrnoClassIO:
		return ErrnoClassIO
	case rawErrnoClassAgain:
		return ErrnoClassAgain
	case rawErrnoClassOther:
		return ErrnoClassOther
	default:
		return ErrnoClassOther
	}
}

const (
	RPCEventResend  = "resend"
	RPCEventRestart = "restart"
	RPCEventExpire  = "expire"
	RPCEventNotconn = "notconn"

	unknownRPCEvent = "unknown"
)

const (
	rawRPCEventResend  uint8 = 1
	rawRPCEventRestart uint8 = 2
	rawRPCEventExpire  uint8 = 3
	rawRPCEventNotconn uint8 = 4
)

func rpcEventTypeName(raw uint8) string {
	switch raw {
	case rawRPCEventResend:
		return RPCEventResend
	case rawRPCEventRestart:
		return RPCEventRestart
	case rawRPCEventExpire:
		return RPCEventExpire
	case rawRPCEventNotconn:
		return RPCEventNotconn
	default:
		return ""
	}
}

// bpfAggKey mirrors the BPF agg_key struct. Byte layout must match the C definition.
type bpfAggKey struct {
	UID       uint32
	Op        uint8
	MountIdx  uint8
	ActorType uint8
	Intent    uint8
	Comm      [16]byte
}

// bpfCounterVal mirrors the BPF counter_val struct.
type bpfCounterVal struct {
	OpsCount uint64
	BytesSum uint64
}

// bpfErrorAggKey mirrors the BPF error_agg_key struct. Byte layout must match the C definition.
type bpfErrorAggKey struct {
	UID       uint32
	Op        uint8
	MountIdx  uint8
	ActorType uint8
	Intent    uint8
	Reason    uint8
	Pad       [7]byte
	Comm      [16]byte
}

// bpfErrorCounterVal mirrors the BPF error_counter_val struct.
type bpfErrorCounterVal struct {
	OpsCount uint64
}

const (
	rawActorUser         uint8 = 0
	rawActorClientWorker uint8 = 1
	rawActorBatchJob     uint8 = 2
	rawActorSystemDaemon uint8 = 3

	rawIntentNamespaceRead     uint8 = 0
	rawIntentNamespaceMutation uint8 = 1
	rawIntentDataRead          uint8 = 2
	rawIntentDataWrite         uint8 = 3
	rawIntentSync              uint8 = 4
	rawIntentUnknown           uint8 = 0xFF
)

func actorTypeName(raw uint8) string {
	switch raw {
	case rawActorUser:
		return ActorUser
	case rawActorClientWorker:
		return ActorClientWorker
	case rawActorBatchJob:
		return ActorBatchJob
	case rawActorSystemDaemon:
		return ActorSystemDaemon
	default:
		return ActorUser
	}
}

func intentName(raw uint8) string {
	switch raw {
	case rawIntentNamespaceRead:
		return IntentNamespaceRead
	case rawIntentNamespaceMutation:
		return IntentNamespaceMutation
	case rawIntentDataRead:
		return IntentDataRead
	case rawIntentDataWrite:
		return IntentDataWrite
	case rawIntentSync:
		return IntentSync
	default:
		return ""
	}
}

var (
	IntentForOp = map[string]string{
		OpLookup: IntentNamespaceRead, OpOpen: IntentNamespaceRead,
		OpClose: IntentNamespaceRead, OpGetattr: IntentNamespaceRead,
		OpGetxattr: IntentNamespaceRead, OpStatfs: IntentNamespaceRead,
		OpRename: IntentNamespaceMutation, OpUnlink: IntentNamespaceMutation,
		OpMkdir: IntentNamespaceMutation, OpRmdir: IntentNamespaceMutation,
		OpMknod: IntentNamespaceMutation, OpSetattr: IntentNamespaceMutation,
		OpSetxattr: IntentNamespaceMutation,
		OpRead:  IntentDataRead, OpWrite: IntentDataWrite,
		OpFsync: IntentSync,
		// PCC lifecycle ops.
		OpPCCAttach: IntentNamespaceMutation, OpPCCDetach: IntentNamespaceMutation,
		OpPCCInvalidate: IntentNamespaceMutation,
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
		1e-2, 2.5e-2, 5e-2, 1e-1, 2.5e-1, 5e-1, 1.0, 2.5, 5.0, 10.0,
	}
)

type Config struct {
	MountPaths               []string
	DrainInterval            time.Duration
	Duration                 time.Duration
	Once                     bool
	LegacySymbolAllowMissing bool
	WebListenAddress         string
	WebTelemetryPath         string

	// SlurmJobIDEnabled turns on per-pid Slurm job id resolution via
	// /proc/<pid>/environ and /proc/<pid>/cgroup. The slurm_job_id label
	// is always part of the metric schema (emitted as "" when disabled or
	// when the process is not in a Slurm job).
	SlurmJobIDEnabled bool
	// SlurmJobIDTTL is the cache lifetime for a successful lookup.
	SlurmJobIDTTL time.Duration
	// SlurmJobIDNegativeTTL is the cache lifetime for a miss.
	SlurmJobIDNegativeTTL time.Duration
	// SlurmJobIDVerifyTTL is how long a cached entry can be served
	// without re-checking /proc/<pid>/stat for pid reuse.
	SlurmJobIDVerifyTTL time.Duration
	// SlurmJobIDCacheSize bounds the number of cached pids.
	SlurmJobIDCacheSize int

	// PCCEnabled turns on PCC (Persistent Client Cache) metrics collection.
	// When false (default), PCC kprobes are not attached and PCC metrics
	// are not registered.
	PCCEnabled bool
}

type Event struct {
	Plane      string
	Op         string
	ErrnoClass string
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
		ErrnoClass: errnoClassName(sample[2]),
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
	case rawPlanePCC:
		return PlanePCC, nil
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
	case rawOpClose:
		return OpClose, nil
	case rawOpGetattr:
		return OpGetattr, nil
	case rawOpGetxattr:
		return OpGetxattr, nil
	case rawOpMkdir:
		return OpMkdir, nil
	case rawOpMknod:
		return OpMknod, nil
	case rawOpRename:
		return OpRename, nil
	case rawOpRmdir:
		return OpRmdir, nil
	case rawOpSetattr:
		return OpSetattr, nil
	case rawOpSetxattr:
		return OpSetxattr, nil
	case rawOpStatfs:
		return OpStatfs, nil
	// PCC I/O ops normalise to the same strings as llite ops.
	case rawOpPCCRead:
		return OpRead, nil
	case rawOpPCCWrite:
		return OpWrite, nil
	case rawOpPCCOpen:
		return OpOpen, nil
	case rawOpPCCLookup:
		return OpLookup, nil
	case rawOpPCCFsync:
		return OpFsync, nil
	// PCC lifecycle ops.
	case rawOpPCCAttach:
		return OpPCCAttach, nil
	case rawOpPCCDetach:
		return OpPCCDetach, nil
	case rawOpPCCInvalidate:
		return OpPCCInvalidate, nil
	default:
		return "", fmt.Errorf("unknown op code: %d", raw)
	}
}

// DecodePCCAttachInfo extracts mode and trigger from the request_ptr field
// of a PCC attach/detach observer_event. The BPF side packs them as
// (mode << 8) | trigger.
func DecodePCCAttachInfo(requestPtr uint64) (mode, trigger string) {
	rawMode := uint8(requestPtr >> 8)
	rawTrigger := uint8(requestPtr & 0xFF)
	switch rawMode {
	case rawPCCModeRO:
		mode = PCCModeRO
	case rawPCCModeRW:
		mode = PCCModeRW
	default:
		mode = "unknown"
	}
	switch rawTrigger {
	case rawPCCTriggerManual:
		trigger = PCCTriggerManual
	case rawPCCTriggerAuto:
		trigger = PCCTriggerAuto
	default:
		trigger = "unknown"
	}
	return
}
