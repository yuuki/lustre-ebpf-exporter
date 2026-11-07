package goexporter

import (
	"bytes"
	"encoding/binary"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
)

// encodeRawEvent returns the perf sample the BPF program writes for raw.
func encodeRawEvent(raw rawObserverEvent) []byte {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &raw); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func rawEventSeed(plane, op, errnoClass uint8, comm string) []byte {
	raw := rawObserverEvent{
		Plane: plane, Op: op, ErrnoClass: errnoClass,
		UID: 1001, PID: 4321, MountIdx: 2,
		DurationUS: 250, SizeBytes: 4096, RequestPtr: 0xffff888012345678,
	}
	copy(raw.Comm[:], comm)
	return encodeRawEvent(raw)
}

// FuzzParseObserverEvent decodes arbitrary perf samples. A sample decodes only
// when it is long enough and names a known plane and op; a decoded event then
// carries the fields at the offsets of struct observer_event (checked against
// rawObserverEvent, an independent decoder) and a comm that is a valid label
// value.
func FuzzParseObserverEvent(f *testing.F) {
	f.Add(rawEventSeed(rawPlaneLLite, rawOpWrite, rawErrnoClassNone, "dd"))
	f.Add(rawEventSeed(rawPlanePtlRPC, rawOpQueueWait, rawErrnoClassTimeout, "ptlrpcd_00_01"))
	f.Add(rawEventSeed(rawPlaneLLite, rawOpReaddir, 0xff, "0123456789abcdef")) // comm without NUL
	f.Add(rawEventSeed(rawPlaneLLite, rawOpOpen, rawErrnoClassPerm, "\x00\x00ls"))
	f.Add(rawEventSeed(rawPlaneLLite, rawOpRead, rawErrnoClassNone, "\xff\xfecat"))
	f.Add(rawEventSeed(rawPlanePCC, rawOpPCCRead, rawErrnoClassNone, "dd"))
	f.Add(rawEventSeed(rawPlaneLLite, 0xff, rawErrnoClassNone, "dd"))
	f.Add(rawEventSeed(rawPlaneLLite, rawOpWrite, rawErrnoClassNone, "dd")[:63])
	f.Add([]byte{})

	knownErrnoClasses := []string{"", ErrnoClassTimeout, ErrnoClassNotconn, ErrnoClassPerm,
		ErrnoClassNotfound, ErrnoClassIO, ErrnoClassAgain, ErrnoClassOther}
	f.Fuzz(func(t *testing.T, sample []byte) {
		event, err := parseObserverEvent(sample)
		if len(sample) < 64 {
			if err == nil {
				t.Fatalf("decoded a %d-byte sample", len(sample))
			}
			return
		}
		var raw rawObserverEvent
		if err := binary.Read(bytes.NewReader(sample), binary.LittleEndian, &raw); err != nil {
			t.Fatal(err)
		}
		_, planeErr := planeName(raw.Plane)
		_, opErr := opName(raw.Op)
		if (err == nil) != (planeErr == nil && opErr == nil) {
			t.Fatalf("err = %v for plane %d, op %d", err, raw.Plane, raw.Op)
		}
		if err != nil {
			return
		}
		if event.Plane != PlaneLLite && event.Plane != PlanePtlRPC {
			t.Fatalf("plane %q", event.Plane)
		}
		if event.UID != raw.UID || event.PID != raw.PID || event.MountIdx != raw.MountIdx ||
			event.DurationUS != raw.DurationUS || event.SizeBytes != raw.SizeBytes || event.RequestPtr != raw.RequestPtr {
			t.Fatalf("event %+v does not match the sample fields %+v", event, raw)
		}
		if !slices.Contains(knownErrnoClasses, event.ErrnoClass) || (event.ErrnoClass == "") != (raw.ErrnoClass == rawErrnoClassNone) {
			t.Fatalf("errno class %q for raw %d", event.ErrnoClass, raw.ErrnoClass)
		}
		checkCommLabel(t, raw.Comm[:], event.Comm)
	})
}

// checkCommLabel fails unless comm is the label value for the comm bytes raw:
// the first NUL-terminated run after leading NULs, verbatim when it is valid
// UTF-8 and otherwise with each invalid sequence replaced by U+FFFD.
func checkCommLabel(t *testing.T, raw []byte, comm string) {
	t.Helper()
	want, _, _ := bytes.Cut(bytes.TrimLeft(raw, "\x00"), []byte{0})
	if !utf8.ValidString(comm) || strings.ContainsRune(comm, 0) {
		t.Fatalf("comm %q from %q is not a valid label value", comm, raw)
	}
	if utf8.Valid(want) && comm != string(want) {
		t.Fatalf("comm %q, want %q", comm, want)
	}
	if len(comm) > 3*len(want) {
		t.Fatalf("comm %q grew from %d to %d bytes", comm, len(want), len(comm))
	}
}

// FuzzDetectLustreMountsFromText feeds arbitrary mount tables: detection
// returns at most one path per line, each from a line whose type is lustre.
func FuzzDetectLustreMountsFromText(f *testing.F) {
	f.Add("10.0.0.1@tcp:/scratch /mnt/lustre lustre rw,seclabel 0 0\nsysfs /sys sysfs rw 0 0\n")
	f.Add("a /b lustre\nc /d\\0 lustre\ne /f\\777 lustre\n\\")
	f.Add("lustre lustre lustre lustre\n\n   \n")
	f.Fuzz(func(t *testing.T, table string) {
		paths, err := DetectLustreMountsFromText(table)
		if err != nil {
			return // a line over bufio.MaxScanTokenSize; /proc/mounts lines are far shorter
		}
		if lines := strings.Count(table, "\n") + 1; len(paths) > lines {
			t.Fatalf("%d paths from %d lines", len(paths), lines)
		}
		if lustreLines := strings.Count(table, "lustre"); len(paths) > lustreLines {
			t.Fatalf("%d paths from %d lustre fields", len(paths), lustreLines)
		}
	})
}

// FuzzProcessLabel follows a process name from its two sources, the task comm
// in BPF events and counter keys and argv[0] in /proc/<pid>/cmdline, through
// the process filter into a counter, and checks that the result is always a
// label value Prometheus accepts (an invalid one fails the whole scrape).
func FuzzProcessLabel(f *testing.F) {
	f.Add([]byte("dd\x00"), []byte("/usr/bin/python3\x00script.py\x00"), "dd,python3", false)
	f.Add([]byte("Bun Pool 1\x00"), []byte("Bun Pool 1"), "", true)
	f.Add([]byte("ptlrpcd_00_01"), []byte("\x00"), "", true)
	f.Add([]byte("\xff\xfeevil\x00"), []byte("/tmp/\xc3\x28\x00"), "", false)
	f.Add([]byte("slurmstepd\x00"), []byte("/usr/sbin/slurmstepd"), "other", true)

	actors := []string{ActorUser, ActorClientWorker, ActorBatchJob, ActorSystemDaemon}
	desc := prometheus.NewDesc("lustre_client_access_operations_total", "fuzz", buildLliteLabels(true, true), nil)
	f.Fuzz(func(t *testing.T, comm, cmdline []byte, allowlist string, strip bool) {
		if len(comm) > 16 {
			comm = comm[:16] // TASK_COMM_LEN
		}
		filter := NewProcessFilter(strings.Split(allowlist, ","), strip)
		if allowlist == "" {
			filter = NewProcessFilter(nil, strip)
		}
		commName := sanitizeComm(comm)
		checkCommLabel(t, comm, commName)
		cmdlineName := parseCmdlineName(cmdline)
		if !utf8.ValidString(cmdlineName) || strings.ContainsRune(cmdlineName, 0) {
			t.Fatalf("cmdline name %q from %q is not a valid label value", cmdlineName, cmdline)
		}

		for _, name := range []string{commName, cmdlineName} {
			if actor := ClassifyActorType(name); !slices.Contains(actors, actor) {
				t.Fatalf("actor type %q for %q", actor, name)
			}
			process := filter.Normalize(name)
			switch {
			case allowlist != "":
				if process != processOther && !slices.Contains(strings.Split(allowlist, ","), process) {
					t.Fatalf("%q normalized to %q, which is neither allowlisted nor %q", name, process, processOther)
				}
			case strip:
				if !strings.HasPrefix(name, process) || (name != "" && process == "") {
					t.Fatalf("%q normalized to %q, not a non-empty prefix", name, process)
				}
			default:
				if process != name {
					t.Fatalf("%q changed to %q without a filter", name, process)
				}
			}
			values := lliteLabelValues("fs", "/mnt/lustre", IntentDataRead, OpRead, "1001", "user", process, ClassifyActorType(name), "42", true, true)
			if _, err := prometheus.NewConstMetric(desc, prometheus.CounterValue, 1, values...); err != nil {
				t.Fatalf("process %q from %q: %v", process, name, err)
			}
		}
	})
}
