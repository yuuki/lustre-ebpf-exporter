package goexporter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"testing"
)

func TestResolveMountInfosRejectsTooManyMounts(t *testing.T) {
	t.Parallel()

	paths := make([]string, MaxMountPoints+1)
	for i := range paths {
		paths[i] = fmt.Sprintf("/nonexistent-%d", i)
	}
	infos, err := resolveMountInfos(paths)
	// The limit is checked before any path is resolved: resolving the first
	// path would fail with a different error.
	want := fmt.Sprintf("too many mount paths (%d); maximum is %d", MaxMountPoints+1, MaxMountPoints)
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
	if infos != nil {
		t.Fatalf("infos = %v, want nil", infos)
	}
}

func TestResolveMountInfosNoMounts(t *testing.T) {
	t.Parallel()

	infos, err := resolveMountInfos(nil)
	if err != nil || infos != nil {
		t.Fatalf("resolveMountInfos(nil) = %v, %v; want nil, nil", infos, err)
	}
}

func TestResolveMountInfosFailsOnUnresolvablePath(t *testing.T) {
	t.Parallel()

	infos, err := resolveMountInfos([]string{"/nonexistent-lustre-mount"})
	if err == nil {
		t.Fatal("expected an error for a path that is not a Lustre mount")
	}
	if infos != nil {
		t.Fatalf("infos = %v, want nil", infos)
	}
}

// TestEventHandlerHandle checks the per-event enrichment of Run: the mount is
// taken from the event's mount index, the process name is resolved from /proc
// and normalized, the raw name drives actor classification, and the warning
// and debug lines are logged. It captures the standard logger, so it must not
// run in parallel.
func TestEventHandlerHandle(t *testing.T) {
	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	// pid 7 runs slurmstepd; every other pid has exited, so its BPF comm is used.
	procNames := newProcNameResolver(
		func(path string) ([]byte, error) {
			if path == "/proc/7/cmdline" {
				return []byte("/usr/sbin/slurmstepd\x00--flag"), nil
			}
			return nil, errors.New("no such process")
		},
		func(path string) ([]byte, error) {
			if path == "/proc/7/stat" {
				return []byte("7 (slurmstepd) S 1 1 1 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 12345 0 0"), nil
			}
			return nil, errors.New("no such process")
		},
	)
	h := &eventHandler{
		mountInfos: []MountInfo{
			{Path: "/mnt/a", FSName: "fsa"},
			{Path: "/mnt/b", FSName: "fsb"},
		},
		procNameResolver: procNames,
		processFilter:    NewProcessFilter([]string{"dd"}, true),
		debugEnabled:     true,
		exporter:         exporter,
		inflight:         NewInflightTracker(exporter.Inflight, false, true),
		resolver:         testResolver(),
		slurmResolver:    testSlurmResolver(),
	}

	var logs bytes.Buffer
	flags, out := log.Flags(), log.Writer()
	log.SetFlags(0)
	log.SetOutput(&logs)
	defer func() {
		log.SetFlags(flags)
		log.SetOutput(out)
	}()

	base := Event{Plane: PlanePtlRPC, Op: OpSendNewReq, UID: 1001, MountPath: "/preset", FSName: "preset"}
	slurmstepd := base
	slurmstepd.PID, slurmstepd.Comm, slurmstepd.MountIdx = 7, "slurmstepd", 1
	worker := base
	worker.PID, worker.Comm, worker.MountIdx = 99, "dd-3", 0
	// The first index past the mounts, and one further out.
	pastLastMount := base
	pastLastMount.PID, pastLastMount.Comm, pastLastMount.MountIdx = 99, "dd", 2
	pastLastMount.MountPath, pastLastMount.FSName = "/preset2", "preset2"
	unknownMount := base
	unknownMount.PID, unknownMount.Comm, unknownMount.MountIdx = 99, "dd", 5
	for _, event := range []Event{slurmstepd, worker, pastLastMount, unknownMount} {
		h.handle(event)
	}

	wantLogs := []string{
		"debug: event plane=ptlrpc op=send_new_req uid=1001 pid=7 mount=/mnt/b comm=other dur_us=0 bytes=0 req=0",
		"debug: event plane=ptlrpc op=send_new_req uid=1001 pid=99 mount=/mnt/a comm=dd dur_us=0 bytes=0 req=0",
		"warning: event has unknown mount index 2",
		"debug: event plane=ptlrpc op=send_new_req uid=1001 pid=99 mount=/preset2 comm=dd dur_us=0 bytes=0 req=0",
		"warning: event has unknown mount index 5",
		"debug: event plane=ptlrpc op=send_new_req uid=1001 pid=99 mount=/preset comm=dd dur_us=0 bytes=0 req=0",
	}
	if got, want := logs.String(), strings.Join(wantLogs, "\n")+"\n"; got != want {
		t.Fatalf("log mismatch\n got:\n%s\nwant:\n%s", got, want)
	}

	// Positional order matches baseLabelsNoSlurm (slurmEnabled=false).
	for _, labels := range [][]string{
		// Not allowlisted, so the process label is "other"; the actor type
		// still comes from the unfiltered name.
		{"fsb", "/mnt/b", "1001", "testuser", "other", ActorBatchJob},
		// "dd-3" is normalized to the allowlisted "dd".
		{"fsa", "/mnt/a", "1001", "testuser", "dd", ActorUser},
		// An unknown mount index keeps the event's own mount fields.
		{"preset2", "/preset2", "1001", "testuser", "dd", ActorUser},
		{"preset", "/preset", "1001", "testuser", "dd", ActorUser},
	} {
		if got := readCounterValue(t, exporter.RequestsStarted.WithLabelValues(labels...)); got != 1 {
			t.Errorf("requests started %v = %v, want 1", labels, got)
		}
	}
}
