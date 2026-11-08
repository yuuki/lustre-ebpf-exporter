package goexporter

import (
	"context"
	"testing"
	"time"

	"go.uber.org/goleak"
)

// TestStartDrainStopsOnCancel checks that the drain goroutine ends when its
// context is cancelled.
func TestStartDrainStopsOnCancel(t *testing.T) {
	ignore := goleak.IgnoreCurrent()
	c := NewBPFCounterCollector(nil, nil, nil, nil, nil, testResolver(), testSlurmResolver(), NewProcessFilter(nil, false), false, true)
	ctx, cancel := context.WithCancel(context.Background())
	c.StartDrain(ctx, time.Millisecond)
	time.Sleep(5 * time.Millisecond) // let a few ticks drain the (absent) maps
	cancel()
	goleak.VerifyNone(t, ignore)
}

func TestPrometheusExporterBoundsHeaderReads(t *testing.T) {
	t.Parallel()

	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())
	if got := exporter.server.ReadHeaderTimeout; got != readHeaderTimeout || got <= 0 {
		t.Fatalf("ReadHeaderTimeout = %v, want %v", got, readHeaderTimeout)
	}
}

// Counter labels classify the key's comm with ClassifyActorType, like events:
// the BPF program never reports a system daemon, so its ActorType is not used.
func TestCommLabelsClassifyLikeEvents(t *testing.T) {
	c := NewBPFCounterCollector(nil, nil, nil, nil, nil, testResolver(), testSlurmResolver(), NewProcessFilter(nil, false), false, true)
	comm := func(s string) (b [16]byte) {
		copy(b[:], s)
		return b
	}
	for _, tc := range []struct{ comm, process, actor string }{
		{"dd", "dd", ActorUser},
		{"node_exporter", "node_exporter", ActorSystemDaemon},
		{"sshd", "sshd", ActorSystemDaemon},
		{"slurmstepd", "slurmstepd", ActorBatchJob},
		{"ptlrpcd_00_01", "ptlrpcd_00_01", ActorClientWorker},
	} {
		process, actor := c.commLabels(comm(tc.comm))
		if process != tc.process || actor != tc.actor {
			t.Errorf("commLabels(%q) = %q, %q; want %q, %q", tc.comm, process, actor, tc.process, tc.actor)
		}
		if got := ClassifyActorType(tc.comm); got != actor {
			t.Errorf("commLabels(%q) actor %q, but events classify it as %q", tc.comm, actor, got)
		}
	}
}
