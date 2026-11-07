package goexporter

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// The per-event path: every perf sample is decoded, its comm sanitized and
// normalized, and recorded. Compare runs with benchstat (make bench).

func BenchmarkParseObserverEvent(b *testing.B) {
	sample := rawEventSeed(rawPlaneLLite, rawOpWrite, rawErrnoClassNone, "python3")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := parseObserverEvent(sample); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProcessFilterNormalize(b *testing.B) {
	filter := NewProcessFilter([]string{"dd", "python3", "Bun Pool"}, true)
	names := []string{"dd", "Bun Pool 12", "kworker/107", "client.poll12", "python3.11"}
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		filter.Normalize(names[i%len(names)])
	}
}

func BenchmarkEventHandlerHandle(b *testing.B) {
	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil, false, true, false)
	if err != nil {
		b.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())
	gone := func(string) ([]byte, error) { return nil, errors.New("no such process") }
	h := &eventHandler{
		mountInfos:       []MountInfo{{Path: "/mnt/lustre", FSName: "fs"}},
		procNameResolver: newProcNameResolver(gone, gone),
		processFilter:    NewProcessFilter(nil, true),
		exporter:         exporter,
		inflight:         NewInflightTracker(exporter.Inflight, false, true),
		resolver:         testResolver(),
		slurmResolver:    testSlurmResolver(),
	}
	events := []Event{
		{Plane: PlaneLLite, Op: OpRead, UID: 1001, PID: 7, Comm: "dd", DurationUS: 120},
		{Plane: PlanePtlRPC, Op: OpQueueWait, UID: 1001, PID: 7, Comm: "ptlrpcd_00_01", DurationUS: 900},
		{Plane: PlanePtlRPC, Op: OpSendNewReq, UID: 1001, PID: 8, Comm: "worker-3"},
		{Plane: PlanePtlRPC, Op: OpFreeReq, UID: 1001, PID: 8, Comm: "worker-3"},
	}
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		h.handle(events[i%len(events)])
	}
}

// BenchmarkBPFCounterCollectorCollect measures a scrape of the counter
// families, which runs under the collector's read lock.
func BenchmarkBPFCounterCollectorCollect(b *testing.B) {
	c := NewBPFCounterCollector(nil, nil, nil, nil, nil, testResolver(), testSlurmResolver(), NewProcessFilter(nil, false), false, true)
	for i := range 500 {
		vals := lliteLabelValues("fs", "/mnt/lustre", IntentDataRead, OpRead, "1001", "testuser", fmt.Sprintf("proc%d", i), ActorUser, "", false, true)
		c.lliteAcc[joinLabelKey(vals...)] = &lliteAccum{opsCount: 10, bytesSum: 4096, values: vals}
	}
	ch := make(chan prometheus.Metric, 1024)
	b.ReportAllocs()
	for b.Loop() {
		c.Collect(ch)
		for len(ch) > 0 {
			<-ch
		}
	}
}
