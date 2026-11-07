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
