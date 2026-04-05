package goexporter

import (
	"context"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestClassifyActorType(t *testing.T) {
	t.Parallel()

	if got := ClassifyActorType("ptlrpcd_01_104"); got != "worker" {
		t.Fatalf("expected worker, got %q", got)
	}
	if got := ClassifyActorType("node_exporter"); got != "daemon" {
		t.Fatalf("expected daemon, got %q", got)
	}
	if got := ClassifyActorType("bash"); got != "user" {
		t.Fatalf("expected user, got %q", got)
	}
}

func TestAccessClassForOp(t *testing.T) {
	t.Parallel()

	if got := AccessClassForOp(OpLookup); got != "metadata" {
		t.Fatalf("expected metadata, got %q", got)
	}
	if got := AccessClassForOp(OpWrite); got != "data" {
		t.Fatalf("expected data, got %q", got)
	}
	if got := AccessClassForOp(OpQueueWait); got != "" {
		t.Fatalf("expected empty access class, got %q", got)
	}
}

func TestResolveMountInfoFromText(t *testing.T) {
	t.Parallel()

	info, err := ResolveMountInfoFromText(
		"/mnt/lustre1",
		"10.0.0.1@tcp:/fs1/home /mnt/lustre1 lustre rw 0 0\n10.0.0.1@tcp:/fs2/data /mnt/lustre2 lustre rw 0 0\n",
		func(path string) (string, error) { return path, nil },
		func(path string) (os.FileInfo, error) {
			return fakeFileInfo{sys: &syscall.Stat_t{Dev: 424242}}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if info.Path != "/mnt/lustre1" {
		t.Fatalf("unexpected path %q", info.Path)
	}
	if info.FSName != "home" {
		t.Fatalf("unexpected fs name %q", info.FSName)
	}
	if info.Major != uint32(unixMajor(424242)) || info.Minor != uint32(unixMinor(424242)) {
		t.Fatalf("unexpected device identity: %#v", info)
	}
}

func TestAggregatorCollectsExpectedMetrics(t *testing.T) {
	t.Parallel()

	aggregator := NewAggregator()
	aggregator.Consume(Event{Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd", DurationUS: 250, SizeBytes: 1024})
	aggregator.Consume(Event{Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd", DurationUS: 500, SizeBytes: 2048})
	aggregator.Consume(Event{Plane: PlanePtlRPC, Op: OpQueueWait, UID: 1001, PID: 123, Comm: "dd", DurationUS: 75})
	aggregator.Consume(Event{Plane: PlanePtlRPC, Op: OpSendNewReq, UID: 1001, PID: 123, Comm: "dd"})
	aggregator.Consume(Event{Plane: PlanePtlRPC, Op: OpFreeReq, UID: 1001, PID: 123, Comm: "dd"})

	metrics := aggregator.Collect()
	text := renderMetricsForTest(t, metrics)

	if !strings.Contains(text, "lustre.client.access.operations") {
		t.Fatalf("missing access operations metric: %s", text)
	}
	if !strings.Contains(text, "lustre.client.data.bytes") {
		t.Fatalf("missing data bytes metric: %s", text)
	}
	if !strings.Contains(text, "lustre.client.rpc.wait.operations") {
		t.Fatalf("missing rpc wait metric: %s", text)
	}
	if !strings.Contains(text, "lustre.client.inflight.requests") {
		t.Fatalf("missing inflight metric: %s", text)
	}
}

func TestPrometheusExporterRendersFamilies(t *testing.T) {
	t.Parallel()

	exporter, err := NewPrometheusExporter(
		MountInfo{FSName: "lustrefs", Path: "/mnt/lustre"},
		"127.0.0.1:0",
		"/metrics",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	exporter.Export([]AggregatedMetric{
		{
			Name:  "lustre.client.access.operations",
			Type:  "counter",
			Value: 2,
			Attributes: map[string]string{
				"user.id": "1001", "process.name": "dd", "lustre.actor.type": "user",
				"lustre.access.class": "data", "lustre.access.op": "write",
			},
		},
		{
			Name:      "lustre.client.access.duration",
			Type:      "histogram",
			Histogram: []float64{250, 500},
			Attributes: map[string]string{
				"user.id": "1001", "process.name": "dd", "lustre.actor.type": "user",
				"lustre.access.class": "data", "lustre.access.op": "write",
			},
		},
	})

	text, err := exporter.RenderText()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "lustre_client_access_operations_total") {
		t.Fatalf("missing counter family: %s", text)
	}
	if !strings.Contains(text, "lustre_client_access_duration_seconds_bucket") {
		t.Fatalf("missing histogram family: %s", text)
	}
	if !strings.Contains(text, "mount=\"/mnt/lustre\"") {
		t.Fatalf("missing mount label: %s", text)
	}
}

type fakeFileInfo struct {
	sys any
}

func (f fakeFileInfo) Name() string       { return "" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return 0 }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return true }
func (f fakeFileInfo) Sys() any           { return f.sys }

func renderMetricsForTest(t *testing.T, metrics []AggregatedMetric) string {
	t.Helper()
	var b strings.Builder
	for _, metric := range metrics {
		b.WriteString(metric.Name)
	}
	return b.String()
}
