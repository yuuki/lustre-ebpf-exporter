package goexporter

import (
	"context"
	"encoding/binary"
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
	aggregator.Consume(Event{Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd", DurationUS: 250, SizeBytes: 1024, MountPath: "/mnt/lustre", FSName: "lustrefs"})
	aggregator.Consume(Event{Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd", DurationUS: 500, SizeBytes: 2048, MountPath: "/mnt/lustre", FSName: "lustrefs"})
	aggregator.Consume(Event{Plane: PlanePtlRPC, Op: OpQueueWait, UID: 1001, PID: 123, Comm: "dd", DurationUS: 75, MountPath: "/mnt/lustre", FSName: "lustrefs"})
	aggregator.Consume(Event{Plane: PlanePtlRPC, Op: OpSendNewReq, UID: 1001, PID: 123, Comm: "dd", MountPath: "/mnt/lustre", FSName: "lustrefs"})
	aggregator.Consume(Event{Plane: PlanePtlRPC, Op: OpFreeReq, UID: 1001, PID: 123, Comm: "dd", MountPath: "/mnt/lustre", FSName: "lustrefs"})

	metrics := aggregator.Collect()
	text := renderMetricsForTest(t, metrics)

	if !strings.Contains(text, "lustre.client.access.operations") {
		t.Fatalf("missing access operations metric: %s", text)
	}
	if !strings.Contains(text, "lustre.client.rpc.wait.operations") {
		t.Fatalf("missing rpc wait metric: %s", text)
	}
	if !strings.Contains(text, "lustre.client.inflight.requests") {
		t.Fatalf("missing inflight metric: %s", text)
	}
}

func TestAggregatorSkipsZeroValuedLlIteDurationAndBytes(t *testing.T) {
	t.Parallel()

	aggregator := NewAggregator()
	aggregator.Consume(Event{Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd", DurationUS: 0, SizeBytes: 0, MountPath: "/mnt/lustre", FSName: "lustrefs"})

	metrics := aggregator.Collect()
	names := map[string]bool{}
	for _, metric := range metrics {
		names[metric.Name] = true
	}

	if !names["lustre.client.access.operations"] {
		t.Fatalf("missing access operations metric: %#v", metrics)
	}
	if names["lustre.client.access.duration"] {
		t.Fatalf("unexpected zero-valued duration metric: %#v", metrics)
	}
	if names["lustre.client.data.bytes"] {
		t.Fatalf("unexpected zero-valued data bytes metric: %#v", metrics)
	}
}

func TestSanitizeCommTrimsLeadingAndTrailingNulls(t *testing.T) {
	t.Parallel()

	got := sanitizeComm([]byte{0, 0, 'd', 'd', 0, 0})
	if got != "dd" {
		t.Fatalf("expected dd, got %q", got)
	}
}

func TestParseObserverEventMatchesBPFLayout(t *testing.T) {
	t.Parallel()

	sample := make([]byte, 64)
	sample[0] = 1
	sample[1] = 4
	binary.LittleEndian.PutUint32(sample[8:12], 1001)
	binary.LittleEndian.PutUint32(sample[12:16], 4321)
	binary.LittleEndian.PutUint64(sample[24:32], 250)
	binary.LittleEndian.PutUint64(sample[32:40], 4096)
	binary.LittleEndian.PutUint64(sample[40:48], 12345)
	copy(sample[48:64], []byte("dd\x00"))

	event, err := parseObserverEvent(sample)
	if err != nil {
		t.Fatal(err)
	}
	if event.Plane != PlaneLLite {
		t.Fatalf("expected llite plane, got %q", event.Plane)
	}
	if event.Op != OpWrite {
		t.Fatalf("expected write op, got %q", event.Op)
	}
	if event.Comm != "dd" {
		t.Fatalf("expected process dd, got %q", event.Comm)
	}
	if event.DurationUS != 250 {
		t.Fatalf("expected duration 250, got %d", event.DurationUS)
	}
	if event.SizeBytes != 4096 {
		t.Fatalf("expected size 4096, got %d", event.SizeBytes)
	}
	if event.RequestPtr != 12345 {
		t.Fatalf("expected request 12345, got %d", event.RequestPtr)
	}
}

func TestPrometheusExporterRendersFamilies(t *testing.T) {
	t.Parallel()

	exporter, err := NewPrometheusExporter(
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
				"lustre.mount.path": "/mnt/lustre", "lustre.fs.name": "lustrefs",
			},
		},
		{
			Name:      "lustre.client.access.duration",
			Type:      "histogram",
			Histogram: []float64{250, 500},
			Attributes: map[string]string{
				"user.id": "1001", "process.name": "dd", "lustre.actor.type": "user",
				"lustre.access.class": "data", "lustre.access.op": "write",
				"lustre.mount.path": "/mnt/lustre", "lustre.fs.name": "lustrefs",
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
