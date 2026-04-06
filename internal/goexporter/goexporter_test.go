package goexporter

import (
	"context"
	"encoding/binary"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestClassifyActorType(t *testing.T) {
	t.Parallel()

	if got := ClassifyActorType("ptlrpcd_01_104"); got != "client_worker" {
		t.Fatalf("expected client_worker, got %q", got)
	}
	if got := ClassifyActorType("slurmstepd"); got != "batch_job" {
		t.Fatalf("expected batch_job, got %q", got)
	}
	if got := ClassifyActorType("pbs_mom"); got != "batch_job" {
		t.Fatalf("expected batch_job, got %q", got)
	}
	if got := ClassifyActorType("node_exporter"); got != "system_daemon" {
		t.Fatalf("expected system_daemon, got %q", got)
	}
	if got := ClassifyActorType("bash"); got != "user" {
		t.Fatalf("expected user, got %q", got)
	}
}

func TestAccessIntentForOp(t *testing.T) {
	t.Parallel()

	if got := AccessIntentForOp(OpLookup); got != "namespace_read" {
		t.Fatalf("expected namespace_read, got %q", got)
	}
	if got := AccessIntentForOp(OpOpen); got != "namespace_read" {
		t.Fatalf("expected namespace_read, got %q", got)
	}
	if got := AccessIntentForOp(OpRename); got != "namespace_mutation" {
		t.Fatalf("expected namespace_mutation, got %q", got)
	}
	if got := AccessIntentForOp(OpRead); got != "data_read" {
		t.Fatalf("expected data_read, got %q", got)
	}
	if got := AccessIntentForOp(OpWrite); got != "data_write" {
		t.Fatalf("expected data_write, got %q", got)
	}
	if got := AccessIntentForOp(OpFsync); got != "sync" {
		t.Fatalf("expected sync, got %q", got)
	}
	if got := AccessIntentForOp(OpQueueWait); got != "" {
		t.Fatalf("expected empty intent, got %q", got)
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

func testResolver() *UsernameResolver {
	r := NewUsernameResolver()
	r.cache[1001] = "testuser"
	return r
}

// TestDirectObserveUpdatesHistogram verifies that events update
// Prometheus histogram metrics directly (no aggregator buffering).
func TestDirectObserveUpdatesHistogram(t *testing.T) {
	t.Parallel()

	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	resolver := testResolver()
	inflight := NewInflightTracker(exporter.Inflight, resolver)

	events := []Event{
		{Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd", DurationUS: 250, SizeBytes: 1024, MountPath: "/mnt/lustre", FSName: "lustrefs"},
		{Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd", DurationUS: 500, SizeBytes: 2048, MountPath: "/mnt/lustre", FSName: "lustrefs"},
		{Plane: PlanePtlRPC, Op: OpQueueWait, UID: 1001, PID: 123, Comm: "dd", DurationUS: 75, MountPath: "/mnt/lustre", FSName: "lustrefs"},
		{Plane: PlanePtlRPC, Op: OpSendNewReq, UID: 1001, PID: 123, Comm: "dd", MountPath: "/mnt/lustre", FSName: "lustrefs"},
		{Plane: PlanePtlRPC, Op: OpFreeReq, UID: 1001, PID: 123, Comm: "dd", MountPath: "/mnt/lustre", FSName: "lustrefs"},
	}
	for _, event := range events {
		processEvent(event, exporter, inflight, resolver)
	}

	text, err := exporter.RenderText()
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(text, "lustre_client_access_duration_seconds_bucket") {
		t.Fatalf("missing histogram family: %s", text)
	}
	if !strings.Contains(text, "lustre_client_rpc_wait_duration_seconds_bucket") {
		t.Fatalf("missing rpc wait histogram: %s", text)
	}
	if !strings.Contains(text, "lustre_client_inflight_requests") {
		t.Fatalf("missing inflight metric: %s", text)
	}
}

// TestDirectObserveSkipsZeroDuration verifies zero-duration events
// do not produce histogram observations.
func TestDirectObserveSkipsZeroDuration(t *testing.T) {
	t.Parallel()

	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	resolver := testResolver()
	inflight := NewInflightTracker(exporter.Inflight, resolver)

	processEvent(Event{Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd", DurationUS: 0, SizeBytes: 0, MountPath: "/mnt/lustre", FSName: "lustrefs"}, exporter, inflight, resolver)

	text, err := exporter.RenderText()
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(text, "lustre_client_access_duration_seconds_bucket") {
		t.Fatalf("unexpected histogram for zero-duration event: %s", text)
	}
}

func TestInflightTrackerClampsAtZero(t *testing.T) {
	t.Parallel()

	gauge := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "test_inflight", Help: "test"},
		baseLabels,
	)
	resolver := testResolver()
	tracker := NewInflightTracker(gauge, resolver)

	event := Event{Plane: PlanePtlRPC, Op: OpFreeReq, UID: 1001, PID: 123, Comm: "dd", MountPath: "/mnt/lustre", FSName: "lustrefs"}

	// free_req without prior send_new_req
	tracker.Update(-1, event)
	tracker.Update(-1, event)

	// Verify the gauge never goes negative
	labels := BuildBasePrometheusLabels("1001", "testuser", "dd", "user", "/mnt/lustre", "lustrefs")
	metric := gauge.With(labels)
	dto := readGaugeValue(t, metric)
	if dto < 0 {
		t.Fatalf("inflight went negative: %f", dto)
	}
}

func TestInflightTrackerPersistsAcrossReads(t *testing.T) {
	t.Parallel()

	gauge := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "test_inflight2", Help: "test"},
		baseLabels,
	)
	resolver := testResolver()
	tracker := NewInflightTracker(gauge, resolver)

	event := Event{Plane: PlanePtlRPC, Op: OpSendNewReq, UID: 1001, PID: 123, Comm: "dd", MountPath: "/mnt/lustre", FSName: "lustrefs"}

	tracker.Update(+1, event)
	tracker.Update(+1, event)

	labels := BuildBasePrometheusLabels("1001", "testuser", "dd", "user", "/mnt/lustre", "lustrefs")
	val := readGaugeValue(t, gauge.With(labels))
	if val != 2 {
		t.Fatalf("expected inflight=2, got %f", val)
	}

	// free one request
	tracker.Update(-1, event)
	val = readGaugeValue(t, gauge.With(labels))
	if val != 1 {
		t.Fatalf("expected inflight=1, got %f", val)
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
	binary.LittleEndian.PutUint32(sample[16:20], 2)
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
	if event.MountIdx != 2 {
		t.Fatalf("expected mount index 2, got %d", event.MountIdx)
	}
	if event.RequestPtr != 12345 {
		t.Fatalf("expected request 12345, got %d", event.RequestPtr)
	}
}

func TestPrometheusExporterRendersFamilies(t *testing.T) {
	t.Parallel()

	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	resolver := testResolver()
	inflight := NewInflightTracker(exporter.Inflight, resolver)

	// Feed events through the direct pipeline
	processEvent(Event{
		Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd",
		DurationUS: 250, SizeBytes: 1024, MountPath: "/mnt/lustre", FSName: "lustrefs",
	}, exporter, inflight, resolver)

	processEvent(Event{
		Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd",
		DurationUS: 500, SizeBytes: 2048, MountPath: "/mnt/lustre", FSName: "lustrefs",
	}, exporter, inflight, resolver)

	text, err := exporter.RenderText()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "lustre_client_access_duration_seconds_bucket") {
		t.Fatalf("missing histogram family: %s", text)
	}
	if !strings.Contains(text, "mount=\"/mnt/lustre\"") {
		t.Fatalf("missing mount label: %s", text)
	}
	if !strings.Contains(text, "username=\"testuser\"") {
		t.Fatalf("missing username label: %s", text)
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

func TestActorTypeName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw  uint8
		want string
	}{
		{rawActorUser, "user"},
		{rawActorClientWorker, "client_worker"},
		{rawActorBatchJob, "batch_job"},
		{rawActorSystemDaemon, "system_daemon"},
		{99, "user"},
	}
	for _, tc := range cases {
		if got := actorTypeName(tc.raw); got != tc.want {
			t.Errorf("actorTypeName(%d) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestIntentName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw  uint8
		want string
	}{
		{rawIntentNamespaceRead, "namespace_read"},
		{rawIntentNamespaceMutation, "namespace_mutation"},
		{rawIntentDataRead, "data_read"},
		{rawIntentDataWrite, "data_write"},
		{rawIntentSync, "sync"},
		{rawIntentUnknown, ""},
	}
	for _, tc := range cases {
		if got := intentName(tc.raw); got != tc.want {
			t.Errorf("intentName(%d) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestBpfAggKeySize(t *testing.T) {
	t.Parallel()

	var key bpfAggKey
	size := int(unsafe.Sizeof(key))
	if size != 24 {
		t.Fatalf("bpfAggKey size = %d, want 24 (must match BPF struct)", size)
	}
}

func TestBpfCounterValSize(t *testing.T) {
	t.Parallel()

	var val bpfCounterVal
	size := int(unsafe.Sizeof(val))
	if size != 16 {
		t.Fatalf("bpfCounterVal size = %d, want 16 (must match BPF struct)", size)
	}
}

// readGaugeValue extracts the float64 value from a Prometheus gauge metric.
func readGaugeValue(t *testing.T, metric prometheus.Gauge) float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 1)
	metric.(prometheus.Collector).Collect(ch)
	m := <-ch
	var d dto.Metric
	if err := m.Write(&d); err != nil {
		t.Fatalf("failed to read gauge value: %v", err)
	}
	return d.GetGauge().GetValue()
}
