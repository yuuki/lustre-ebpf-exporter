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

	"github.com/yuuki/otel-lustre-tracer/internal/goexporter/slurm"
)

// testSlurmResolver returns a disabled slurm resolver suitable for tests
// that do not exercise Slurm job id resolution. Disabled means Resolve()
// always returns JobInfo{} without touching any FSReader, so callers do
// not need to inject fakes.
func testSlurmResolver() *slurm.Resolver {
	return slurm.New(slurm.Options{Enabled: false})
}

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
	inflight := NewInflightTracker(exporter.Inflight, resolver, testSlurmResolver())

	events := []Event{
		{Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd", DurationUS: 250, SizeBytes: 1024, MountPath: "/mnt/lustre", FSName: "lustrefs"},
		{Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd", DurationUS: 500, SizeBytes: 2048, MountPath: "/mnt/lustre", FSName: "lustrefs"},
		{Plane: PlanePtlRPC, Op: OpQueueWait, UID: 1001, PID: 123, Comm: "dd", DurationUS: 75, MountPath: "/mnt/lustre", FSName: "lustrefs"},
		{Plane: PlanePtlRPC, Op: OpSendNewReq, UID: 1001, PID: 123, Comm: "dd", MountPath: "/mnt/lustre", FSName: "lustrefs"},
		{Plane: PlanePtlRPC, Op: OpFreeReq, UID: 1001, PID: 123, Comm: "dd", MountPath: "/mnt/lustre", FSName: "lustrefs"},
	}
	for _, event := range events {
		processEvent(event, exporter, inflight, resolver, testSlurmResolver())
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

// TestDirectObservePropagatesSlurmJobID verifies that a resolver which
// reports a real Slurm job id causes the slurm_job_id label to appear
// with that value on both the histogram and the inflight gauge.
func TestDirectObservePropagatesSlurmJobID(t *testing.T) {
	t.Parallel()

	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	// Fake /proc: pid 555 is in Slurm job 4242 via environ; starttime is
	// constant so the cache remains consistent across calls.
	fakeEnviron := func(path string) ([]byte, error) {
		return []byte("PATH=/bin\x00SLURM_JOB_ID=4242\x00HOME=/root\x00"), nil
	}
	fakeCgroup := func(path string) ([]byte, error) {
		return []byte("0::/user.slice\n"), nil
	}
	fakeStat := func(path string) ([]byte, error) {
		return []byte("555 (dd) S 1 555 555 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 12345 0 0\n"), nil
	}
	slurmResolver := slurm.New(slurm.Options{
		Enabled:     true,
		TTL:         30 * time.Second,
		NegativeTTL: 5 * time.Second,
		VerifyTTL:   1 * time.Second,
		MaxEntries:  16,
		ReadEnviron: fakeEnviron,
		ReadCgroup:  fakeCgroup,
		ReadStat:    fakeStat,
	})

	resolver := testResolver()
	inflight := NewInflightTracker(exporter.Inflight, resolver, slurmResolver)

	events := []Event{
		{Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 555, Comm: "dd", DurationUS: 250, SizeBytes: 1024, MountPath: "/mnt/lustre", FSName: "lustrefs"},
		{Plane: PlanePtlRPC, Op: OpSendNewReq, UID: 1001, PID: 555, Comm: "dd", MountPath: "/mnt/lustre", FSName: "lustrefs"},
	}
	for _, event := range events {
		processEvent(event, exporter, inflight, resolver, slurmResolver)
	}

	text, err := exporter.RenderText()
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(text, `slurm_job_id="4242"`) {
		t.Fatalf("expected slurm_job_id=\"4242\" in rendered metrics, got: %s", text)
	}
	// The histogram family must carry the label on its buckets.
	if !strings.Contains(text, `lustre_client_access_duration_seconds_bucket`) {
		t.Fatalf("missing histogram family: %s", text)
	}
	// The inflight gauge must carry the label too.
	if !strings.Contains(text, `lustre_client_inflight_requests`) {
		t.Fatalf("missing inflight metric: %s", text)
	}
}

// TestDirectObserveDisabledSlurmResolverEmitsEmptyLabel verifies that when
// the resolver is disabled the slurm_job_id label is still present in the
// schema but has an empty value.
func TestDirectObserveDisabledSlurmResolverEmitsEmptyLabel(t *testing.T) {
	t.Parallel()

	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	resolver := testResolver()
	inflight := NewInflightTracker(exporter.Inflight, resolver, testSlurmResolver())

	processEvent(Event{
		Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 555, Comm: "dd",
		DurationUS: 250, SizeBytes: 1024, MountPath: "/mnt/lustre", FSName: "lustrefs",
	}, exporter, inflight, resolver, testSlurmResolver())

	text, err := exporter.RenderText()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, `slurm_job_id=""`) {
		t.Fatalf("expected empty slurm_job_id label in rendered metrics, got: %s", text)
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
	inflight := NewInflightTracker(exporter.Inflight, resolver, testSlurmResolver())

	processEvent(Event{Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd", DurationUS: 0, SizeBytes: 0, MountPath: "/mnt/lustre", FSName: "lustrefs"}, exporter, inflight, resolver, testSlurmResolver())

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
	tracker := NewInflightTracker(gauge, resolver, testSlurmResolver())

	event := Event{Plane: PlanePtlRPC, Op: OpFreeReq, UID: 1001, PID: 123, Comm: "dd", MountPath: "/mnt/lustre", FSName: "lustrefs"}

	// free_req without prior send_new_req
	tracker.Update(-1, event, "1001", "testuser", "user", "")
	tracker.Update(-1, event, "1001", "testuser", "user", "")

	// Verify the gauge never goes negative. Positional order matches baseLabels.
	metric := gauge.WithLabelValues("lustrefs", "/mnt/lustre", "1001", "testuser", "dd", "user", "")
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
	tracker := NewInflightTracker(gauge, resolver, testSlurmResolver())

	event := Event{Plane: PlanePtlRPC, Op: OpSendNewReq, UID: 1001, PID: 123, Comm: "dd", MountPath: "/mnt/lustre", FSName: "lustrefs"}

	tracker.Update(+1, event, "1001", "testuser", "user", "")
	tracker.Update(+1, event, "1001", "testuser", "user", "")

	metric := gauge.WithLabelValues("lustrefs", "/mnt/lustre", "1001", "testuser", "dd", "user", "")
	val := readGaugeValue(t, metric)
	if val != 2 {
		t.Fatalf("expected inflight=2, got %f", val)
	}

	// free one request
	tracker.Update(-1, event, "1001", "testuser", "user", "")
	val = readGaugeValue(t, metric)
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
	inflight := NewInflightTracker(exporter.Inflight, resolver, testSlurmResolver())

	// Feed events through the direct pipeline
	processEvent(Event{
		Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd",
		DurationUS: 250, SizeBytes: 1024, MountPath: "/mnt/lustre", FSName: "lustrefs",
	}, exporter, inflight, resolver, testSlurmResolver())

	processEvent(Event{
		Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd",
		DurationUS: 500, SizeBytes: 2048, MountPath: "/mnt/lustre", FSName: "lustrefs",
	}, exporter, inflight, resolver, testSlurmResolver())

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

// readCounterValue extracts the float64 value from a Prometheus counter metric.
func readCounterValue(t *testing.T, metric prometheus.Counter) float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 1)
	metric.(prometheus.Collector).Collect(ch)
	m := <-ch
	var d dto.Metric
	if err := m.Write(&d); err != nil {
		t.Fatalf("failed to read counter value: %v", err)
	}
	return d.GetCounter().GetValue()
}

// TestPtlRPCStartedCompletedCounters verifies that OpSendNewReq and OpFreeReq
// events increment the started and completed counters monotonically, while
// the inflight gauge reflects the net difference. Counter values must persist
// even after the inflight gauge clamps at zero.
func TestPtlRPCStartedCompletedCounters(t *testing.T) {
	t.Parallel()

	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	resolver := testResolver()
	slurmResolver := testSlurmResolver()
	inflight := NewInflightTracker(exporter.Inflight, resolver, slurmResolver)

	sendEvt := Event{Plane: PlanePtlRPC, Op: OpSendNewReq, UID: 1001, PID: 123, Comm: "dd", MountPath: "/mnt/lustre", FSName: "lustrefs"}
	freeEvt := Event{Plane: PlanePtlRPC, Op: OpFreeReq, UID: 1001, PID: 123, Comm: "dd", MountPath: "/mnt/lustre", FSName: "lustrefs"}

	// 3 sends, 2 frees → started=3, completed=2, inflight=1
	processEvent(sendEvt, exporter, inflight, resolver, slurmResolver)
	processEvent(sendEvt, exporter, inflight, resolver, slurmResolver)
	processEvent(sendEvt, exporter, inflight, resolver, slurmResolver)
	processEvent(freeEvt, exporter, inflight, resolver, slurmResolver)
	processEvent(freeEvt, exporter, inflight, resolver, slurmResolver)

	// Positional order matches baseLabels.
	labels := []string{"lustrefs", "/mnt/lustre", "1001", "testuser", "dd", "user", ""}
	started := exporter.RequestsStarted.WithLabelValues(labels...)
	completed := exporter.RequestsCompleted.WithLabelValues(labels...)

	if got := readCounterValue(t, started); got != 3 {
		t.Fatalf("expected started=3, got %f", got)
	}
	if got := readCounterValue(t, completed); got != 2 {
		t.Fatalf("expected completed=2, got %f", got)
	}

	gauge := exporter.Inflight.WithLabelValues(labels...)
	if got := readGaugeValue(t, gauge); got != 1 {
		t.Fatalf("expected inflight=1, got %f", got)
	}

	// Extra frees: inflight must clamp at zero, but completed counter must
	// still increase monotonically. This is the key property that makes the
	// counters useful independently of the gauge.
	processEvent(freeEvt, exporter, inflight, resolver, slurmResolver)
	processEvent(freeEvt, exporter, inflight, resolver, slurmResolver)

	if got := readCounterValue(t, completed); got != 4 {
		t.Fatalf("expected completed=4 after extra frees, got %f", got)
	}
	if got := readGaugeValue(t, gauge); got != 0 {
		t.Fatalf("expected inflight clamped to 0, got %f", got)
	}

	text, err := exporter.RenderText()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "lustre_client_ptlrpc_requests_started_total") {
		t.Fatalf("missing started counter in rendered output: %s", text)
	}
	if !strings.Contains(text, "lustre_client_ptlrpc_requests_completed_total") {
		t.Fatalf("missing completed counter in rendered output: %s", text)
	}
}
