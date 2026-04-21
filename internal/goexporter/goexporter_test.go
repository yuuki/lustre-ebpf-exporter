package goexporter

import (
	"context"
	"encoding/binary"
	"os"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/yuuki/lustre-ebpf-exporter/internal/goexporter/slurm"
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

	namespaceReads := []string{OpClose, OpGetattr, OpGetxattr, OpStatfs}
	for _, op := range namespaceReads {
		if got := AccessIntentForOp(op); got != IntentNamespaceRead {
			t.Fatalf("op %q: expected %q, got %q", op, IntentNamespaceRead, got)
		}
	}
	namespaceMutations := []string{OpMkdir, OpMknod, OpRename, OpRmdir, OpSetattr, OpSetxattr, OpUnlink}
	for _, op := range namespaceMutations {
		if got := AccessIntentForOp(op); got != IntentNamespaceMutation {
			t.Fatalf("op %q: expected %q, got %q", op, IntentNamespaceMutation, got)
		}
	}
}

func TestOpNameRoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[uint8]string{
		rawOpLookup:     OpLookup,
		rawOpOpen:       OpOpen,
		rawOpRead:       OpRead,
		rawOpWrite:      OpWrite,
		rawOpFsync:      OpFsync,
		rawOpQueueWait:  OpQueueWait,
		rawOpSendNewReq: OpSendNewReq,
		rawOpFreeReq:    OpFreeReq,
		rawOpClose:      OpClose,
		rawOpGetattr:    OpGetattr,
		rawOpGetxattr:   OpGetxattr,
		rawOpMkdir:      OpMkdir,
		rawOpMknod:      OpMknod,
		rawOpRename:     OpRename,
		rawOpRmdir:      OpRmdir,
		rawOpSetattr:    OpSetattr,
		rawOpSetxattr:   OpSetxattr,
		rawOpStatfs:     OpStatfs,
	}
	for raw, want := range cases {
		got, err := opName(raw)
		if err != nil {
			t.Errorf("opName(%d) returned error: %v", raw, err)
			continue
		}
		if got != want {
			t.Errorf("opName(%d) = %q, want %q", raw, got, want)
		}
	}
	if _, err := opName(255); err == nil {
		t.Errorf("opName(255) should return error for unknown code")
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

func labelNamesForMetricFamily(t *testing.T, exporter *PrometheusExporter, familyName string) []string {
	t.Helper()

	families, err := exporter.registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, family := range families {
		if family.GetName() != familyName {
			continue
		}
		if len(family.Metric) == 0 {
			t.Fatalf("metric family %q has no metrics", familyName)
		}
		names := make([]string, 0, len(family.Metric[0].Label))
		for _, label := range family.Metric[0].Label {
			names = append(names, label.GetName())
		}
		sort.Strings(names)
		return names
	}
	t.Fatalf("metric family %q not found", familyName)
	return nil
}

func hasLabel(labelNames []string, want string) bool {
	for _, name := range labelNames {
		if name == want {
			return true
		}
	}
	return false
}

// TestDirectObserveUpdatesHistogram verifies that events update
// Prometheus histogram metrics directly (no aggregator buffering).
func TestDirectObserveUpdatesHistogram(t *testing.T) {
	t.Parallel()

	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil, false, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	resolver := testResolver()
	inflight := NewInflightTracker(exporter.Inflight, false, true)

	events := []Event{
		{Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd", DurationUS: 250, SizeBytes: 1024, MountPath: "/mnt/lustre", FSName: "lustrefs"},
		{Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd", DurationUS: 500, SizeBytes: 2048, MountPath: "/mnt/lustre", FSName: "lustrefs"},
		{Plane: PlanePtlRPC, Op: OpQueueWait, UID: 1001, PID: 123, Comm: "dd", DurationUS: 75, MountPath: "/mnt/lustre", FSName: "lustrefs"},
		{Plane: PlanePtlRPC, Op: OpSendNewReq, UID: 1001, PID: 123, Comm: "dd", MountPath: "/mnt/lustre", FSName: "lustrefs"},
		{Plane: PlanePtlRPC, Op: OpFreeReq, UID: 1001, PID: 123, Comm: "dd", MountPath: "/mnt/lustre", FSName: "lustrefs"},
	}
	for _, event := range events {
		processEvent(event, event.Comm, exporter, inflight, resolver, testSlurmResolver())
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

	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil, false, true, true, false)
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
	inflight := NewInflightTracker(exporter.Inflight, true, true)

	events := []Event{
		{Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 555, Comm: "dd", DurationUS: 250, SizeBytes: 1024, MountPath: "/mnt/lustre", FSName: "lustrefs"},
		{Plane: PlanePtlRPC, Op: OpSendNewReq, UID: 1001, PID: 555, Comm: "dd", MountPath: "/mnt/lustre", FSName: "lustrefs"},
	}
	for _, event := range events {
		processEvent(event, event.Comm, exporter, inflight, resolver, slurmResolver)
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

// TestDirectObserveSlurmDisabledAbsentsLabel verifies that when slurmEnabled=false,
// the slurm_job_id label is completely absent from the rendered metrics output.
func TestDirectObserveSlurmDisabledAbsentsLabel(t *testing.T) {
	t.Parallel()

	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil, false, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	resolver := testResolver()
	inflight := NewInflightTracker(exporter.Inflight, false, true)

	processEvent(Event{
		Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 555, Comm: "dd",
		DurationUS: 250, SizeBytes: 1024, MountPath: "/mnt/lustre", FSName: "lustrefs",
	}, "dd", exporter, inflight, resolver, testSlurmResolver())

	text, err := exporter.RenderText()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, "slurm_job_id") {
		t.Fatalf("expected slurm_job_id to be absent when slurmEnabled=false, got: %s", text)
	}
}

// TestDirectObserveUIDDisabledAbsentsLabels verifies that when uidEnabled=false,
// the uid and username labels are completely absent from the rendered metrics
// output, and the UsernameResolver is never consulted on the hot path.
func TestDirectObserveUIDDisabledAbsentsLabels(t *testing.T) {
	t.Parallel()

	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil, false, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	// Freshly constructed resolver: its cache must stay empty if the
	// hot path correctly skips Resolve() when uidEnabled=false.
	resolver := NewUsernameResolver()
	inflight := NewInflightTracker(exporter.Inflight, false, false)

	events := []Event{
		{Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd", DurationUS: 250, SizeBytes: 1024, MountPath: "/mnt/lustre", FSName: "lustrefs"},
		{Plane: PlanePtlRPC, Op: OpQueueWait, UID: 1001, PID: 123, Comm: "dd", DurationUS: 75, MountPath: "/mnt/lustre", FSName: "lustrefs"},
		{Plane: PlanePtlRPC, Op: OpSendNewReq, UID: 1001, PID: 123, Comm: "dd", MountPath: "/mnt/lustre", FSName: "lustrefs"},
	}
	for _, event := range events {
		processEvent(event, event.Comm, exporter, inflight, resolver, testSlurmResolver())
	}

	text, err := exporter.RenderText()
	if err != nil {
		t.Fatal(err)
	}
	for _, lbl := range []string{"uid=", "username="} {
		if strings.Contains(text, lbl) {
			t.Fatalf("expected %q to be absent when uidEnabled=false, got: %s", lbl, text)
		}
	}
	// Resolve() must not have been called — otherwise either the cache or
	// the perf-event path is bypassing the uidEnabled guard.
	resolver.mu.RLock()
	cacheLen := len(resolver.cache)
	resolver.mu.RUnlock()
	if cacheLen != 0 {
		t.Fatalf("UsernameResolver was called unexpectedly (cache size=%d)", cacheLen)
	}
}

// TestDirectObserveSkipsZeroDuration verifies zero-duration events
// do not produce histogram observations.
func TestDirectObserveSkipsZeroDuration(t *testing.T) {
	t.Parallel()

	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil, false, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	resolver := testResolver()
	inflight := NewInflightTracker(exporter.Inflight, false, true)

	processEvent(Event{Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd", DurationUS: 0, SizeBytes: 0, MountPath: "/mnt/lustre", FSName: "lustrefs"}, "dd", exporter, inflight, resolver, testSlurmResolver())

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
		buildBaseLabels(true, true),
	)
	tracker := NewInflightTracker(gauge, true, true)

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
		buildBaseLabels(true, true),
	)
	tracker := NewInflightTracker(gauge, true, true)

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

	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil, false, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	resolver := testResolver()
	inflight := NewInflightTracker(exporter.Inflight, false, true)

	// Feed events through the direct pipeline
	processEvent(Event{
		Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd",
		DurationUS: 250, SizeBytes: 1024, MountPath: "/mnt/lustre", FSName: "lustrefs",
	}, "dd", exporter, inflight, resolver, testSlurmResolver())

	processEvent(Event{
		Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd",
		DurationUS: 500, SizeBytes: 2048, MountPath: "/mnt/lustre", FSName: "lustrefs",
	}, "dd", exporter, inflight, resolver, testSlurmResolver())

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

func TestErrnoClassName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw  uint8
		want string
	}{
		{rawErrnoClassNone, ""},
		{rawErrnoClassTimeout, ErrnoClassTimeout},
		{rawErrnoClassNotconn, ErrnoClassNotconn},
		{rawErrnoClassPerm, ErrnoClassPerm},
		{rawErrnoClassNotfound, ErrnoClassNotfound},
		{rawErrnoClassIO, ErrnoClassIO},
		{rawErrnoClassAgain, ErrnoClassAgain},
		{rawErrnoClassOther, ErrnoClassOther},
		{255, ErrnoClassOther},
	}
	for _, tc := range cases {
		if got := errnoClassName(tc.raw); got != tc.want {
			t.Errorf("errnoClassName(%d) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestRpcEventTypeName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw  uint8
		want string
	}{
		{rawRPCEventResend, RPCEventResend},
		{rawRPCEventRestart, RPCEventRestart},
		{rawRPCEventExpire, RPCEventExpire},
		{rawRPCEventNotconn, RPCEventNotconn},
		{0, ""},
		{99, ""},
	}
	for _, tc := range cases {
		if got := rpcEventTypeName(tc.raw); got != tc.want {
			t.Errorf("rpcEventTypeName(%d) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestParseObserverEventErrnoClass(t *testing.T) {
	t.Parallel()

	sample := make([]byte, 64)
	sample[0] = rawPlaneLLite
	sample[1] = rawOpOpen
	sample[2] = rawErrnoClassNotfound
	binary.LittleEndian.PutUint32(sample[8:12], 1001)
	binary.LittleEndian.PutUint32(sample[12:16], 4321)
	binary.LittleEndian.PutUint32(sample[16:20], 0)
	binary.LittleEndian.PutUint64(sample[24:32], 100)
	copy(sample[48:64], []byte("cat\x00"))

	event, err := parseObserverEvent(sample)
	if err != nil {
		t.Fatal(err)
	}
	if event.ErrnoClass != ErrnoClassNotfound {
		t.Fatalf("expected errno_class=%q, got %q", ErrnoClassNotfound, event.ErrnoClass)
	}
	if event.Op != OpOpen {
		t.Fatalf("expected op=%q, got %q", OpOpen, event.Op)
	}
}

func TestParseObserverEventErrnoClassZero(t *testing.T) {
	t.Parallel()

	sample := make([]byte, 64)
	sample[0] = rawPlaneLLite
	sample[1] = rawOpWrite
	// sample[2] = 0 (default, no error)
	binary.LittleEndian.PutUint32(sample[8:12], 1001)
	binary.LittleEndian.PutUint64(sample[24:32], 250)
	copy(sample[48:64], []byte("dd\x00"))

	event, err := parseObserverEvent(sample)
	if err != nil {
		t.Fatal(err)
	}
	if event.ErrnoClass != "" {
		t.Fatalf("expected empty errno_class for success, got %q", event.ErrnoClass)
	}
}

func TestBpfErrorAggKeySize(t *testing.T) {
	t.Parallel()

	var key bpfErrorAggKey
	size := int(unsafe.Sizeof(key))
	if size != 32 {
		t.Fatalf("bpfErrorAggKey size = %d, want 32 (must match BPF struct)", size)
	}
}

func TestBpfErrorCounterValSize(t *testing.T) {
	t.Parallel()

	var val bpfErrorCounterVal
	size := int(unsafe.Sizeof(val))
	if size != 8 {
		t.Fatalf("bpfErrorCounterVal size = %d, want 8 (must match BPF struct)", size)
	}
}

// TestPtlRPCStartedCompletedCounters verifies that OpSendNewReq and OpFreeReq
// events increment the started and completed counters monotonically, while
// the inflight gauge reflects the net difference. Counter values must persist
// even after the inflight gauge clamps at zero.
func TestPtlRPCStartedCompletedCounters(t *testing.T) {
	t.Parallel()

	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil, false, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	resolver := testResolver()
	slurmResolver := testSlurmResolver()
	inflight := NewInflightTracker(exporter.Inflight, false, true)

	sendEvt := Event{Plane: PlanePtlRPC, Op: OpSendNewReq, UID: 1001, PID: 123, Comm: "dd", MountPath: "/mnt/lustre", FSName: "lustrefs"}
	freeEvt := Event{Plane: PlanePtlRPC, Op: OpFreeReq, UID: 1001, PID: 123, Comm: "dd", MountPath: "/mnt/lustre", FSName: "lustrefs"}

	// 3 sends, 2 frees → started=3, completed=2, inflight=1
	processEvent(sendEvt, sendEvt.Comm, exporter, inflight, resolver, slurmResolver)
	processEvent(sendEvt, sendEvt.Comm, exporter, inflight, resolver, slurmResolver)
	processEvent(sendEvt, sendEvt.Comm, exporter, inflight, resolver, slurmResolver)
	processEvent(freeEvt, freeEvt.Comm, exporter, inflight, resolver, slurmResolver)
	processEvent(freeEvt, freeEvt.Comm, exporter, inflight, resolver, slurmResolver)

	// Positional order matches baseLabelsNoSlurm (slurmEnabled=false).
	labels := []string{"lustrefs", "/mnt/lustre", "1001", "testuser", "dd", "user"}
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
	processEvent(freeEvt, freeEvt.Comm, exporter, inflight, resolver, slurmResolver)
	processEvent(freeEvt, freeEvt.Comm, exporter, inflight, resolver, slurmResolver)

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

// ---------- PCC tests ----------

func TestPlaneNamePCC(t *testing.T) {
	t.Parallel()
	name, err := planeName(rawPlanePCC)
	if err != nil {
		t.Fatal(err)
	}
	if name != PlanePCC {
		t.Fatalf("expected %q, got %q", PlanePCC, name)
	}
}

func TestOpNamePCCCodes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		raw  uint8
		want string
	}{
		{rawOpPCCRead, OpRead},
		{rawOpPCCWrite, OpWrite},
		{rawOpPCCOpen, OpOpen},
		{rawOpPCCLookup, OpLookup},
		{rawOpPCCFsync, OpFsync},
		{rawOpPCCAttach, OpPCCAttach},
		{rawOpPCCDetach, OpPCCDetach},
		{rawOpPCCInvalidate, OpPCCInvalidate},
	}
	for _, tt := range tests {
		got, err := opName(tt.raw)
		if err != nil {
			t.Fatalf("opName(%d): %v", tt.raw, err)
		}
		if got != tt.want {
			t.Fatalf("opName(%d) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestParseObserverEventPCC(t *testing.T) {
	t.Parallel()
	sample := make([]byte, 64)
	sample[0] = rawPlanePCC
	sample[1] = rawOpPCCRead
	sample[2] = rawErrnoClassNone
	binary.LittleEndian.PutUint32(sample[8:12], 1001)
	binary.LittleEndian.PutUint32(sample[12:16], 4321)
	binary.LittleEndian.PutUint32(sample[16:20], 0)
	binary.LittleEndian.PutUint64(sample[24:32], 150)
	binary.LittleEndian.PutUint64(sample[32:40], 8192)
	copy(sample[48:64], []byte("cp\x00"))

	event, err := parseObserverEvent(sample)
	if err != nil {
		t.Fatal(err)
	}
	if event.Plane != PlanePCC {
		t.Fatalf("expected plane %q, got %q", PlanePCC, event.Plane)
	}
	if event.Op != OpRead {
		t.Fatalf("expected op %q, got %q", OpRead, event.Op)
	}
	if event.DurationUS != 150 {
		t.Fatalf("expected duration 150, got %d", event.DurationUS)
	}
	if event.SizeBytes != 8192 {
		t.Fatalf("expected size 8192, got %d", event.SizeBytes)
	}
	if event.Comm != "cp" {
		t.Fatalf("expected comm %q, got %q", "cp", event.Comm)
	}
}

func TestDirectObservePCCHistogram(t *testing.T) {
	t.Parallel()
	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil, true, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	resolver := testResolver()
	inflight := NewInflightTracker(exporter.Inflight, false, true)
	slurmResolver := testSlurmResolver()

	events := []Event{
		{Plane: PlanePCC, Op: OpRead, UID: 1001, PID: 123, Comm: "cp", DurationUS: 100, SizeBytes: 4096, MountPath: "/mnt/lustre", FSName: "lustrefs"},
		{Plane: PlanePCC, Op: OpWrite, UID: 1001, PID: 123, Comm: "cp", DurationUS: 200, SizeBytes: 8192, MountPath: "/mnt/lustre", FSName: "lustrefs"},
	}
	for _, event := range events {
		processEvent(event, event.Comm, exporter, inflight, resolver, slurmResolver)
	}

	text, err := exporter.RenderText()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "lustre_client_pcc_operation_duration_seconds_bucket") {
		t.Fatalf("missing PCC histogram family: %s", text)
	}
}

func TestPCCSkipsZeroDuration(t *testing.T) {
	t.Parallel()
	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil, true, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	resolver := testResolver()
	inflight := NewInflightTracker(exporter.Inflight, false, true)
	slurmResolver := testSlurmResolver()

	event := Event{Plane: PlanePCC, Op: OpRead, UID: 1001, PID: 123, Comm: "cp", DurationUS: 0, SizeBytes: 4096, MountPath: "/mnt/lustre", FSName: "lustrefs"}
	processEvent(event, event.Comm, exporter, inflight, resolver, slurmResolver)

	text, err := exporter.RenderText()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, "lustre_client_pcc_operation_duration_seconds_bucket") {
		t.Fatalf("zero-duration PCC event should not produce histogram observation: %s", text)
	}
}

func TestPCCAttachDecoding(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		requestPtr  uint64
		wantMode    string
		wantTrigger string
	}{
		{"ro_manual", (1 << 8) | 1, PCCModeRO, PCCTriggerManual},
		{"rw_auto", (2 << 8) | 2, PCCModeRW, PCCTriggerAuto},
		{"ro_auto", (1 << 8) | 2, PCCModeRO, PCCTriggerAuto},
		{"unknown_mode", (0 << 8) | 1, "unknown", PCCTriggerManual},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode, trigger := DecodePCCAttachInfo(tt.requestPtr)
			if mode != tt.wantMode {
				t.Fatalf("mode: got %q, want %q", mode, tt.wantMode)
			}
			if trigger != tt.wantTrigger {
				t.Fatalf("trigger: got %q, want %q", trigger, tt.wantTrigger)
			}
		})
	}
}

func TestPCCAttachEvent(t *testing.T) {
	t.Parallel()
	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil, true, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	resolver := testResolver()
	inflight := NewInflightTracker(exporter.Inflight, false, true)
	slurmResolver := testSlurmResolver()

	// Successful RO auto-attach.
	attachEvent := Event{
		Plane: PlanePCC, Op: OpPCCAttach, UID: 1001, PID: 123, Comm: "cp",
		DurationUS: 50, RequestPtr: (1 << 8) | 2, // mode=RO, trigger=auto
		MountPath: "/mnt/lustre", FSName: "lustrefs",
	}
	processEvent(attachEvent, attachEvent.Comm, exporter, inflight, resolver, slurmResolver)

	// Failed RW manual-attach.
	failedAttach := Event{
		Plane: PlanePCC, Op: OpPCCAttach, UID: 1001, PID: 123, Comm: "cp",
		DurationUS: 30, RequestPtr: (2 << 8) | 1, // mode=RW, trigger=manual
		ErrnoClass: ErrnoClassIO,
		MountPath:  "/mnt/lustre", FSName: "lustrefs",
	}
	processEvent(failedAttach, failedAttach.Comm, exporter, inflight, resolver, slurmResolver)

	text, err := exporter.RenderText()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "lustre_client_pcc_attach_total") {
		t.Fatalf("missing pcc_attach_total: %s", text)
	}
	if !strings.Contains(text, "lustre_client_pcc_attach_failures_total") {
		t.Fatalf("missing pcc_attach_failures_total: %s", text)
	}
	if !strings.Contains(text, `mode="ro"`) {
		t.Fatalf("missing mode=ro label: %s", text)
	}
	if !strings.Contains(text, `trigger="auto"`) {
		t.Fatalf("missing trigger=auto label: %s", text)
	}
}

func TestPCCDetachAndInvalidateEvents(t *testing.T) {
	t.Parallel()
	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil, true, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	resolver := testResolver()
	inflight := NewInflightTracker(exporter.Inflight, false, true)
	slurmResolver := testSlurmResolver()

	detachEvent := Event{
		Plane: PlanePCC, Op: OpPCCDetach, UID: 1001, PID: 123, Comm: "lfs",
		MountPath: "/mnt/lustre", FSName: "lustrefs",
	}
	invalidateEvent := Event{
		Plane: PlanePCC, Op: OpPCCInvalidate, UID: 1001, PID: 123, Comm: "lustre",
		MountPath: "/mnt/lustre", FSName: "lustrefs",
	}
	processEvent(detachEvent, detachEvent.Comm, exporter, inflight, resolver, slurmResolver)
	processEvent(invalidateEvent, invalidateEvent.Comm, exporter, inflight, resolver, slurmResolver)

	text, err := exporter.RenderText()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "lustre_client_pcc_detach_total") {
		t.Fatalf("missing pcc_detach_total: %s", text)
	}
	if !strings.Contains(text, "lustre_client_pcc_layout_invalidations_total") {
		t.Fatalf("missing pcc_layout_invalidations_total: %s", text)
	}
}

func TestHistogramProcessLabelsDisabledByDefault(t *testing.T) {
	t.Parallel()

	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil, true, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	resolver := testResolver()
	inflight := NewInflightTracker(exporter.Inflight, false, true)
	slurmResolver := testSlurmResolver()

	processEvent(Event{
		Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd",
		DurationUS: 250, MountPath: "/mnt/lustre", FSName: "lustrefs",
	}, "dd", exporter, inflight, resolver, slurmResolver)
	processEvent(Event{
		Plane: PlanePtlRPC, Op: OpQueueWait, UID: 1001, PID: 123, Comm: "dd",
		DurationUS: 75, MountPath: "/mnt/lustre", FSName: "lustrefs",
	}, "dd", exporter, inflight, resolver, slurmResolver)
	processEvent(Event{
		Plane: PlanePCC, Op: OpRead, UID: 1001, PID: 123, Comm: "cp",
		DurationUS: 100, MountPath: "/mnt/lustre", FSName: "lustrefs",
	}, "cp", exporter, inflight, resolver, slurmResolver)

	for _, familyName := range []string{
		"lustre_client_access_duration_seconds",
		"lustre_client_rpc_wait_duration_seconds",
		"lustre_client_pcc_operation_duration_seconds",
	} {
		labelNames := labelNamesForMetricFamily(t, exporter, familyName)
		if hasLabel(labelNames, "process") {
			t.Fatalf("%s unexpectedly contains process label: %v", familyName, labelNames)
		}
		if !hasLabel(labelNames, "actor_type") {
			t.Fatalf("%s missing actor_type label: %v", familyName, labelNames)
		}
	}
}

func TestHistogramProcessLabelsCanBeReEnabled(t *testing.T) {
	t.Parallel()

	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil, true, false, true, true)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	resolver := testResolver()
	inflight := NewInflightTracker(exporter.Inflight, false, true)
	slurmResolver := testSlurmResolver()

	processEvent(Event{
		Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd",
		DurationUS: 250, MountPath: "/mnt/lustre", FSName: "lustrefs",
	}, "dd", exporter, inflight, resolver, slurmResolver)
	processEvent(Event{
		Plane: PlanePtlRPC, Op: OpQueueWait, UID: 1001, PID: 123, Comm: "dd",
		DurationUS: 75, MountPath: "/mnt/lustre", FSName: "lustrefs",
	}, "dd", exporter, inflight, resolver, slurmResolver)
	processEvent(Event{
		Plane: PlanePCC, Op: OpRead, UID: 1001, PID: 123, Comm: "cp",
		DurationUS: 100, MountPath: "/mnt/lustre", FSName: "lustrefs",
	}, "cp", exporter, inflight, resolver, slurmResolver)

	for _, familyName := range []string{
		"lustre_client_access_duration_seconds",
		"lustre_client_rpc_wait_duration_seconds",
		"lustre_client_pcc_operation_duration_seconds",
	} {
		labelNames := labelNamesForMetricFamily(t, exporter, familyName)
		if !hasLabel(labelNames, "process") {
			t.Fatalf("histogram process label was not restored for %s: %v", familyName, labelNames)
		}
	}
}

func TestDirectObserveDoesNotExposeDurationTotalCounters(t *testing.T) {
	t.Parallel()

	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil, true, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	resolver := testResolver()
	inflight := NewInflightTracker(exporter.Inflight, false, true)
	slurmResolver := testSlurmResolver()

	processEvent(Event{
		Plane: PlaneLLite, Op: OpWrite, UID: 1001, PID: 123, Comm: "dd",
		DurationUS: 250, MountPath: "/mnt/lustre", FSName: "lustrefs",
	}, "dd", exporter, inflight, resolver, slurmResolver)
	processEvent(Event{
		Plane: PlanePtlRPC, Op: OpQueueWait, UID: 1001, PID: 123, Comm: "dd",
		DurationUS: 75, MountPath: "/mnt/lustre", FSName: "lustrefs",
	}, "dd", exporter, inflight, resolver, slurmResolver)
	processEvent(Event{
		Plane: PlanePCC, Op: OpRead, UID: 1001, PID: 123, Comm: "cp",
		DurationUS: 100, MountPath: "/mnt/lustre", FSName: "lustrefs",
	}, "cp", exporter, inflight, resolver, slurmResolver)

	text, err := exporter.RenderText()
	if err != nil {
		t.Fatal(err)
	}
	for _, familyName := range []string{
		"lustre_client_access_duration_seconds_total",
		"lustre_client_rpc_wait_duration_seconds_total",
		"lustre_client_pcc_operation_duration_seconds_total",
	} {
		if strings.Contains(text, familyName) {
			t.Fatalf("%s should not be exposed: %s", familyName, text)
		}
	}
}
