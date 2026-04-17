package goexporter

import (
	"context"
	"math"
	"testing"

	dto "github.com/prometheus/client_model/go"
)

func TestWindowedWorkloadCollectorRoutesLowShareActorToOther(t *testing.T) {
	t.Parallel()

	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil, false, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	resolver := testResolver()
	resolver.cache[1002] = "unknown"
	inflight := NewInflightTracker(exporter.Inflight, false, true)

	for i := 0; i < 20; i++ {
		processEvent(Event{
			Plane:      PlaneLLite,
			Op:         OpWrite,
			UID:        1001,
			PID:        123,
			Comm:       "dd",
			DurationUS: 1000,
			SizeBytes:  4 * 1024 * 1024,
			MountPath:  "/mnt/lustre",
			FSName:     "lustrefs",
		}, "dd", exporter, inflight, resolver, testSlurmResolver())
	}
	processEvent(Event{
		Plane:      PlaneLLite,
		Op:         OpWrite,
		UID:        1002,
		PID:        124,
		Comm:       "cat",
		DurationUS: 500,
		SizeBytes:  1 * 1024 * 1024,
		MountPath:  "/mnt/lustre",
		FSName:     "lustrefs",
	}, "cat", exporter, inflight, resolver, testSlurmResolver())

	exporter.FlushWorkloadWindow()

	families, err := exporter.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	ddLabels := map[string]string{
		"fs":            "lustrefs",
		"mount":         "/mnt/lustre",
		"access_intent": IntentDataWrite,
		"uid":           "1001",
		"username":      "testuser",
		"process":       "dd",
		"actor_type":    ActorUser,
		"aggregation":   "individual",
	}
	otherLabels := map[string]string{
		"fs":            "lustrefs",
		"mount":         "/mnt/lustre",
		"access_intent": IntentDataWrite,
		"uid":           "_other",
		"username":      "_other",
		"process":       "_other",
		"actor_type":    ActorUser,
		"aggregation":   "other",
	}
	if got := metricCounterValue(t, families, "lustre_client_relevance_access_operations_total", ddLabels); got != 20 {
		t.Fatalf("dd individual ops = %v, want 20", got)
	}
	if got := metricCounterValue(t, families, "lustre_client_relevance_access_operations_total", otherLabels); got != 1 {
		t.Fatalf("other ops = %v, want 1", got)
	}
	if got := metricCounterValue(t, families, "lustre_client_relevance_data_bytes_total", ddLabels); got != 20*(4*1024*1024) {
		t.Fatalf("dd bytes = %v, want %v", got, 20*(4*1024*1024))
	}
	if got := metricCounterValue(t, families, "lustre_client_relevance_data_bytes_total", otherLabels); got != 1*(1024*1024) {
		t.Fatalf("other bytes = %v, want %v", got, 1*(1024*1024))
	}

	h := metricHistogram(t, families, "lustre_client_relevance_access_duration_seconds", ddLabels)
	if got := h.GetSampleCount(); got != 20 {
		t.Fatalf("dd histogram count = %d, want 20", got)
	}
	if got := h.GetSampleSum(); math.Abs(got-(20*0.001)) > 1e-9 {
		t.Fatalf("dd histogram sum = %v, want %v", got, 20*0.001)
	}

	otherHist := metricHistogram(t, families, "lustre_client_relevance_access_duration_seconds", otherLabels)
	if got := otherHist.GetSampleCount(); got != 1 {
		t.Fatalf("other histogram count = %d, want 1", got)
	}

	if metricExists(families, "lustre_client_relevance_access_operations_total", map[string]string{
		"fs":            "lustrefs",
		"mount":         "/mnt/lustre",
		"access_intent": IntentDataWrite,
		"uid":           "1002",
		"process":       "cat",
		"actor_type":    ActorUser,
		"aggregation":   "individual",
	}) {
		t.Fatal("cat should not survive as an individual series")
	}
}

func TestWindowedWorkloadCollectorKeepsIndividualCountersVisibleOnly(t *testing.T) {
	t.Parallel()

	exporter, err := NewPrometheusExporter("127.0.0.1:0", "/metrics", nil, false, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Shutdown(context.Background())

	resolver := testResolver()
	resolver.cache[1002] = "unknown"
	inflight := NewInflightTracker(exporter.Inflight, false, true)

	// Window 1: cat is tiny and should land in other.
	for i := 0; i < 25; i++ {
		processEvent(Event{
			Plane:      PlaneLLite,
			Op:         OpWrite,
			UID:        1001,
			PID:        123,
			Comm:       "dd",
			DurationUS: 1000,
			SizeBytes:  4 * 1024 * 1024,
			MountPath:  "/mnt/lustre",
			FSName:     "lustrefs",
		}, "dd", exporter, inflight, resolver, testSlurmResolver())
	}
	processEvent(Event{
		Plane:      PlaneLLite,
		Op:         OpWrite,
		UID:        1002,
		PID:        124,
		Comm:       "cat",
		DurationUS: 1000,
		SizeBytes:  4 * 1024 * 1024,
		MountPath:  "/mnt/lustre",
		FSName:     "lustrefs",
	}, "cat", exporter, inflight, resolver, testSlurmResolver())
	exporter.FlushWorkloadWindow()

	// Window 2: cat becomes dominant and should now surface individually.
	for i := 0; i < 30; i++ {
		processEvent(Event{
			Plane:      PlaneLLite,
			Op:         OpWrite,
			UID:        1002,
			PID:        124,
			Comm:       "cat",
			DurationUS: 1000,
			SizeBytes:  4 * 1024 * 1024,
			MountPath:  "/mnt/lustre",
			FSName:     "lustrefs",
		}, "cat", exporter, inflight, resolver, testSlurmResolver())
	}
	processEvent(Event{
		Plane:      PlaneLLite,
		Op:         OpWrite,
		UID:        1001,
		PID:        123,
		Comm:       "dd",
		DurationUS: 1000,
		SizeBytes:  4 * 1024 * 1024,
		MountPath:  "/mnt/lustre",
		FSName:     "lustrefs",
	}, "dd", exporter, inflight, resolver, testSlurmResolver())
	exporter.FlushWorkloadWindow()

	families, err := exporter.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	catIndividual := map[string]string{
		"fs":            "lustrefs",
		"mount":         "/mnt/lustre",
		"access_intent": IntentDataWrite,
		"uid":           "1002",
		"username":      "unknown",
		"process":       "cat",
		"actor_type":    ActorUser,
		"aggregation":   "individual",
	}
	if got := metricCounterValue(t, families, "lustre_client_relevance_access_operations_total", catIndividual); got != 30 {
		t.Fatalf("cat individual ops = %v, want 30", got)
	}

	otherLabels := map[string]string{
		"fs":            "lustrefs",
		"mount":         "/mnt/lustre",
		"access_intent": IntentDataWrite,
		"uid":           "_other",
		"username":      "_other",
		"process":       "_other",
		"actor_type":    ActorUser,
		"aggregation":   "other",
	}
	if got := metricCounterValue(t, families, "lustre_client_relevance_access_operations_total", otherLabels); got != 1 {
		t.Fatalf("other ops = %v, want 1", got)
	}
}

func TestWindowedWorkloadCollectorPurgesHiddenSeriesAfterRetention(t *testing.T) {
	t.Parallel()

	collector := NewWorkloadWindowCollector(WorkloadFilterConfig{
		TopN:             1,
		PromoteWindows:   1,
		DemoteWindows:    1,
		RetentionWindows: 2,
	}, nil, false, true)

	hot := Event{Plane: PlaneLLite, Op: OpWrite, UID: 1001, Comm: "dd", DurationUS: 1000, SizeBytes: 64 * 1024 * 1024, MountPath: "/mnt/lustre", FSName: "lustrefs"}
	cold := Event{Plane: PlaneLLite, Op: OpWrite, UID: 1002, Comm: "cat", DurationUS: 1000, SizeBytes: 64 * 1024 * 1024, MountPath: "/mnt/lustre", FSName: "lustrefs"}

	collector.ObserveAccess(hot, "1001", "testuser", ActorUser, "")
	collector.ObserveAccess(cold, "1002", "unknown", ActorUser, "")
	collector.RotateWindow()

	// cat is hidden and should be purged after enough empty windows.
	for i := 0; i < 3; i++ {
		collector.RotateWindow()
	}

	collector.mu.RLock()
	defer collector.mu.RUnlock()

	catLabels := workloadAccessLabelValues("lustrefs", "/mnt/lustre", IntentDataWrite, "1002", "unknown", "cat", ActorUser, "", aggregationIndividual, false, true)
	key := joinLabelKey(catLabels...)
	if _, ok := collector.accessOpsSeries[key]; ok {
		t.Fatal("expected hidden cat series to be purged after retention window")
	}
	if _, ok := collector.accessState[collector.accessStateKey(accessEntityIntentKey{
		FSName: "lustrefs", MountPath: "/mnt/lustre", Intent: IntentDataWrite, UID: "1002", Username: "unknown", Process: "cat", ActorType: ActorUser,
	})]; ok {
		t.Fatal("expected hidden cat state to be purged after retention window")
	}
}

func metricCounterValue(t *testing.T, families []*dto.MetricFamily, name string, labels map[string]string) float64 {
	t.Helper()

	metric := findMetric(t, families, name, labels)
	return metric.GetCounter().GetValue()
}

func metricHistogram(t *testing.T, families []*dto.MetricFamily, name string, labels map[string]string) *dto.Histogram {
	t.Helper()

	metric := findMetric(t, families, name, labels)
	return metric.GetHistogram()
}

func metricExists(families []*dto.MetricFamily, name string, labels map[string]string) bool {
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if metricHasLabels(metric, labels) {
				return true
			}
		}
	}
	return false
}

func findMetric(t *testing.T, families []*dto.MetricFamily, name string, labels map[string]string) *dto.Metric {
	t.Helper()

	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if metricHasLabels(metric, labels) {
				return metric
			}
		}
	}
	t.Fatalf("metric %s with labels %v not found", name, labels)
	return nil
}

func metricHasLabels(metric *dto.Metric, want map[string]string) bool {
	if len(metric.GetLabel()) != len(want) {
		return false
	}
	for _, label := range metric.GetLabel() {
		gotValue, ok := want[label.GetName()]
		if !ok || gotValue != label.GetValue() {
			return false
		}
	}
	return true
}
