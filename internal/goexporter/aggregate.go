package goexporter

import (
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// InflightTracker tracks in-flight PtlRPC requests with zero-clamping
// and updates a Prometheus GaugeVec. Thread-safe.
type InflightTracker struct {
	mu       sync.Mutex
	counts   map[string]float64
	gauge    *prometheus.GaugeVec
	resolver *UsernameResolver
}

func NewInflightTracker(gauge *prometheus.GaugeVec, resolver *UsernameResolver) *InflightTracker {
	return &InflightTracker{
		counts:   map[string]float64{},
		gauge:    gauge,
		resolver: resolver,
	}
}

// Update adjusts the inflight count for the given event by delta (+1 or -1),
// clamps at zero, and updates the Prometheus gauge.
func (t *InflightTracker) Update(delta float64, event Event) {
	labels := t.buildBaseLabels(event)
	key := labelsKey(labels)

	t.mu.Lock()
	t.counts[key] += delta
	if t.counts[key] < 0 {
		t.counts[key] = 0
	}
	val := t.counts[key]
	if val == 0 {
		delete(t.counts, key)
	}
	t.mu.Unlock()

	t.gauge.With(labels).Set(val)
}

func (t *InflightTracker) buildBaseLabels(event Event) prometheus.Labels {
	return BuildBasePrometheusLabels(
		strconv.FormatUint(uint64(event.UID), 10),
		t.resolver.Resolve(event.UID),
		event.Comm,
		ClassifyActorType(event.Comm),
		event.MountPath,
		event.FSName,
	)
}

// labelsKey builds a deterministic string key from sorted label key-value pairs.
func labelsKey(labels prometheus.Labels) string {
	keys := slices.Sorted(maps.Keys(labels))
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte(0)
		b.WriteString(labels[k])
		b.WriteByte(0)
	}
	return b.String()
}

// BuildBasePrometheusLabels creates the base label set used by all metric types.
func BuildBasePrometheusLabels(uid, username, comm, actorType, mountPath, fsName string) prometheus.Labels {
	return prometheus.Labels{
		"fs":         fsName,
		"mount":      mountPath,
		"uid":        uid,
		"username":   username,
		"process":    comm,
		"actor_type": actorType,
	}
}

// BuildLLitePrometheusLabels creates the label set for llite metrics (base + intent + op).
func BuildLLitePrometheusLabels(uid, username, comm, actorType, mountPath, fsName, intent, op string) prometheus.Labels {
	return prometheus.Labels{
		"fs":            fsName,
		"mount":         mountPath,
		"access_intent": intent,
		"op":            op,
		"uid":           uid,
		"username":      username,
		"process":       comm,
		"actor_type":    actorType,
	}
}

// BuildPtlRPCPrometheusLabels creates the label set for ptlrpc metrics (base + op).
func BuildPtlRPCPrometheusLabels(uid, username, comm, actorType, mountPath, fsName, op string) prometheus.Labels {
	return prometheus.Labels{
		"fs":         fsName,
		"mount":      mountPath,
		"op":         op,
		"uid":        uid,
		"username":   username,
		"process":    comm,
		"actor_type": actorType,
	}
}

// buildCoreAttrs builds OTel-style attribute maps (used by BPFCounterCollector).
func buildCoreAttrs(uid, username, comm, actorType, mountPath, fsName string) map[string]string {
	return map[string]string{
		AttrUserID:      uid,
		AttrUserName:    username,
		AttrProcessName: comm,
		AttrActorType:   actorType,
		AttrMountPath:   mountPath,
		AttrFSName:      fsName,
	}
}
