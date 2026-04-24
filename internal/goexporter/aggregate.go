package goexporter

import (
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// InflightTracker tracks in-flight PtlRPC requests with zero-clamping
// and updates a Prometheus GaugeVec. Thread-safe.
type InflightTracker struct {
	mu           sync.Mutex
	counts       map[string]float64
	gauge        *prometheus.GaugeVec
	slurmEnabled bool
	uidEnabled   bool
}

func NewInflightTracker(gauge *prometheus.GaugeVec, slurmEnabled, uidEnabled bool) *InflightTracker {
	return &InflightTracker{
		counts:       map[string]float64{},
		gauge:        gauge,
		slurmEnabled: slurmEnabled,
		uidEnabled:   uidEnabled,
	}
}

// Update adjusts the inflight count for the given event by delta (+1 or -1),
// clamps at zero, and updates the Prometheus gauge. Identity fields must
// be pre-resolved by the caller (typically via resolveEventIdentity) so the
// hot path does not pay for username/slurm lookups twice when the caller
// also needs them for sibling counters.
func (t *InflightTracker) Update(delta float64, event Event, uid, username, actorType, slurmJobID string) {
	vals := baseLabelValues(event, uid, username, actorType, slurmJobID, t.slurmEnabled, t.uidEnabled)
	// The positional arity already encodes both toggles (slurm × uid) so the
	// label-values slice doubles as a collision-free cache key.
	key := joinLabelKey(vals...)

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

	t.gauge.WithLabelValues(vals...).Set(val)
}

// appendUIDValues mirrors appendUIDLabels in prometheus.go on the values
// side: keeping the label-name and label-value shapers symmetric makes it
// impossible for one to drift without breaking the arity invariant.
func appendUIDValues(dst []string, uid, username string, uidEnabled bool) []string {
	if uidEnabled {
		return append(dst, uid, username)
	}
	return dst
}

func appendSlurmValue(dst []string, slurmJobID string, slurmEnabled bool) []string {
	if slurmEnabled {
		return append(dst, slurmJobID)
	}
	return dst
}

func appendProcessValue(dst []string, process string, processEnabled bool) []string {
	if processEnabled {
		return append(dst, process)
	}
	return dst
}

// baseLabelValues returns label values matching buildBaseLabels(slurmEnabled, uidEnabled).
// Centralizing this prevents drift between the gauge, counters, and any
// future metric that shares the base label schema.
func baseLabelValues(event Event, uid, username, actorType, slurmJobID string, slurmEnabled, uidEnabled bool) []string {
	vals := []string{event.FSName, event.MountPath}
	vals = appendUIDValues(vals, uid, username, uidEnabled)
	vals = append(vals, event.Comm, actorType)
	return appendSlurmValue(vals, slurmJobID, slurmEnabled)
}

func lliteLabelValues(fsName, mountPath, intent, op, uid, username, comm, actorType, slurmJobID string, slurmEnabled, uidEnabled bool) []string {
	vals := []string{fsName, mountPath, intent, op}
	vals = appendUIDValues(vals, uid, username, uidEnabled)
	vals = append(vals, comm, actorType)
	return appendSlurmValue(vals, slurmJobID, slurmEnabled)
}

func lliteHistogramLabelValues(fsName, mountPath, intent, op, uid, username, comm, actorType, slurmJobID string, slurmEnabled, uidEnabled, processEnabled bool) []string {
	vals := []string{fsName, mountPath, intent, op}
	vals = appendUIDValues(vals, uid, username, uidEnabled)
	vals = appendProcessValue(vals, comm, processEnabled)
	vals = append(vals, actorType)
	return appendSlurmValue(vals, slurmJobID, slurmEnabled)
}

func ptlrpcLabelValues(fsName, mountPath, op, uid, username, comm, actorType, slurmJobID string, slurmEnabled, uidEnabled bool) []string {
	vals := []string{fsName, mountPath, op}
	vals = appendUIDValues(vals, uid, username, uidEnabled)
	vals = append(vals, comm, actorType)
	return appendSlurmValue(vals, slurmJobID, slurmEnabled)
}

func ptlrpcHistogramLabelValues(fsName, mountPath, op, uid, username, comm, actorType, slurmJobID string, slurmEnabled, uidEnabled, processEnabled bool) []string {
	vals := []string{fsName, mountPath, op}
	vals = appendUIDValues(vals, uid, username, uidEnabled)
	vals = appendProcessValue(vals, comm, processEnabled)
	vals = append(vals, actorType)
	return appendSlurmValue(vals, slurmJobID, slurmEnabled)
}

// labelKeySep is used to join positional label values into a cache key.
// Null bytes cannot legitimately appear inside label values sourced from
// /proc, sanitized comms, or numeric ids, so collisions are impossible as
// long as every call site uses the same arity.
const labelKeySep = "\x00"

// joinLabelKey concatenates label values with labelKeySep using a
// strings.Builder, avoiding the intermediate slice allocation of
// strings.Join.
func joinLabelKey(parts ...string) string {
	n := len(parts) - 1 // separators
	for _, p := range parts {
		n += len(p)
	}
	var b strings.Builder
	b.Grow(n)
	for i, p := range parts {
		if i > 0 {
			b.WriteString(labelKeySep)
		}
		b.WriteString(p)
	}
	return b.String()
}
