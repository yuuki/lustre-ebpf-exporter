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

// baseLabelValues returns label values matching buildBaseLabels(slurmEnabled, uidEnabled).
// When !uidEnabled, uid/username are omitted. Centralizing this prevents drift between
// the gauge, counters, and any future metric that shares the base label schema.
func baseLabelValues(event Event, uid, username, actorType, slurmJobID string, slurmEnabled, uidEnabled bool) []string {
	vals := []string{event.FSName, event.MountPath}
	if uidEnabled {
		vals = append(vals, uid, username)
	}
	vals = append(vals, event.Comm, actorType)
	if slurmEnabled {
		vals = append(vals, slurmJobID)
	}
	return vals
}

// lliteLabelValues returns label values matching buildLliteLabels(slurmEnabled, uidEnabled).
func lliteLabelValues(fsName, mountPath, intent, op, uid, username, comm, actorType, slurmJobID string, slurmEnabled, uidEnabled bool) []string {
	vals := []string{fsName, mountPath, intent, op}
	if uidEnabled {
		vals = append(vals, uid, username)
	}
	vals = append(vals, comm, actorType)
	if slurmEnabled {
		vals = append(vals, slurmJobID)
	}
	return vals
}

// ptlrpcLabelValues returns label values matching buildPtlrpcLabels(slurmEnabled, uidEnabled).
func ptlrpcLabelValues(fsName, mountPath, op, uid, username, comm, actorType, slurmJobID string, slurmEnabled, uidEnabled bool) []string {
	vals := []string{fsName, mountPath, op}
	if uidEnabled {
		vals = append(vals, uid, username)
	}
	vals = append(vals, comm, actorType)
	if slurmEnabled {
		vals = append(vals, slurmJobID)
	}
	return vals
}

// pccAttachLabelValues returns label values matching buildPCCAttachLabels(slurmEnabled, uidEnabled).
func pccAttachLabelValues(fsName, mountPath, mode, trigger, uid, username, comm, actorType, slurmJobID string, slurmEnabled, uidEnabled bool) []string {
	vals := []string{fsName, mountPath, mode, trigger}
	if uidEnabled {
		vals = append(vals, uid, username)
	}
	vals = append(vals, comm, actorType)
	if slurmEnabled {
		vals = append(vals, slurmJobID)
	}
	return vals
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

