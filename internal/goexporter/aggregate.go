package goexporter

import (
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// InflightTracker tracks in-flight PtlRPC requests with zero-clamping
// and updates a Prometheus GaugeVec. Thread-safe.
type InflightTracker struct {
	mu     sync.Mutex
	counts map[string]float64
	gauge  *prometheus.GaugeVec
}

func NewInflightTracker(gauge *prometheus.GaugeVec) *InflightTracker {
	return &InflightTracker{
		counts: map[string]float64{},
		gauge:  gauge,
	}
}

// Update adjusts the inflight count for the given event by delta (+1 or -1),
// clamps at zero, and updates the Prometheus gauge. Identity fields must
// be pre-resolved by the caller (typically via resolveEventIdentity) so the
// hot path does not pay for username/slurm lookups twice when the caller
// also needs them for sibling counters.
func (t *InflightTracker) Update(delta float64, event Event, uid, username, actorType, slurmJobID string) {
	key := joinLabelKey(event.FSName, event.MountPath, uid, username, event.Comm, actorType, slurmJobID)

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

	t.gauge.WithLabelValues(baseLabelValues(event, uid, username, actorType, slurmJobID)...).Set(val)
}

// baseLabelValues returns label values in baseLabels positional order.
// Centralizing this prevents drift between the gauge, counters, and any
// future metric that shares the base label schema.
func baseLabelValues(event Event, uid, username, actorType, slurmJobID string) []string {
	return []string{event.FSName, event.MountPath, uid, username, event.Comm, actorType, slurmJobID}
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

