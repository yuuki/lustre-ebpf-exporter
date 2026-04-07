package goexporter

import (
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/yuuki/otel-lustre-tracer/internal/goexporter/slurm"
)

// InflightTracker tracks in-flight PtlRPC requests with zero-clamping
// and updates a Prometheus GaugeVec. Thread-safe.
type InflightTracker struct {
	mu       sync.Mutex
	counts   map[string]float64
	gauge    *prometheus.GaugeVec
	resolver *UsernameResolver
	slurm    *slurm.Resolver
}

func NewInflightTracker(gauge *prometheus.GaugeVec, resolver *UsernameResolver, slurmResolver *slurm.Resolver) *InflightTracker {
	return &InflightTracker{
		counts:   map[string]float64{},
		gauge:    gauge,
		resolver: resolver,
		slurm:    slurmResolver,
	}
}

// Update adjusts the inflight count for the given event by delta (+1 or -1),
// clamps at zero, and updates the Prometheus gauge.
func (t *InflightTracker) Update(delta float64, event Event) {
	uid, username, actorType, slurmJobID := resolveEventIdentity(event, t.resolver, t.slurm)
	key := baseLabelKey(event.FSName, event.MountPath, uid, username, event.Comm, actorType, slurmJobID)

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

	t.gauge.WithLabelValues(
		event.FSName, event.MountPath, uid, username, event.Comm, actorType, slurmJobID,
	).Set(val)
}

// labelKeySep is used to join positional label values into a cache key.
// Null bytes cannot legitimately appear inside label values sourced from
// /proc, sanitized comms, or numeric ids, so collisions are impossible as
// long as every call site uses the same arity.
const labelKeySep = "\x00"

// baseLabelKey joins the base label values in baseLabels order (see prometheus.go).
func baseLabelKey(fs, mount, uid, username, process, actorType, slurmJobID string) string {
	total := len(fs) + len(mount) + len(uid) + len(username) + len(process) + len(actorType) + len(slurmJobID) + 6
	var b strings.Builder
	b.Grow(total)
	b.WriteString(fs)
	b.WriteString(labelKeySep)
	b.WriteString(mount)
	b.WriteString(labelKeySep)
	b.WriteString(uid)
	b.WriteString(labelKeySep)
	b.WriteString(username)
	b.WriteString(labelKeySep)
	b.WriteString(process)
	b.WriteString(labelKeySep)
	b.WriteString(actorType)
	b.WriteString(labelKeySep)
	b.WriteString(slurmJobID)
	return b.String()
}
