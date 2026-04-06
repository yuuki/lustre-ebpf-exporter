package goexporter

import (
	"sort"
	"strconv"
	"strings"
)

type Aggregator struct {
	counters   map[string]float64
	histograms map[string][]float64
	inflight   map[string]float64 // persistent gauge, not reset on Collect
	resolver   *UsernameResolver
}

func NewAggregator(resolver *UsernameResolver) *Aggregator {
	return &Aggregator{
		counters:   map[string]float64{},
		histograms: map[string][]float64{},
		inflight:   map[string]float64{},
		resolver:   resolver,
	}
}

func (a *Aggregator) Consume(event Event) {
	uid := strconv.FormatUint(uint64(event.UID), 10)
	username := a.resolver.Resolve(event.UID)
	actorType := ClassifyActorType(event.Comm)

	if event.Plane == PlaneLLite {
		intent := AccessIntentForOp(event.Op)
		if intent == "" {
			return
		}
		attrs := map[string]string{
			"user.id":              uid,
			"user.name":            username,
			"process.name":         event.Comm,
			"lustre.actor.type":    actorType,
			"lustre.access.intent": intent,
			"lustre.access.op":    event.Op,
			"lustre.mount.path":   event.MountPath,
			"lustre.fs.name":      event.FSName,
		}
		a.addCounter("lustre.client.access.operations", 1, attrs)
		if event.DurationUS > 0 {
			a.addHistogram("lustre.client.access.duration", float64(event.DurationUS), attrs)
		}
		if event.SizeBytes > 0 {
			a.addCounter("lustre.client.data.bytes", float64(event.SizeBytes), attrs)
		}
		return
	}

	if event.Plane != PlanePtlRPC {
		return
	}
	if event.Op == OpQueueWait {
		attrs := map[string]string{
			"user.id":           uid,
			"user.name":         username,
			"process.name":      event.Comm,
			"lustre.actor.type": actorType,
			"lustre.access.op":  event.Op,
			"lustre.mount.path": event.MountPath,
			"lustre.fs.name":    event.FSName,
		}
		a.addCounter("lustre.client.rpc.wait.operations", 1, attrs)
		if event.DurationUS > 0 {
			a.addHistogram("lustre.client.rpc.wait.duration", float64(event.DurationUS), attrs)
		}
		return
	}
	attrs := map[string]string{
		"user.id":           uid,
		"user.name":         username,
		"process.name":      event.Comm,
		"lustre.actor.type": actorType,
		"lustre.mount.path": event.MountPath,
		"lustre.fs.name":    event.FSName,
	}
	switch event.Op {
	case OpSendNewReq:
		a.updateInflight(1, attrs)
	case OpFreeReq:
		a.updateInflight(-1, attrs)
	}
}

func (a *Aggregator) Collect() []AggregatedMetric {
	metrics := make([]AggregatedMetric, 0, len(a.counters)+len(a.histograms))

	counterKeys := make([]string, 0, len(a.counters))
	for key := range a.counters {
		counterKeys = append(counterKeys, key)
	}
	sort.Strings(counterKeys)
	for _, key := range counterKeys {
		name, attrs := splitMetricKey(key)
		unit := "1"
		if name == "lustre.client.data.bytes" {
			unit = "By"
		}
		metrics = append(metrics, AggregatedMetric{
			Name:       name,
			Type:       "counter",
			Unit:       unit,
			Value:      a.counters[key],
			Attributes: attrs,
		})
	}

	inflightKeys := make([]string, 0, len(a.inflight))
	for key := range a.inflight {
		inflightKeys = append(inflightKeys, key)
	}
	sort.Strings(inflightKeys)
	for _, key := range inflightKeys {
		_, attrs := splitMetricKey(key)
		metrics = append(metrics, AggregatedMetric{
			Name:       "lustre.client.inflight.requests",
			Type:       "gauge",
			Unit:       "1",
			Value:      a.inflight[key],
			Attributes: attrs,
		})
	}

	histKeys := make([]string, 0, len(a.histograms))
	for key := range a.histograms {
		histKeys = append(histKeys, key)
	}
	sort.Strings(histKeys)
	for _, key := range histKeys {
		name, attrs := splitMetricKey(key)
		values := append([]float64(nil), a.histograms[key]...)
		metrics = append(metrics, AggregatedMetric{
			Name:       name,
			Type:       "histogram",
			Unit:       "us",
			Histogram:  values,
			Attributes: attrs,
		})
	}

	a.counters = map[string]float64{}
	a.histograms = map[string][]float64{}
	return metrics
}

func (a *Aggregator) addCounter(name string, value float64, attrs map[string]string) {
	key := buildMetricKey(name, attrs)
	a.counters[key] += value
}

func (a *Aggregator) updateInflight(delta float64, attrs map[string]string) {
	key := buildMetricKey("lustre.client.inflight.requests", attrs)
	a.inflight[key] += delta
	if a.inflight[key] < 0 {
		a.inflight[key] = 0
	}
}

func (a *Aggregator) addHistogram(name string, value float64, attrs map[string]string) {
	key := buildMetricKey(name, attrs)
	a.histograms[key] = append(a.histograms[key], value)
}

func buildMetricKey(name string, attrs map[string]string) string {
	keys := make([]string, 0, len(attrs))
	for key := range attrs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(name)
	for _, key := range keys {
		b.WriteByte(0)
		b.WriteString(key)
		b.WriteByte(0)
		b.WriteString(attrs[key])
	}
	return b.String()
}

func splitMetricKey(key string) (string, map[string]string) {
	parts := strings.Split(key, "\x00")
	name := parts[0]
	attrs := map[string]string{}
	for i := 1; i+1 < len(parts); i += 2 {
		attrs[parts[i]] = parts[i+1]
	}
	return name, attrs
}
