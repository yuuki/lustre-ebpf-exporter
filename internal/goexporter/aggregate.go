package goexporter

import (
	"maps"
	"slices"
	"strconv"
	"strings"
)

type Aggregator struct {
	histograms map[string][]float64
	inflight   map[string]float64 // persistent gauge, not reset on Collect
	resolver   *UsernameResolver
}

func NewAggregator(resolver *UsernameResolver) *Aggregator {
	return &Aggregator{
		histograms: map[string][]float64{},
		inflight:   map[string]float64{},
		resolver:   resolver,
	}
}

func (a *Aggregator) baseAttrs(event Event) map[string]string {
	return map[string]string{
		AttrUserID:      strconv.FormatUint(uint64(event.UID), 10),
		AttrUserName:    a.resolver.Resolve(event.UID),
		AttrProcessName: event.Comm,
		AttrActorType:   ClassifyActorType(event.Comm),
		AttrMountPath:   event.MountPath,
		AttrFSName:      event.FSName,
	}
}

func (a *Aggregator) Consume(event Event) {
	if event.Plane == PlaneLLite {
		intent := AccessIntentForOp(event.Op)
		if intent == "" {
			return
		}
		// Counters (ops_count, bytes_sum) are now authoritative from BPF maps.
		// Only collect histogram samples from perf events.
		if event.DurationUS > 0 {
			attrs := a.baseAttrs(event)
			attrs[AttrAccessIntent] = intent
			attrs[AttrAccessOp] = event.Op
			a.addHistogram(MetricAccessDuration, float64(event.DurationUS), attrs)
		}
		return
	}

	if event.Plane != PlanePtlRPC {
		return
	}
	if event.Op == OpQueueWait {
		// Counter is now authoritative from BPF maps. Only histograms here.
		if event.DurationUS > 0 {
			attrs := a.baseAttrs(event)
			attrs[AttrAccessOp] = event.Op
			a.addHistogram(MetricRPCWaitDuration, float64(event.DurationUS), attrs)
		}
		return
	}
	attrs := a.baseAttrs(event)
	switch event.Op {
	case OpSendNewReq:
		a.updateInflight(1, attrs)
	case OpFreeReq:
		a.updateInflight(-1, attrs)
	}
}

func (a *Aggregator) Collect() []AggregatedMetric {
	metrics := make([]AggregatedMetric, 0, len(a.histograms)+len(a.inflight))

	for _, key := range slices.Sorted(maps.Keys(a.inflight)) {
		_, attrs := splitMetricKey(key)
		metrics = append(metrics, AggregatedMetric{
			Name:       MetricInflight,
			Type:       "gauge",
			Unit:       "1",
			Value:      a.inflight[key],
			Attributes: attrs,
		})
	}
	for key, val := range a.inflight {
		if val == 0 {
			delete(a.inflight, key)
		}
	}

	for _, key := range slices.Sorted(maps.Keys(a.histograms)) {
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

	a.histograms = map[string][]float64{}
	return metrics
}

func (a *Aggregator) updateInflight(delta float64, attrs map[string]string) {
	key := buildMetricKey(MetricInflight, attrs)
	a.inflight[key] += delta
	if a.inflight[key] < 0 {
		a.inflight[key] = 0
	}
}

func (a *Aggregator) addHistogram(name string, value float64, attrs map[string]string) {
	key := buildMetricKey(name, attrs)
	s := a.histograms[key]
	if len(s) >= MaxHistogramSamples {
		return
	}
	a.histograms[key] = append(s, value)
}

func buildMetricKey(name string, attrs map[string]string) string {
	keys := slices.Sorted(maps.Keys(attrs))
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
