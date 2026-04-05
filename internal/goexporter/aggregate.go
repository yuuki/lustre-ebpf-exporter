package goexporter

import "sort"

type Aggregator struct {
	counters   map[string]float64
	histograms map[string][]float64
	attrs      map[string]map[string]string
}

func NewAggregator() *Aggregator {
	return &Aggregator{
		counters:   map[string]float64{},
		histograms: map[string][]float64{},
		attrs:      map[string]map[string]string{},
	}
}

func (a *Aggregator) Consume(event Event) {
	baseAttrs := map[string]string{
		"user.id":           formatUint32(event.UID),
		"process.name":      event.Comm,
		"lustre.actor.type": ClassifyActorType(event.Comm),
	}

	if event.Plane == PlaneLLite {
		accessClass := AccessClassForOp(event.Op)
		if accessClass == "" {
			return
		}
		attrs := mergeAttrs(baseAttrs, map[string]string{
			"lustre.access.class": accessClass,
			"lustre.access.op":    event.Op,
		})
		a.addCounter("lustre.client.access.operations", 1, attrs)
		a.addHistogram("lustre.client.access.duration", float64(event.DurationUS), attrs)
		if accessClass == "data" {
			a.addCounter("lustre.client.data.bytes", float64(event.SizeBytes), attrs)
		}
		return
	}

	if event.Plane != PlanePtlRPC {
		return
	}
	if event.Op == OpQueueWait {
		attrs := mergeAttrs(baseAttrs, map[string]string{
			"lustre.access.op": event.Op,
		})
		a.addCounter("lustre.client.rpc.wait.operations", 1, attrs)
		if event.DurationUS > 0 {
			a.addHistogram("lustre.client.rpc.wait.duration", float64(event.DurationUS), attrs)
		}
		return
	}
	attrs := baseAttrs
	switch event.Op {
	case OpSendNewReq:
		a.addCounter("lustre.client.inflight.requests", 1, attrs)
	case OpFreeReq:
		a.addCounter("lustre.client.inflight.requests", -1, attrs)
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
		metricType := "counter"
		if name == "lustre.client.inflight.requests" {
			metricType = "updowncounter"
		}
		unit := "1"
		if name == "lustre.client.data.bytes" {
			unit = "By"
		}
		metrics = append(metrics, AggregatedMetric{
			Name:       name,
			Type:       metricType,
			Unit:       unit,
			Value:      a.counters[key],
			Attributes: cloneAttrs(attrs),
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
			Attributes: cloneAttrs(attrs),
		})
	}

	a.counters = map[string]float64{}
	a.histograms = map[string][]float64{}
	a.attrs = map[string]map[string]string{}
	return metrics
}

func (a *Aggregator) addCounter(name string, value float64, attrs map[string]string) {
	key := buildMetricKey(name, attrs)
	a.counters[key] += value
	a.attrs[key] = cloneAttrs(attrs)
}

func (a *Aggregator) addHistogram(name string, value float64, attrs map[string]string) {
	key := buildMetricKey(name, attrs)
	a.histograms[key] = append(a.histograms[key], value)
	a.attrs[key] = cloneAttrs(attrs)
}

func buildMetricKey(name string, attrs map[string]string) string {
	keys := make([]string, 0, len(attrs))
	for key := range attrs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := name
	for _, key := range keys {
		out += "\x00" + key + "\x00" + attrs[key]
	}
	return out
}

func splitMetricKey(key string) (string, map[string]string) {
	parts := stringsSplitNul(key)
	name := parts[0]
	attrs := map[string]string{}
	for i := 1; i+1 < len(parts); i += 2 {
		attrs[parts[i]] = parts[i+1]
	}
	return name, attrs
}

func stringsSplitNul(in string) []string {
	var out []string
	last := 0
	for i := 0; i < len(in); i++ {
		if in[i] != 0 {
			continue
		}
		out = append(out, in[last:i])
		last = i + 1
	}
	out = append(out, in[last:])
	return out
}

func mergeAttrs(left map[string]string, right map[string]string) map[string]string {
	out := cloneAttrs(left)
	for key, value := range right {
		out[key] = value
	}
	return out
}

func cloneAttrs(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func formatUint32(v uint32) string {
	return formatUint64(uint64(v))
}

func formatUint64(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + (v % 10))
		v /= 10
	}
	return string(buf[i:])
}
