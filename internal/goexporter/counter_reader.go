package goexporter

import (
	"log"
	"strconv"

	"github.com/cilium/ebpf"
)

// CounterReader reads aggregated counters from BPF PERCPU_HASH maps.
type CounterReader struct {
	lliteMap   *ebpf.Map
	rpcMap     *ebpf.Map
	mountInfos []MountInfo
	resolver   *UsernameResolver
}

func NewCounterReader(lliteMap, rpcMap *ebpf.Map, mountInfos []MountInfo, resolver *UsernameResolver) *CounterReader {
	return &CounterReader{
		lliteMap:   lliteMap,
		rpcMap:     rpcMap,
		mountInfos: mountInfos,
		resolver:   resolver,
	}
}

// Read iterates both BPF counter maps, sums per-CPU values, and returns
// AggregatedMetric slices for counters. Entries are deleted after reading.
func (r *CounterReader) Read() []AggregatedMetric {
	var metrics []AggregatedMetric
	if r.lliteMap != nil {
		metrics = append(metrics, r.readMap(r.lliteMap, true)...)
	}
	if r.rpcMap != nil {
		metrics = append(metrics, r.readMap(r.rpcMap, false)...)
	}
	return metrics
}

func (r *CounterReader) readMap(m *ebpf.Map, isLLite bool) []AggregatedMetric {
	var metrics []AggregatedMetric
	var keysToDelete []bpfAggKey

	var key bpfAggKey
	var values []bpfCounterVal
	iter := m.Iterate()
	for iter.Next(&key, &values) {
		var total bpfCounterVal
		for _, v := range values {
			total.OpsCount += v.OpsCount
			total.BytesSum += v.BytesSum
		}

		attrs := r.buildAttrs(key)

		if total.OpsCount > 0 {
			metricName := MetricAccessOps
			if !isLLite {
				metricName = MetricRPCWaitOps
			}
			metrics = append(metrics, AggregatedMetric{
				Name:       metricName,
				Type:       "counter",
				Unit:       "1",
				Value:      float64(total.OpsCount),
				Attributes: attrs,
			})
		}

		if isLLite && total.BytesSum > 0 {
			metrics = append(metrics, AggregatedMetric{
				Name:       MetricDataBytes,
				Type:       "counter",
				Unit:       "By",
				Value:      float64(total.BytesSum),
				Attributes: cloneAttrs(attrs),
			})
		}

		keyCopy := key
		keysToDelete = append(keysToDelete, keyCopy)
	}
	if err := iter.Err(); err != nil {
		log.Printf("warning: BPF counter map iteration error: %v", err)
	}

	for i := range keysToDelete {
		if err := m.Delete(&keysToDelete[i]); err != nil {
			log.Printf("warning: BPF counter map delete error: %v", err)
		}
	}

	return metrics
}

func (r *CounterReader) buildAttrs(key bpfAggKey) map[string]string {
	uid := uintToString(key.UID)
	username := r.resolver.Resolve(key.UID)
	comm := sanitizeComm(key.Comm[:])
	actorType := actorTypeName(key.ActorType)
	intent := intentName(key.Intent)
	op := rawOpToName(key.Op)

	mountPath := ""
	fsName := ""
	if int(key.MountIdx) < len(r.mountInfos) {
		mi := r.mountInfos[key.MountIdx]
		mountPath = mi.Path
		fsName = mi.FSName
	}

	attrs := map[string]string{
		AttrUserID:      uid,
		AttrUserName:    username,
		AttrProcessName: comm,
		AttrActorType:   actorType,
		AttrMountPath:   mountPath,
		AttrFSName:      fsName,
	}
	if intent != "" {
		attrs[AttrAccessIntent] = intent
	}
	if op != "" {
		attrs[AttrAccessOp] = op
	}
	return attrs
}

func cloneAttrs(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func rawOpToName(raw uint8) string {
	name, err := opName(raw)
	if err != nil {
		return ""
	}
	return name
}

func uintToString(v uint32) string {
	return strconv.FormatUint(uint64(v), 10)
}
