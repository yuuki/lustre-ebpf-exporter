package goexporter

import (
	"context"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
)

// BPFCounterCollector reads aggregated counters from BPF PERCPU_HASH maps
// and implements prometheus.Collector. A background drain goroutine periodically
// reads and deletes BPF map entries, accumulating them in a Go-side map.
// At scrape time, Collect() returns the accumulated values.
type BPFCounterCollector struct {
	mu         sync.Mutex
	lliteMap   *ebpf.Map
	rpcMap     *ebpf.Map
	mountInfos []MountInfo
	resolver   *UsernameResolver

	accumulated map[string]*accumulatedCounter

	accessOpsDesc  *prometheus.Desc
	dataBytesDesc  *prometheus.Desc
	rpcWaitOpsDesc *prometheus.Desc
}

type accumulatedCounter struct {
	opsCount float64
	bytesSum float64
	labels   prometheus.Labels
}

func NewBPFCounterCollector(lliteMap, rpcMap *ebpf.Map, mountInfos []MountInfo, resolver *UsernameResolver) *BPFCounterCollector {
	return &BPFCounterCollector{
		lliteMap:    lliteMap,
		rpcMap:      rpcMap,
		mountInfos:  mountInfos,
		resolver:    resolver,
		accumulated: map[string]*accumulatedCounter{},
		accessOpsDesc: prometheus.NewDesc(
			"lustre_client_access_operations_total",
			"Aggregated llite access operation count",
			lliteLabels, nil,
		),
		dataBytesDesc: prometheus.NewDesc(
			"lustre_client_data_bytes_total",
			"Aggregated llite data volume in bytes",
			lliteLabels, nil,
		),
		rpcWaitOpsDesc: prometheus.NewDesc(
			"lustre_client_rpc_wait_operations_total",
			"Aggregated ptlrpc queue wait count",
			ptlrpcLabels, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *BPFCounterCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.accessOpsDesc
	ch <- c.dataBytesDesc
	ch <- c.rpcWaitOpsDesc
}

// Collect implements prometheus.Collector. Called at scrape time.
func (c *BPFCounterCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, acc := range c.accumulated {
		if _, hasIntent := acc.labels["access_intent"]; hasIntent {
			// llite metrics
			if acc.opsCount > 0 {
				ch <- prometheus.MustNewConstMetric(
					c.accessOpsDesc, prometheus.CounterValue, acc.opsCount,
					acc.labels["fs"], acc.labels["mount"], acc.labels["access_intent"], acc.labels["op"],
					acc.labels["uid"], acc.labels["username"], acc.labels["process"], acc.labels["actor_type"],
				)
			}
			if acc.bytesSum > 0 {
				ch <- prometheus.MustNewConstMetric(
					c.dataBytesDesc, prometheus.CounterValue, acc.bytesSum,
					acc.labels["fs"], acc.labels["mount"], acc.labels["access_intent"], acc.labels["op"],
					acc.labels["uid"], acc.labels["username"], acc.labels["process"], acc.labels["actor_type"],
				)
			}
		} else {
			// ptlrpc metrics
			if acc.opsCount > 0 {
				ch <- prometheus.MustNewConstMetric(
					c.rpcWaitOpsDesc, prometheus.CounterValue, acc.opsCount,
					acc.labels["fs"], acc.labels["mount"], acc.labels["op"],
					acc.labels["uid"], acc.labels["username"], acc.labels["process"], acc.labels["actor_type"],
				)
			}
		}
	}
}

// StartDrain launches a background goroutine that periodically reads BPF maps.
func (c *BPFCounterCollector) StartDrain(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				c.DrainOnce()
				return
			case <-ticker.C:
				c.DrainOnce()
			}
		}
	}()
}

// DrainOnce reads both BPF counter maps and accumulates values.
func (c *BPFCounterCollector) DrainOnce() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.lliteMap != nil {
		c.drainMap(c.lliteMap, true)
	}
	if c.rpcMap != nil {
		c.drainMap(c.rpcMap, false)
	}
}

func (c *BPFCounterCollector) drainMap(m *ebpf.Map, isLLite bool) {
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

		labels := c.buildLabels(key, isLLite)
		accKey := labelsKey(labels)

		acc, ok := c.accumulated[accKey]
		if !ok {
			acc = &accumulatedCounter{labels: labels}
			c.accumulated[accKey] = acc
		}
		acc.opsCount += float64(total.OpsCount)
		if isLLite {
			acc.bytesSum += float64(total.BytesSum)
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
}

func (c *BPFCounterCollector) buildLabels(key bpfAggKey, isLLite bool) prometheus.Labels {
	mountPath := ""
	fsName := ""
	if int(key.MountIdx) < len(c.mountInfos) {
		mi := c.mountInfos[key.MountIdx]
		mountPath = mi.Path
		fsName = mi.FSName
	}

	uid := strconv.FormatUint(uint64(key.UID), 10)
	username := c.resolver.Resolve(key.UID)
	comm := sanitizeComm(key.Comm[:])
	actorType := actorTypeName(key.ActorType)

	if isLLite {
		intent := intentName(key.Intent)
		op := rawOpToName(key.Op)
		return BuildLLitePrometheusLabels(uid, username, comm, actorType, mountPath, fsName, intent, op)
	}

	op := rawOpToName(key.Op)
	return BuildPtlRPCPrometheusLabels(uid, username, comm, actorType, mountPath, fsName, op)
}

func rawOpToName(raw uint8) string {
	name, err := opName(raw)
	if err != nil {
		return ""
	}
	return name
}
