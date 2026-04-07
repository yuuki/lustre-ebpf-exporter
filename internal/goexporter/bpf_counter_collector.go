package goexporter

import (
	"context"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/yuuki/otel-lustre-tracer/internal/goexporter/slurm"
)

// BPFCounterCollector reads aggregated counters from BPF PERCPU_HASH maps
// and implements prometheus.Collector. A background drain goroutine periodically
// reads and deletes BPF map entries, accumulating them in a Go-side map.
// At scrape time, Collect() returns the accumulated values.
type BPFCounterCollector struct {
	mu         sync.RWMutex
	lliteMap   *ebpf.Map
	rpcMap     *ebpf.Map
	mountInfos []MountInfo
	resolver   *UsernameResolver
	// slurmResolver is accepted for API symmetry with the perf-event path,
	// but counter metrics cannot resolve slurm_job_id: the BPF agg_key is
	// keyed kernel-side without a pid, so by the time userspace drains the
	// map there is no pid to feed into /proc/<pid>/environ. Phase 1 always
	// emits slurm_job_id="" on counters. A Phase 2 design could push the
	// pid->jobid mapping into a BPF LRU map and include job_id in agg_key.
	slurmResolver *slurm.Resolver

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

func NewBPFCounterCollector(lliteMap, rpcMap *ebpf.Map, mountInfos []MountInfo, resolver *UsernameResolver, slurmResolver *slurm.Resolver) *BPFCounterCollector {
	return &BPFCounterCollector{
		lliteMap:      lliteMap,
		rpcMap:        rpcMap,
		mountInfos:    mountInfos,
		resolver:      resolver,
		slurmResolver: slurmResolver,
		accumulated:   map[string]*accumulatedCounter{},
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
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, acc := range c.accumulated {
		if _, hasIntent := acc.labels["access_intent"]; hasIntent {
			// llite metrics
			if acc.opsCount > 0 {
				ch <- prometheus.MustNewConstMetric(
					c.accessOpsDesc, prometheus.CounterValue, acc.opsCount,
					acc.labels["fs"], acc.labels["mount"], acc.labels["access_intent"], acc.labels["op"],
					acc.labels["uid"], acc.labels["username"], acc.labels["process"], acc.labels["actor_type"],
					acc.labels["slurm_job_id"],
				)
			}
			if acc.bytesSum > 0 {
				ch <- prometheus.MustNewConstMetric(
					c.dataBytesDesc, prometheus.CounterValue, acc.bytesSum,
					acc.labels["fs"], acc.labels["mount"], acc.labels["access_intent"], acc.labels["op"],
					acc.labels["uid"], acc.labels["username"], acc.labels["process"], acc.labels["actor_type"],
					acc.labels["slurm_job_id"],
				)
			}
		} else {
			// ptlrpc metrics
			if acc.opsCount > 0 {
				ch <- prometheus.MustNewConstMetric(
					c.rpcWaitOpsDesc, prometheus.CounterValue, acc.opsCount,
					acc.labels["fs"], acc.labels["mount"], acc.labels["op"],
					acc.labels["uid"], acc.labels["username"], acc.labels["process"], acc.labels["actor_type"],
					acc.labels["slurm_job_id"],
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

	// slurm_job_id is always empty for counters. See BPFCounterCollector
	// doc for rationale (agg_key has no pid, so we cannot resolve it here).
	const slurmJobID = ""

	if isLLite {
		intent := intentName(key.Intent)
		op := rawOpToName(key.Op)
		return BuildLLitePrometheusLabels(uid, username, comm, actorType, mountPath, fsName, intent, op, slurmJobID)
	}

	op := rawOpToName(key.Op)
	return BuildPtlRPCPrometheusLabels(uid, username, comm, actorType, mountPath, fsName, op, slurmJobID)
}

func rawOpToName(raw uint8) string {
	name, err := opName(raw)
	if err != nil {
		return ""
	}
	return name
}
