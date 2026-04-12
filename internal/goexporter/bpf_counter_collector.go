package goexporter

import (
	"context"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/yuuki/otel-lustre-tracer/internal/goexporter/slurm"
)

// BPFCounterCollector reads aggregated counters from BPF PERCPU_HASH maps
// and implements prometheus.Collector. A background drain goroutine periodically
// reads and deletes BPF map entries, accumulating them in Go-side maps.
// At scrape time, Collect() emits the accumulated values.
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

	// Accumulator maps grow monotonically: one entry per unique label
	// combination observed. BPF-side maps are bounded (max_entries), but
	// these Go-side maps are not. In practice, cardinality is constrained
	// by the small label domains (op × actor_type × intent × errno_class),
	// but operators should monitor map sizes under sustained high-error
	// workloads.
	lliteAcc map[string]*lliteAccum
	rpcAcc   map[string]*rpcAccum

	lliteErrorMap *ebpf.Map
	rpcErrorMap   *ebpf.Map
	lliteErrorAcc map[string]*lliteErrorAccum
	rpcErrorAcc   map[string]*rpcErrorAccum

	processFilter *ProcessFilter

	// rawProcessOps tracks ops per raw (pre-normalization) process name
	// observed in the current drain cycle. Reset each drain so the
	// tail-trim ranking reflects recent activity, not lifetime totals,
	// and to prevent unbounded growth from short-lived process names.
	rawProcessOps map[string]float64

	accessOpsDesc   *prometheus.Desc
	dataBytesDesc   *prometheus.Desc
	rpcWaitOpsDesc  *prometheus.Desc
	accessErrorsDesc *prometheus.Desc
	rpcErrorsDesc    *prometheus.Desc
}

// lliteAccum stores label values in lliteLabels order:
// fs, mount, access_intent, op, uid, username, process, actor_type, slurm_job_id.
type lliteAccum struct {
	opsCount float64
	bytesSum float64
	values   [9]string
}

// rpcAccum stores label values in ptlrpcLabels order:
// fs, mount, op, uid, username, process, actor_type, slurm_job_id.
type rpcAccum struct {
	opsCount float64
	values   [8]string
}

// lliteErrorAccum stores label values in lliteErrLabels order:
// fs, mount, access_intent, op, uid, username, process, actor_type, slurm_job_id, errno_class.
type lliteErrorAccum struct {
	opsCount float64
	values   [10]string
}

// rpcErrorAccum stores label values in rpcErrorLabels order:
// fs, mount, event, uid, username, process, actor_type, slurm_job_id.
type rpcErrorAccum struct {
	opsCount float64
	values   [8]string
}

func NewBPFCounterCollector(lliteMap, rpcMap, lliteErrorMap, rpcErrorMap *ebpf.Map, mountInfos []MountInfo, resolver *UsernameResolver, slurmResolver *slurm.Resolver, processFilter *ProcessFilter) *BPFCounterCollector {
	return &BPFCounterCollector{
		lliteMap:      lliteMap,
		rpcMap:        rpcMap,
		lliteErrorMap: lliteErrorMap,
		rpcErrorMap:   rpcErrorMap,
		mountInfos:    mountInfos,
		resolver:      resolver,
		slurmResolver: slurmResolver,
		processFilter: processFilter,
		rawProcessOps: map[string]float64{},
		lliteAcc:      map[string]*lliteAccum{},
		rpcAcc:        map[string]*rpcAccum{},
		lliteErrorAcc: map[string]*lliteErrorAccum{},
		rpcErrorAcc:   map[string]*rpcErrorAccum{},
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
		accessErrorsDesc: prometheus.NewDesc(
			"lustre_client_operation_errors_total",
			"Aggregated llite operation error count by errno class",
			lliteErrLabels, nil,
		),
		rpcErrorsDesc: prometheus.NewDesc(
			"lustre_client_rpc_errors_total",
			"Aggregated ptlrpc error/recovery event count",
			rpcErrorLabels, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *BPFCounterCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.accessOpsDesc
	ch <- c.dataBytesDesc
	ch <- c.rpcWaitOpsDesc
	ch <- c.accessErrorsDesc
	ch <- c.rpcErrorsDesc
}

// Collect implements prometheus.Collector. Called at scrape time.
func (c *BPFCounterCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, acc := range c.lliteAcc {
		if acc.opsCount > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.accessOpsDesc, prometheus.CounterValue, acc.opsCount,
				acc.values[:]...,
			)
		}
		if acc.bytesSum > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.dataBytesDesc, prometheus.CounterValue, acc.bytesSum,
				acc.values[:]...,
			)
		}
	}
	for _, acc := range c.rpcAcc {
		if acc.opsCount > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.rpcWaitOpsDesc, prometheus.CounterValue, acc.opsCount,
				acc.values[:]...,
			)
		}
	}
	for _, acc := range c.lliteErrorAcc {
		if acc.opsCount > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.accessErrorsDesc, prometheus.CounterValue, acc.opsCount,
				acc.values[:]...,
			)
		}
	}
	for _, acc := range c.rpcErrorAcc {
		if acc.opsCount > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.rpcErrorsDesc, prometheus.CounterValue, acc.opsCount,
				acc.values[:]...,
			)
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

// DrainOnce reads both BPF counter maps, accumulates values, and updates
// the dynamic tail-trim set based on per-process ops observed this cycle.
func (c *BPFCounterCollector) DrainOnce() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Reset per-cycle ops so the trim ranking reflects only the latest
	// drain window, preventing unbounded growth from short-lived processes.
	c.rawProcessOps = make(map[string]float64, len(c.rawProcessOps))

	if c.lliteMap != nil {
		c.drainLLite(c.lliteMap)
	}
	if c.rpcMap != nil {
		c.drainRPC(c.rpcMap)
	}
	if c.lliteErrorMap != nil {
		c.drainLLiteErrors(c.lliteErrorMap)
	}
	if c.rpcErrorMap != nil {
		c.drainRPCErrors(c.rpcErrorMap)
	}

	if c.processFilter.ShouldUpdateTrimSet() {
		c.processFilter.UpdateTrimSet(c.opsPerProcess())
	}
}

// opsPerProcess returns ops per raw (pre-normalization) process name
// observed in the current drain cycle, suitable for tail-trim ranking.
func (c *BPFCounterCollector) opsPerProcess() map[string]float64 {
	return c.rawProcessOps
}

// drainCounterMap iterates a BPF counter map, invokes onEntry for each
// (key, per-cpu-summed total), and then deletes every visited key. The
// per-entry work — label extraction and accumulator update — is specific
// to each plane and lives in the callback.
func drainCounterMap(m *ebpf.Map, onEntry func(key bpfAggKey, total bpfCounterVal)) {
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
		onEntry(key, total)
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

func (c *BPFCounterCollector) drainLLite(m *ebpf.Map) {
	drainCounterMap(m, func(key bpfAggKey, total bpfCounterVal) {
		mountPath, fsName := c.mountLabel(key.MountIdx)
		// slurm_job_id is always empty for counters; see BPFCounterCollector doc.
		const slurmJobID = ""
		process := c.normalizeProcess(key.Comm, total.OpsCount)
		vals := [9]string{
			fsName,
			mountPath,
			intentName(key.Intent),
			rawOpToName(key.Op),
			strconv.FormatUint(uint64(key.UID), 10),
			c.resolver.Resolve(key.UID),
			process,
			actorTypeName(key.ActorType),
			slurmJobID,
		}
		accKey := joinLabelKey(vals[:]...)

		acc, ok := c.lliteAcc[accKey]
		if !ok {
			acc = &lliteAccum{values: vals}
			c.lliteAcc[accKey] = acc
		}
		acc.opsCount += float64(total.OpsCount)
		acc.bytesSum += float64(total.BytesSum)
	})
}

func (c *BPFCounterCollector) drainRPC(m *ebpf.Map) {
	drainCounterMap(m, func(key bpfAggKey, total bpfCounterVal) {
		mountPath, fsName := c.mountLabel(key.MountIdx)
		const slurmJobID = ""
		process := c.normalizeProcess(key.Comm, total.OpsCount)
		vals := [8]string{
			fsName,
			mountPath,
			rawOpToName(key.Op),
			strconv.FormatUint(uint64(key.UID), 10),
			c.resolver.Resolve(key.UID),
			process,
			actorTypeName(key.ActorType),
			slurmJobID,
		}
		accKey := joinLabelKey(vals[:]...)

		acc, ok := c.rpcAcc[accKey]
		if !ok {
			acc = &rpcAccum{values: vals}
			c.rpcAcc[accKey] = acc
		}
		acc.opsCount += float64(total.OpsCount)
	})
}

// drainErrorCounterMap iterates a BPF error counter map (error_agg_key →
// error_counter_val), sums per-CPU values, and calls onEntry for each key.
func drainErrorCounterMap(m *ebpf.Map, onEntry func(key bpfErrorAggKey, total bpfErrorCounterVal)) {
	var keysToDelete []bpfErrorAggKey
	var key bpfErrorAggKey
	var values []bpfErrorCounterVal
	iter := m.Iterate()
	for iter.Next(&key, &values) {
		var total bpfErrorCounterVal
		for _, v := range values {
			total.OpsCount += v.OpsCount
		}
		onEntry(key, total)
		keyCopy := key
		keysToDelete = append(keysToDelete, keyCopy)
	}
	if err := iter.Err(); err != nil {
		log.Printf("warning: BPF error counter map iteration error: %v", err)
	}
	for i := range keysToDelete {
		if err := m.Delete(&keysToDelete[i]); err != nil {
			log.Printf("warning: BPF error counter map delete error: %v", err)
		}
	}
}

func (c *BPFCounterCollector) drainLLiteErrors(m *ebpf.Map) {
	drainErrorCounterMap(m, func(key bpfErrorAggKey, total bpfErrorCounterVal) {
		mountPath, fsName := c.mountLabel(key.MountIdx)
		const slurmJobID = ""
		process := c.normalizeProcess(key.Comm, total.OpsCount)
		vals := [10]string{
			fsName,
			mountPath,
			intentName(key.Intent),
			rawOpToName(key.Op),
			strconv.FormatUint(uint64(key.UID), 10),
			c.resolver.Resolve(key.UID),
			process,
			actorTypeName(key.ActorType),
			slurmJobID,
			errnoClassName(key.Reason),
		}
		accKey := joinLabelKey(vals[:]...)

		acc, ok := c.lliteErrorAcc[accKey]
		if !ok {
			acc = &lliteErrorAccum{values: vals}
			c.lliteErrorAcc[accKey] = acc
		}
		acc.opsCount += float64(total.OpsCount)
	})
}

func (c *BPFCounterCollector) drainRPCErrors(m *ebpf.Map) {
	drainErrorCounterMap(m, func(key bpfErrorAggKey, total bpfErrorCounterVal) {
		mountPath, fsName := c.mountLabel(key.MountIdx)
		const slurmJobID = ""
		eventName := rpcEventTypeName(key.Reason)
		if eventName == "" {
			eventName = unknownRPCEvent
		}
		process := c.normalizeProcess(key.Comm, total.OpsCount)
		vals := [8]string{
			fsName,
			mountPath,
			eventName,
			strconv.FormatUint(uint64(key.UID), 10),
			c.resolver.Resolve(key.UID),
			process,
			actorTypeName(key.ActorType),
			slurmJobID,
		}
		accKey := joinLabelKey(vals[:]...)

		acc, ok := c.rpcErrorAcc[accKey]
		if !ok {
			acc = &rpcErrorAccum{values: vals}
			c.rpcErrorAcc[accKey] = acc
		}
		acc.opsCount += float64(total.OpsCount)
	})
}

func (c *BPFCounterCollector) mountLabel(idx uint8) (mountPath, fsName string) {
	if int(idx) < len(c.mountInfos) {
		mi := c.mountInfos[idx]
		return mi.Path, mi.FSName
	}
	return "", ""
}

// normalizeProcess sanitizes the BPF comm field, records raw ops for
// tail-trim ranking, and returns the filtered process name.
func (c *BPFCounterCollector) normalizeProcess(comm [16]byte, opsCount uint64) string {
	raw := sanitizeComm(comm[:])
	if opsCount > 0 {
		c.rawProcessOps[raw] += float64(opsCount)
	}
	return c.processFilter.Normalize(raw)
}

// joinLabelKey concatenates label values with labelKeySep using a
// strings.Builder, avoiding the intermediate slice allocation of
// strings.Join. Used by all drain callbacks.
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

func rawOpToName(raw uint8) string {
	name, err := opName(raw)
	if err != nil {
		return ""
	}
	return name
}
