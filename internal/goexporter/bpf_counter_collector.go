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

	// PCC counter maps and accumulators.
	pccMap      *ebpf.Map
	pccErrorMap *ebpf.Map
	pccAcc      map[string]*lliteAccum      // reuses lliteAccum shape (9 labels)
	pccErrorAcc map[string]*lliteErrorAccum  // reuses lliteErrorAccum shape (10 labels)

	accessOpsDesc    *prometheus.Desc
	dataBytesDesc    *prometheus.Desc
	rpcWaitOpsDesc   *prometheus.Desc
	accessErrorsDesc *prometheus.Desc
	rpcErrorsDesc    *prometheus.Desc
	pccOpsDesc       *prometheus.Desc
	pccBytesDesc     *prometheus.Desc
	pccErrorsDesc    *prometheus.Desc
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

func NewBPFCounterCollector(lliteMap, rpcMap, lliteErrorMap, rpcErrorMap, pccMap, pccErrorMap *ebpf.Map, mountInfos []MountInfo, resolver *UsernameResolver, slurmResolver *slurm.Resolver) *BPFCounterCollector {
	return &BPFCounterCollector{
		lliteMap:      lliteMap,
		rpcMap:        rpcMap,
		lliteErrorMap: lliteErrorMap,
		rpcErrorMap:   rpcErrorMap,
		pccMap:        pccMap,
		pccErrorMap:   pccErrorMap,
		mountInfos:    mountInfos,
		resolver:      resolver,
		slurmResolver: slurmResolver,
		lliteAcc:      map[string]*lliteAccum{},
		rpcAcc:        map[string]*rpcAccum{},
		lliteErrorAcc: map[string]*lliteErrorAccum{},
		rpcErrorAcc:   map[string]*rpcErrorAccum{},
		pccAcc:        map[string]*lliteAccum{},
		pccErrorAcc:   map[string]*lliteErrorAccum{},
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
		pccOpsDesc: prometheus.NewDesc(
			"lustre_client_pcc_operations_total",
			"Aggregated PCC I/O operation count",
			pccLabels, nil,
		),
		pccBytesDesc: prometheus.NewDesc(
			"lustre_client_pcc_data_bytes_total",
			"Aggregated PCC data volume in bytes",
			pccLabels, nil,
		),
		pccErrorsDesc: prometheus.NewDesc(
			"lustre_client_pcc_operation_errors_total",
			"Aggregated PCC operation error count by errno class",
			pccErrLabels, nil,
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
	ch <- c.pccOpsDesc
	ch <- c.pccBytesDesc
	ch <- c.pccErrorsDesc
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
	for _, acc := range c.pccAcc {
		if acc.opsCount > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.pccOpsDesc, prometheus.CounterValue, acc.opsCount,
				acc.values[:]...,
			)
		}
		if acc.bytesSum > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.pccBytesDesc, prometheus.CounterValue, acc.bytesSum,
				acc.values[:]...,
			)
		}
	}
	for _, acc := range c.pccErrorAcc {
		if acc.opsCount > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.pccErrorsDesc, prometheus.CounterValue, acc.opsCount,
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

// DrainOnce reads both BPF counter maps and accumulates values.
func (c *BPFCounterCollector) DrainOnce() {
	c.mu.Lock()
	defer c.mu.Unlock()

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
	if c.pccMap != nil {
		c.drainPCC(c.pccMap)
	}
	if c.pccErrorMap != nil {
		c.drainPCCErrors(c.pccErrorMap)
	}
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
		vals := [9]string{
			fsName,
			mountPath,
			intentName(key.Intent),
			rawOpToName(key.Op),
			strconv.FormatUint(uint64(key.UID), 10),
			c.resolver.Resolve(key.UID),
			sanitizeComm(key.Comm[:]),
			actorTypeName(key.ActorType),
			slurmJobID,
		}
		accKey := strings.Join(vals[:], labelKeySep)

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
		vals := [8]string{
			fsName,
			mountPath,
			rawOpToName(key.Op),
			strconv.FormatUint(uint64(key.UID), 10),
			c.resolver.Resolve(key.UID),
			sanitizeComm(key.Comm[:]),
			actorTypeName(key.ActorType),
			slurmJobID,
		}
		accKey := strings.Join(vals[:], labelKeySep)

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
		vals := [10]string{
			fsName,
			mountPath,
			intentName(key.Intent),
			rawOpToName(key.Op),
			strconv.FormatUint(uint64(key.UID), 10),
			c.resolver.Resolve(key.UID),
			sanitizeComm(key.Comm[:]),
			actorTypeName(key.ActorType),
			slurmJobID,
			errnoClassName(key.Reason),
		}
		accKey := strings.Join(vals[:], labelKeySep)

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
		vals := [8]string{
			fsName,
			mountPath,
			eventName,
			strconv.FormatUint(uint64(key.UID), 10),
			c.resolver.Resolve(key.UID),
			sanitizeComm(key.Comm[:]),
			actorTypeName(key.ActorType),
			slurmJobID,
		}
		accKey := strings.Join(vals[:], labelKeySep)

		acc, ok := c.rpcErrorAcc[accKey]
		if !ok {
			acc = &rpcErrorAccum{values: vals}
			c.rpcErrorAcc[accKey] = acc
		}
		acc.opsCount += float64(total.OpsCount)
	})
}

func (c *BPFCounterCollector) drainPCC(m *ebpf.Map) {
	drainCounterMap(m, func(key bpfAggKey, total bpfCounterVal) {
		mountPath, fsName := c.mountLabel(key.MountIdx)
		const slurmJobID = ""
		vals := [9]string{
			fsName,
			mountPath,
			intentName(key.Intent),
			rawOpToName(key.Op),
			strconv.FormatUint(uint64(key.UID), 10),
			c.resolver.Resolve(key.UID),
			sanitizeComm(key.Comm[:]),
			actorTypeName(key.ActorType),
			slurmJobID,
		}
		accKey := strings.Join(vals[:], labelKeySep)

		acc, ok := c.pccAcc[accKey]
		if !ok {
			acc = &lliteAccum{values: vals}
			c.pccAcc[accKey] = acc
		}
		acc.opsCount += float64(total.OpsCount)
		acc.bytesSum += float64(total.BytesSum)
	})
}

func (c *BPFCounterCollector) drainPCCErrors(m *ebpf.Map) {
	drainErrorCounterMap(m, func(key bpfErrorAggKey, total bpfErrorCounterVal) {
		mountPath, fsName := c.mountLabel(key.MountIdx)
		const slurmJobID = ""
		vals := [10]string{
			fsName,
			mountPath,
			intentName(key.Intent),
			rawOpToName(key.Op),
			strconv.FormatUint(uint64(key.UID), 10),
			c.resolver.Resolve(key.UID),
			sanitizeComm(key.Comm[:]),
			actorTypeName(key.ActorType),
			slurmJobID,
			errnoClassName(key.Reason),
		}
		accKey := strings.Join(vals[:], labelKeySep)

		acc, ok := c.pccErrorAcc[accKey]
		if !ok {
			acc = &lliteErrorAccum{values: vals}
			c.pccErrorAcc[accKey] = acc
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

func rawOpToName(raw uint8) string {
	name, err := opName(raw)
	if err != nil {
		return ""
	}
	return name
}
