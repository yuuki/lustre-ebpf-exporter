package goexporter

import (
	"context"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/yuuki/lustre-ebpf-exporter/internal/goexporter/slurm"
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
	slurmEnabled  bool
	// uidEnabled mirrors the BPF-side `uid_labels_enabled` global. When
	// false, the kernel has already zeroed agg_key.uid so PERCPU_HASH rows
	// fold across users; userspace skips the UsernameResolver syscall on
	// the drain path and omits the uid/username label values.
	uidEnabled bool

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

	processFilter *ProcessFilter

	// processOps tracks ops per process name (suffix-stripped when enabled)
	// observed in the current drain cycle. Reset each drain so the
	// tail-trim ranking reflects recent activity, not lifetime totals,
	// and to prevent unbounded growth from short-lived process names.
	processOps map[string]float64

	accessOpsDesc    *prometheus.Desc
	dataBytesDesc    *prometheus.Desc
	rpcWaitOpsDesc   *prometheus.Desc
	accessErrorsDesc *prometheus.Desc
	rpcErrorsDesc    *prometheus.Desc
	pccOpsDesc       *prometheus.Desc
	pccBytesDesc     *prometheus.Desc
	pccErrorsDesc    *prometheus.Desc
}

type lliteAccum struct {
	opsCount float64
	bytesSum float64
	values   []string
}

type rpcAccum struct {
	opsCount float64
	values   []string
}

type lliteErrorAccum struct {
	opsCount float64
	values   []string
}

type rpcErrorAccum struct {
	opsCount float64
	values   []string
}

func NewBPFCounterCollector(lliteMap, rpcMap, lliteErrorMap, rpcErrorMap, pccMap, pccErrorMap *ebpf.Map, mountInfos []MountInfo, resolver *UsernameResolver, slurmResolver *slurm.Resolver, processFilter *ProcessFilter, slurmEnabled, uidEnabled bool) *BPFCounterCollector {
	c := &BPFCounterCollector{
		lliteMap:      lliteMap,
		rpcMap:        rpcMap,
		lliteErrorMap: lliteErrorMap,
		rpcErrorMap:   rpcErrorMap,
		pccMap:        pccMap,
		pccErrorMap:   pccErrorMap,
		mountInfos:    mountInfos,
		resolver:      resolver,
		slurmResolver: slurmResolver,
		slurmEnabled:  slurmEnabled,
		uidEnabled:    uidEnabled,
		processFilter: processFilter,
		processOps:    map[string]float64{},
		lliteAcc:      map[string]*lliteAccum{},
		rpcAcc:        map[string]*rpcAccum{},
		lliteErrorAcc: map[string]*lliteErrorAccum{},
		rpcErrorAcc:   map[string]*rpcErrorAccum{},
		pccAcc:        map[string]*lliteAccum{},
		pccErrorAcc:   map[string]*lliteErrorAccum{},
		accessOpsDesc: prometheus.NewDesc(
			"lustre_client_access_operations_total",
			"Aggregated llite access operation count",
			buildLliteLabels(slurmEnabled, uidEnabled), nil,
		),
		dataBytesDesc: prometheus.NewDesc(
			"lustre_client_data_bytes_total",
			"Aggregated llite data volume in bytes",
			buildLliteLabels(slurmEnabled, uidEnabled), nil,
		),
		rpcWaitOpsDesc: prometheus.NewDesc(
			"lustre_client_rpc_wait_operations_total",
			"Aggregated ptlrpc queue wait count",
			buildPtlrpcLabels(slurmEnabled, uidEnabled), nil,
		),
		accessErrorsDesc: prometheus.NewDesc(
			"lustre_client_operation_errors_total",
			"Aggregated llite operation error count by errno class",
			buildLliteErrLabels(slurmEnabled, uidEnabled), nil,
		),
		rpcErrorsDesc: prometheus.NewDesc(
			"lustre_client_rpc_errors_total",
			"Aggregated ptlrpc error/recovery event count",
			buildRPCErrorLabels(slurmEnabled, uidEnabled), nil,
		),
	}
	if pccMap != nil {
		c.pccOpsDesc = prometheus.NewDesc(
			"lustre_client_pcc_operations_total",
			"Aggregated PCC I/O operation count",
			buildLliteLabels(slurmEnabled, uidEnabled), nil,
		)
		c.pccBytesDesc = prometheus.NewDesc(
			"lustre_client_pcc_data_bytes_total",
			"Aggregated PCC data volume in bytes",
			buildLliteLabels(slurmEnabled, uidEnabled), nil,
		)
		c.pccErrorsDesc = prometheus.NewDesc(
			"lustre_client_pcc_operation_errors_total",
			"Aggregated PCC operation error count by errno class",
			buildLliteErrLabels(slurmEnabled, uidEnabled), nil,
		)
	}
	return c
}

// Describe implements prometheus.Collector.
func (c *BPFCounterCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.accessOpsDesc
	ch <- c.dataBytesDesc
	ch <- c.rpcWaitOpsDesc
	ch <- c.accessErrorsDesc
	ch <- c.rpcErrorsDesc
	if c.pccOpsDesc != nil {
		ch <- c.pccOpsDesc
		ch <- c.pccBytesDesc
		ch <- c.pccErrorsDesc
	}
}

// Collect implements prometheus.Collector. Called at scrape time.
func (c *BPFCounterCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, acc := range c.lliteAcc {
		if acc.opsCount > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.accessOpsDesc, prometheus.CounterValue, acc.opsCount,
				acc.values...,
			)
		}
		if acc.bytesSum > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.dataBytesDesc, prometheus.CounterValue, acc.bytesSum,
				acc.values...,
			)
		}
	}
	for _, acc := range c.rpcAcc {
		if acc.opsCount > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.rpcWaitOpsDesc, prometheus.CounterValue, acc.opsCount,
				acc.values...,
			)
		}
	}
	for _, acc := range c.lliteErrorAcc {
		if acc.opsCount > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.accessErrorsDesc, prometheus.CounterValue, acc.opsCount,
				acc.values...,
			)
		}
	}
	for _, acc := range c.rpcErrorAcc {
		if acc.opsCount > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.rpcErrorsDesc, prometheus.CounterValue, acc.opsCount,
				acc.values...,
			)
		}
	}
	if c.pccOpsDesc != nil {
		for _, acc := range c.pccAcc {
			if acc.opsCount > 0 {
				ch <- prometheus.MustNewConstMetric(
					c.pccOpsDesc, prometheus.CounterValue, acc.opsCount,
					acc.values...,
				)
			}
			if acc.bytesSum > 0 {
				ch <- prometheus.MustNewConstMetric(
					c.pccBytesDesc, prometheus.CounterValue, acc.bytesSum,
					acc.values...,
				)
			}
		}
		for _, acc := range c.pccErrorAcc {
			if acc.opsCount > 0 {
				ch <- prometheus.MustNewConstMetric(
					c.pccErrorsDesc, prometheus.CounterValue, acc.opsCount,
					acc.values...,
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

// DrainOnce reads both BPF counter maps, accumulates values, and updates
// the dynamic tail-trim set. The trim set is updated BEFORE draining so
// that the current drain's labels reflect the latest ranking, not the
// previous cycle's.
func (c *BPFCounterCollector) DrainOnce() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update trim set from the PREVIOUS drain's per-process ops before
	// labeling the current drain. This eliminates the off-by-one where
	// newly trimmed processes would only appear as "other" one drain late.
	if c.processFilter.ShouldUpdateTrimSet() {
		c.processFilter.UpdateTrimSet(c.opsPerProcess())
	}

	// Reset per-cycle ops so the trim ranking reflects only the latest
	// drain window, preventing unbounded growth from short-lived processes.
	c.processOps = make(map[string]float64, len(c.processOps))

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

// opsPerProcess returns ops per raw (pre-normalization) process name
// observed in the current drain cycle, suitable for tail-trim ranking.
func (c *BPFCounterCollector) opsPerProcess() map[string]float64 {
	return c.processOps
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

// resolveUID returns the uid/username pair for a BPF counter key. Returns
// empty strings when uidEnabled is false: the kernel has already zeroed
// key.UID (see fill_start_info in the BPF source), so we skip the
// UsernameResolver syscall and keep the label values in sync with the
// metric descriptor arity produced by buildLliteLabels et al.
func (c *BPFCounterCollector) resolveUID(keyUID uint32) (uid, username string) {
	if !c.uidEnabled {
		return "", ""
	}
	return strconv.FormatUint(uint64(keyUID), 10), c.resolver.Resolve(keyUID)
}

// drainLLiteStyle drains a BPF counter map with the llite label schema
// into the provided accumulator map. Used by both llite and PCC planes.
func (c *BPFCounterCollector) drainLLiteStyle(m *ebpf.Map, acc map[string]*lliteAccum) {
	drainCounterMap(m, func(key bpfAggKey, total bpfCounterVal) {
		mountPath, fsName := c.mountLabel(key.MountIdx)
		process := c.normalizeProcess(key.Comm, total.OpsCount)
		intent := intentName(key.Intent)
		op := rawOpToName(key.Op)
		uid, username := c.resolveUID(key.UID)
		actor := actorTypeName(key.ActorType)

		// slurm_job_id is always empty for counters; the label arity
		// already encodes both slurm and uid toggles so vals is a
		// collision-free accumulator key.
		vals := lliteLabelValues(fsName, mountPath, intent, op, uid, username, process, actor, "", c.slurmEnabled, c.uidEnabled)
		accKey := joinLabelKey(vals...)

		a, ok := acc[accKey]
		if !ok {
			a = &lliteAccum{values: vals}
			acc[accKey] = a
		}
		a.opsCount += float64(total.OpsCount)
		a.bytesSum += float64(total.BytesSum)
	})
}

func (c *BPFCounterCollector) drainLLite(m *ebpf.Map) {
	c.drainLLiteStyle(m, c.lliteAcc)
}

func (c *BPFCounterCollector) drainRPC(m *ebpf.Map) {
	drainCounterMap(m, func(key bpfAggKey, total bpfCounterVal) {
		mountPath, fsName := c.mountLabel(key.MountIdx)
		process := c.normalizeProcess(key.Comm, total.OpsCount)
		op := rawOpToName(key.Op)
		uid, username := c.resolveUID(key.UID)
		actor := actorTypeName(key.ActorType)

		vals := ptlrpcLabelValues(fsName, mountPath, op, uid, username, process, actor, "", c.slurmEnabled, c.uidEnabled)
		accKey := joinLabelKey(vals...)

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

// drainLLiteStyleErrors drains a BPF error counter map with the llite error
// label schema into the provided accumulator map. Used by both llite and PCC.
// When slurmEnabled, slurm_job_id is inserted before errno_class.
func (c *BPFCounterCollector) drainLLiteStyleErrors(m *ebpf.Map, acc map[string]*lliteErrorAccum) {
	drainErrorCounterMap(m, func(key bpfErrorAggKey, total bpfErrorCounterVal) {
		mountPath, fsName := c.mountLabel(key.MountIdx)
		process := c.normalizeProcess(key.Comm, total.OpsCount)
		intent := intentName(key.Intent)
		op := rawOpToName(key.Op)
		uid, username := c.resolveUID(key.UID)
		actor := actorTypeName(key.ActorType)
		errno := errnoClassName(key.Reason)

		// lliteLabelValues owns the shared prefix (including slurm_job_id
		// placement); append errno_class to match buildLliteErrLabels order.
		base := lliteLabelValues(fsName, mountPath, intent, op, uid, username, process, actor, "", c.slurmEnabled, c.uidEnabled)
		vals := append(base, errno)
		accKey := joinLabelKey(vals...)

		a, ok := acc[accKey]
		if !ok {
			a = &lliteErrorAccum{values: vals}
			acc[accKey] = a
		}
		a.opsCount += float64(total.OpsCount)
	})
}

func (c *BPFCounterCollector) drainLLiteErrors(m *ebpf.Map) {
	c.drainLLiteStyleErrors(m, c.lliteErrorAcc)
}

func (c *BPFCounterCollector) drainRPCErrors(m *ebpf.Map) {
	drainErrorCounterMap(m, func(key bpfErrorAggKey, total bpfErrorCounterVal) {
		mountPath, fsName := c.mountLabel(key.MountIdx)
		eventName := rpcEventTypeName(key.Reason)
		if eventName == "" {
			eventName = unknownRPCEvent
		}
		process := c.normalizeProcess(key.Comm, total.OpsCount)
		uid, username := c.resolveUID(key.UID)
		actor := actorTypeName(key.ActorType)

		// buildRPCErrorLabels order: fs, mount, event, [uid, username,]
		// process, actor_type, [slurm_job_id]. ptlrpcLabelValues happens
		// to match after substituting "event" for "op".
		vals := ptlrpcLabelValues(fsName, mountPath, eventName, uid, username, process, actor, "", c.slurmEnabled, c.uidEnabled)
		accKey := joinLabelKey(vals...)

		acc, ok := c.rpcErrorAcc[accKey]
		if !ok {
			acc = &rpcErrorAccum{values: vals}
			c.rpcErrorAcc[accKey] = acc
		}
		acc.opsCount += float64(total.OpsCount)
	})
}

func (c *BPFCounterCollector) drainPCC(m *ebpf.Map) {
	c.drainLLiteStyle(m, c.pccAcc)
}

func (c *BPFCounterCollector) drainPCCErrors(m *ebpf.Map) {
	c.drainLLiteStyleErrors(m, c.pccErrorAcc)
}

func (c *BPFCounterCollector) mountLabel(idx uint8) (mountPath, fsName string) {
	if int(idx) < len(c.mountInfos) {
		mi := c.mountInfos[idx]
		return mi.Path, mi.FSName
	}
	return "", ""
}

// normalizeProcess sanitizes the BPF comm field, records ops for
// tail-trim ranking (keyed by suffix-stripped name when enabled),
// and returns the filtered process name.
func (c *BPFCounterCollector) normalizeProcess(comm [16]byte, opsCount uint64) string {
	raw := sanitizeComm(comm[:])
	// Use the suffix-stripped name as the ops accumulation key so that
	// UpdateTrimSet and Normalize operate on the same names.
	stripped := c.processFilter.StripName(raw)
	if opsCount > 0 {
		c.processOps[stripped] += float64(opsCount)
	}
	return c.processFilter.Normalize(raw)
}

func rawOpToName(raw uint8) string {
	name, err := opName(raw)
	if err != nil {
		return ""
	}
	return name
}
