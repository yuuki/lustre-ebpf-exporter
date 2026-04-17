package goexporter

import (
	"math"
	"sort"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	aggregationIndividual = "individual"
	aggregationOther      = "other"
	aggregationTotal      = "total"

	aggregateIdentityOther = "_other"
	aggregateIdentityTotal = "_all"
)

type WorkloadFilterConfig struct {
	TopN           int
	PromoteWindows int
	DemoteWindows  int
	TTLWindows     uint64
}

func DefaultWorkloadFilterConfig() WorkloadFilterConfig {
	return WorkloadFilterConfig{
		TopN:           5,
		PromoteWindows: 2,
		DemoteWindows:  3,
		TTLWindows:     12,
	}
}

type visibilityState uint8

const (
	visibilitySuppressed visibilityState = iota
	visibilityPromoting
	visibilityKept
	visibilityDemoting
)

type entityVisibility struct {
	State       visibilityState
	PromoteHits int
	DemoteHits  int
}

type accessEntityOpKey struct {
	FSName     string
	MountPath  string
	Intent     string
	Op         string
	UID        string
	Username   string
	Process    string
	ActorType  string
	SlurmJobID string
}

type accessEntityIntentKey struct {
	FSName     string
	MountPath  string
	Intent     string
	UID        string
	Username   string
	Process    string
	ActorType  string
	SlurmJobID string
}

type accessLaneKey struct {
	FSName    string
	MountPath string
	Intent    string
	Op        string
	ActorType string
}

type accessExportLane struct {
	FSName    string
	MountPath string
	Intent    string
	ActorType string
}

type rpcEntityKey struct {
	FSName     string
	MountPath  string
	UID        string
	Username   string
	Process    string
	ActorType  string
	SlurmJobID string
}

type rpcLaneKey struct {
	FSName    string
	MountPath string
	ActorType string
}

type histogramState struct {
	Count   uint64
	Sum     float64
	Buckets []uint64
}

func newHistogramState() histogramState {
	return histogramState{Buckets: make([]uint64, len(PrometheusLatencyBucketsSeconds))}
}

func (h *histogramState) Observe(v float64) {
	h.Count++
	h.Sum += v
	for i, upper := range PrometheusLatencyBucketsSeconds {
		if v <= upper {
			h.Buckets[i]++
		}
	}
}

func (h *histogramState) Add(other histogramState) {
	h.Count += other.Count
	h.Sum += other.Sum
	if len(h.Buckets) == 0 {
		h.Buckets = make([]uint64, len(other.Buckets))
	}
	for i := range other.Buckets {
		h.Buckets[i] += other.Buckets[i]
	}
}

func (h *histogramState) toPromBuckets() map[float64]uint64 {
	buckets := make(map[float64]uint64, len(PrometheusLatencyBucketsSeconds))
	for i, upper := range PrometheusLatencyBucketsSeconds {
		if h.Buckets[i] == 0 {
			continue
		}
		buckets[upper] = h.Buckets[i]
	}
	return buckets
}

type accessAggregate struct {
	Ops         float64
	Bytes       float64
	LatencyHist histogramState
	ForceKeep   bool
}

func newAccessAggregate() accessAggregate {
	return accessAggregate{LatencyHist: newHistogramState()}
}

func (a *accessAggregate) Add(other accessAggregate) {
	a.Ops += other.Ops
	a.Bytes += other.Bytes
	a.LatencyHist.Add(other.LatencyHist)
	a.ForceKeep = a.ForceKeep || other.ForceKeep
}

type rpcAggregate struct {
	Ops         float64
	LatencyHist histogramState
	ForceKeep   bool
}

func newRPCAggregate() rpcAggregate {
	return rpcAggregate{LatencyHist: newHistogramState()}
}

func (a *rpcAggregate) Add(other rpcAggregate) {
	a.Ops += other.Ops
	a.LatencyHist.Add(other.LatencyHist)
	a.ForceKeep = a.ForceKeep || other.ForceKeep
}

type accessRelevance struct {
	Keep     bool
	HardKeep bool
	Score    float64
}

type seriesMeta struct {
	Labels          []string
	LastUpdatedTick uint64
}

type counterSeries struct {
	seriesMeta
	Value float64
}

type histogramSeries struct {
	seriesMeta
	Value histogramState
}

// WorkloadWindowCollector applies share-based visibility at window close and
// emits cumulative counter/histogram families that preserve the original metric
// types while collapsing low-relevance actors into "other".
type WorkloadWindowCollector struct {
	mu sync.RWMutex

	cfg           WorkloadFilterConfig
	slurmEnabled  bool
	uidEnabled    bool
	processFilter *ProcessFilter

	accessOpsDesc     *prometheus.Desc
	dataBytesDesc     *prometheus.Desc
	accessLatencyDesc *prometheus.Desc
	rpcWaitOpsDesc    *prometheus.Desc
	rpcWaitLatDesc    *prometheus.Desc

	currentAccess map[accessEntityOpKey]*accessAggregate
	currentRPC    map[rpcEntityKey]*rpcAggregate

	accessState map[string]entityVisibility
	rpcState    map[string]entityVisibility

	accessOpsSeries  map[string]*counterSeries
	dataBytesSeries  map[string]*counterSeries
	accessHistSeries map[string]*histogramSeries
	rpcOpsSeries     map[string]*counterSeries
	rpcHistSeries    map[string]*histogramSeries

	tick uint64
}

func NewWorkloadWindowCollector(cfg WorkloadFilterConfig, processFilter *ProcessFilter, slurmEnabled, uidEnabled bool) *WorkloadWindowCollector {
	if cfg.TopN <= 0 {
		cfg = DefaultWorkloadFilterConfig()
	}
	if cfg.PromoteWindows < 1 {
		cfg.PromoteWindows = 1
	}
	if cfg.DemoteWindows < 1 {
		cfg.DemoteWindows = 1
	}
	return &WorkloadWindowCollector{
		cfg:               cfg,
		processFilter:     processFilter,
		slurmEnabled:      slurmEnabled,
		uidEnabled:        uidEnabled,
		accessOpsDesc:     prometheus.NewDesc("lustre_client_relevance_access_operations_total", "Relevance-routed llite access operation count", buildWorkloadAccessLabels(slurmEnabled, uidEnabled), nil),
		dataBytesDesc:     prometheus.NewDesc("lustre_client_relevance_data_bytes_total", "Relevance-routed llite data volume in bytes", buildWorkloadAccessLabels(slurmEnabled, uidEnabled), nil),
		accessLatencyDesc: prometheus.NewDesc("lustre_client_relevance_access_duration_seconds", "Relevance-routed llite access latency in seconds", buildWorkloadAccessLabels(slurmEnabled, uidEnabled), nil),
		rpcWaitOpsDesc:    prometheus.NewDesc("lustre_client_relevance_rpc_wait_operations_total", "Relevance-routed ptlrpc queue wait count", buildWorkloadRPCWaitLabels(slurmEnabled, uidEnabled), nil),
		rpcWaitLatDesc:    prometheus.NewDesc("lustre_client_relevance_rpc_wait_duration_seconds", "Relevance-routed ptlrpc queue wait latency in seconds", buildWorkloadRPCWaitLabels(slurmEnabled, uidEnabled), nil),
		currentAccess:     map[accessEntityOpKey]*accessAggregate{},
		currentRPC:        map[rpcEntityKey]*rpcAggregate{},
		accessState:       map[string]entityVisibility{},
		rpcState:          map[string]entityVisibility{},
		accessOpsSeries:   map[string]*counterSeries{},
		dataBytesSeries:   map[string]*counterSeries{},
		accessHistSeries:  map[string]*histogramSeries{},
		rpcOpsSeries:      map[string]*counterSeries{},
		rpcHistSeries:     map[string]*histogramSeries{},
	}
}

func (c *WorkloadWindowCollector) SetProcessFilter(filter *ProcessFilter) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.processFilter = filter
}

func (c *WorkloadWindowCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.accessOpsDesc
	ch <- c.dataBytesDesc
	ch <- c.accessLatencyDesc
	ch <- c.rpcWaitOpsDesc
	ch <- c.rpcWaitLatDesc
}

func (c *WorkloadWindowCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	c.collectCounters(ch, c.accessOpsDesc, c.accessOpsSeries)
	c.collectCounters(ch, c.dataBytesDesc, c.dataBytesSeries)
	c.collectHistograms(ch, c.accessLatencyDesc, c.accessHistSeries)
	c.collectCounters(ch, c.rpcWaitOpsDesc, c.rpcOpsSeries)
	c.collectHistograms(ch, c.rpcWaitLatDesc, c.rpcHistSeries)
}

func (c *WorkloadWindowCollector) collectCounters(ch chan<- prometheus.Metric, desc *prometheus.Desc, series map[string]*counterSeries) {
	for _, s := range series {
		if !c.shouldEmitSeries(s.seriesMeta) {
			continue
		}
		ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, s.Value, s.Labels...)
	}
}

func (c *WorkloadWindowCollector) collectHistograms(ch chan<- prometheus.Metric, desc *prometheus.Desc, series map[string]*histogramSeries) {
	for _, s := range series {
		if !c.shouldEmitSeries(s.seriesMeta) {
			continue
		}
		ch <- prometheus.MustNewConstHistogram(desc, s.Value.Count, s.Value.Sum, s.Value.toPromBuckets(), s.Labels...)
	}
}

func (c *WorkloadWindowCollector) shouldEmitSeries(meta seriesMeta) bool {
	if len(meta.Labels) == 0 {
		return false
	}
	aggregation := meta.Labels[len(meta.Labels)-1]
	if aggregation == aggregationTotal || aggregation == aggregationOther {
		return true
	}
	if c.cfg.TTLWindows == 0 {
		return true
	}
	return c.tick-meta.LastUpdatedTick <= c.cfg.TTLWindows
}

func (c *WorkloadWindowCollector) ObserveAccess(event Event, uid, username, actorType, slurmJobID string) {
	intent := AccessIntentForOp(event.Op)
	if intent == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	key := accessEntityOpKey{
		FSName:     event.FSName,
		MountPath:  event.MountPath,
		Intent:     intent,
		Op:         event.Op,
		UID:        uid,
		Username:   username,
		Process:    event.Comm,
		ActorType:  actorType,
		SlurmJobID: slurmJobID,
	}
	agg, ok := c.currentAccess[key]
	if !ok {
		a := newAccessAggregate()
		agg = &a
		c.currentAccess[key] = agg
	}
	agg.Ops++
	agg.Bytes += float64(event.SizeBytes)
	if event.DurationUS > 0 {
		agg.LatencyHist.Observe(float64(event.DurationUS) / 1_000_000.0)
	}
	if c.processFilter != nil && c.processFilter.AlwaysKeep(event.Comm) {
		agg.ForceKeep = true
	}
}

func (c *WorkloadWindowCollector) ObserveRPCWait(event Event, uid, username, actorType, slurmJobID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := rpcEntityKey{
		FSName:     event.FSName,
		MountPath:  event.MountPath,
		UID:        uid,
		Username:   username,
		Process:    event.Comm,
		ActorType:  actorType,
		SlurmJobID: slurmJobID,
	}
	agg, ok := c.currentRPC[key]
	if !ok {
		a := newRPCAggregate()
		agg = &a
		c.currentRPC[key] = agg
	}
	agg.Ops++
	if event.DurationUS > 0 {
		agg.LatencyHist.Observe(float64(event.DurationUS) / 1_000_000.0)
	}
	if c.processFilter != nil && c.processFilter.AlwaysKeep(event.Comm) {
		agg.ForceKeep = true
	}
}

func (c *WorkloadWindowCollector) RotateWindow() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.tick++
	c.rotateAccessLocked()
	c.rotateRPCLocked()
	c.currentAccess = map[accessEntityOpKey]*accessAggregate{}
	c.currentRPC = map[rpcEntityKey]*rpcAggregate{}
}

func (c *WorkloadWindowCollector) rotateAccessLocked() {
	if len(c.currentAccess) == 0 {
		return
	}

	laneTotals := map[accessLaneKey]accessAggregate{}
	entities := map[accessEntityIntentKey]accessAggregate{}
	relevanceByEntity := map[accessEntityIntentKey]accessRelevance{}
	for key, agg := range c.currentAccess {
		laneKey := accessLaneKey{
			FSName:    key.FSName,
			MountPath: key.MountPath,
			Intent:    key.Intent,
			Op:        key.Op,
			ActorType: key.ActorType,
		}
		lane := laneTotals[laneKey]
		lane.Add(*agg)
		laneTotals[laneKey] = lane

		entityKey := accessEntityIntentKey{
			FSName:     key.FSName,
			MountPath:  key.MountPath,
			Intent:     key.Intent,
			UID:        key.UID,
			Username:   key.Username,
			Process:    key.Process,
			ActorType:  key.ActorType,
			SlurmJobID: key.SlurmJobID,
		}
		entityAgg := entities[entityKey]
		entityAgg.Add(*agg)
		entities[entityKey] = entityAgg

	}

	for key, agg := range c.currentAccess {
		entityKey := accessEntityIntentKey{
			FSName:     key.FSName,
			MountPath:  key.MountPath,
			Intent:     key.Intent,
			UID:        key.UID,
			Username:   key.Username,
			Process:    key.Process,
			ActorType:  key.ActorType,
			SlurmJobID: key.SlurmJobID,
		}
		laneKey := accessLaneKey{
			FSName:    key.FSName,
			MountPath: key.MountPath,
			Intent:    key.Intent,
			Op:        key.Op,
			ActorType: key.ActorType,
		}
		relevance := c.evaluateAccessRelevance(key.Intent, *agg, laneTotals[laneKey])
		prev := relevanceByEntity[entityKey]
		prev.Keep = prev.Keep || relevance.Keep || agg.ForceKeep
		prev.HardKeep = prev.HardKeep || relevance.HardKeep || agg.ForceKeep
		prev.Score = math.Max(prev.Score, relevance.Score)
		relevanceByEntity[entityKey] = prev
	}

	totalByLane := map[accessExportLane]accessAggregate{}
	otherByLane := map[accessExportLane]accessAggregate{}
	visibleByLane := map[accessExportLane][]rankedAccessEntity{}

	for entityKey, agg := range entities {
		exportLane := accessExportLane{
			FSName:    entityKey.FSName,
			MountPath: entityKey.MountPath,
			Intent:    entityKey.Intent,
			ActorType: entityKey.ActorType,
		}
		total := totalByLane[exportLane]
		total.Add(agg)
		totalByLane[exportLane] = total

		relevance := relevanceByEntity[entityKey]
		stateKey := c.accessStateKey(entityKey)
		next, visible := transitionVisibility(c.accessState[stateKey], relevance.Keep, relevance.HardKeep, c.cfg.PromoteWindows, c.cfg.DemoteWindows)
		c.accessState[stateKey] = next

		if visible {
			visibleByLane[exportLane] = append(visibleByLane[exportLane], rankedAccessEntity{Key: entityKey, Aggregate: agg, Score: relevance.Score})
			continue
		}
		other := otherByLane[exportLane]
		other.Add(agg)
		otherByLane[exportLane] = other
	}

	for lane := range totalByLane {
		visible := visibleByLane[lane]
		if len(visible) > 0 {
			sort.Slice(visible, func(i, j int) bool {
				if visible[i].Score != visible[j].Score {
					return visible[i].Score > visible[j].Score
				}
				if visible[i].Key.Process != visible[j].Key.Process {
					return visible[i].Key.Process < visible[j].Key.Process
				}
				return visible[i].Key.UID < visible[j].Key.UID
			})
		}

		limit := c.cfg.TopN
		if limit <= 0 || limit > len(visible) {
			limit = len(visible)
		}

		for i, item := range visible {
			if i < limit {
				c.incrementAccessSeriesLocked(lane, item.Key.UID, item.Key.Username, item.Key.Process, item.Key.SlurmJobID, aggregationIndividual, item.Aggregate)
				continue
			}
			other := otherByLane[lane]
			other.Add(item.Aggregate)
			otherByLane[lane] = other
		}

		if other, ok := otherByLane[lane]; ok && (other.Ops > 0 || other.Bytes > 0 || other.LatencyHist.Count > 0) {
			c.incrementAccessSeriesLocked(lane, aggregateIdentityOther, aggregateIdentityOther, aggregateIdentityOther, aggregateIdentityOther, aggregationOther, other)
		}
	}
}

func (c *WorkloadWindowCollector) rotateRPCLocked() {
	if len(c.currentRPC) == 0 {
		return
	}

	laneTotals := map[rpcLaneKey]rpcAggregate{}
	for key, agg := range c.currentRPC {
		laneKey := rpcLaneKey{FSName: key.FSName, MountPath: key.MountPath, ActorType: key.ActorType}
		lane := laneTotals[laneKey]
		lane.Add(*agg)
		laneTotals[laneKey] = lane
	}

	totalByLane := map[rpcLaneKey]rpcAggregate{}
	otherByLane := map[rpcLaneKey]rpcAggregate{}
	visibleByLane := map[rpcLaneKey][]rankedRPCEntity{}

	for key, agg := range c.currentRPC {
		laneKey := rpcLaneKey{FSName: key.FSName, MountPath: key.MountPath, ActorType: key.ActorType}
		total := totalByLane[laneKey]
		total.Add(*agg)
		totalByLane[laneKey] = total

		relevance := c.evaluateRPCRelevance(*agg, laneTotals[laneKey])
		if agg.ForceKeep {
			relevance.Keep = true
			relevance.HardKeep = true
			relevance.Score = math.Max(relevance.Score, 1.0)
		}
		stateKey := c.rpcStateKey(key)
		next, visible := transitionVisibility(c.rpcState[stateKey], relevance.Keep, relevance.HardKeep, c.cfg.PromoteWindows, c.cfg.DemoteWindows)
		c.rpcState[stateKey] = next
		if visible {
			visibleByLane[laneKey] = append(visibleByLane[laneKey], rankedRPCEntity{Key: key, Aggregate: *agg, Score: relevance.Score})
			continue
		}
		other := otherByLane[laneKey]
		other.Add(*agg)
		otherByLane[laneKey] = other
	}

	for lane := range totalByLane {
		visible := visibleByLane[lane]
		sort.Slice(visible, func(i, j int) bool {
			if visible[i].Score != visible[j].Score {
				return visible[i].Score > visible[j].Score
			}
			if visible[i].Key.Process != visible[j].Key.Process {
				return visible[i].Key.Process < visible[j].Key.Process
			}
			return visible[i].Key.UID < visible[j].Key.UID
		})
		limit := c.cfg.TopN
		if limit <= 0 || limit > len(visible) {
			limit = len(visible)
		}
		for i, item := range visible {
			if i < limit {
				c.incrementRPCSeriesLocked(lane, item.Key.UID, item.Key.Username, item.Key.Process, item.Key.SlurmJobID, aggregationIndividual, item.Aggregate)
				continue
			}
			other := otherByLane[lane]
			other.Add(item.Aggregate)
			otherByLane[lane] = other
		}
		if other, ok := otherByLane[lane]; ok && (other.Ops > 0 || other.LatencyHist.Count > 0) {
			c.incrementRPCSeriesLocked(lane, aggregateIdentityOther, aggregateIdentityOther, aggregateIdentityOther, aggregateIdentityOther, aggregationOther, other)
		}
	}
}

type rankedAccessEntity struct {
	Key       accessEntityIntentKey
	Aggregate accessAggregate
	Score     float64
}

type rankedRPCEntity struct {
	Key       rpcEntityKey
	Aggregate rpcAggregate
	Score     float64
}

func (c *WorkloadWindowCollector) evaluateAccessRelevance(intent string, agg, total accessAggregate) accessRelevance {
	if agg.ForceKeep {
		return accessRelevance{Keep: true, HardKeep: true, Score: 1.0}
	}
	countShare := share(agg.Ops, total.Ops)
	byteShare := share(agg.Bytes, total.Bytes)
	latencyShare := share(agg.LatencyHist.Sum, total.LatencyHist.Sum)
	switch intent {
	case IntentNamespaceRead, IntentNamespaceMutation:
		keep := (countShare >= 0.03 && agg.Ops >= 20) || (latencyShare >= 0.05 && agg.LatencyHist.Sum >= 0.25)
		hard := (countShare >= 0.30 && agg.Ops >= 20) || (latencyShare >= 0.10 && agg.LatencyHist.Sum >= 0.25)
		return accessRelevance{Keep: keep, HardKeep: hard, Score: math.Max(countShare, latencyShare)}
	case IntentDataRead, IntentDataWrite:
		keep := (byteShare >= 0.03 && agg.Bytes >= 64*1024*1024) || (latencyShare >= 0.05 && agg.LatencyHist.Sum >= 0.25) || (countShare >= 0.05 && agg.Ops >= 32)
		hard := (byteShare >= 0.30 && agg.Bytes >= 64*1024*1024) || (latencyShare >= 0.10 && agg.LatencyHist.Sum >= 0.25)
		return accessRelevance{Keep: keep, HardKeep: hard, Score: math.Max(math.Max(byteShare, latencyShare), 0.5*countShare)}
	case IntentSync:
		keep := (latencyShare >= 0.05 && agg.LatencyHist.Sum >= 0.10) || (countShare >= 0.05 && agg.Ops >= 4)
		hard := (latencyShare >= 0.10 && agg.LatencyHist.Sum >= 0.10)
		return accessRelevance{Keep: keep, HardKeep: hard, Score: math.Max(latencyShare, countShare)}
	default:
		return accessRelevance{}
	}
}

func (c *WorkloadWindowCollector) evaluateRPCRelevance(agg, total rpcAggregate) accessRelevance {
	if agg.ForceKeep {
		return accessRelevance{Keep: true, HardKeep: true, Score: 1.0}
	}
	countShare := share(agg.Ops, total.Ops)
	latencyShare := share(agg.LatencyHist.Sum, total.LatencyHist.Sum)
	keep := (latencyShare >= 0.05 && agg.LatencyHist.Sum >= 0.10) || (countShare >= 0.05 && agg.Ops >= 3)
	hard := (latencyShare >= 0.10 && agg.LatencyHist.Sum >= 0.10)
	return accessRelevance{Keep: keep, HardKeep: hard, Score: math.Max(latencyShare, countShare)}
}

func share(value, total float64) float64 {
	if total <= 0 || value <= 0 {
		return 0
	}
	return value / total
}

func transitionVisibility(current entityVisibility, candidate, hard bool, promoteWindows, demoteWindows int) (entityVisibility, bool) {
	if hard {
		return entityVisibility{State: visibilityKept}, true
	}
	if candidate {
		switch current.State {
		case visibilityKept, visibilityDemoting:
			return entityVisibility{State: visibilityKept}, true
		case visibilityPromoting:
			current.PromoteHits++
			if current.PromoteHits >= promoteWindows {
				return entityVisibility{State: visibilityKept}, true
			}
			current.State = visibilityPromoting
			return current, false
		default:
			if promoteWindows <= 1 {
				return entityVisibility{State: visibilityKept}, true
			}
			return entityVisibility{State: visibilityPromoting, PromoteHits: 1}, false
		}
	}

	switch current.State {
	case visibilityKept:
		if demoteWindows <= 1 {
			return entityVisibility{State: visibilitySuppressed}, false
		}
		return entityVisibility{State: visibilityDemoting, DemoteHits: 1}, true
	case visibilityDemoting:
		current.DemoteHits++
		if current.DemoteHits >= demoteWindows {
			return entityVisibility{State: visibilitySuppressed}, false
		}
		current.State = visibilityDemoting
		return current, true
	default:
		return entityVisibility{State: visibilitySuppressed}, false
	}
}

func (c *WorkloadWindowCollector) incrementAccessSeriesLocked(lane accessExportLane, uid, username, process, slurmJobID, aggregation string, agg accessAggregate) {
	labels := workloadAccessLabelValues(lane.FSName, lane.MountPath, lane.Intent, uid, username, process, lane.ActorType, slurmJobID, aggregation, c.slurmEnabled, c.uidEnabled)
	if agg.Ops > 0 {
		c.incrementCounterSeriesLocked(c.accessOpsSeries, labels, agg.Ops)
	}
	if agg.Bytes > 0 {
		c.incrementCounterSeriesLocked(c.dataBytesSeries, labels, agg.Bytes)
	}
	if agg.LatencyHist.Count > 0 {
		c.incrementHistogramSeriesLocked(c.accessHistSeries, labels, agg.LatencyHist)
	}
}

func (c *WorkloadWindowCollector) incrementRPCSeriesLocked(lane rpcLaneKey, uid, username, process, slurmJobID, aggregation string, agg rpcAggregate) {
	labels := workloadRPCWaitLabelValues(lane.FSName, lane.MountPath, uid, username, process, lane.ActorType, slurmJobID, aggregation, c.slurmEnabled, c.uidEnabled)
	if agg.Ops > 0 {
		c.incrementCounterSeriesLocked(c.rpcOpsSeries, labels, agg.Ops)
	}
	if agg.LatencyHist.Count > 0 {
		c.incrementHistogramSeriesLocked(c.rpcHistSeries, labels, agg.LatencyHist)
	}
}

func (c *WorkloadWindowCollector) incrementCounterSeriesLocked(store map[string]*counterSeries, labels []string, value float64) {
	key := joinLabelKey(labels...)
	series, ok := store[key]
	if !ok {
		series = &counterSeries{seriesMeta: seriesMeta{Labels: labels}}
		store[key] = series
	}
	series.Value += value
	series.LastUpdatedTick = c.tick
}

func (c *WorkloadWindowCollector) incrementHistogramSeriesLocked(store map[string]*histogramSeries, labels []string, value histogramState) {
	key := joinLabelKey(labels...)
	series, ok := store[key]
	if !ok {
		series = &histogramSeries{seriesMeta: seriesMeta{Labels: labels}, Value: newHistogramState()}
		store[key] = series
	}
	series.Value.Add(value)
	series.LastUpdatedTick = c.tick
}

func (c *WorkloadWindowCollector) accessStateKey(key accessEntityIntentKey) string {
	return joinLabelKey(key.FSName, key.MountPath, key.Intent, key.UID, key.Username, key.Process, key.ActorType, key.SlurmJobID)
}

func (c *WorkloadWindowCollector) rpcStateKey(key rpcEntityKey) string {
	return joinLabelKey(key.FSName, key.MountPath, key.UID, key.Username, key.Process, key.ActorType, key.SlurmJobID)
}
