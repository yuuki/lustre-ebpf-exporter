package goexporter

import (
	"sort"
	"sync"
	"sync/atomic"
)

const processOther = "other"

// ProcessFilter normalizes process names to reduce Prometheus label
// cardinality. It supports two complementary strategies:
//
//  1. Static allowlist: only names in the allowlist pass through; everything
//     else becomes "other". When set, the allowlist takes priority and
//     tail-trimming is not applied.
//
//  2. Dynamic tail-trimming: after each drain interval, processes are ranked
//     by cumulative operation count. The bottom trimPercent% of unique process
//     names (by ops) are collapsed to "other". A hysteresis window (consecutive
//     drain cycles a process must be in the trim set) prevents label churn.
type ProcessFilter struct {
	// Static allowlist (nil means disabled). Immutable after construction.
	allowlist map[string]struct{}

	// Tail-trim configuration. Immutable after construction.
	trimPercent float64 // 0–100; 0 means disabled.
	hysteresis  int     // consecutive cycles before actually trimming.

	// stripSuffix removes trailing separator+digits before filtering.
	stripSuffix bool

	// trimmed is stored as atomic.Value holding map[string]struct{} for
	// lock-free reads on the hot path. Updated by UpdateTrimSet only.
	trimmed atomic.Value // map[string]struct{}

	// trimCandidateCount is only accessed by UpdateTrimSet (single writer,
	// called from the drain goroutine), protected by candidateMu.
	candidateMu        sync.Mutex
	trimCandidateCount map[string]int
}

// NewProcessFilter creates a filter. Pass nil allowlist and trimPercent=0
// to create a no-op filter (all names pass through).
func NewProcessFilter(allowlist []string, trimPercent float64, hysteresis int, stripSuffix bool) *ProcessFilter {
	var al map[string]struct{}
	if len(allowlist) > 0 {
		al = make(map[string]struct{}, len(allowlist))
		for _, name := range allowlist {
			al[name] = struct{}{}
		}
	}
	if hysteresis < 1 {
		hysteresis = 1 // defensive: callers should validate before construction
	}
	f := &ProcessFilter{
		allowlist:          al,
		trimPercent:        trimPercent,
		hysteresis:         hysteresis,
		stripSuffix:        stripSuffix,
		trimCandidateCount: map[string]int{},
	}
	f.trimmed.Store(map[string]struct{}{})
	return f
}

// Normalize returns the filtered process name. Non-matching processes
// are replaced with "other". Lock-free on the hot path.
//
// bpfComm is the optional BPF comm fallback name (max 15 chars). When
// the trim set is built from BPF counter maps (which only have comm),
// the full resolved name may not match. Passing bpfComm allows the
// filter to check both names against the trim set.
func (f *ProcessFilter) Normalize(process string, bpfComm ...string) string {
	if f.stripSuffix {
		process = stripTrailingNumericSuffix(process)
		// Only strip bpfComm when trim set is active; it is only used
		// as a fallback for trim-set matching below.
		if f.trimPercent > 0 && len(bpfComm) > 0 {
			bpfComm[0] = stripTrailingNumericSuffix(bpfComm[0])
		}
	}

	if f.allowlist != nil {
		if _, ok := f.allowlist[process]; ok {
			return process
		}
		return processOther
	}

	if f.trimPercent > 0 {
		trimmed := f.trimmed.Load().(map[string]struct{})
		if _, ok := trimmed[process]; ok {
			return processOther
		}
		// The trim set is built from BPF comm (max 15 chars). If the
		// resolved full name differs from the BPF comm, also check the
		// BPF comm so that long process names are correctly trimmed.
		if len(bpfComm) > 0 && bpfComm[0] != process {
			if _, ok := trimmed[bpfComm[0]]; ok {
				return processOther
			}
		}
	}

	return process
}

// processOpsEntry is used for sorting processes by ops count.
type processOpsEntry struct {
	name string
	ops  float64
}

// UpdateTrimSet recomputes which processes should be trimmed based on
// the current per-process operation counts. Called once per drain interval.
func (f *ProcessFilter) UpdateTrimSet(opsPerProcess map[string]float64) {
	if f.allowlist != nil || f.trimPercent <= 0 {
		return
	}

	entries := make([]processOpsEntry, 0, len(opsPerProcess))
	for name, ops := range opsPerProcess {
		entries = append(entries, processOpsEntry{name: name, ops: ops})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].ops != entries[j].ops {
			return entries[i].ops < entries[j].ops
		}
		return entries[i].name < entries[j].name
	})

	trimCount := int(float64(len(entries)) * f.trimPercent / 100.0)

	candidates := make(map[string]struct{}, trimCount)
	for i := 0; i < trimCount && i < len(entries); i++ {
		candidates[entries[i].name] = struct{}{}
	}

	// Build new state outside any lock contention path.
	f.candidateMu.Lock()
	newCounts := make(map[string]int, len(candidates))
	for name := range candidates {
		newCounts[name] = f.trimCandidateCount[name] + 1
	}
	f.trimCandidateCount = newCounts
	f.candidateMu.Unlock()

	newTrimmed := make(map[string]struct{})
	for name, count := range newCounts {
		if count >= f.hysteresis {
			newTrimmed[name] = struct{}{}
		}
	}
	// Atomic swap — readers never block.
	f.trimmed.Store(newTrimmed)
}

// ShouldUpdateTrimSet returns true when tail-trimming is enabled and no
// allowlist overrides it.
func (f *ProcessFilter) ShouldUpdateTrimSet() bool {
	return f.trimPercent > 0 && f.allowlist == nil
}

// TrimmedCount returns the number of currently trimmed process names.
func (f *ProcessFilter) TrimmedCount() int {
	return len(f.trimmed.Load().(map[string]struct{}))
}

// IsActive returns true if the filter is doing any filtering.
func (f *ProcessFilter) IsActive() bool {
	return f.allowlist != nil || f.trimPercent > 0 || f.stripSuffix
}

// stripTrailingNumericSuffix removes a trailing separator+digits suffix from
// a process name to collapse numbered variants (e.g. "Bun Pool 1" → "Bun Pool").
// Recognised separators: space, dash, underscore, colon.
// Names where digits follow a period (e.g. "python3.11") are left unchanged.
func stripTrailingNumericSuffix(s string) string {
	i := len(s) - 1
	for i >= 0 && s[i] >= '0' && s[i] <= '9' {
		i--
	}
	if i == len(s)-1 {
		return s // no trailing digits
	}
	if i < 0 {
		return s // entire string is digits
	}
	switch s[i] {
	case ' ', '-', '_', ':':
		if i == 0 {
			return s // would reduce to empty
		}
		return s[:i]
	default:
		return s // separator not recognised (e.g. period)
	}
}
