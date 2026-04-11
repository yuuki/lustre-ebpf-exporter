package goexporter

import (
	"sort"
	"sync"
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
	mu sync.RWMutex

	// Static allowlist (nil means disabled).
	allowlist map[string]struct{}

	// Tail-trim configuration.
	trimPercent float64 // 0–100; 0 means disabled.
	hysteresis  int     // consecutive cycles before actually trimming.

	// Tail-trim state.
	trimmed      map[string]struct{} // currently trimmed processes.
	trimCandidateCount map[string]int // process → consecutive cycles in trim candidate set.
}

// NewProcessFilter creates a filter. Pass nil allowlist and trimPercent=0
// to create a no-op filter (all names pass through).
func NewProcessFilter(allowlist []string, trimPercent float64, hysteresis int) *ProcessFilter {
	var al map[string]struct{}
	if len(allowlist) > 0 {
		al = make(map[string]struct{}, len(allowlist))
		for _, name := range allowlist {
			al[name] = struct{}{}
		}
	}
	if hysteresis < 1 {
		hysteresis = 1
	}
	return &ProcessFilter{
		allowlist:          al,
		trimPercent:        trimPercent,
		hysteresis:         hysteresis,
		trimmed:            map[string]struct{}{},
		trimCandidateCount: map[string]int{},
	}
}

// Normalize returns the filtered process name. Non-matching processes
// are replaced with "other".
func (f *ProcessFilter) Normalize(process string) string {
	// Allowlist mode: takes priority.
	if f.allowlist != nil {
		if _, ok := f.allowlist[process]; ok {
			return process
		}
		return processOther
	}

	// Tail-trim mode.
	if f.trimPercent > 0 {
		f.mu.RLock()
		_, trimmed := f.trimmed[process]
		f.mu.RUnlock()
		if trimmed {
			return processOther
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
// The opsPerProcess map should aggregate ops across all accumulator maps
// (llite + rpc).
func (f *ProcessFilter) UpdateTrimSet(opsPerProcess map[string]float64) {
	if f.allowlist != nil || f.trimPercent <= 0 {
		return
	}

	entries := make([]processOpsEntry, 0, len(opsPerProcess))
	for name, ops := range opsPerProcess {
		entries = append(entries, processOpsEntry{name: name, ops: ops})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ops < entries[j].ops
	})

	// Bottom trimPercent% of unique process names.
	trimCount := int(float64(len(entries)) * f.trimPercent / 100.0)

	// Build candidate set for this cycle.
	candidates := make(map[string]struct{}, trimCount)
	for i := 0; i < trimCount && i < len(entries); i++ {
		candidates[entries[i].name] = struct{}{}
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Update hysteresis counters.
	newCounts := make(map[string]int, len(candidates))
	for name := range candidates {
		newCounts[name] = f.trimCandidateCount[name] + 1
	}
	f.trimCandidateCount = newCounts

	// Only trim processes that have been candidates for hysteresis consecutive cycles.
	newTrimmed := make(map[string]struct{})
	for name, count := range f.trimCandidateCount {
		if count >= f.hysteresis {
			newTrimmed[name] = struct{}{}
		}
	}
	f.trimmed = newTrimmed
}

// TrimmedCount returns the number of currently trimmed process names.
func (f *ProcessFilter) TrimmedCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.trimmed)
}

// IsActive returns true if the filter is doing any filtering.
func (f *ProcessFilter) IsActive() bool {
	return f.allowlist != nil || f.trimPercent > 0
}
