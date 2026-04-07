package slurm

import "time"

// cacheEntry is the value stored in the resolver cache, keyed by pid.
// starttime is used to detect pid reuse: if the pid's current starttime
// differs from the cached one, the cached entry refers to a previous
// process that happened to have the same pid and must be discarded.
type cacheEntry struct {
	starttime  uint64
	info       JobInfo
	expiresAt  time.Time
	verifiedAt time.Time
}

// evictOldest drops a single oldest-by-expiry entry. Called when the map
// exceeds MaxEntries to keep memory bounded. O(n) but only runs when the
// map is saturated; the fast path (normal cache hit) is untouched.
func evictOldest(m map[uint32]cacheEntry) {
	var oldestKey uint32
	var oldestSet bool
	var oldestExp time.Time
	for k, v := range m {
		if !oldestSet || v.expiresAt.Before(oldestExp) {
			oldestKey = k
			oldestExp = v.expiresAt
			oldestSet = true
		}
	}
	if oldestSet {
		delete(m, oldestKey)
	}
}
