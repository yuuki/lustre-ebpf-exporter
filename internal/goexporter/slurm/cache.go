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

// Expirable is implemented by cache entry types that carry an expiration time.
type Expirable interface {
	ExpireTime() time.Time
}

func (e cacheEntry) ExpireTime() time.Time { return e.expiresAt }

// EvictOldest drops the single entry closest to expiry from a map.
// O(n) but only runs at saturation; the fast path is untouched.
func EvictOldest[K comparable, V Expirable](m map[K]V) {
	var oldestKey K
	var oldestSet bool
	var oldestExp time.Time
	for k, v := range m {
		if !oldestSet || v.ExpireTime().Before(oldestExp) {
			oldestKey = k
			oldestExp = v.ExpireTime()
			oldestSet = true
		}
	}
	if oldestSet {
		delete(m, oldestKey)
	}
}

func evictOldest(m map[uint32]cacheEntry) {
	EvictOldest(m)
}
