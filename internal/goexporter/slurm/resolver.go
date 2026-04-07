// Package slurm resolves a process id to its Slurm job context by reading
// /proc/<pid>/environ and /proc/<pid>/cgroup. It is designed to be called
// from the perf-event hot path: cache hits are O(1) map lookups and
// failures never return errors — they collapse to an empty JobInfo.
package slurm

import (
	"strconv"
	"sync"
	"time"
)

// FSReader reads a file. Injected into the resolver so tests can fake
// /proc without touching the real filesystem.
type FSReader func(path string) ([]byte, error)

// Options configures a Resolver.
type Options struct {
	// Enabled turns resolution on. When false, Resolve() is a zero-cost
	// shim that always returns JobInfo{} without touching any FSReader.
	Enabled bool

	// TTL is how long a successful lookup stays cached.
	TTL time.Duration

	// NegativeTTL is how long an unsuccessful lookup stays cached.
	// Kept short so that a newly-started Slurm job starts being labeled
	// quickly after the resolver initially missed it.
	NegativeTTL time.Duration

	// VerifyTTL is how long a cached entry can be served without
	// re-reading /proc/<pid>/stat to confirm the pid still points at the
	// same process. Larger values trade staleness for fewer syscalls.
	VerifyTTL time.Duration

	// MaxEntries caps the cache size.
	MaxEntries int

	// ReadEnviron, ReadCgroup, ReadStat are the file readers used.
	// Defaults are installed by the platform-specific constructor.
	ReadEnviron FSReader
	ReadCgroup  FSReader
	ReadStat    FSReader

	// Now returns the current time. Defaults to time.Now. Overridden in tests.
	Now func() time.Time
}

// JobInfo holds the resolved Slurm context for a pid. An empty JobID means
// the pid did not belong to a Slurm job, or the lookup failed.
type JobInfo struct {
	JobID string
}

// Resolver is a concurrency-safe pid -> JobInfo lookup with TTL caching
// and pid-reuse protection via /proc/<pid>/stat starttime.
type Resolver struct {
	opts Options

	mu      sync.Mutex
	entries map[uint32]cacheEntry
}

// New constructs a Resolver. Callers should populate FSReader fields unless
// the default Linux implementation (installed by NewDefault) is acceptable.
func New(opts Options) *Resolver {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.TTL <= 0 {
		opts.TTL = 30 * time.Second
	}
	if opts.NegativeTTL <= 0 {
		opts.NegativeTTL = 5 * time.Second
	}
	if opts.VerifyTTL <= 0 {
		opts.VerifyTTL = time.Second
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = 8192
	}
	return &Resolver{
		opts:    opts,
		entries: make(map[uint32]cacheEntry),
	}
}

// Enabled reports whether the resolver actually performs lookups.
func (r *Resolver) Enabled() bool { return r != nil && r.opts.Enabled }

// Invalidate drops the cached entry for pid if present.
func (r *Resolver) Invalidate(pid uint32) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.entries, pid)
	r.mu.Unlock()
}

// Resolve returns the Slurm context for pid. It never blocks on IO-heavy
// work that is not bounded: the slow path reads up to three small /proc
// files once. All failures collapse to JobInfo{}.
func (r *Resolver) Resolve(pid uint32) JobInfo {
	if r == nil || !r.opts.Enabled {
		return JobInfo{}
	}

	now := r.opts.Now()

	// Fast path: cache hit within VerifyTTL skips even the stat read.
	r.mu.Lock()
	entry, ok := r.entries[pid]
	if ok && entry.expiresAt.After(now) && entry.verifiedAt.Add(r.opts.VerifyTTL).After(now) {
		info := entry.info
		r.mu.Unlock()
		return info
	}
	r.mu.Unlock()

	// Slow path: read starttime, compare against cached value.
	statPath := "/proc/" + strconv.FormatUint(uint64(pid), 10) + "/stat"
	statRaw, err := r.opts.ReadStat(statPath)
	if err != nil {
		// Process gone or inaccessible. Do not poison the cache; a new
		// event for this pid may come with different conditions.
		return JobInfo{}
	}
	start, err := parseProcStatStarttime(statRaw)
	if err != nil {
		return JobInfo{}
	}

	// Re-check cache with the fresh starttime so a concurrent refresh
	// does not cause duplicate /proc reads.
	r.mu.Lock()
	entry, ok = r.entries[pid]
	if ok && entry.starttime == start && entry.expiresAt.After(now) {
		entry.verifiedAt = now
		r.entries[pid] = entry
		info := entry.info
		r.mu.Unlock()
		return info
	}
	r.mu.Unlock()

	// Fetch: environ -> cgroup -> empty.
	info := JobInfo{}
	environPath := "/proc/" + strconv.FormatUint(uint64(pid), 10) + "/environ"
	if raw, err := r.opts.ReadEnviron(environPath); err == nil {
		if v, ok := parseSlurmJobIDFromEnviron(raw); ok {
			info.JobID = v
		}
	}
	if info.JobID == "" {
		cgroupPath := "/proc/" + strconv.FormatUint(uint64(pid), 10) + "/cgroup"
		if raw, err := r.opts.ReadCgroup(cgroupPath); err == nil {
			if v, ok := parseSlurmJobIDFromCgroup(raw); ok {
				info.JobID = v
			}
		}
	}

	ttl := r.opts.NegativeTTL
	if info.JobID != "" {
		ttl = r.opts.TTL
	}

	r.mu.Lock()
	if len(r.entries) >= r.opts.MaxEntries {
		evictOldest(r.entries)
	}
	r.entries[pid] = cacheEntry{
		starttime:  start,
		info:       info,
		expiresAt:  now.Add(ttl),
		verifiedAt: now,
	}
	r.mu.Unlock()

	return info
}
