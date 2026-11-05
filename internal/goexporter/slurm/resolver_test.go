package slurm

import (
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// statBlob builds a /proc/<pid>/stat blob whose field 22 is the given starttime.
func statBlob(starttime uint64) []byte {
	s := "1 (t) S"
	for i := 4; i <= 22; i++ {
		s += " "
		if i == 22 {
			s += formatUint(starttime)
		} else {
			s += "0"
		}
	}
	s += " 1 2 3\n"
	return []byte(s)
}

type fakeFS struct {
	stat    []byte
	statErr error
	environ []byte
	envErr  error
	cgroup  []byte
	cgErr   error

	statCalls    atomic.Int64
	environCalls atomic.Int64
	cgroupCalls  atomic.Int64
}

func (f *fakeFS) readStat(_ string) ([]byte, error) {
	f.statCalls.Add(1)
	return f.stat, f.statErr
}

func (f *fakeFS) readEnviron(_ string) ([]byte, error) {
	f.environCalls.Add(1)
	return f.environ, f.envErr
}

func (f *fakeFS) readCgroup(_ string) ([]byte, error) {
	f.cgroupCalls.Add(1)
	return f.cgroup, f.cgErr
}

func newResolver(fs *fakeFS, opts Options) *Resolver {
	opts.Enabled = true
	opts.ReadStat = fs.readStat
	opts.ReadEnviron = fs.readEnviron
	opts.ReadCgroup = fs.readCgroup
	return New(opts)
}

func TestResolverDisabledIsZeroCost(t *testing.T) {
	t.Parallel()

	fs := &fakeFS{stat: statBlob(100), environ: []byte("SLURM_JOB_ID=42\x00")}
	r := New(Options{
		Enabled:     false,
		ReadStat:    fs.readStat,
		ReadEnviron: fs.readEnviron,
		ReadCgroup:  fs.readCgroup,
	})

	info := r.Resolve(123)
	if info.JobID != "" {
		t.Fatalf("expected empty JobID, got %q", info.JobID)
	}
	if fs.statCalls.Load()+fs.environCalls.Load()+fs.cgroupCalls.Load() != 0 {
		t.Fatalf("disabled resolver must not read /proc")
	}
}

func TestResolverEnvironPath(t *testing.T) {
	t.Parallel()

	fs := &fakeFS{
		stat:    statBlob(100),
		environ: []byte("FOO=bar\x00SLURM_JOB_ID=42\x00"),
	}
	r := newResolver(fs, Options{})
	info := r.Resolve(123)
	if info.JobID != "42" {
		t.Fatalf("expected 42, got %q", info.JobID)
	}
}

func TestResolverCgroupFallback(t *testing.T) {
	t.Parallel()

	fs := &fakeFS{
		stat:   statBlob(100),
		envErr: errors.New("EACCES"),
		cgroup: []byte("0::/slurm/uid_1000/job_7/step_0\n"),
	}
	r := newResolver(fs, Options{})
	info := r.Resolve(123)
	if info.JobID != "7" {
		t.Fatalf("expected 7, got %q", info.JobID)
	}
}

func TestResolverEmptyWhenNoSlurm(t *testing.T) {
	t.Parallel()

	fs := &fakeFS{
		stat:    statBlob(100),
		environ: []byte("PATH=/usr/bin\x00"),
		cgroup:  []byte("0::/user.slice/user-1000.slice\n"),
	}
	r := newResolver(fs, Options{})
	info := r.Resolve(123)
	if info.JobID != "" {
		t.Fatalf("expected empty JobID, got %q", info.JobID)
	}
}

func TestResolverStatErrorDoesNotCache(t *testing.T) {
	t.Parallel()

	fs := &fakeFS{statErr: os.ErrNotExist}
	r := newResolver(fs, Options{})
	_ = r.Resolve(123)
	_ = r.Resolve(123)

	// Both calls should hit the stat reader; no cache entry should have
	// been created because we have no starttime to validate with.
	if got := fs.statCalls.Load(); got != 2 {
		t.Fatalf("expected 2 stat calls, got %d", got)
	}
}

func TestResolverCachesPositive(t *testing.T) {
	t.Parallel()

	fs := &fakeFS{
		stat:    statBlob(100),
		environ: []byte("SLURM_JOB_ID=42\x00"),
	}
	r := newResolver(fs, Options{TTL: time.Minute, VerifyTTL: time.Minute})

	r.Resolve(123)
	r.Resolve(123)
	r.Resolve(123)

	// First call fetches; subsequent calls should hit the verify-TTL
	// fast path and never touch the readers.
	if fs.statCalls.Load() != 1 {
		t.Fatalf("expected 1 stat call, got %d", fs.statCalls.Load())
	}
	if fs.environCalls.Load() != 1 {
		t.Fatalf("expected 1 environ call, got %d", fs.environCalls.Load())
	}
}

func TestResolverCachesNegative(t *testing.T) {
	t.Parallel()

	fs := &fakeFS{
		stat:    statBlob(100),
		environ: []byte(""),
		cgroup:  []byte(""),
	}
	r := newResolver(fs, Options{NegativeTTL: time.Minute, VerifyTTL: time.Minute})

	r.Resolve(123)
	r.Resolve(123)

	if fs.environCalls.Load() != 1 {
		t.Fatalf("expected 1 environ call, got %d", fs.environCalls.Load())
	}
	if fs.cgroupCalls.Load() != 1 {
		t.Fatalf("expected 1 cgroup call, got %d", fs.cgroupCalls.Load())
	}
}

func TestResolverPidReuseInvalidates(t *testing.T) {
	t.Parallel()

	// Controllable clock
	clock := time.Unix(1000, 0)
	now := func() time.Time { return clock }

	fs := &fakeFS{
		stat:    statBlob(100),
		environ: []byte("SLURM_JOB_ID=42\x00"),
	}
	r := New(Options{
		Enabled:     true,
		TTL:         time.Hour,
		VerifyTTL:   0, // force starttime verification every call
		ReadStat:    fs.readStat,
		ReadEnviron: fs.readEnviron,
		ReadCgroup:  fs.readCgroup,
		Now:         now,
	})

	info := r.Resolve(123)
	if info.JobID != "42" {
		t.Fatalf("expected 42, got %q", info.JobID)
	}

	// Simulate pid reuse: new process has different starttime and no slurm env.
	fs.stat = statBlob(200)
	fs.environ = []byte("PATH=/bin\x00")
	fs.cgroup = []byte("0::/user.slice\n")

	clock = clock.Add(time.Second)
	info = r.Resolve(123)
	if info.JobID != "" {
		t.Fatalf("expected pid reuse to clear JobID, got %q", info.JobID)
	}
}

func TestResolverVerifyTTLSkipsStat(t *testing.T) {
	t.Parallel()

	clock := time.Unix(1000, 0)
	now := func() time.Time { return clock }

	fs := &fakeFS{
		stat:    statBlob(100),
		environ: []byte("SLURM_JOB_ID=42\x00"),
	}
	r := New(Options{
		Enabled:     true,
		TTL:         time.Hour,
		VerifyTTL:   10 * time.Second,
		ReadStat:    fs.readStat,
		ReadEnviron: fs.readEnviron,
		ReadCgroup:  fs.readCgroup,
		Now:         now,
	})

	r.Resolve(123)
	// Within VerifyTTL window: no additional stat read.
	clock = clock.Add(5 * time.Second)
	r.Resolve(123)
	if fs.statCalls.Load() != 1 {
		t.Fatalf("expected 1 stat call within verify TTL, got %d", fs.statCalls.Load())
	}
	// Outside VerifyTTL but within TTL: stat read happens again, but
	// environ/cgroup do not.
	clock = clock.Add(30 * time.Second)
	r.Resolve(123)
	if fs.statCalls.Load() != 2 {
		t.Fatalf("expected 2 stat calls after verify TTL expired, got %d", fs.statCalls.Load())
	}
	if fs.environCalls.Load() != 1 {
		t.Fatalf("expected 1 environ call, got %d", fs.environCalls.Load())
	}
}

func TestResolverEvictionAtCapacity(t *testing.T) {
	t.Parallel()

	clock := time.Unix(1000, 0)
	now := func() time.Time { return clock }

	fs := &fakeFS{
		stat:    statBlob(100),
		environ: []byte("SLURM_JOB_ID=42\x00"),
	}
	r := New(Options{
		Enabled:     true,
		TTL:         time.Hour,
		VerifyTTL:   time.Hour,
		MaxEntries:  2,
		ReadStat:    fs.readStat,
		ReadEnviron: fs.readEnviron,
		ReadCgroup:  fs.readCgroup,
		Now:         now,
	})

	r.Resolve(100)
	clock = clock.Add(time.Second)
	r.Resolve(101)
	clock = clock.Add(time.Second)
	r.Resolve(102)

	r.mu.Lock()
	size := len(r.entries)
	r.mu.Unlock()
	if size > 2 {
		t.Fatalf("cache exceeded MaxEntries: got %d", size)
	}
}

func TestResolverEnabledReportsState(t *testing.T) {
	t.Parallel()

	var nilResolver *Resolver
	if nilResolver.Enabled() {
		t.Fatalf("nil resolver should not be enabled")
	}
	on := New(Options{Enabled: true})
	if !on.Enabled() {
		t.Fatalf("enabled resolver should report true")
	}
	off := New(Options{Enabled: false})
	if off.Enabled() {
		t.Fatalf("disabled resolver should report false")
	}
}

// recordingFS serves /proc files from a map and records every path read, in
// order. A path missing from the map fails with os.ErrNotExist.
type recordingFS struct {
	files map[string][]byte
	reads []string
}

func (f *recordingFS) read(path string) ([]byte, error) {
	f.reads = append(f.reads, path)
	if b, ok := f.files[path]; ok {
		return b, nil
	}
	return nil, os.ErrNotExist
}

// countingClock is a settable clock that counts how often it is read.
type countingClock struct {
	now   time.Time
	calls int
}

func (c *countingClock) Now() time.Time {
	c.calls++
	return c.now
}

var resolveEpoch = time.Unix(1000, 0)

const (
	resolveTTL         = time.Minute
	resolveNegativeTTL = 10 * time.Second
	resolveVerifyTTL   = 5 * time.Second
)

// newRecordingResolver returns an enabled resolver whose readers are fs.read
// and whose clock is clock, with seed already cached.
func newRecordingResolver(fs *recordingFS, clock *countingClock, maxEntries int, seed map[uint32]cacheEntry) *Resolver {
	r := New(Options{
		Enabled:     true,
		TTL:         resolveTTL,
		NegativeTTL: resolveNegativeTTL,
		VerifyTTL:   resolveVerifyTTL,
		MaxEntries:  maxEntries,
		ReadEnviron: fs.read,
		ReadCgroup:  fs.read,
		ReadStat:    fs.read,
		Now:         clock.Now,
	})
	for pid, e := range seed {
		r.entries[pid] = e
	}
	return r
}

func assertEntries(t *testing.T, r *Resolver, want map[uint32]cacheEntry) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) != len(want) {
		t.Fatalf("cache = %+v, want %+v", r.entries, want)
	}
	for pid, w := range want {
		g, ok := r.entries[pid]
		if !ok || g.starttime != w.starttime || g.info != w.info || !g.expiresAt.Equal(w.expiresAt) || !g.verifiedAt.Equal(w.verifiedAt) {
			t.Fatalf("cache[%d] = %+v (present=%v), want %+v", pid, g, ok, w)
		}
	}
}

func assertReads(t *testing.T, fs *recordingFS, want ...string) {
	t.Helper()
	if strings.Join(fs.reads, " ") != strings.Join(want, " ") {
		t.Fatalf("reads = %q, want %q", fs.reads, want)
	}
}

// TestResolveFetch pins a lookup of an uncached pid: the files read, in order,
// the environ-then-cgroup precedence, and the entry cached for each outcome.
func TestResolveFetch(t *testing.T) {
	const (
		stat    = "/proc/4242/stat"
		environ = "/proc/4242/environ"
		cgroup  = "/proc/4242/cgroup"
	)
	slurmCgroup := []byte("0::/slurm/uid_1000/job_7/step_0\n")
	positive := func(jobID string) map[uint32]cacheEntry {
		return map[uint32]cacheEntry{4242: {starttime: 100, info: JobInfo{JobID: jobID},
			expiresAt: resolveEpoch.Add(resolveTTL), verifiedAt: resolveEpoch}}
	}
	negative := map[uint32]cacheEntry{4242: {starttime: 100, expiresAt: resolveEpoch.Add(resolveNegativeTTL), verifiedAt: resolveEpoch}}
	tests := []struct {
		name      string
		files     map[string][]byte
		want      string
		wantReads []string
		wantCache map[uint32]cacheEntry
	}{
		{
			name:      "environ job skips the cgroup",
			files:     map[string][]byte{stat: statBlob(100), environ: []byte("SLURM_JOB_ID=42\x00"), cgroup: slurmCgroup},
			want:      "42",
			wantReads: []string{stat, environ},
			wantCache: positive("42"),
		},
		{
			name:      "unreadable environ falls back to the cgroup",
			files:     map[string][]byte{stat: statBlob(100), cgroup: slurmCgroup},
			want:      "7",
			wantReads: []string{stat, environ, cgroup},
			wantCache: positive("7"),
		},
		{
			name:      "environ without a job falls back to the cgroup",
			files:     map[string][]byte{stat: statBlob(100), environ: []byte("PATH=/bin\x00SLURM_JOB_ID=\x00"), cgroup: slurmCgroup},
			want:      "7",
			wantReads: []string{stat, environ, cgroup},
			wantCache: positive("7"),
		},
		{
			name:      "no job is cached for NegativeTTL",
			files:     map[string][]byte{stat: statBlob(100), environ: []byte("PATH=/bin\x00"), cgroup: []byte("0::/user.slice\n")},
			wantReads: []string{stat, environ, cgroup},
			wantCache: negative,
		},
		{
			name:      "unreadable cgroup is cached for NegativeTTL",
			files:     map[string][]byte{stat: statBlob(100), environ: []byte("PATH=/bin\x00")},
			wantReads: []string{stat, environ, cgroup},
			wantCache: negative,
		},
		{
			name:      "unreadable stat is not cached",
			files:     map[string][]byte{environ: []byte("SLURM_JOB_ID=42\x00")},
			wantReads: []string{stat},
			wantCache: map[uint32]cacheEntry{},
		},
		{
			name:      "unparsable stat is not cached",
			files:     map[string][]byte{stat: []byte("4242 (x) S 1 2"), environ: []byte("SLURM_JOB_ID=42\x00")},
			wantReads: []string{stat},
			wantCache: map[uint32]cacheEntry{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := &recordingFS{files: tt.files}
			clock := &countingClock{now: resolveEpoch}
			r := newRecordingResolver(fs, clock, 8, nil)
			if got := r.Resolve(4242); got != (JobInfo{JobID: tt.want}) {
				t.Fatalf("Resolve = %+v, want JobID %q", got, tt.want)
			}
			assertReads(t, fs, tt.wantReads...)
			assertEntries(t, r, tt.wantCache)
			if clock.calls != 1 {
				t.Fatalf("clock read %d times, want 1", clock.calls)
			}
		})
	}
}

// TestResolveCachedEntry pins how a cached entry is served: from memory while
// it is unexpired and verified within VerifyTTL, after a stat read while it
// is unexpired and the starttime matches, and refetched otherwise. Both time
// limits are exclusive. A failed stat read leaves the entry alone.
func TestResolveCachedEntry(t *testing.T) {
	const (
		stat    = "/proc/7/stat"
		environ = "/proc/7/environ"
	)
	at := func(d time.Duration) time.Time { return resolveEpoch.Add(d) }
	cached := func(expires, verified time.Duration) cacheEntry {
		return cacheEntry{starttime: 100, info: JobInfo{JobID: "9"}, expiresAt: at(expires), verifiedAt: at(verified)}
	}
	refetched := func(now time.Duration, starttime uint64) cacheEntry {
		return cacheEntry{starttime: starttime, info: JobInfo{JobID: "42"}, expiresAt: at(now + resolveTTL), verifiedAt: at(now)}
	}
	env := []byte("SLURM_JOB_ID=42\x00")
	tests := []struct {
		name      string
		entry     cacheEntry
		now       time.Duration
		stat      []byte
		want      string
		wantReads []string
		wantEntry cacheEntry
	}{
		{
			name:      "verified entry is served without reads",
			entry:     cached(10*time.Second, 0),
			now:       resolveVerifyTTL - time.Nanosecond,
			stat:      statBlob(100),
			want:      "9",
			wantEntry: cached(10*time.Second, 0),
		},
		{
			name:      "verification expires at VerifyTTL",
			entry:     cached(10*time.Second, 0),
			now:       resolveVerifyTTL,
			stat:      statBlob(100),
			want:      "9",
			wantReads: []string{stat},
			wantEntry: cached(10*time.Second, resolveVerifyTTL),
		},
		{
			name:      "expired entry is not served inside the verify window",
			entry:     cached(3*time.Second, 0),
			now:       4 * time.Second,
			stat:      statBlob(100),
			want:      "42",
			wantReads: []string{stat, environ},
			wantEntry: refetched(4*time.Second, 100),
		},
		{
			name:      "entry expiring inside the verify window expires at expiresAt",
			entry:     cached(3*time.Second, 0),
			now:       3 * time.Second,
			stat:      statBlob(100),
			want:      "42",
			wantReads: []string{stat, environ},
			wantEntry: refetched(3*time.Second, 100),
		},
		{
			name:      "entry expires at expiresAt",
			entry:     cached(10*time.Second, 0),
			now:       10 * time.Second,
			stat:      statBlob(100),
			want:      "42",
			wantReads: []string{stat, environ},
			wantEntry: refetched(10*time.Second, 100),
		},
		{
			name:      "pid reuse refetches",
			entry:     cached(10*time.Second, 0),
			now:       6 * time.Second,
			stat:      statBlob(200),
			want:      "42",
			wantReads: []string{stat, environ},
			wantEntry: refetched(6*time.Second, 200),
		},
		{
			name:      "unreadable stat keeps the entry",
			entry:     cached(10*time.Second, 0),
			now:       6 * time.Second,
			wantReads: []string{stat},
			wantEntry: cached(10*time.Second, 0),
		},
		{
			name:      "unparsable stat keeps the entry",
			entry:     cached(10*time.Second, 0),
			now:       6 * time.Second,
			stat:      []byte("no paren"),
			wantReads: []string{stat},
			wantEntry: cached(10*time.Second, 0),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string][]byte{environ: env}
			if tt.stat != nil {
				files[stat] = tt.stat
			}
			fs := &recordingFS{files: files}
			clock := &countingClock{now: at(tt.now)}
			r := newRecordingResolver(fs, clock, 8, map[uint32]cacheEntry{7: tt.entry})
			if got := r.Resolve(7); got != (JobInfo{JobID: tt.want}) {
				t.Fatalf("Resolve = %+v, want JobID %q", got, tt.want)
			}
			assertReads(t, fs, tt.wantReads...)
			assertEntries(t, r, map[uint32]cacheEntry{7: tt.wantEntry})
			if clock.calls != 1 {
				t.Fatalf("clock read %d times, want 1", clock.calls)
			}
		})
	}
}

// TestResolveVerificationRestartsVerifyWindow checks that a stat read that
// confirms the cached process opens a new VerifyTTL window.
func TestResolveVerificationRestartsVerifyWindow(t *testing.T) {
	fs := &recordingFS{files: map[string][]byte{"/proc/7/stat": statBlob(100)}}
	clock := &countingClock{now: resolveEpoch.Add(resolveVerifyTTL)}
	entry := cacheEntry{starttime: 100, info: JobInfo{JobID: "9"}, expiresAt: resolveEpoch.Add(time.Minute), verifiedAt: resolveEpoch}
	r := newRecordingResolver(fs, clock, 8, map[uint32]cacheEntry{7: entry})

	steps := []struct {
		now       time.Duration
		wantReads int
	}{
		{now: resolveVerifyTTL, wantReads: 1},
		{now: 2*resolveVerifyTTL - time.Nanosecond, wantReads: 1},
		{now: 2 * resolveVerifyTTL, wantReads: 2},
	}
	for _, step := range steps {
		clock.now = resolveEpoch.Add(step.now)
		if got := r.Resolve(7); got.JobID != "9" {
			t.Fatalf("at %v: Resolve = %+v, want JobID 9", step.now, got)
		}
		if len(fs.reads) != step.wantReads {
			t.Fatalf("at %v: %d reads, want %d", step.now, len(fs.reads), step.wantReads)
		}
	}
}

// TestResolveEviction pins that storing a lookup into a full cache first
// evicts the entry closest to expiry, also when the pid itself is cached.
func TestResolveEviction(t *testing.T) {
	at := func(d time.Duration) time.Time { return resolveEpoch.Add(d) }
	older := cacheEntry{starttime: 100, info: JobInfo{JobID: "1"}, expiresAt: at(20 * time.Second), verifiedAt: at(-30 * time.Second)}
	newer := cacheEntry{starttime: 100, info: JobInfo{JobID: "2"}, expiresAt: at(30 * time.Second), verifiedAt: at(-30 * time.Second)}
	stored := func(starttime uint64) cacheEntry {
		return cacheEntry{starttime: starttime, info: JobInfo{JobID: "42"}, expiresAt: at(resolveTTL), verifiedAt: resolveEpoch}
	}
	files := map[string][]byte{
		"/proc/2/stat": statBlob(200), "/proc/2/environ": []byte("SLURM_JOB_ID=42\x00"),
		"/proc/3/stat": statBlob(300), "/proc/3/environ": []byte("SLURM_JOB_ID=42\x00"),
	}
	tests := []struct {
		name       string
		maxEntries int
		pid        uint32
		want       map[uint32]cacheEntry
	}{
		{
			name:       "full cache evicts the entry closest to expiry",
			maxEntries: 2,
			pid:        3,
			want:       map[uint32]cacheEntry{2: newer, 3: stored(300)},
		},
		{
			name:       "cache below capacity evicts nothing",
			maxEntries: 3,
			pid:        3,
			want:       map[uint32]cacheEntry{1: older, 2: newer, 3: stored(300)},
		},
		{
			name:       "refreshing a cached pid evicts too",
			maxEntries: 2,
			pid:        2, // cached with starttime 100, now 200
			want:       map[uint32]cacheEntry{2: stored(200)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := &recordingFS{files: files}
			r := newRecordingResolver(fs, &countingClock{now: resolveEpoch}, tt.maxEntries, map[uint32]cacheEntry{1: older, 2: newer})
			if got := r.Resolve(tt.pid); got.JobID != "42" {
				t.Fatalf("Resolve = %+v, want JobID 42", got)
			}
			assertEntries(t, r, tt.want)
		})
	}
}

func TestResolveDisabledReadsNothing(t *testing.T) {
	fs := &recordingFS{files: map[string][]byte{"/proc/7/stat": statBlob(100)}}
	clock := &countingClock{now: resolveEpoch}
	r := newRecordingResolver(fs, clock, 8, nil)
	r.opts.Enabled = false
	if got := r.Resolve(7); got != (JobInfo{}) {
		t.Fatalf("Resolve = %+v, want empty", got)
	}
	var nilResolver *Resolver
	if got := nilResolver.Resolve(7); got != (JobInfo{}) {
		t.Fatalf("nil Resolve = %+v, want empty", got)
	}
	assertReads(t, fs)
	if clock.calls != 0 {
		t.Fatalf("clock read %d times, want 0", clock.calls)
	}
}
