package slurm

import (
	"errors"
	"os"
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
		stat:    statBlob(100),
		envErr:  errors.New("EACCES"),
		cgroup:  []byte("0::/slurm/uid_1000/job_7/step_0\n"),
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

func TestResolverInvalidate(t *testing.T) {
	t.Parallel()

	fs := &fakeFS{
		stat:    statBlob(100),
		environ: []byte("SLURM_JOB_ID=42\x00"),
	}
	r := newResolver(fs, Options{VerifyTTL: time.Hour})

	r.Resolve(123)
	r.Invalidate(123)
	r.Resolve(123)

	if fs.statCalls.Load() != 2 {
		t.Fatalf("expected invalidate to cause a refetch, got %d stat calls", fs.statCalls.Load())
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
