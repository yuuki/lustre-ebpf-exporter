package goexporter

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/yuuki/lustre-ebpf-exporter/internal/goexporter/slurm"
)

// procFSReader is an alias for the same injectable reader type used by slurm.Resolver.
type procFSReader = slurm.FSReader

const (
	procNameTTL         = 60 * time.Second
	procNameNegativeTTL = 5 * time.Second
	procNameMaxEntries  = 8192
)

type procNameEntry struct {
	name      string // "" means lookup failed
	starttime uint64
	expiresAt time.Time
}

func (e procNameEntry) ExpireTime() time.Time { return e.expiresAt }

// ProcNameResolver resolves a PID to the full process name (basename of
// argv[0] from /proc/<pid>/cmdline) with TTL caching and pid-reuse detection
// via /proc/<pid>/stat starttime. Falls back to the BPF comm field (max 15
// chars) when /proc is unavailable.
type ProcNameResolver struct {
	mu          sync.Mutex
	entries     map[uint32]procNameEntry
	readCmdline procFSReader
	readStat    procFSReader
}

// NewProcNameResolver creates a resolver backed by the real /proc filesystem.
func NewProcNameResolver() *ProcNameResolver {
	return newProcNameResolver(os.ReadFile, os.ReadFile)
}

func newProcNameResolver(readCmdline, readStat procFSReader) *ProcNameResolver {
	return &ProcNameResolver{
		entries:     make(map[uint32]procNameEntry),
		readCmdline: readCmdline,
		readStat:    readStat,
	}
}

// Resolve returns the full process name for pid. Falls back to commFallback
// when the process is gone or /proc is inaccessible.
func (r *ProcNameResolver) Resolve(pid uint32, commFallback string) string {
	now := time.Now()
	pidStr := strconv.FormatUint(uint64(pid), 10)

	r.mu.Lock()
	entry, ok := r.entries[pid]
	if ok && entry.expiresAt.After(now) {
		name := entry.name
		r.mu.Unlock()
		if name == "" {
			return commFallback
		}
		return name
	}
	r.mu.Unlock()

	statRaw, err := r.readStat("/proc/" + pidStr + "/stat")
	if err != nil {
		return commFallback
	}
	start, err := slurm.ParseProcStatStarttime(statRaw)
	if err != nil {
		return commFallback
	}

	r.mu.Lock()
	entry, ok = r.entries[pid]
	if ok && entry.starttime == start && entry.expiresAt.After(now) {
		name := entry.name
		r.mu.Unlock()
		if name == "" {
			return commFallback
		}
		return name
	}
	r.mu.Unlock()

	name := ""
	if raw, err := r.readCmdline("/proc/" + pidStr + "/cmdline"); err == nil {
		name = parseCmdlineName(raw)
	}

	ttl := procNameNegativeTTL
	if name != "" {
		ttl = procNameTTL
	}

	r.mu.Lock()
	if len(r.entries) >= procNameMaxEntries {
		slurm.EvictOldest(r.entries)
	}
	r.entries[pid] = procNameEntry{
		name:      name,
		starttime: start,
		expiresAt: now.Add(ttl),
	}
	r.mu.Unlock()

	if name == "" {
		return commFallback
	}
	return name
}


// parseCmdlineName returns the basename of argv[0] from a /proc/<pid>/cmdline blob.
func parseCmdlineName(raw []byte) string {
	if i := bytes.IndexByte(raw, 0); i >= 0 {
		raw = raw[:i]
	}
	if len(raw) == 0 {
		return ""
	}
	return filepath.Base(string(raw))
}
