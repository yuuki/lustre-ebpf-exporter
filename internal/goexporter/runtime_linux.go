//go:build linux

package goexporter

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/yuuki/lustre-ebpf-exporter/internal/bpf"
)

type bpfMountKey struct {
	Major uint32
	Minor uint32
}

type linuxEventSource struct {
	events     chan Event
	reader     recordReader
	collection *ebpf.Collection
	links      []link.Link
	once       sync.Once
	done       chan struct{}
	started    bool
	debugHex   bool
	loggedHex  bool
}

// recordReader is the part of *perf.Reader that linuxEventSource uses. Tests
// replace it to drive readLoop without loading BPF programs.
type recordReader interface {
	Read() (perf.Record, error)
	Close() error
}

func newEventSource(ctx context.Context, cfg Config, mountInfos []MountInfo) (EventSource, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	required := []probeSpec{
		{symbol: "ll_lookup_nd", program: "ll_lookup_nd_enter"},
		{symbol: "ll_file_open", program: "ll_file_open_enter"},
		{symbol: "ll_file_read_iter", program: "ll_file_read_iter_enter"},
		{symbol: "ll_file_write_iter", program: "ll_file_write_iter_enter"},
		{symbol: "ll_fsync", program: "ll_fsync_enter"},
		{symbol: "__x64_sys_openat", program: "sys_exit_openat", ret: true},
		{symbol: "__x64_sys_read", program: "sys_exit_read", ret: true},
		{symbol: "__x64_sys_write", program: "sys_exit_write", ret: true},
		{symbol: "__x64_sys_fsync", program: "sys_exit_fsync", ret: true},
	}
	optional := []probeSpec{
		{symbol: "__x64_sys_openat2", program: "sys_exit_openat2", ret: true, optional: true},
		{symbol: "ptlrpc_queue_wait", program: "ptlrpc_queue_wait_enter", optional: true},
		{symbol: "ptlrpc_queue_wait", program: "ptlrpc_queue_wait_exit", ret: true, optional: true},
		{symbol: "ptlrpc_send_new_req", program: "ptlrpc_send_new_req_enter", optional: true},
		{symbol: "__ptlrpc_free_req", program: "ptlrpc_free_req_enter", optional: true},
		// Metadata-op probes (Linux 5.12+ assumed). Marked optional to tolerate
		// symbol/signature drift across kernel and Lustre versions.
		{symbol: "ll_file_release", program: "ll_file_release_enter", optional: true},
		{symbol: "ll_file_release", program: "ll_file_release_exit", ret: true, optional: true},
		{symbol: "ll_getattr", program: "ll_getattr_enter", optional: true},
		{symbol: "ll_getattr", program: "ll_getattr_exit", ret: true, optional: true},
		{symbol: "ll_xattr_get_common", program: "ll_getxattr_enter", optional: true},
		{symbol: "ll_xattr_get_common", program: "ll_getxattr_exit", ret: true, optional: true},
		{symbol: "ll_xattr_set_common", program: "ll_setxattr_enter", optional: true},
		{symbol: "ll_xattr_set_common", program: "ll_setxattr_exit", ret: true, optional: true},
		{symbol: "ll_mkdir", program: "ll_mkdir_enter", optional: true},
		{symbol: "ll_mkdir", program: "ll_mkdir_exit", ret: true, optional: true},
		{symbol: "ll_mknod", program: "ll_mknod_enter", optional: true},
		{symbol: "ll_mknod", program: "ll_mknod_exit", ret: true, optional: true},
		{symbol: "ll_rename", program: "ll_rename_enter", optional: true},
		{symbol: "ll_rename", program: "ll_rename_exit", ret: true, optional: true},
		{symbol: "ll_rmdir", program: "ll_rmdir_enter", optional: true},
		{symbol: "ll_rmdir", program: "ll_rmdir_exit", ret: true, optional: true},
		{symbol: "ll_setattr", program: "ll_setattr_enter", optional: true},
		{symbol: "ll_setattr", program: "ll_setattr_exit", ret: true, optional: true},
		{symbol: "ll_statfs", program: "ll_statfs_enter", optional: true},
		{symbol: "ll_statfs", program: "ll_statfs_exit", ret: true, optional: true},
		{symbol: "ll_create_nd", program: "ll_create_nd_enter", optional: true},
		{symbol: "ll_create_nd", program: "ll_create_nd_exit", ret: true, optional: true},
		{symbol: "ll_unlink", program: "ll_unlink_enter", optional: true},
		{symbol: "ll_unlink", program: "ll_unlink_exit", ret: true, optional: true},
		{symbol: "ll_link", program: "ll_link_enter", optional: true},
		{symbol: "ll_link", program: "ll_link_exit", ret: true, optional: true},
		{symbol: "ll_symlink", program: "ll_symlink_enter", optional: true},
		{symbol: "ll_symlink", program: "ll_symlink_exit", ret: true, optional: true},
		{symbol: "ll_listxattr", program: "ll_listxattr_enter", optional: true},
		{symbol: "ll_listxattr", program: "ll_listxattr_exit", ret: true, optional: true},
		{symbol: "ll_get_inode_acl", program: "ll_get_inode_acl_enter", optional: true},
		{symbol: "ll_get_inode_acl", program: "ll_get_inode_acl_exit", ret: true, optional: true},
		{symbol: "ll_get_link", program: "ll_get_link_enter", optional: true},
		{symbol: "ll_get_link", program: "ll_get_link_exit", ret: true, optional: true},
		{symbol: "ll_iterate", program: "ll_iterate_enter", optional: true},
		{symbol: "ll_iterate", program: "ll_iterate_exit", ret: true, optional: true},
		// PtlRPC error/recovery event probes.
		{symbol: "ptlrpc_resend_req", program: "ptlrpc_resend_req_enter", optional: true},
		{symbol: "ptlrpc_restart_req", program: "ptlrpc_restart_req_enter", optional: true},
		{symbol: "ptlrpc_expire_one_request", program: "ptlrpc_expire_one_request_enter", optional: true},
		{symbol: "ptlrpc_request_handle_notconn", program: "ptlrpc_request_handle_notconn_enter", optional: true},
	}

	spec, err := bpf.LoadCollectionSpec()
	if err != nil {
		return nil, err
	}
	if err := setUIDLabelsEnabled(spec, cfg.UIDLabelsEnabled); err != nil {
		return nil, err
	}
	collection, skippedPrograms, err := loadCollectionWithOptionalPrograms(spec, optional)
	if err != nil {
		return nil, err
	}
	if err := writeMountFilter(collection, mountInfos); err != nil {
		collection.Close()
		return nil, err
	}

	reader, err := perf.NewReader(collection.Maps["events"], os.Getpagesize()*8)
	if err != nil {
		collection.Close()
		return nil, err
	}

	source := &linuxEventSource{
		events:     make(chan Event, 1024),
		reader:     reader,
		collection: collection,
		done:       make(chan struct{}),
		debugHex:   os.Getenv("LUSTRE_OBSERVER_DEBUG_HEX") == "1",
	}

	if err := source.attachProbes(required, optional, cfg.LegacySymbolAllowMissing, skippedPrograms); err != nil {
		source.Close()
		return nil, err
	}

	source.started = true
	go source.readLoop(ctx)
	return source, nil
}

// setUIDLabelsEnabled rewrites the `const volatile __u8 uid_labels_enabled`
// global of spec before load. When disabled, fill_start_info() in the BPF
// program skips bpf_get_current_uid_gid() so every event and counter-map key
// carries uid=0 — collapsing PERCPU_HASH rows across users. Fail fast when
// the operator asked for --uid-labels=false but the embedded .o predates the
// toggle: silently falling back would keep collecting per-UID kernel-side
// while userspace drops the labels, which misleads the startup log and the
// types.go doc comment about end-to-end behavior.
func setUIDLabelsEnabled(spec *ebpf.CollectionSpec, enabled bool) error {
	v, ok := spec.Variables["uid_labels_enabled"]
	switch {
	case ok:
		val := uint8(1)
		if !enabled {
			val = 0
		}
		if err := v.Set(val); err != nil {
			return fmt.Errorf("set uid_labels_enabled: %w", err)
		}
	case !enabled:
		return fmt.Errorf("embedded BPF object does not expose uid_labels_enabled; --uid-labels=false cannot be honored")
	}
	return nil
}

// writeMountFilter stores the index of each mount in config_map, keyed by
// its device numbers, so that the BPF programs report events on those mounts
// only.
func writeMountFilter(collection *ebpf.Collection, mountInfos []MountInfo) error {
	configMap := collection.Maps["config_map"]
	if configMap == nil {
		return fmt.Errorf("config_map not found in embedded BPF object")
	}
	for i, mi := range mountInfos {
		key := bpfMountKey{Major: mi.Major, Minor: mi.Minor}
		value := uint8(i)
		if err := configMap.Update(&key, &value, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

// attachProbes attaches the required probes, which allowMissing lets fail,
// then the optional ones except the programs that
// loadCollectionWithOptionalPrograms dropped.
func (s *linuxEventSource) attachProbes(required, optional []probeSpec, allowMissing bool, skippedPrograms []string) error {
	if err := s.attachAll(required, allowMissing, nil); err != nil {
		return err
	}
	skippedSet := make(map[string]struct{})
	for _, name := range skippedPrograms {
		skippedSet[name] = struct{}{}
	}
	return s.attachAll(optional, false, skippedSet)
}

type probeSpec struct {
	symbol          string
	program         string
	ret             bool
	optional        bool
	tracepointGroup string
	tracepointName  string
}

// attachAll attaches specs in order, skipping the programs in alreadySkipped,
// and stops at the first probe that may not be skipped.
func (s *linuxEventSource) attachAll(specs []probeSpec, allowMissing bool, alreadySkipped map[string]struct{}) error {
	for _, spec := range specs {
		if alreadySkipped != nil {
			if _, ok := alreadySkipped[spec.program]; ok {
				continue
			}
		}
		if err := s.attach(spec, allowMissing); err != nil {
			return err
		}
	}
	return nil
}

// attach attaches one probe and keeps its link. A probe whose program is
// missing or whose attach fails is logged and skipped when it is optional or
// allowMissing is set; a failed attach is also skipped when its error reports a
// missing symbol (isMissingSymbolError).
func (s *linuxEventSource) attach(spec probeSpec, allowMissing bool) error {
	prog := s.collection.Programs[spec.program]
	if prog == nil {
		if spec.optional || allowMissing {
			log.Printf("warning: BPF program %s not found", spec.program)
			return nil
		}
		return fmt.Errorf("required BPF program missing: %s", spec.program)
	}
	lnk, err := linkProbe(spec, prog)
	if err != nil {
		if spec.optional || allowMissing || isMissingSymbolError(err) {
			log.Printf("warning: skipping probe %s/%s: %v", spec.symbol, spec.program, err)
			return nil
		}
		return err
	}
	s.links = append(s.links, lnk)
	return nil
}

// The constructors linkProbe dispatches to. Tests replace them to check the
// dispatch and link bookkeeping, since attaching real probes needs root and
// kernel support.
var (
	linkTracepoint = link.Tracepoint
	linkKretprobe  = link.Kretprobe
	linkKprobe     = link.Kprobe
)

// linkProbe attaches prog as the tracepoint, kretprobe or kprobe that spec
// describes.
func linkProbe(spec probeSpec, prog *ebpf.Program) (link.Link, error) {
	switch {
	case spec.tracepointGroup != "":
		return linkTracepoint(spec.tracepointGroup, spec.tracepointName, prog, nil)
	case spec.ret:
		return linkKretprobe(spec.symbol, prog, nil)
	default:
		return linkKprobe(spec.symbol, prog, nil)
	}
}

// readLoop sends the events decoded from the perf reader to s.events until
// the reader is closed or ctx is done, then closes s.done and s.events.
func (s *linuxEventSource) readLoop(ctx context.Context) {
	defer close(s.events)
	defer close(s.done)
	for {
		record, err := s.reader.Read()
		if err != nil {
			if readLoopEnds(ctx, err) {
				return
			}
			continue
		}
		event, ok := s.decodeRecord(record)
		if !ok {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case s.events <- event:
		}
	}
}

// readLoopEnds reports whether a failed read ends readLoop: when the reader
// is closed or ctx is done. Any other failure is logged.
func readLoopEnds(ctx context.Context, err error) bool {
	if errors.Is(err, perf.ErrClosed) {
		return true
	}
	select {
	case <-ctx.Done():
		return true
	default:
		log.Printf("warning: perf event read failed: %v", err)
		return false
	}
}

// decodeRecord returns the event in record, or false after logging why for a
// lost-samples record or a sample that does not decode. With debugHex, the
// first sample that is not lost is logged before it is decoded.
func (s *linuxEventSource) decodeRecord(record perf.Record) (Event, bool) {
	if record.LostSamples > 0 {
		log.Printf("warning: lost %d perf samples", record.LostSamples)
		return Event{}, false
	}
	if s.debugHex && !s.loggedHex {
		s.loggedHex = true
		slog.Info("debug raw sample", "len", len(record.RawSample), "hex", fmt.Sprintf("%x", record.RawSample))
	}
	event, err := parseObserverEvent(record.RawSample)
	if err != nil {
		log.Printf("warning: decode raw event: %v", err)
		return Event{}, false
	}
	return event, true
}

func (s *linuxEventSource) Events() <-chan Event {
	return s.events
}

func (s *linuxEventSource) CounterMaps() (llite, rpc *ebpf.Map) {
	return s.collection.Maps["llite_counters"], s.collection.Maps["rpc_counters"]
}

func (s *linuxEventSource) ErrorCounterMaps() (lliteErrors, rpcErrors *ebpf.Map) {
	return s.collection.Maps["llite_error_counters"], s.collection.Maps["rpc_error_counters"]
}

func (s *linuxEventSource) Close() error {
	var closeErr error
	s.once.Do(func() {
		if s.reader != nil {
			closeErr = errors.Join(closeErr, s.reader.Close())
		}
		for _, lnk := range s.links {
			closeErr = errors.Join(closeErr, lnk.Close())
		}
		if s.collection != nil {
			s.collection.Close()
		}
		if s.started {
			<-s.done
		}
	})
	return closeErr
}

func isMissingSymbolError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "no such file") || strings.Contains(msg, "symbol") || strings.Contains(msg, "not found")
}

func loadCollectionWithOptionalPrograms(spec *ebpf.CollectionSpec, optional []probeSpec) (*ebpf.Collection, []string, error) {
	collection, err := ebpf.NewCollection(spec)
	if err == nil {
		return collection, nil, nil
	}

	log.Printf("warning: initial BPF collection load failed: %v", err)

	specCopy := spec.Copy()
	var skipped []string
	for _, probe := range optional {
		if _, ok := specCopy.Programs[probe.program]; ok {
			delete(specCopy.Programs, probe.program)
			skipped = append(skipped, probe.program)
		}
	}
	if len(skipped) == 0 {
		return nil, nil, err
	}

	log.Printf("warning: retrying without optional programs: %s", strings.Join(skipped, ", "))
	collection, retryErr := ebpf.NewCollection(specCopy)
	if retryErr != nil {
		return nil, nil, err
	}
	return collection, skipped, nil
}
