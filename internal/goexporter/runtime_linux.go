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
	reader     *perf.Reader
	collection *ebpf.Collection
	links      []link.Link
	once       sync.Once
	done       chan struct{}
	started    bool
	debugHex   bool
	loggedHex  bool
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
		// PtlRPC error/recovery event probes.
		{symbol: "ptlrpc_resend_req", program: "ptlrpc_resend_req_enter", optional: true},
		{symbol: "ptlrpc_restart_req", program: "ptlrpc_restart_req_enter", optional: true},
		{symbol: "ptlrpc_expire_one_request", program: "ptlrpc_expire_one_request_enter", optional: true},
		{symbol: "ptlrpc_request_handle_notconn", program: "ptlrpc_request_handle_notconn_enter", optional: true},
	}

	if cfg.PCCEnabled {
		// PCC I/O probes (Phase 1). All optional — PCC module may not be loaded.
		optional = append(optional,
			probeSpec{symbol: "pcc_file_read_iter", program: "pcc_file_read_iter_enter", optional: true},
			probeSpec{symbol: "pcc_file_read_iter", program: "pcc_file_read_iter_exit", ret: true, optional: true},
			probeSpec{symbol: "pcc_file_write_iter", program: "pcc_file_write_iter_enter", optional: true},
			probeSpec{symbol: "pcc_file_write_iter", program: "pcc_file_write_iter_exit", ret: true, optional: true},
			probeSpec{symbol: "pcc_file_open", program: "pcc_file_open_enter", optional: true},
			probeSpec{symbol: "pcc_file_open", program: "pcc_file_open_exit", ret: true, optional: true},
			probeSpec{symbol: "pcc_lookup", program: "pcc_lookup_enter", optional: true},
			probeSpec{symbol: "pcc_lookup", program: "pcc_lookup_exit", ret: true, optional: true},
			probeSpec{symbol: "pcc_fsync", program: "pcc_fsync_enter", optional: true},
			probeSpec{symbol: "pcc_fsync", program: "pcc_fsync_exit", ret: true, optional: true},
			// PCC attach/detach probes (Phase 2).
			probeSpec{symbol: "pcc_ioctl_attach", program: "pcc_ioctl_attach_enter", optional: true},
			probeSpec{symbol: "pcc_ioctl_attach", program: "pcc_ioctl_attach_exit", ret: true, optional: true},
			probeSpec{symbol: "pcc_ioctl_detach", program: "pcc_ioctl_detach_enter", optional: true},
			probeSpec{symbol: "pcc_ioctl_detach", program: "pcc_ioctl_detach_exit", ret: true, optional: true},
			probeSpec{symbol: "pcc_try_auto_attach", program: "pcc_try_auto_attach_enter", optional: true},
			probeSpec{symbol: "pcc_try_auto_attach", program: "pcc_try_auto_attach_exit", ret: true, optional: true},
			probeSpec{symbol: "pcc_try_readonly_open_attach", program: "pcc_try_readonly_open_attach_enter", optional: true},
			probeSpec{symbol: "pcc_try_readonly_open_attach", program: "pcc_try_readonly_open_attach_exit", ret: true, optional: true},
			// pcc_readonly_attach_sync and pcc_readwrite_attach are internal
			// functions called by the top-level attach probes above; not probed
			// to avoid inflight_map key collisions on the same thread.
			probeSpec{symbol: "pcc_layout_invalidate", program: "pcc_layout_invalidate_enter", optional: true},
		)
	}

	spec, err := bpf.LoadCollectionSpec()
	if err != nil {
		return nil, err
	}
	// Rewrite the `const volatile __u8 uid_labels_enabled` global before load.
	// When disabled, fill_start_info() in the BPF program skips
	// bpf_get_current_uid_gid() so every event and counter-map key carries
	// uid=0 — collapsing PERCPU_HASH rows across users. The `ok` guard keeps
	// forward compatibility in case the embedded .o predates the const.
	if v, ok := spec.Variables["uid_labels_enabled"]; ok {
		val := uint8(1)
		if !cfg.UIDLabelsEnabled {
			val = 0
		}
		if err := v.Set(val); err != nil {
			return nil, fmt.Errorf("set uid_labels_enabled: %w", err)
		}
	}
	// Remove PCC BPF programs from spec when PCC is disabled to avoid
	// unnecessary verifier work at startup.
	if !cfg.PCCEnabled {
		for name := range spec.Programs {
			if strings.HasPrefix(name, "pcc_") {
				delete(spec.Programs, name)
			}
		}
	}
	skippedSet := make(map[string]struct{})
	collection, skippedPrograms, err := loadCollectionWithOptionalPrograms(spec, optional)
	if err != nil {
		return nil, err
	}
	for _, name := range skippedPrograms {
		skippedSet[name] = struct{}{}
	}

	configMap := collection.Maps["config_map"]
	if configMap == nil {
		collection.Close()
		return nil, fmt.Errorf("config_map not found in embedded BPF object")
	}
	for i, mi := range mountInfos {
		key := bpfMountKey{Major: mi.Major, Minor: mi.Minor}
		value := uint8(i)
		if err := configMap.Update(&key, &value, ebpf.UpdateAny); err != nil {
			collection.Close()
			return nil, err
		}
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

	if err := source.attachAll(required, cfg.LegacySymbolAllowMissing, nil); err != nil {
		source.Close()
		return nil, err
	}
	if err := source.attachAll(optional, false, skippedSet); err != nil {
		source.Close()
		return nil, err
	}

	source.started = true
	go source.readLoop(ctx)
	return source, nil
}

type probeSpec struct {
	symbol          string
	program         string
	ret             bool
	optional        bool
	tracepointGroup string
	tracepointName  string
}

func (s *linuxEventSource) attachAll(specs []probeSpec, allowMissing bool, alreadySkipped map[string]struct{}) error {
	for _, spec := range specs {
		if alreadySkipped != nil {
			if _, ok := alreadySkipped[spec.program]; ok {
				continue
			}
		}
		prog := s.collection.Programs[spec.program]
		if prog == nil {
			if spec.optional || allowMissing {
				log.Printf("warning: BPF program %s not found", spec.program)
				continue
			}
			return fmt.Errorf("required BPF program missing: %s", spec.program)
		}
		var (
			lnk link.Link
			err error
		)
		if spec.tracepointGroup != "" {
			lnk, err = link.Tracepoint(spec.tracepointGroup, spec.tracepointName, prog, nil)
		} else if spec.ret {
			lnk, err = link.Kretprobe(spec.symbol, prog, nil)
		} else {
			lnk, err = link.Kprobe(spec.symbol, prog, nil)
		}
		if err != nil {
			if spec.optional || allowMissing || isMissingSymbolError(err) {
				log.Printf("warning: skipping probe %s/%s: %v", spec.symbol, spec.program, err)
				continue
			}
			return err
		}
		s.links = append(s.links, lnk)
	}
	return nil
}

func (s *linuxEventSource) readLoop(ctx context.Context) {
	defer close(s.events)
	defer close(s.done)
	for {
		record, err := s.reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("warning: perf event read failed: %v", err)
				continue
			}
		}
		if record.LostSamples > 0 {
			log.Printf("warning: lost %d perf samples", record.LostSamples)
			continue
		}
		if s.debugHex && !s.loggedHex {
			s.loggedHex = true
			slog.Info("debug raw sample", "len", len(record.RawSample), "hex", fmt.Sprintf("%x", record.RawSample))
		}
		event, err := parseObserverEvent(record.RawSample)
		if err != nil {
			log.Printf("warning: decode raw event: %v", err)
			continue
		}
		select {
		case <-ctx.Done():
			return
		case s.events <- event:
		}
	}
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

func (s *linuxEventSource) PccCounterMaps() (pcc, pccErrors *ebpf.Map) {
	return s.collection.Maps["pcc_counters"], s.collection.Maps["pcc_error_counters"]
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
