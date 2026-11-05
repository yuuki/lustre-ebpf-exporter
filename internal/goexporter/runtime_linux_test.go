//go:build linux

package goexporter

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/yuuki/lustre-ebpf-exporter/internal/bpf"
)

// TestAttachAllMissingPrograms covers the programs absent from the
// collection: nothing is attached. The attach paths are covered by
// TestAttachAllAttachErrors and TestAttachAllDispatchAndLinks. The test
// captures the standard logger, so it must not run in parallel.
func TestAttachAllMissingPrograms(t *testing.T) {
	specs := []probeSpec{
		{symbol: "sym_a", program: "prog_a"},
		{symbol: "sym_b", program: "prog_b", optional: true},
		{symbol: "sym_c", program: "prog_c"},
		{symbol: "sym_d", program: "prog_d", optional: true},
	}
	tests := []struct {
		name           string
		allowMissing   bool
		alreadySkipped map[string]struct{}
		wantErr        string
		wantLog        []string
	}{
		{
			name:    "required program missing stops at the first one",
			wantErr: "required BPF program missing: prog_a",
		},
		{
			name:           "skipped programs are passed over silently",
			alreadySkipped: map[string]struct{}{"prog_a": {}},
			wantErr:        "required BPF program missing: prog_c",
			wantLog:        []string{"warning: BPF program prog_b not found"},
		},
		{
			name:         "allowMissing tolerates every missing program",
			allowMissing: true,
			wantLog: []string{
				"warning: BPF program prog_a not found",
				"warning: BPF program prog_b not found",
				"warning: BPF program prog_c not found",
				"warning: BPF program prog_d not found",
			},
		},
		{
			name:           "only optional programs left",
			alreadySkipped: map[string]struct{}{"prog_a": {}, "prog_c": {}, "prog_d": {}},
			wantLog:        []string{"warning: BPF program prog_b not found"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			flags, out := log.Flags(), log.Writer()
			log.SetFlags(0)
			log.SetOutput(&logs)
			defer func() {
				log.SetFlags(flags)
				log.SetOutput(out)
			}()

			s := &linuxEventSource{collection: &ebpf.Collection{Programs: map[string]*ebpf.Program{}}}
			err := s.attachAll(specs, tt.allowMissing, tt.alreadySkipped)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != "" && (err == nil || err.Error() != tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
			want := ""
			if len(tt.wantLog) > 0 {
				want = strings.Join(tt.wantLog, "\n") + "\n"
			}
			if logs.String() != want {
				t.Fatalf("log mismatch\n got:\n%s\nwant:\n%s", logs.String(), want)
			}
			if len(s.links) != 0 {
				t.Fatalf("got %d links, want none", len(s.links))
			}
		})
	}
}

// captureStdLog redirects the standard logger, without timestamps, for the
// rest of the test. Tests using it must not run in parallel.
func captureStdLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	flags, out := log.Flags(), log.Writer()
	log.SetFlags(0)
	log.SetOutput(&buf)
	t.Cleanup(func() {
		log.SetFlags(flags)
		log.SetOutput(out)
	})
	return &buf
}

// TestAttachAllAttachErrors runs the real cilium/ebpf attach calls with an
// unloaded program. They reject its program type before touching the kernel,
// so the attach-error paths run without privileges; the error text also shows
// whether the kprobe or the tracepoint constructor was called.
func TestAttachAllAttachErrors(t *testing.T) {
	const (
		notKprobe     = "eBPF program type UnspecifiedProgram is not a Kprobe: invalid input"
		notTracepoint = "eBPF program type UnspecifiedProgram is not a Tracepoint: invalid input"
	)
	kprobe := probeSpec{symbol: "sym_k", program: "prog"}
	kretprobe := probeSpec{symbol: "sym_r", program: "prog", ret: true}
	tracepoint := probeSpec{symbol: "sym_t", program: "prog", ret: true, tracepointGroup: "sched", tracepointName: "sched_switch"}
	optional := func(spec probeSpec) probeSpec {
		spec.optional = true
		return spec
	}
	tests := []struct {
		name         string
		specs        []probeSpec
		allowMissing bool
		wantErr      string
		wantLog      []string
	}{
		{name: "required kprobe fails", specs: []probeSpec{kprobe}, wantErr: notKprobe},
		{name: "required kretprobe fails", specs: []probeSpec{kretprobe}, wantErr: notKprobe},
		{name: "required tracepoint fails", specs: []probeSpec{tracepoint}, wantErr: notTracepoint},
		{
			name:    "optional probes are skipped, then a required one fails",
			specs:   []probeSpec{optional(kprobe), optional(tracepoint), kretprobe},
			wantErr: notKprobe,
			wantLog: []string{
				"warning: skipping probe sym_k/prog: " + notKprobe,
				"warning: skipping probe sym_t/prog: " + notTracepoint,
			},
		},
		{
			name:         "allowMissing skips a failed required probe",
			specs:        []probeSpec{kprobe, tracepoint},
			allowMissing: true,
			wantLog: []string{
				"warning: skipping probe sym_k/prog: " + notKprobe,
				"warning: skipping probe sym_t/prog: " + notTracepoint,
			},
		},
		{
			// isMissingSymbolError matches the "symbol" in this error.
			name:  "a symbol error skips a required probe",
			specs: []probeSpec{{symbol: "bad-symbol", program: "prog"}},
			wantLog: []string{
				"warning: skipping probe bad-symbol/prog: symbol 'bad-symbol' must be a valid symbol in /proc/kallsyms: invalid input",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureStdLog(t)
			s := &linuxEventSource{collection: &ebpf.Collection{Programs: map[string]*ebpf.Program{"prog": {}}}}
			err := s.attachAll(tt.specs, tt.allowMissing, nil)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != "" && (err == nil || err.Error() != tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
			want := ""
			if len(tt.wantLog) > 0 {
				want = strings.Join(tt.wantLog, "\n") + "\n"
			}
			if logs.String() != want {
				t.Fatalf("log mismatch\n got:\n%s\nwant:\n%s", logs.String(), want)
			}
			if len(s.links) != 0 {
				t.Fatalf("got %d links, want none", len(s.links))
			}
		})
	}
}

// fakeLink stands in for an attached probe; only its identity is used.
type fakeLink struct {
	link.Link
	id string
}

// TestAttachAllDispatchAndLinks replaces the link constructors to check, without
// attaching real probes, which constructor each spec uses and that every
// successful attach is kept, in order, while failed optional ones are not.
func TestAttachAllDispatchAndLinks(t *testing.T) {
	var calls []string
	fake := func(kind string) func(string, *ebpf.Program) (link.Link, error) {
		return func(target string, _ *ebpf.Program) (link.Link, error) {
			call := kind + " " + target
			calls = append(calls, call)
			if strings.HasPrefix(target, "fail") {
				return nil, errors.New("attach failed")
			}
			return &fakeLink{id: call}, nil
		}
	}
	tracepoint, kretprobe, kprobe := fake("tracepoint"), fake("kretprobe"), fake("kprobe")
	origTracepoint, origKretprobe, origKprobe := linkTracepoint, linkKretprobe, linkKprobe
	t.Cleanup(func() {
		linkTracepoint, linkKretprobe, linkKprobe = origTracepoint, origKretprobe, origKprobe
	})
	linkTracepoint = func(group, name string, prog *ebpf.Program, _ *link.TracepointOptions) (link.Link, error) {
		return tracepoint(group+"/"+name, prog)
	}
	linkKretprobe = func(symbol string, prog *ebpf.Program, _ *link.KprobeOptions) (link.Link, error) {
		return kretprobe(symbol, prog)
	}
	linkKprobe = func(symbol string, prog *ebpf.Program, _ *link.KprobeOptions) (link.Link, error) {
		return kprobe(symbol, prog)
	}
	logs := captureStdLog(t)

	s := &linuxEventSource{collection: &ebpf.Collection{Programs: map[string]*ebpf.Program{"prog": {}}}}
	specs := []probeSpec{
		// A tracepoint wins over ret.
		{symbol: "sym_t", program: "prog", ret: true, tracepointGroup: "sched", tracepointName: "sched_switch"},
		{symbol: "sym_r", program: "prog", ret: true},
		{symbol: "fail_k", program: "prog", optional: true},
		{symbol: "sym_k", program: "prog"},
	}
	if err := s.attachAll(specs, false, nil); err != nil {
		t.Fatal(err)
	}

	wantCalls := []string{"tracepoint sched/sched_switch", "kretprobe sym_r", "kprobe fail_k", "kprobe sym_k"}
	if strings.Join(calls, ", ") != strings.Join(wantCalls, ", ") {
		t.Fatalf("calls = %v, want %v", calls, wantCalls)
	}
	var gotLinks []string
	for _, lnk := range s.links {
		gotLinks = append(gotLinks, lnk.(*fakeLink).id)
	}
	wantLinks := []string{"tracepoint sched/sched_switch", "kretprobe sym_r", "kprobe sym_k"}
	if strings.Join(gotLinks, ", ") != strings.Join(wantLinks, ", ") {
		t.Fatalf("links = %v, want %v", gotLinks, wantLinks)
	}
	if want := "warning: skipping probe fail_k/prog: attach failed\n"; logs.String() != want {
		t.Fatalf("log = %q, want %q", logs.String(), want)
	}
}

// captureLogs routes the standard logger and slog, without timestamps, into
// one buffer for the rest of the test, keeping the order of their lines.
// Tests using it must not run in parallel.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := captureStdLog(t)
	prev := slog.Default()
	// slog.SetDefault also points the standard logger at this handler.
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// scriptedReader returns its steps in order and then perf.ErrClosed. If the
// reader is read again after that, it cancels the loop's context, so that a
// loop that ignores ErrClosed ends instead of hanging the test.
type scriptedReader struct {
	steps  []readStep
	reads  int
	cancel context.CancelFunc
}

type readStep struct {
	record perf.Record
	err    error
}

func (r *scriptedReader) Read() (perf.Record, error) {
	r.reads++
	if r.reads <= len(r.steps) {
		step := r.steps[r.reads-1]
		return step.record, step.err
	}
	if r.reads > len(r.steps)+1 {
		r.cancel()
	}
	return perf.Record{}, perf.ErrClosed
}

func (r *scriptedReader) Close() error { return nil }

// rawLLiteWrite returns a 64-byte observer event for an llite write by pid,
// and the Event that parseObserverEvent decodes from it.
func rawLLiteWrite(pid uint32, comm string) ([]byte, Event) {
	raw := make([]byte, 64)
	raw[0], raw[1] = rawPlaneLLite, rawOpWrite
	binary.LittleEndian.PutUint32(raw[12:16], pid)
	binary.LittleEndian.PutUint64(raw[32:40], 4096)
	copy(raw[48:64], comm)
	return raw, Event{Plane: PlaneLLite, Op: OpWrite, PID: pid, SizeBytes: 4096, Comm: comm}
}

// TestReadLoop pins how readLoop handles each kind of record and read error:
// which records become events, what is logged, in which order, and when the
// loop ends.
func TestReadLoop(t *testing.T) {
	rawA, eventA := rawLLiteWrite(11, "dd")
	rawB, eventB := rawLLiteWrite(12, "cp")
	badPlane, _ := rawLLiteWrite(13, "x")
	badPlane[0] = 9
	short := []byte{1, 2, 3, 0xab}
	mixed := []readStep{
		{err: errors.New("boom")},
		{record: perf.Record{LostSamples: 3, RawSample: rawA}},
		{record: perf.Record{RawSample: short}},
		{record: perf.Record{RawSample: rawA}},
		{record: perf.Record{RawSample: badPlane}},
		{record: perf.Record{RawSample: rawB}},
		{err: fmt.Errorf("read: %w", perf.ErrClosed)},
	}
	mixedLog := []string{
		`level=INFO msg="warning: perf event read failed: boom"`,
		`level=INFO msg="warning: lost 3 perf samples"`,
		`level=INFO msg="warning: decode raw event: short raw event: got 4 bytes"`,
		`level=INFO msg="warning: decode raw event: unknown plane code: 9"`,
	}
	tests := []struct {
		name       string
		steps      []readStep
		debugHex   bool
		cancelled  bool
		unbuffered bool
		wantEvents []Event
		wantReads  int
		wantLog    []string
	}{
		{
			name:       "events, lost samples, read and decode failures",
			steps:      mixed,
			wantEvents: []Event{eventA, eventB},
			wantReads:  len(mixed),
			wantLog:    mixedLog,
		},
		{
			name:       "debugHex logs the first sample that is not lost, before decoding it",
			steps:      mixed,
			debugHex:   true,
			wantEvents: []Event{eventA, eventB},
			wantReads:  len(mixed),
			wantLog:    append(append(mixedLog[:2:2], `level=INFO msg="debug raw sample" len=4 hex=010203ab`), mixedLog[2:]...),
		},
		{
			name:       "debugHex logs a sample that decodes",
			steps:      []readStep{{record: perf.Record{RawSample: rawA}}, {record: perf.Record{RawSample: rawB}}},
			debugHex:   true,
			wantEvents: []Event{eventA, eventB},
			wantReads:  3, // the third read returns perf.ErrClosed
			wantLog:    []string{fmt.Sprintf(`level=INFO msg="debug raw sample" len=64 hex=%x`, rawA)},
		},
		{
			name:      "a read error after cancellation ends the loop silently",
			steps:     []readStep{{err: errors.New("boom")}, {record: perf.Record{RawSample: rawA}}},
			cancelled: true,
			wantReads: 1,
		},
		{
			name:       "cancellation ends a blocked send",
			steps:      []readStep{{record: perf.Record{RawSample: rawA}}, {record: perf.Record{RawSample: rawB}}},
			cancelled:  true,
			unbuffered: true,
			wantReads:  1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.cancelled {
				cancel()
			}
			reader := &scriptedReader{steps: tt.steps, cancel: cancel}
			events := make(chan Event, 16)
			if tt.unbuffered {
				events = make(chan Event)
			}
			s := &linuxEventSource{events: events, done: make(chan struct{}), reader: reader, debugHex: tt.debugHex}

			returned := make(chan struct{})
			go func() {
				s.readLoop(ctx)
				close(returned)
			}()
			select {
			case <-returned:
			case <-time.After(10 * time.Second):
				t.Fatal("readLoop did not return")
			}

			select {
			case <-s.done:
			default:
				t.Fatal("done is not closed")
			}
			var got []Event
			for open := true; open; {
				select {
				case ev, ok := <-s.events:
					if ok {
						got = append(got, ev)
					}
					open = ok
				default:
					t.Fatal("events is not closed")
				}
			}
			if !reflect.DeepEqual(got, tt.wantEvents) {
				t.Fatalf("events = %+v, want %+v", got, tt.wantEvents)
			}
			if reader.reads != tt.wantReads {
				t.Fatalf("reads = %d, want %d", reader.reads, tt.wantReads)
			}
			want := ""
			if len(tt.wantLog) > 0 {
				want = strings.Join(tt.wantLog, "\n") + "\n"
			}
			if logs.String() != want {
				t.Fatalf("log mismatch\n got:\n%s\nwant:\n%s", logs.String(), want)
			}
		})
	}
}

// wantAttachOrder is every probe newEventSource attaches, as
// "<constructor> <symbol> <program>": the required probes, then the optional
// ones.
var wantAttachOrder = []string{
	"kprobe ll_lookup_nd ll_lookup_nd_enter",
	"kprobe ll_file_open ll_file_open_enter",
	"kprobe ll_file_read_iter ll_file_read_iter_enter",
	"kprobe ll_file_write_iter ll_file_write_iter_enter",
	"kprobe ll_fsync ll_fsync_enter",
	"kretprobe __x64_sys_openat sys_exit_openat",
	"kretprobe __x64_sys_read sys_exit_read",
	"kretprobe __x64_sys_write sys_exit_write",
	"kretprobe __x64_sys_fsync sys_exit_fsync",
	"kretprobe __x64_sys_openat2 sys_exit_openat2",
	"kprobe ptlrpc_queue_wait ptlrpc_queue_wait_enter",
	"kretprobe ptlrpc_queue_wait ptlrpc_queue_wait_exit",
	"kprobe ptlrpc_send_new_req ptlrpc_send_new_req_enter",
	"kprobe __ptlrpc_free_req ptlrpc_free_req_enter",
	"kprobe ll_file_release ll_file_release_enter",
	"kretprobe ll_file_release ll_file_release_exit",
	"kprobe ll_getattr ll_getattr_enter",
	"kretprobe ll_getattr ll_getattr_exit",
	"kprobe ll_xattr_get_common ll_getxattr_enter",
	"kretprobe ll_xattr_get_common ll_getxattr_exit",
	"kprobe ll_xattr_set_common ll_setxattr_enter",
	"kretprobe ll_xattr_set_common ll_setxattr_exit",
	"kprobe ll_mkdir ll_mkdir_enter",
	"kretprobe ll_mkdir ll_mkdir_exit",
	"kprobe ll_mknod ll_mknod_enter",
	"kretprobe ll_mknod ll_mknod_exit",
	"kprobe ll_rename ll_rename_enter",
	"kretprobe ll_rename ll_rename_exit",
	"kprobe ll_rmdir ll_rmdir_enter",
	"kretprobe ll_rmdir ll_rmdir_exit",
	"kprobe ll_setattr ll_setattr_enter",
	"kretprobe ll_setattr ll_setattr_exit",
	"kprobe ll_statfs ll_statfs_enter",
	"kretprobe ll_statfs ll_statfs_exit",
	"kprobe ll_create_nd ll_create_nd_enter",
	"kretprobe ll_create_nd ll_create_nd_exit",
	"kprobe ll_unlink ll_unlink_enter",
	"kretprobe ll_unlink ll_unlink_exit",
	"kprobe ll_link ll_link_enter",
	"kretprobe ll_link ll_link_exit",
	"kprobe ll_symlink ll_symlink_enter",
	"kretprobe ll_symlink ll_symlink_exit",
	"kprobe ll_listxattr ll_listxattr_enter",
	"kretprobe ll_listxattr ll_listxattr_exit",
	"kprobe ll_get_inode_acl ll_get_inode_acl_enter",
	"kretprobe ll_get_inode_acl ll_get_inode_acl_exit",
	"kprobe ll_get_link ll_get_link_enter",
	"kretprobe ll_get_link ll_get_link_exit",
	"kprobe ll_iterate ll_iterate_enter",
	"kretprobe ll_iterate ll_iterate_exit",
	"kprobe ptlrpc_resend_req ptlrpc_resend_req_enter",
	"kprobe ptlrpc_restart_req ptlrpc_restart_req_enter",
	"kprobe ptlrpc_expire_one_request ptlrpc_expire_one_request_enter",
	"kprobe ptlrpc_request_handle_notconn ptlrpc_request_handle_notconn_enter",
}

// requireEmbeddedObject skips the test unless the embedded BPF object can be
// loaded here, which takes privileges and kernel BTF.
func requireEmbeddedObject(t *testing.T) {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot load BPF programs: %v", err)
	}
	spec, err := bpf.LoadCollectionSpec()
	if err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Skipf("cannot load the embedded BPF object: %v", err)
	}
	collection.Close()
}

// closableLink is a fake attached probe that Close accepts.
type closableLink struct {
	link.Link
	prog *ebpf.Program
}

func (l *closableLink) Close() error { return nil }

// fakeAttach replaces the kprobe and kretprobe constructors for the rest of
// the test. They fail for the symbols in fail and record each call: calls
// holds "<constructor> <symbol>" and progs the program passed.
func fakeAttach(t *testing.T, fail map[string]error) (calls *[]string, progs *[]*ebpf.Program) {
	t.Helper()
	calls, progs = new([]string), new([]*ebpf.Program)
	fake := func(kind string) func(string, *ebpf.Program, *link.KprobeOptions) (link.Link, error) {
		return func(symbol string, prog *ebpf.Program, _ *link.KprobeOptions) (link.Link, error) {
			*calls = append(*calls, kind+" "+symbol)
			*progs = append(*progs, prog)
			if err := fail[symbol]; err != nil {
				return nil, err
			}
			return &closableLink{prog: prog}, nil
		}
	}
	origKretprobe, origKprobe := linkKretprobe, linkKprobe
	t.Cleanup(func() { linkKretprobe, linkKprobe = origKretprobe, origKprobe })
	linkKretprobe, linkKprobe = fake("kretprobe"), fake("kprobe")
	return calls, progs
}

func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// closeSource closes src and checks that Close waited for readLoop to end,
// failing the test if Close does not return because readLoop never ran, and
// that the event channel is then closed.
func closeSource(t *testing.T, src EventSource) {
	t.Helper()
	closed := make(chan error, 1)
	go func() { closed <- src.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return: readLoop is not running")
	}
	select {
	case <-src.(*linuxEventSource).done:
	default:
		t.Fatal("Close returned before readLoop ended")
	}
	select {
	case _, ok := <-src.Events():
		if ok {
			t.Fatal("event received after Close")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("events channel not closed after Close")
	}
}

// TestNewEventSource loads the embedded BPF object for real, so it skips
// where that is impossible. The kprobe constructors are faked, which makes
// the attach sequence independent of the kernel's symbols and kprobe support.
func TestNewEventSource(t *testing.T) {
	requireEmbeddedObject(t)
	mounts := []MountInfo{{Major: 8, Minor: 1}, {Major: 0, Minor: 77}, {Major: 8, Minor: 1}}
	tests := []struct {
		name      string
		cfg       Config
		debugHex  string
		wantUID   uint8
		wantHex   bool
		wantCalls []string
		wantLinks int
		wantLog   string
		fail      map[string]error
	}{
		{
			name:      "uid labels enabled",
			cfg:       Config{UIDLabelsEnabled: true},
			wantUID:   1,
			wantCalls: wantAttachOrder,
			wantLinks: len(wantAttachOrder),
		},
		{
			name:      "uid labels disabled, debug hex",
			cfg:       Config{},
			debugHex:  "1",
			wantUID:   0,
			wantHex:   true,
			wantCalls: wantAttachOrder,
			wantLinks: len(wantAttachOrder),
		},
		{
			name:      "debug hex takes exactly 1",
			cfg:       Config{UIDLabelsEnabled: true},
			debugHex:  "true",
			wantUID:   1,
			wantCalls: wantAttachOrder,
			wantLinks: len(wantAttachOrder),
		},
		{
			name:      "LegacySymbolAllowMissing skips a failed required probe",
			cfg:       Config{UIDLabelsEnabled: true, LegacySymbolAllowMissing: true},
			fail:      map[string]error{"ll_file_open": errors.New("attach failed")},
			wantUID:   1,
			wantCalls: wantAttachOrder,
			wantLinks: len(wantAttachOrder) - 1,
			wantLog:   "warning: skipping probe ll_file_open/ll_file_open_enter: attach failed\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureStdLog(t)
			calls, progs := fakeAttach(t, tt.fail)
			t.Setenv("LUSTRE_OBSERVER_DEBUG_HEX", tt.debugHex)

			src, err := newEventSource(context.Background(), tt.cfg, mounts)
			if err != nil {
				t.Fatal(err)
			}
			s := src.(*linuxEventSource)
			defer closeSource(t, src)

			names := map[*ebpf.Program]string{}
			for name, prog := range s.collection.Programs {
				names[prog] = name
			}
			var got []string
			for i, call := range *calls {
				got = append(got, call+" "+names[(*progs)[i]])
			}
			if strings.Join(got, "\n") != strings.Join(tt.wantCalls, "\n") {
				t.Fatalf("attach calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(tt.wantCalls, "\n"))
			}
			if len(s.links) != tt.wantLinks {
				t.Fatalf("got %d links, want %d", len(s.links), tt.wantLinks)
			}
			if logs.String() != tt.wantLog {
				t.Fatalf("log = %q, want %q", logs.String(), tt.wantLog)
			}

			var uid uint8
			if err := s.collection.Variables["uid_labels_enabled"].Get(&uid); err != nil {
				t.Fatal(err)
			}
			if uid != tt.wantUID {
				t.Fatalf("uid_labels_enabled = %d, want %d", uid, tt.wantUID)
			}
			mountFilter := map[bpfMountKey]uint8{}
			var key bpfMountKey
			var idx uint8
			it := s.collection.Maps["config_map"].Iterate()
			for it.Next(&key, &idx) {
				mountFilter[key] = idx
			}
			if err := it.Err(); err != nil {
				t.Fatal(err)
			}
			// The repeated mount keeps the index of its last occurrence.
			wantFilter := map[bpfMountKey]uint8{{Major: 8, Minor: 1}: 2, {Major: 0, Minor: 77}: 1}
			if !reflect.DeepEqual(mountFilter, wantFilter) {
				t.Fatalf("config_map = %v, want %v", mountFilter, wantFilter)
			}
			if size := s.reader.(*perf.Reader).BufferSize(); size != os.Getpagesize()*8 {
				t.Fatalf("perf buffer size = %d, want %d", size, os.Getpagesize()*8)
			}
			if cap(s.events) != 1024 || s.debugHex != tt.wantHex || !s.started {
				t.Fatalf("events cap = %d, debugHex = %v, started = %v", cap(s.events), s.debugHex, s.started)
			}
		})
	}
}

// TestNewEventSourceFailures checks that a failure after the collection is
// loaded returns no source and leaves no file descriptor open.
func TestNewEventSourceFailures(t *testing.T) {
	requireEmbeddedObject(t)
	tooMany := make([]MountInfo, 17) // config_map holds 16 entries
	for i := range tooMany {
		tooMany[i] = MountInfo{Major: 1, Minor: uint32(i)}
	}
	tests := []struct {
		name      string
		mounts    []MountInfo
		fail      map[string]error
		wantErr   string
		wantCalls []string
	}{
		{
			name:    "mount filter update",
			mounts:  tooMany,
			wantErr: "update: key too big for map: argument list too long",
		},
		{
			name:      "required probe attach",
			mounts:    tooMany[:1],
			fail:      map[string]error{"ll_file_open": errors.New("attach failed")},
			wantErr:   "attach failed",
			wantCalls: []string{"kprobe ll_lookup_nd", "kprobe ll_file_open"},
		},
	}
	// Warm up the library's caches first, so that only leaks change the count.
	calls, _ := fakeAttach(t, nil)
	src, err := newEventSource(context.Background(), Config{UIDLabelsEnabled: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	closeSource(t, src)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			captureStdLog(t)
			calls, _ = fakeAttach(t, tt.fail)
			before := openFDs(t)
			src, err := newEventSource(context.Background(), Config{UIDLabelsEnabled: true}, tt.mounts)
			if err == nil || err.Error() != tt.wantErr || src != nil {
				t.Fatalf("newEventSource = %v, %v, want nil, %q", src, err, tt.wantErr)
			}
			if after := openFDs(t); after != before {
				t.Fatalf("%d file descriptors open after the failure, %d before", after, before)
			}
			if strings.Join(*calls, ", ") != strings.Join(tt.wantCalls, ", ") {
				t.Fatalf("attach calls = %v, want %v", *calls, tt.wantCalls)
			}
		})
	}
}
