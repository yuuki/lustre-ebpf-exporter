//go:build linux

package goexporter

import (
	"bytes"
	"errors"
	"log"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
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
