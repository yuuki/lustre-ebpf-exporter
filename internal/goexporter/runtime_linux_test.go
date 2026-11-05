//go:build linux

package goexporter

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// TestAttachAllMissingPrograms covers the attachAll paths that need no kernel
// support: every program is absent from the collection, so nothing is
// attached. Attaching real probes needs root and a kernel with the probed
// symbols, so those paths are left to the e2e suite. The test captures the
// standard logger, so it must not run in parallel.
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
