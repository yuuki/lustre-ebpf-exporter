package goexporter

import (
	"reflect"
	"testing"
)

// TestLabelBuildersMatrix exercises every label builder across the full
// (slurmEnabled × uidEnabled) matrix so that a regression in any one
// conditional branch fails loudly with the exact expected slice order.
// The builders are the single source of truth for label schemas — any
// drift between them and the *LabelValues helpers would silently produce
// Prometheus "inconsistent label cardinality" panics at scrape time.
func TestLabelBuildersMatrix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		slurm      bool
		uid        bool
		base       []string
		ptlrpc     []string
		llite      []string
		ptlrpcHist []string
		lliteHist  []string
		lliteErr   []string
		rpcError   []string
		pccAttach  []string
	}{
		{
			name:       "both_disabled",
			slurm:      false,
			uid:        false,
			base:       []string{"fs", "mount", "process", "actor_type"},
			ptlrpc:     []string{"fs", "mount", "op", "process", "actor_type"},
			llite:      []string{"fs", "mount", "access_intent", "op", "process", "actor_type"},
			ptlrpcHist: []string{"fs", "mount", "op", "actor_type"},
			lliteHist:  []string{"fs", "mount", "access_intent", "op", "actor_type"},
			lliteErr:   []string{"fs", "mount", "access_intent", "op", "process", "actor_type", "errno_class"},
			rpcError:   []string{"fs", "mount", "event", "process", "actor_type"},
			pccAttach:  []string{"fs", "mount", "mode", "trigger", "process", "actor_type"},
		},
		{
			name:       "slurm_only",
			slurm:      true,
			uid:        false,
			base:       []string{"fs", "mount", "process", "actor_type", "slurm_job_id"},
			ptlrpc:     []string{"fs", "mount", "op", "process", "actor_type", "slurm_job_id"},
			llite:      []string{"fs", "mount", "access_intent", "op", "process", "actor_type", "slurm_job_id"},
			ptlrpcHist: []string{"fs", "mount", "op", "actor_type", "slurm_job_id"},
			lliteHist:  []string{"fs", "mount", "access_intent", "op", "actor_type", "slurm_job_id"},
			lliteErr:   []string{"fs", "mount", "access_intent", "op", "process", "actor_type", "slurm_job_id", "errno_class"},
			rpcError:   []string{"fs", "mount", "event", "process", "actor_type", "slurm_job_id"},
			pccAttach:  []string{"fs", "mount", "mode", "trigger", "process", "actor_type", "slurm_job_id"},
		},
		{
			name:       "uid_only",
			slurm:      false,
			uid:        true,
			base:       []string{"fs", "mount", "uid", "username", "process", "actor_type"},
			ptlrpc:     []string{"fs", "mount", "op", "uid", "username", "process", "actor_type"},
			llite:      []string{"fs", "mount", "access_intent", "op", "uid", "username", "process", "actor_type"},
			ptlrpcHist: []string{"fs", "mount", "op", "uid", "username", "actor_type"},
			lliteHist:  []string{"fs", "mount", "access_intent", "op", "uid", "username", "actor_type"},
			lliteErr:   []string{"fs", "mount", "access_intent", "op", "uid", "username", "process", "actor_type", "errno_class"},
			rpcError:   []string{"fs", "mount", "event", "uid", "username", "process", "actor_type"},
			pccAttach:  []string{"fs", "mount", "mode", "trigger", "uid", "username", "process", "actor_type"},
		},
		{
			name:       "both_enabled",
			slurm:      true,
			uid:        true,
			base:       []string{"fs", "mount", "uid", "username", "process", "actor_type", "slurm_job_id"},
			ptlrpc:     []string{"fs", "mount", "op", "uid", "username", "process", "actor_type", "slurm_job_id"},
			llite:      []string{"fs", "mount", "access_intent", "op", "uid", "username", "process", "actor_type", "slurm_job_id"},
			ptlrpcHist: []string{"fs", "mount", "op", "uid", "username", "actor_type", "slurm_job_id"},
			lliteHist:  []string{"fs", "mount", "access_intent", "op", "uid", "username", "actor_type", "slurm_job_id"},
			lliteErr:   []string{"fs", "mount", "access_intent", "op", "uid", "username", "process", "actor_type", "slurm_job_id", "errno_class"},
			rpcError:   []string{"fs", "mount", "event", "uid", "username", "process", "actor_type", "slurm_job_id"},
			pccAttach:  []string{"fs", "mount", "mode", "trigger", "uid", "username", "process", "actor_type", "slurm_job_id"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			checks := []struct {
				builder string
				got     []string
				want    []string
			}{
				{"buildBaseLabels", buildBaseLabels(tc.slurm, tc.uid), tc.base},
				{"buildPtlrpcLabels", buildPtlrpcLabels(tc.slurm, tc.uid), tc.ptlrpc},
				{"buildLliteLabels", buildLliteLabels(tc.slurm, tc.uid), tc.llite},
				{"buildPtlrpcHistogramLabels", buildPtlrpcHistogramLabels(tc.slurm, tc.uid, false), tc.ptlrpcHist},
				{"buildLliteHistogramLabels", buildLliteHistogramLabels(tc.slurm, tc.uid, false), tc.lliteHist},
				{"buildLliteErrLabels", buildLliteErrLabels(tc.slurm, tc.uid), tc.lliteErr},
				{"buildRPCErrorLabels", buildRPCErrorLabels(tc.slurm, tc.uid), tc.rpcError},
				{"buildPCCAttachLabels", buildPCCAttachLabels(tc.slurm, tc.uid), tc.pccAttach},
			}
			for _, c := range checks {
				if !reflect.DeepEqual(c.got, c.want) {
					t.Errorf("%s(%v, %v):\n  got  %v\n  want %v", c.builder, tc.slurm, tc.uid, c.got, c.want)
				}
			}
		})
	}
}

// TestLabelValuesMatchBuilderArity guards the invariant that every
// *LabelValues helper emits exactly as many values as the corresponding
// builder declares label names. A cardinality mismatch is the number-one
// cause of prometheus.WithLabelValues panics at runtime, so pinning the
// arity check in a cheap table test catches regressions early.
func TestLabelValuesMatchBuilderArity(t *testing.T) {
	t.Parallel()

	for _, slurm := range []bool{false, true} {
		for _, uid := range []bool{false, true} {
			if got, want := len(baseLabelValues(Event{}, "", "", "", "", slurm, uid)), len(buildBaseLabels(slurm, uid)); got != want {
				t.Errorf("baseLabelValues arity mismatch (slurm=%v uid=%v): got %d want %d", slurm, uid, got, want)
			}
			if got, want := len(ptlrpcLabelValues("", "", "", "", "", "", "", "", slurm, uid)), len(buildPtlrpcLabels(slurm, uid)); got != want {
				t.Errorf("ptlrpcLabelValues arity mismatch (slurm=%v uid=%v): got %d want %d", slurm, uid, got, want)
			}
			if got, want := len(ptlrpcHistogramLabelValues("", "", "", "", "", "", "", "", slurm, uid, false)), len(buildPtlrpcHistogramLabels(slurm, uid, false)); got != want {
				t.Errorf("ptlrpcHistogramLabelValues arity mismatch (slurm=%v uid=%v): got %d want %d", slurm, uid, got, want)
			}
			if got, want := len(lliteLabelValues("", "", "", "", "", "", "", "", "", slurm, uid)), len(buildLliteLabels(slurm, uid)); got != want {
				t.Errorf("lliteLabelValues arity mismatch (slurm=%v uid=%v): got %d want %d", slurm, uid, got, want)
			}
			if got, want := len(lliteHistogramLabelValues("", "", "", "", "", "", "", "", "", slurm, uid, false)), len(buildLliteHistogramLabels(slurm, uid, false)); got != want {
				t.Errorf("lliteHistogramLabelValues arity mismatch (slurm=%v uid=%v): got %d want %d", slurm, uid, got, want)
			}
			if got, want := len(pccAttachLabelValues("", "", "", "", "", "", "", "", "", slurm, uid)), len(buildPCCAttachLabels(slurm, uid)); got != want {
				t.Errorf("pccAttachLabelValues arity mismatch (slurm=%v uid=%v): got %d want %d", slurm, uid, got, want)
			}
		}
	}
}
