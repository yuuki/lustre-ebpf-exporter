package goexporter

import (
	"testing"
)

func TestProcessFilterAllowlist(t *testing.T) {
	t.Parallel()

	f := NewProcessFilter([]string{"python", "dd", "rsync"}, 0, 1, false)

	if got := f.Normalize("python"); got != "python" {
		t.Fatalf("expected python, got %q", got)
	}
	if got := f.Normalize("dd"); got != "dd" {
		t.Fatalf("expected dd, got %q", got)
	}
	if got := f.Normalize("my_custom_app"); got != "other" {
		t.Fatalf("expected other, got %q", got)
	}
	if got := f.Normalize("bash"); got != "other" {
		t.Fatalf("expected other for bash, got %q", got)
	}
}

func TestProcessFilterAllowlistEmpty(t *testing.T) {
	t.Parallel()

	f := NewProcessFilter(nil, 0, 1, false)

	// No allowlist and no trim → pass-through.
	if got := f.Normalize("anything"); got != "anything" {
		t.Fatalf("expected pass-through, got %q", got)
	}
}

func TestProcessFilterTailTrimBasic(t *testing.T) {
	t.Parallel()

	// Trim bottom 50% with hysteresis=1 (immediate).
	f := NewProcessFilter(nil, 50, 1, false)

	ops := map[string]float64{
		"dd":     1000,
		"python": 500,
		"bash":   10,
		"cat":    5,
	}
	// 4 unique processes, 50% = bottom 2 (cat, bash).
	f.UpdateTrimSet(ops)

	if got := f.Normalize("dd"); got != "dd" {
		t.Fatalf("expected dd (top), got %q", got)
	}
	if got := f.Normalize("python"); got != "python" {
		t.Fatalf("expected python (top), got %q", got)
	}
	if got := f.Normalize("bash"); got != "other" {
		t.Fatalf("expected other for bash (trimmed), got %q", got)
	}
	if got := f.Normalize("cat"); got != "other" {
		t.Fatalf("expected other for cat (trimmed), got %q", got)
	}
	// Unknown process not in trim set → pass-through.
	if got := f.Normalize("new_proc"); got != "new_proc" {
		t.Fatalf("expected pass-through for unknown, got %q", got)
	}
}

func TestProcessFilterTailTrimHysteresis(t *testing.T) {
	t.Parallel()

	// Hysteresis=3: process must be trim candidate for 3 consecutive cycles.
	f := NewProcessFilter(nil, 50, 3, false)

	ops := map[string]float64{
		"dd":   1000,
		"bash": 10,
	}

	// Cycle 1: bash is candidate but not yet trimmed.
	f.UpdateTrimSet(ops)
	if got := f.Normalize("bash"); got != "bash" {
		t.Fatalf("cycle 1: expected bash (not yet trimmed), got %q", got)
	}

	// Cycle 2: still candidate.
	f.UpdateTrimSet(ops)
	if got := f.Normalize("bash"); got != "bash" {
		t.Fatalf("cycle 2: expected bash (not yet trimmed), got %q", got)
	}

	// Cycle 3: now trimmed.
	f.UpdateTrimSet(ops)
	if got := f.Normalize("bash"); got != "other" {
		t.Fatalf("cycle 3: expected other (trimmed), got %q", got)
	}
}

func TestProcessFilterTailTrimHysteresisReset(t *testing.T) {
	t.Parallel()

	f := NewProcessFilter(nil, 50, 3, false)

	ops := map[string]float64{
		"dd":   1000,
		"bash": 10,
	}

	// 2 cycles: bash is candidate.
	f.UpdateTrimSet(ops)
	f.UpdateTrimSet(ops)

	// Cycle 3: bash moves out of trim set (ops increased).
	ops["bash"] = 5000
	f.UpdateTrimSet(ops)

	// bash was not a candidate in cycle 3, counter resets.
	if got := f.Normalize("bash"); got != "bash" {
		t.Fatalf("expected bash (hysteresis reset), got %q", got)
	}
}

func TestProcessFilterAllowlistPriorityOverTrim(t *testing.T) {
	t.Parallel()

	// Both allowlist and trim set → allowlist wins.
	f := NewProcessFilter([]string{"dd"}, 50, 1, false)

	ops := map[string]float64{
		"dd":   10,
		"bash": 1000,
	}
	f.UpdateTrimSet(ops)

	// dd is in the allowlist, so it passes even though it would be trimmed.
	if got := f.Normalize("dd"); got != "dd" {
		t.Fatalf("expected dd (allowlist), got %q", got)
	}
	// bash is not in allowlist → other.
	if got := f.Normalize("bash"); got != "other" {
		t.Fatalf("expected other (not in allowlist), got %q", got)
	}
}

func TestProcessFilterTrimmedCount(t *testing.T) {
	t.Parallel()

	f := NewProcessFilter(nil, 50, 1, false)

	ops := map[string]float64{
		"dd":     1000,
		"python": 500,
		"bash":   10,
		"cat":    5,
	}
	f.UpdateTrimSet(ops)

	if got := f.TrimmedCount(); got != 2 {
		t.Fatalf("expected 2 trimmed processes, got %d", got)
	}
}

func TestProcessFilterBPFCommFallback(t *testing.T) {
	t.Parallel()

	// Trim set is built from BPF comm (15-char max).
	// Full resolved name differs from BPF comm for long names.
	f := NewProcessFilter(nil, 50, 1, false)

	bpfComm := "python3.11-conf" // truncated at 15 chars
	fullName := "python3.11-config"

	ops := map[string]float64{
		bpfComm: 1,
		"dd":    1000,
	}
	f.UpdateTrimSet(ops)

	// Without bpfComm fallback, fullName wouldn't match the trim set.
	if got := f.Normalize(fullName, bpfComm); got != "other" {
		t.Fatalf("expected other for long name with bpfComm fallback, got %q", got)
	}
	// Short name that matches directly should still work.
	if got := f.Normalize("dd"); got != "dd" {
		t.Fatalf("expected dd (not trimmed), got %q", got)
	}
}

func TestProcessFilterBPFCommFallbackNotNeeded(t *testing.T) {
	t.Parallel()

	// When bpfComm equals the resolved name, no fallback needed.
	f := NewProcessFilter(nil, 50, 1, false)

	ops := map[string]float64{
		"cat": 1,
		"dd":  1000,
	}
	f.UpdateTrimSet(ops)

	if got := f.Normalize("cat", "cat"); got != "other" {
		t.Fatalf("expected other, got %q", got)
	}
}

func TestProcessFilterIsActive(t *testing.T) {
	t.Parallel()

	noop := NewProcessFilter(nil, 0, 1, false)
	if noop.IsActive() {
		t.Fatal("expected inactive for noop filter")
	}

	al := NewProcessFilter([]string{"dd"}, 0, 1, false)
	if !al.IsActive() {
		t.Fatal("expected active for allowlist filter")
	}

	trim := NewProcessFilter(nil, 10, 1, false)
	if !trim.IsActive() {
		t.Fatal("expected active for trim filter")
	}

	strip := NewProcessFilter(nil, 0, 1, true)
	if !strip.IsActive() {
		t.Fatal("expected active for strip-suffix filter")
	}
}

func TestStripTrailingNumericSuffix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
	}{
		{"Bun Pool 1", "Bun Pool"},
		{"Bun Pool 23", "Bun Pool"},
		{"worker-3", "worker"},
		{"thread_42", "thread"},
		{"handler:7", "handler"},
		{"pool 0", "pool"},

		// Version numbers — must NOT strip.
		{"python3.11", "python3.11"},
		{"python3", "python3"},
		{"go1.21.5", "go1.21.5"},

		// Parenthesised numeric suffix.
		{"worker(1)", "worker"},
		{"worker(23)", "worker"},
		{"pool(0)", "pool"},

		// Edge cases.
		{"dd", "dd"},
		{"123", "123"},
		{"a-1", "a"},
		{" 1", " 1"},   // would reduce to empty → leave unchanged
		{"-1", "-1"},    // would reduce to empty → leave unchanged
		{"v2", "v2"},    // no recognised separator
		{"name--42", "name-"},
		{"(1)", "(1)"},  // would reduce to empty → leave unchanged
		{"x()", "x()"},         // no digits inside parens → leave unchanged
		{"x(ab)", "x(ab)"},     // non-digits inside parens → leave unchanged
		{"a(1)", "a"},          // shortest valid parenthesised input
		{"foo(bar)-1", "foo(bar)"}, // paren path misses, falls through to separator path
	}
	for _, tt := range tests {
		if got := stripTrailingNumericSuffix(tt.input); got != tt.want {
			t.Errorf("stripTrailingNumericSuffix(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestProcessFilterStripSuffixEnabled(t *testing.T) {
	t.Parallel()
	f := NewProcessFilter(nil, 0, 1, true)

	if got := f.Normalize("Bun Pool 1"); got != "Bun Pool" {
		t.Fatalf("expected 'Bun Pool', got %q", got)
	}
	if got := f.Normalize("worker-3"); got != "worker" {
		t.Fatalf("expected 'worker', got %q", got)
	}
	if got := f.Normalize("python3.11"); got != "python3.11" {
		t.Fatalf("expected 'python3.11', got %q", got)
	}
}

func TestProcessFilterStripSuffixDisabled(t *testing.T) {
	t.Parallel()
	f := NewProcessFilter(nil, 0, 1, false)

	if got := f.Normalize("Bun Pool 1"); got != "Bun Pool 1" {
		t.Fatalf("expected pass-through, got %q", got)
	}
}

func TestProcessFilterStripSuffixWithAllowlist(t *testing.T) {
	t.Parallel()
	f := NewProcessFilter([]string{"Bun Pool"}, 0, 1, true)

	if got := f.Normalize("Bun Pool 1"); got != "Bun Pool" {
		t.Fatalf("expected 'Bun Pool', got %q", got)
	}
	if got := f.Normalize("Bun Pool 99"); got != "Bun Pool" {
		t.Fatalf("expected 'Bun Pool', got %q", got)
	}
	if got := f.Normalize("other_proc"); got != "other" {
		t.Fatalf("expected 'other', got %q", got)
	}
}

func TestProcessFilterStripSuffixWithTailTrim(t *testing.T) {
	t.Parallel()
	// stripSuffix=true + trimPercent=50: trim set keys must use stripped names
	// so that numbered variants like "worker-1" are correctly trimmed.
	f := NewProcessFilter(nil, 50, 1, true)

	// Simulate ops accumulated under stripped names (as normalizeProcess now does).
	ops := map[string]float64{
		"dd":     1000,
		"worker": 5, // stripped form of "worker-1", "worker-2", etc.
	}
	f.UpdateTrimSet(ops)

	// "worker-1" should be stripped to "worker", which is in the trim set.
	if got := f.Normalize("worker-1"); got != "other" {
		t.Fatalf("expected 'other' (stripped then trimmed), got %q", got)
	}
	// "dd" should survive.
	if got := f.Normalize("dd"); got != "dd" {
		t.Fatalf("expected 'dd', got %q", got)
	}
}

func TestProcessFilterStripName(t *testing.T) {
	t.Parallel()

	enabled := NewProcessFilter(nil, 0, 1, true)
	if got := enabled.StripName("worker-3"); got != "worker" {
		t.Fatalf("expected 'worker', got %q", got)
	}

	disabled := NewProcessFilter(nil, 0, 1, false)
	if got := disabled.StripName("worker-3"); got != "worker-3" {
		t.Fatalf("expected pass-through, got %q", got)
	}
}
