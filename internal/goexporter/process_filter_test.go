package goexporter

import (
	"testing"
)

func TestProcessFilterAllowlist(t *testing.T) {
	t.Parallel()

	f := NewProcessFilter([]string{"python", "dd", "rsync"}, false)

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

	f := NewProcessFilter(nil, false)

	// No allowlist → pass-through.
	if got := f.Normalize("anything"); got != "anything" {
		t.Fatalf("expected pass-through, got %q", got)
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
		{"worker (1)", "worker"},   // separator before paren is also stripped
		{"task-(2)", "task"},       // dash separator before paren
		{"job_(3)", "job"},         // underscore separator before paren

		// Bracketed numeric suffix.
		{"worker[10]", "worker"},
		{"worker[11]", "worker"},
		{"pool[0]", "pool"},
		{"task [3]", "task"},       // separator before bracket is also stripped
		{"job-[99]", "job"},        // dash separator before bracket

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
	f := NewProcessFilter(nil, true)

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
	f := NewProcessFilter(nil, false)

	if got := f.Normalize("Bun Pool 1"); got != "Bun Pool 1" {
		t.Fatalf("expected pass-through, got %q", got)
	}
}

func TestProcessFilterStripSuffixWithAllowlist(t *testing.T) {
	t.Parallel()
	f := NewProcessFilter([]string{"Bun Pool"}, true)

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
