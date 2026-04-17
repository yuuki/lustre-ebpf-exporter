package goexporter

import "testing"

func TestProcessFilterNormalizePassThrough(t *testing.T) {
	t.Parallel()

	f := NewProcessFilter([]string{"dd"}, false)
	if got := f.Normalize("dd"); got != "dd" {
		t.Fatalf("expected dd, got %q", got)
	}
	if got := f.Normalize("bash"); got != "bash" {
		t.Fatalf("expected pass-through for bash, got %q", got)
	}
}

func TestProcessFilterAlwaysKeep(t *testing.T) {
	t.Parallel()

	f := NewProcessFilter([]string{"dd", "Bun Pool"}, true)
	if !f.AlwaysKeep("dd") {
		t.Fatal("expected dd to be allowlisted")
	}
	if !f.AlwaysKeep("Bun Pool 1") {
		t.Fatal("expected suffix-stripped allowlist match")
	}
	if f.AlwaysKeep("bash") {
		t.Fatal("did not expect bash to be allowlisted")
	}
}

func TestProcessFilterIsActive(t *testing.T) {
	t.Parallel()

	noop := NewProcessFilter(nil, false)
	if noop.IsActive() {
		t.Fatal("expected inactive for noop filter")
	}

	al := NewProcessFilter([]string{"dd"}, false)
	if !al.IsActive() {
		t.Fatal("expected active for allowlist override")
	}

	strip := NewProcessFilter(nil, true)
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
		{"python3.11", "python3.11"},
		{"python3", "python3"},
		{"go1.21.5", "go1.21.5"},
		{"worker(1)", "worker"},
		{"worker (1)", "worker"},
		{"worker[10]", "worker"},
	}

	for _, tt := range tests {
		if got := stripTrailingNumericSuffix(tt.input); got != tt.want {
			t.Fatalf("stripTrailingNumericSuffix(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestProcessFilterStripName(t *testing.T) {
	t.Parallel()

	enabled := NewProcessFilter(nil, true)
	if got := enabled.StripName("worker-3"); got != "worker" {
		t.Fatalf("expected stripped worker, got %q", got)
	}

	disabled := NewProcessFilter(nil, false)
	if got := disabled.StripName("worker-3"); got != "worker-3" {
		t.Fatalf("expected unchanged name, got %q", got)
	}
}
