package goexporter

import (
	"strings"
)

const processOther = "other"

// ProcessFilter normalizes process names to reduce exported label cardinality.
// It intentionally no longer performs dynamic trimming: relevance filtering is
// handled later by the windowed workload collector. The allowlist is retained
// only as an operator override so specific process names can bypass relevance
// suppression when that support is enabled by the caller.
type ProcessFilter struct {
	allowlist   map[string]struct{}
	stripSuffix bool
}

func NewProcessFilter(allowlist []string, stripSuffix bool) *ProcessFilter {
	var al map[string]struct{}
	if len(allowlist) > 0 {
		al = make(map[string]struct{}, len(allowlist))
		for _, name := range allowlist {
			al[strings.TrimSpace(name)] = struct{}{}
		}
	}
	return &ProcessFilter{allowlist: al, stripSuffix: stripSuffix}
}

// Normalize returns the suffix-normalized process name. It no longer performs
// allowlist or tail-trim collapsing; those decisions belong to the workload
// relevance filter once per window, not on the hot path.
func (f *ProcessFilter) Normalize(process string, bpfComm ...string) string {
	if f.stripSuffix {
		process = stripTrailingNumericSuffix(process)
		if len(bpfComm) > 0 {
			bpfComm[0] = stripTrailingNumericSuffix(bpfComm[0])
		}
	}
	return process
}

func (f *ProcessFilter) AlwaysKeep(process string) bool {
	if f.allowlist == nil {
		return false
	}
	normalized := process
	if f.stripSuffix {
		normalized = stripTrailingNumericSuffix(normalized)
	}
	_, ok := f.allowlist[normalized]
	return ok
}

func (f *ProcessFilter) StripName(s string) string {
	if f.stripSuffix {
		return stripTrailingNumericSuffix(s)
	}
	return s
}

// IsActive returns true if suffix normalization or allowlist overrides are enabled.
func (f *ProcessFilter) IsActive() bool {
	return f.allowlist != nil || f.stripSuffix
}

func isSeparator(c byte) bool {
	switch c {
	case ' ', '-', '_', ':':
		return true
	}
	return false
}

// stripTrailingNumericSuffix removes a trailing separator+digits suffix from
// a process name to collapse numbered variants (e.g. "Bun Pool 1" → "Bun Pool").
// Bracketed suffixes like "(1)" and "[1]" are also stripped.
// Names where digits follow a period (e.g. "python3.11") are left unchanged.
func stripTrailingNumericSuffix(s string) string {
	if n := len(s); n >= 3 {
		var open byte
		switch s[n-1] {
		case ')':
			open = '('
		case ']':
			open = '['
		}
		if open != 0 {
			j := n - 2
			for j >= 0 && s[j] >= '0' && s[j] <= '9' {
				j--
			}
			hasDigits := j < n-2
			if j >= 0 && hasDigits && s[j] == open {
				cut := j
				if j > 0 && isSeparator(s[j-1]) {
					cut = j - 1
				}
				if cut == 0 {
					return s // would reduce to empty
				}
				return s[:cut]
			}
		}
	}

	i := len(s) - 1
	for i >= 0 && s[i] >= '0' && s[i] <= '9' {
		i--
	}
	if i == len(s)-1 {
		return s // no trailing digits
	}
	if i < 0 {
		return s // entire string is digits
	}
	if isSeparator(s[i]) {
		if i == 0 {
			return s // would reduce to empty
		}
		return s[:i]
	}
	return s // separator not recognised (e.g. period)
}
