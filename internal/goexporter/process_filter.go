package goexporter

const processOther = "other"

// ProcessFilter normalizes process names to reduce Prometheus label
// cardinality. It supports a static allowlist: only names in the allowlist
// pass through; everything else becomes "other". An optional suffix-stripping
// pass can collapse numbered variants (e.g. "Bun Pool 1" → "Bun Pool")
// before the allowlist check.
type ProcessFilter struct {
	// Static allowlist (nil means disabled). Immutable after construction.
	allowlist map[string]struct{}

	// stripSuffix removes trailing separator+digits before filtering.
	stripSuffix bool
}

// NewProcessFilter creates a filter. Pass nil allowlist and stripSuffix=false
// to create a no-op filter (all names pass through).
func NewProcessFilter(allowlist []string, stripSuffix bool) *ProcessFilter {
	var al map[string]struct{}
	if len(allowlist) > 0 {
		al = make(map[string]struct{}, len(allowlist))
		for _, name := range allowlist {
			al[name] = struct{}{}
		}
	}
	return &ProcessFilter{
		allowlist:   al,
		stripSuffix: stripSuffix,
	}
}

// Normalize returns the filtered process name. Non-matching processes
// are replaced with "other". Lock-free on the hot path.
func (f *ProcessFilter) Normalize(process string) string {
	if f.stripSuffix {
		process = stripTrailingNumericSuffix(process)
	}

	if f.allowlist != nil {
		if _, ok := f.allowlist[process]; ok {
			return process
		}
		return processOther
	}

	return process
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
