package goexporter

const processOther = "other"

// ProcessFilter normalizes process names to reduce Prometheus label
// cardinality. It supports a static allowlist: only names in the allowlist
// pass through; everything else becomes "other". An optional normalization
// pass can collapse instance variants (e.g. "Bun Pool 1" → "Bun Pool")
// before the allowlist check.
type ProcessFilter struct {
	// Static allowlist (nil means disabled). Immutable after construction.
	allowlist map[string]struct{}

	// stripSuffix normalizes process instance variants before filtering.
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
		process = normalizeProcessInstanceVariant(process)
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
	case ' ', '-', '_', ':', '/':
		return true
	}
	return false
}

// normalizeProcessInstanceVariant removes instance tokens from process names to
// collapse variants (e.g. "Bun Pool 1" → "Bun Pool").
// Bracketed suffixes like "(1)" and "[1]" are also stripped. Version-like names
// such as "python3.11" and "go1.21.5" are left unchanged.
func normalizeProcessInstanceVariant(s string) string {
	if stripped := stripSeparatorInstanceToken(s); stripped != s {
		return stripped
	}

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
	return stripDottedTrailingNumber(s)
}

func stripSeparatorInstanceToken(s string) string {
	for i := 0; i < len(s)-1; i++ {
		if !isSeparator(s[i]) {
			continue
		}

		j := i + 1
		if s[j] >= '0' && s[j] <= '9' {
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
		} else if isASCIIAlpha(s[j]) {
			j++
		} else {
			continue
		}
		if j < len(s) && !isSeparator(s[j]) && s[j] != '(' && s[j] != '[' {
			continue
		}
		if i == 0 {
			return s // would reduce to empty
		}
		return s[:i]
	}
	return s
}

func isASCIIAlpha(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func stripDottedTrailingNumber(s string) string {
	dot := -1
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 || dot == len(s)-1 {
		return s
	}

	i := len(s) - 1
	for i > dot && s[i] >= '0' && s[i] <= '9' {
		i--
	}
	if i == len(s)-1 || i == dot {
		return s
	}
	return s[:i+1]
}
