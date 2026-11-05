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
	if stripped, ok := stripBracketedNumber(s); ok {
		return stripped
	}
	return stripTrailingNumber(s)
}

// stripBracketedNumber strips a "(N)" or "[N]" suffix, together with one
// separator before it ("worker (1)" → "worker"). ok reports whether s ends with
// such a suffix; s is returned unchanged when stripping would leave it empty.
func stripBracketedNumber(s string) (stripped string, ok bool) {
	n := len(s)
	if n < 3 {
		return s, false
	}
	open := openingBracket(s[n-1])
	if open == 0 {
		return s, false
	}
	j := lastNonDigit(s, n-2)
	hasDigits := j < n-2
	if j < 0 || !hasDigits || s[j] != open {
		return s, false
	}
	cut := j
	if j > 0 && isSeparator(s[j-1]) {
		cut = j - 1
	}
	if cut == 0 {
		return s, true // would reduce to empty
	}
	return s[:cut], true
}

// openingBracket returns the bracket that the closing bracket c pairs with, or
// 0 if c is not ')' or ']'.
func openingBracket(c byte) byte {
	switch c {
	case ')':
		return '('
	case ']':
		return '['
	}
	return 0
}

// stripTrailingNumber strips trailing digits together with the separator
// before them ("worker-3" → "worker"). Digits that follow any other character
// are left to stripDottedTrailingNumber, which strips them only after a dot
// ("client.poll12" → "client.poll", while "python3" is kept).
func stripTrailingNumber(s string) string {
	i := lastNonDigit(s, len(s)-1)
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

// lastNonDigit returns the index of the last byte of s[:i+1] that is not an
// ASCII digit, or -1 if there is none.
func lastNonDigit(s string, i int) int {
	for i >= 0 && s[i] >= '0' && s[i] <= '9' {
		i--
	}
	return i
}

// stripSeparatorInstanceToken cuts s before the first separator that starts
// an instance token ("Bun Pool 1" → "Bun Pool", "ray-dashboard-A" →
// "ray-dashboard"). s is returned unchanged when there is none, or when the
// first one begins s, as cutting there would leave it empty.
func stripSeparatorInstanceToken(s string) string {
	for i := 0; i < len(s)-1; i++ {
		if !isSeparator(s[i]) || !isInstanceToken(s, i+1) {
			continue
		}
		if i == 0 {
			return s // would reduce to empty
		}
		return s[:i]
	}
	return s
}

// isInstanceToken reports whether an instance token starts at s[j], which must
// exist: a run of digits or a single ASCII letter, followed by the end of s, a
// separator, '(' or '['.
func isInstanceToken(s string, j int) bool {
	end := instanceTokenEnd(s, j)
	if end < 0 {
		return false
	}
	return end == len(s) || isSeparator(s[end]) || s[end] == '(' || s[end] == '['
}

// instanceTokenEnd returns the index just past the digit run or the single
// ASCII letter at s[j], or -1 if s[j] is neither.
func instanceTokenEnd(s string, j int) int {
	switch {
	case isASCIIDigit(s[j]):
		for j < len(s) && isASCIIDigit(s[j]) {
			j++
		}
		return j
	case isASCIIAlpha(s[j]):
		return j + 1
	default:
		return -1
	}
}

func isASCIIDigit(c byte) bool {
	return c >= '0' && c <= '9'
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
