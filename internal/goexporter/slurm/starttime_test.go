package slurm

import "testing"

func TestParseProcStatStarttime(t *testing.T) {
	t.Parallel()

	// Build a /proc/<pid>/stat line with 52 fields, placing starttime at field 22.
	// Fields 1 and 2: pid, (comm). Then fields 3..22 are 20 items, so starttime
	// is the 20th token after the last ')'.
	makeStat := func(comm string, starttime uint64) string {
		s := "123 (" + comm + ")"
		// 20 tokens after the last ')', with the 20th being starttime.
		for i := 3; i <= 22; i++ {
			s += " "
			if i == 22 {
				s += formatUint(starttime)
			} else {
				s += "0"
			}
		}
		// Some trailing fields to make it look realistic.
		s += " 1 2 3\n"
		return s
	}

	cases := []struct {
		name string
		raw  string
		want uint64
	}{
		{name: "simple comm", raw: makeStat("cat", 67890), want: 67890},
		{name: "comm with space", raw: makeStat("foo bar", 12345), want: 12345},
		{name: "comm with parens", raw: makeStat("evil (name) with paren", 54321), want: 54321},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseProcStatStarttime([]byte(tc.raw))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestParseProcStatStarttimeErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
	}{
		{name: "missing paren", raw: "123 nope"},
		{name: "too few fields", raw: "123 (cat) S 1 2 3 4\n"},
		{name: "non-numeric starttime", raw: "123 (cat) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 bad\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseProcStatStarttime([]byte(tc.raw))
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

// formatUint avoids importing strconv in the test helper.
func formatUint(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for v > 0 {
		pos--
		buf[pos] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[pos:])
}
