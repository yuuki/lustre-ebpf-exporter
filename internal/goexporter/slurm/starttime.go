package slurm

import (
	"bytes"
	"fmt"
	"strconv"
)

// parseProcStatStarttime returns field 22 (starttime in clock ticks) from a
// /proc/<pid>/stat blob. The comm field (field 2) may contain spaces and
// parentheses, so we split on the last ')' to find the remaining fields.
//
// Layout (1-indexed):
//
//	1: pid
//	2: (comm)
//	3: state
//	... (fields 4..21)
//	22: starttime
//
// Post-')' tokens correspond to fields 3..N, so starttime is index 19.
func parseProcStatStarttime(raw []byte) (uint64, error) {
	lastParen := bytes.LastIndexByte(raw, ')')
	if lastParen < 0 {
		return 0, fmt.Errorf("slurm: /proc/<pid>/stat missing ')'")
	}
	rest := raw[lastParen+1:]
	fields := bytes.Fields(rest)
	// Field 22 is index 19 in post-')' tokens (fields 3..22 are 20 items).
	const starttimeIndex = 19
	if len(fields) <= starttimeIndex {
		return 0, fmt.Errorf("slurm: /proc/<pid>/stat has only %d post-comm fields", len(fields))
	}
	v, err := strconv.ParseUint(string(fields[starttimeIndex]), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("slurm: parse starttime: %w", err)
	}
	return v, nil
}
