package slurm

import (
	"bytes"
	"regexp"
)

// jobPathRe matches /job_<digits>/ or /job_<digits>$ inside a cgroup path
// to cover cgroup v1 (/slurm/uid_N/job_N/step_...) and cgroup v2
// (/system.slice/slurmstepd.scope/job_N/step_...).
var jobPathRe = regexp.MustCompile(`(?:^|/)job_(\d+)(?:/|$)`)

// parseSlurmJobIDFromCgroup scans /proc/<pid>/cgroup content line by line
// and returns the first Slurm job id it finds. Lines without a slurm path
// are skipped.
func parseSlurmJobIDFromCgroup(raw []byte) (string, bool) {
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		m := jobPathRe.FindSubmatch(line)
		if m != nil {
			return string(m[1]), true
		}
	}
	return "", false
}
