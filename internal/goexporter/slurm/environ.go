package slurm

import "bytes"

// parseSlurmJobIDFromEnviron scans a NUL-separated /proc/<pid>/environ blob
// for SLURM_JOB_ID (preferred) or the legacy SLURM_JOBID. Empty values are
// treated as "not found".
func parseSlurmJobIDFromEnviron(raw []byte) (string, bool) {
	var legacy string
	var legacyFound bool

	for _, record := range bytes.Split(raw, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		eq := bytes.IndexByte(record, '=')
		if eq < 0 {
			continue
		}
		key := record[:eq]
		val := record[eq+1:]
		if len(val) == 0 {
			continue
		}
		switch string(key) {
		case "SLURM_JOB_ID":
			return string(val), true
		case "SLURM_JOBID":
			legacy = string(val)
			legacyFound = true
		}
	}
	if legacyFound {
		return legacy, true
	}
	return "", false
}
