package slurm

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzParseSlurmJobIDFromEnviron compares the parser of /proc/<pid>/environ,
// which any process controls, with a simple model: the first non-empty
// SLURM_JOB_ID, else the last non-empty SLURM_JOBID, as a valid label value.
func FuzzParseSlurmJobIDFromEnviron(f *testing.F) {
	f.Add([]byte("FOO=bar\x00SLURM_JOB_ID=12345\x00BAZ=qux\x00"))
	f.Add([]byte("SLURM_JOBID=1\x00SLURM_JOBID=2\x00SLURM_JOB_ID=\x00"))
	f.Add([]byte("SLURM_JOB_ID=4\xff2\x00SLURM_JOB_ID=7"))
	f.Add([]byte("SLURM_JOB_ID==\x00=SLURM_JOB_ID\x00"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		var want, legacy string
		for record := range bytes.SplitSeq(raw, []byte{0}) {
			key, val, ok := bytes.Cut(record, []byte("="))
			if !ok || len(val) == 0 {
				continue
			}
			if string(key) == "SLURM_JOB_ID" && want == "" {
				want = string(val)
			}
			if string(key) == "SLURM_JOBID" {
				legacy = string(val)
			}
		}
		if want == "" {
			want = legacy
		}
		want = strings.ToValidUTF8(want, "�")

		got, ok := parseSlurmJobIDFromEnviron(raw)
		if got != want || ok != (want != "") {
			t.Fatalf("parse = %q, %v, want %q", got, ok, want)
		}
		if !utf8.ValidString(got) || strings.ContainsRune(got, 0) {
			t.Fatalf("job id %q is not a valid label value", got)
		}
	})
}

// FuzzParseSlurmJobIDFromCgroup checks that a job id read from
// /proc/<pid>/cgroup is always a run of ASCII digits.
func FuzzParseSlurmJobIDFromCgroup(f *testing.F) {
	f.Add([]byte("0::/system.slice/slurmstepd.scope/job_12345/step_0/user/task_0\n"))
	f.Add([]byte("4:memory:/slurm/uid_1000/job_42/step_batch\n1:name=systemd:/user.slice\n"))
	f.Add([]byte("0::/job_/job_x/notjob_1/job_7"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, ok := parseSlurmJobIDFromCgroup(raw)
		if ok != (got != "") {
			t.Fatalf("parse = %q, %v", got, ok)
		}
		for _, c := range []byte(got) {
			if c < '0' || c > '9' {
				t.Fatalf("job id %q is not numeric", got)
			}
		}
		if ok && !bytes.Contains(raw, []byte("job_"+got)) {
			t.Fatalf("job id %q not in the input", got)
		}
	})
}

// FuzzParseProcStatStarttime builds /proc/<pid>/stat lines around an arbitrary
// comm, which may contain spaces and parentheses, and checks that field 22 is
// read back; arbitrary input must not panic.
func FuzzParseProcStatStarttime(f *testing.F) {
	f.Add([]byte("bash"), uint64(12345), []byte("1 (t) S 0"))
	f.Add([]byte("a) R (b"), uint64(1)<<63, []byte(")))"))
	f.Add([]byte("tmux: server"), uint64(0), []byte("1 (x) "+strings.Repeat("9 ", 25)))
	f.Fuzz(func(t *testing.T, comm []byte, starttime uint64, arbitrary []byte) {
		_, _ = ParseProcStatStarttime(arbitrary)

		if len(comm) > 64 || bytes.IndexByte(comm, 0) >= 0 {
			return // the kernel prints at most TASK_COMM_LEN-1 bytes, never a NUL
		}
		fields := make([]string, 0, 20)
		for i := 3; i <= 22; i++ {
			v := strconv.Itoa(i)
			if i == 3 {
				v = "S"
			}
			if i == 22 {
				v = strconv.FormatUint(starttime, 10)
			}
			fields = append(fields, v)
		}
		line := "4242 (" + string(comm) + ") " + strings.Join(fields, " ") + " 0 0 0\n"
		got, err := ParseProcStatStarttime([]byte(line))
		if err != nil || got != starttime {
			t.Fatalf("ParseProcStatStarttime(%q) = %d, %v, want %d", line, got, err, starttime)
		}
	})
}
