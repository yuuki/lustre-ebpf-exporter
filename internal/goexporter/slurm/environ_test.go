package slurm

import "testing"

func TestParseSlurmJobIDFromEnviron(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		raw     string
		want    string
		wantOK  bool
	}{
		{
			name: "empty",
			raw:  "",
		},
		{
			name:   "slurm_job_id present",
			raw:    "FOO=bar\x00SLURM_JOB_ID=12345\x00BAZ=qux\x00",
			want:   "12345",
			wantOK: true,
		},
		{
			name:   "legacy slurm_jobid",
			raw:    "FOO=bar\x00SLURM_JOBID=999\x00",
			want:   "999",
			wantOK: true,
		},
		{
			name: "slurm_job_id empty value",
			raw:  "SLURM_JOB_ID=\x00",
		},
		{
			name:   "no trailing nul",
			raw:    "FOO=bar\x00SLURM_JOB_ID=42",
			want:   "42",
			wantOK: true,
		},
		{
			name: "prefix collision",
			raw:  "SLURM_JOB_IDX=nope\x00",
		},
		{
			name: "no slurm var",
			raw:  "PATH=/usr/bin\x00HOME=/root\x00",
		},
		{
			name:   "slurm_job_id wins over legacy",
			raw:    "SLURM_JOBID=999\x00SLURM_JOB_ID=42\x00",
			want:   "42",
			wantOK: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseSlurmJobIDFromEnviron([]byte(tc.raw))
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
