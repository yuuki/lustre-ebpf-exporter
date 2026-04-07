package slurm

import "testing"

func TestParseSlurmJobIDFromCgroup(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		raw    string
		want   string
		wantOK bool
	}{
		{
			name:   "cgroup v1 classic",
			raw:    "11:memory:/slurm/uid_1000/job_42/step_batch/task_0\n4:freezer:/slurm/uid_1000/job_42/step_batch/task_0\n",
			want:   "42",
			wantOK: true,
		},
		{
			name:   "cgroup v2 systemd scope",
			raw:    "0::/system.slice/slurmstepd.scope/job_4242/step_extern\n",
			want:   "4242",
			wantOK: true,
		},
		{
			name:   "cgroup v2 slurm plugin",
			raw:    "0::/slurm/uid_1000/job_7/step_0\n",
			want:   "7",
			wantOK: true,
		},
		{
			name:   "job_ at end of line",
			raw:    "0::/slurm/uid_1000/job_99\n",
			want:   "99",
			wantOK: true,
		},
		{
			name: "no slurm",
			raw:  "0::/user.slice/user-1000.slice/session-1.scope\n",
		},
		{
			name: "malformed job_abc",
			raw:  "0::/slurm/uid_1000/job_abc/step_0\n",
		},
		{
			name: "empty input",
			raw:  "",
		},
		{
			name:   "multiple lines only one slurm",
			raw:    "12:devices:/user.slice\n11:memory:/slurm/uid_1000/job_12345/step_0\n",
			want:   "12345",
			wantOK: true,
		},
		{
			name: "job_ without leading slash should not match",
			raw:  "12:devices:job_123\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseSlurmJobIDFromCgroup([]byte(tc.raw))
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
