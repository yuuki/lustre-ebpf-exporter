package goexporter

import "testing"

func TestDetectLustreMountsFromText(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "single lustre mount",
			input: "10.0.0.1@tcp:/scratch /mnt/lustre lustre rw,seclabel 0 0\n",
			want:  []string{"/mnt/lustre"},
		},
		{
			name: "multiple lustre mounts",
			input: "10.0.0.1@tcp:/scratch /mnt/scratch lustre rw 0 0\n" +
				"10.0.0.2@tcp:/home /mnt/home lustre rw 0 0\n",
			want: []string{"/mnt/scratch", "/mnt/home"},
		},
		{
			name: "mixed filesystems",
			input: "sysfs /sys sysfs rw 0 0\n" +
				"10.0.0.1@tcp:/scratch /mnt/lustre lustre rw 0 0\n" +
				"/dev/sda1 / ext4 rw 0 0\n",
			want: []string{"/mnt/lustre"},
		},
		{
			name:  "no lustre mounts",
			input: "sysfs /sys sysfs rw 0 0\n/dev/sda1 / ext4 rw 0 0\n",
			want:  nil,
		},
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DetectLustreMountsFromText(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d mounts, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("mount[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
