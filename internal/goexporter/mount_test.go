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
		{
			// The kernel escapes space, tab, newline and backslash in the
			// device and mount point fields as octal; a bare backslash that
			// starts no such escape is kept.
			name: "escaped mount points",
			input: "10.0.0.1@tcp:/scratch /mnt/my\\040lustre lustre rw 0 0\n" +
				"10.0.0.1@tcp:/home /mnt/a\\011b\\012c\\134d lustre rw 0 0\n" +
				"10.0.0.1@tcp:/data /mnt/x\\9\\04 lustre rw 0 0\n",
			want: []string{"/mnt/my lustre", "/mnt/a\tb\nc\\d", "/mnt/x\\9\\04"},
		},
		{
			// Whitespace that the kernel does not escape is part of the field.
			name:  "unescaped whitespace in a mount point",
			input: "10.0.0.1@tcp:/scratch /mnt/no\u00a0break\vtab lustre rw 0 0\n",
			want:  []string{"/mnt/no\u00a0break\vtab"},
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
