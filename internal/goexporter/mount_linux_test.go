//go:build linux

package goexporter

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// mangleMountField escapes s the way the kernel writes the device and mount
// point fields of /proc/mounts (seq_escape with " \t\n\\").
func mangleMountField(s string) string {
	var b strings.Builder
	for i := range len(s) {
		switch c := s[i]; c {
		case ' ', '\t', '\n', '\\':
			fmt.Fprintf(&b, `\%03o`, c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// FuzzMountTable writes a Lustre mount between other mounts into a mount table
// as the kernel does and checks that it is detected and resolved with its own
// device and path, whatever bytes they contain.
func FuzzMountTable(f *testing.F) {
	f.Add("10.0.0.1@tcp:/scratch", "/mnt/lustre", uint64(424242))
	f.Add("10.0.0.1@tcp:/fs1/home", "/mnt/my lustre", uint64(0x0001_0000))
	f.Add(`mgs@o2ib:/fs\x`, "/mnt/tab\there/new\nline", uint64(0x4f_ff))
	f.Add(`10.0.0.1@tcp:/a\040b`, `/mnt/back\slash\134`, uint64(0xfff_fff00))
	f.Add("10.0.0.1@tcp:/scratch", "/mnt/caf\xc3\xa9", uint64(1))

	f.Fuzz(func(t *testing.T, device, mountPath string, dev uint64) {
		// Kernel strings have no NUL; paths are absolute and fit in PATH_MAX.
		if device == "" || mountPath == "" || mountPath[0] != '/' ||
			strings.ContainsRune(device, 0) || strings.ContainsRune(mountPath, 0) ||
			len(device) > 4096 || len(mountPath) > 4096 {
			t.Skip()
		}
		table := "sysfs /sys sysfs rw 0 0\n" +
			mangleMountField(device) + " " + mangleMountField(mountPath) + " lustre rw,flock 0 0\n" +
			"10.0.0.9@tcp:/other /mnt/other\\040fs lustre rw 0 0\n"

		paths, err := DetectLustreMountsFromText(table)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{mountPath, "/mnt/other fs"}; !slices.Equal(paths, want) {
			t.Fatalf("detected %q, want %q", paths, want)
		}

		info, err := ResolveMountInfoFromText(mountPath, table,
			func(p string) (string, error) { return p, nil },
			func(p string) (os.FileInfo, error) {
				if p != mountPath {
					t.Fatalf("stat %q, want %q", p, mountPath)
				}
				return fakeFileInfo{sys: &syscall.Stat_t{Dev: dev}}, nil
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		want := MountInfo{
			Source: device, Path: mountPath, FSName: deriveFSName(device),
			Major: uint32((dev >> 8) & 0xfff), Minor: uint32((dev & 0xff) | ((dev >> 12) & 0xffffff00)),
		}
		if info != want {
			t.Fatalf("resolved %+v, want %+v", info, want)
		}
		if info.FSName == "" {
			t.Fatal("empty fs name")
		}
	})
}
