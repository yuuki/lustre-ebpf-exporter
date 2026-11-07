package goexporter

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
)

func ResolveMountInfo(mountPath string) (MountInfo, error) {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return MountInfo{}, err
	}
	return ResolveMountInfoFromText(mountPath, string(data), filepath.EvalSymlinks, os.Stat)
}

// DetectLustreMounts scans /proc/mounts and returns the paths of all
// currently mounted Lustre filesystems.
func DetectLustreMounts() ([]string, error) {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return nil, err
	}
	return DetectLustreMountsFromText(string(data))
}

// DetectLustreMountsFromText parses mount table text and returns paths of
// all Lustre mounts. Exported for testing.
func DetectLustreMountsFromText(mountsText string) ([]string, error) {
	var paths []string
	scanner := bufio.NewScanner(strings.NewReader(mountsText))
	for scanner.Scan() {
		fields := mountFields(scanner.Text())
		if len(fields) < 3 || fields[2] != "lustre" {
			continue
		}
		paths = append(paths, unescapeMountField(fields[1]))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return paths, nil
}

func ResolveMountInfoFromText(
	mountPath string,
	mountsText string,
	realpathFn func(string) (string, error),
	statFn func(string) (os.FileInfo, error),
) (MountInfo, error) {
	resolvedMount, err := realpathFn(mountPath)
	if err != nil {
		return MountInfo{}, err
	}

	scanner := bufio.NewScanner(strings.NewReader(mountsText))
	for scanner.Scan() {
		fields := mountFields(scanner.Text())
		if len(fields) < 3 || fields[2] != "lustre" {
			continue
		}
		resolvedCandidate, err := realpathFn(unescapeMountField(fields[1]))
		if err != nil {
			return MountInfo{}, err
		}
		if resolvedCandidate != resolvedMount {
			continue
		}
		info, err := statFn(resolvedCandidate)
		if err != nil {
			return MountInfo{}, err
		}
		statT, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return MountInfo{}, fmt.Errorf("unexpected stat type for %s", resolvedCandidate)
		}
		source := unescapeMountField(fields[0])
		dev := uint64(statT.Dev) //nolint:unconvert // Stat_t.Dev is not uint64 everywhere (int32 on darwin)
		return MountInfo{
			Source: source,
			Path:   resolvedCandidate,
			FSName: deriveFSName(source),
			Major:  unixMajor(dev),
			Minor:  unixMinor(dev),
		}, nil
	}
	if err := scanner.Err(); err != nil {
		return MountInfo{}, err
	}
	return MountInfo{}, fmt.Errorf("mount path is not a lustre mount: %s", mountPath)
}

// mountFields splits a /proc/mounts line into its fields. The kernel separates
// them with a space and escapes the spaces, tabs, newlines and backslashes in
// a field, but no other whitespace: strings.Fields would also split a mount
// point at, say, a no-break space.
func mountFields(line string) []string {
	return strings.FieldsFunc(line, func(r rune) bool { return r == ' ' })
}

// unescapeMountField undoes the octal escapes that the kernel writes for a
// space, tab, newline or backslash in the device and mount point fields of
// /proc/mounts (\040, \011, \012, \134), so that a mount point such as
// "/mnt/my lustre" resolves to its real path.
func unescapeMountField(field string) string {
	if !strings.Contains(field, `\`) {
		return field
	}
	var b strings.Builder
	b.Grow(len(field))
	for i := 0; i < len(field); i++ {
		if c, ok := octalEscape(field[i:]); ok {
			b.WriteByte(c)
			i += 3
			continue
		}
		b.WriteByte(field[i])
	}
	return b.String()
}

// octalEscape decodes the \ooo escape (\000 to \377) at the start of s.
func octalEscape(s string) (byte, bool) {
	if len(s) < 4 || s[0] != '\\' || s[1] < '0' || s[1] > '3' {
		return 0, false
	}
	c := s[1] - '0'
	for _, d := range []byte(s[2:4]) {
		if d < '0' || d > '7' {
			return 0, false
		}
		c = c<<3 | (d - '0')
	}
	return c, true
}

func deriveFSName(source string) string {
	parts := strings.SplitN(source, ":", 2)
	if len(parts) != 2 {
		return "lustre"
	}
	name := path.Base(parts[1])
	if name == "." || name == "/" || name == "" {
		return "lustre"
	}
	return name
}

// unixMajor and unixMinor split the device number that stat(2) reports (the
// kernel's new_encode_dev: 12-bit major, 20-bit minor), which the masks keep
// within 32 bits.
func unixMajor(dev uint64) uint32 {
	return uint32((dev >> 8) & 0xfff)
}

func unixMinor(dev uint64) uint32 {
	return uint32((dev & 0xff) | ((dev >> 12) & 0xffffff00)) //nolint:gosec // G115: both operands are masked to 32 bits
}
