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
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || fields[2] != "lustre" {
			continue
		}
		resolvedCandidate, err := realpathFn(fields[1])
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
		fsName := deriveFSName(fields[0])
		return MountInfo{
			Source: fields[0],
			Path:   resolvedCandidate,
			FSName: fsName,
			Major:  uint32(unixMajor(uint64(statT.Dev))),
			Minor:  uint32(unixMinor(uint64(statT.Dev))),
		}, nil
	}
	if err := scanner.Err(); err != nil {
		return MountInfo{}, err
	}
	return MountInfo{}, fmt.Errorf("mount path is not a lustre mount: %s", mountPath)
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

func unixMajor(dev uint64) uint64 {
	return (dev >> 8) & 0xfff
}

func unixMinor(dev uint64) uint64 {
	return (dev & 0xff) | ((dev >> 12) & 0xffffff00)
}
