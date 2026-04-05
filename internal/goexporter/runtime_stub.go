//go:build !linux

package goexporter

import (
	"context"
	"fmt"
)

func newEventSource(ctx context.Context, cfg Config, mountInfo MountInfo) (EventSource, error) {
	_, _, _ = ctx, cfg, mountInfo
	return nil, fmt.Errorf("lustre-ebpf-exporter Go exporter is supported on linux only")
}
