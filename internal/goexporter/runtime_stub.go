//go:build !linux

package goexporter

import (
	"context"
	"fmt"

	"github.com/cilium/ebpf"
)

// Compile-time interface check.
var _ EventSource = (*stubEventSource)(nil)

type stubEventSource struct{}

func newEventSource(ctx context.Context, cfg Config, mountInfos []MountInfo) (EventSource, error) {
	_, _, _ = ctx, cfg, mountInfos
	return nil, fmt.Errorf("lustre-ebpf-exporter Go exporter is supported on linux only")
}

func (s *stubEventSource) Events() <-chan Event                    { return nil }
func (s *stubEventSource) CounterMaps() (llite, rpc *ebpf.Map)    { return nil, nil }
func (s *stubEventSource) Close() error                           { return nil }
