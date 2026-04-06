//go:build linux

package bpf

import "github.com/cilium/ebpf"

// LoadCollectionSpec returns the CollectionSpec from the embedded BPF object.
func LoadCollectionSpec() (*ebpf.CollectionSpec, error) {
	return loadLustreebpfexporter()
}
