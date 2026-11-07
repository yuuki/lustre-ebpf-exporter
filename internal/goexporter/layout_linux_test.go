//go:build linux

package goexporter

import (
	"reflect"
	"testing"

	"github.com/cilium/ebpf/btf"

	"github.com/yuuki/lustre-ebpf-exporter/internal/bpf"
)

// TestBPFMapLayoutsMatchBTF checks the Go mirrors of the map keys and values
// against the BTF that clang emitted into the embedded object, the layout the
// kernel actually uses. It parses the object only, so it needs no privileges.
// (struct observer_event never appears in a map, so it has no BTF; the source
// check in TestBPFStructLayoutsMatchSource covers it.)
func TestBPFMapLayoutsMatchBTF(t *testing.T) {
	t.Parallel()

	spec, err := bpf.LoadCollectionSpec()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mapName string
		key     reflect.Type
		value   reflect.Type
	}{
		{"config_map", reflect.TypeFor[bpfMountKey](), reflect.TypeFor[uint8]()},
		{"llite_counters", reflect.TypeFor[bpfAggKey](), reflect.TypeFor[bpfCounterVal]()},
		{"rpc_counters", reflect.TypeFor[bpfAggKey](), reflect.TypeFor[bpfCounterVal]()},
		{"llite_error_counters", reflect.TypeFor[bpfErrorAggKey](), reflect.TypeFor[bpfErrorCounterVal]()},
		{"rpc_error_counters", reflect.TypeFor[bpfErrorAggKey](), reflect.TypeFor[bpfErrorCounterVal]()},
	} {
		t.Run(tc.mapName, func(t *testing.T) {
			m, ok := spec.Maps[tc.mapName]
			if !ok {
				t.Fatalf("map %s not in the embedded object", tc.mapName)
			}
			checkBTFLayout(t, m.Key, tc.key)
			checkBTFLayout(t, m.Value, tc.value)
		})
	}
}

// checkBTFLayout fails unless goType has the size of typ and, for a struct,
// one field per member at the member's offset and size.
func checkBTFLayout(t *testing.T, typ btf.Type, goType reflect.Type) {
	t.Helper()
	size, err := btf.Sizeof(typ)
	if err != nil {
		t.Fatal(err)
	}
	if int(goType.Size()) != size {
		t.Fatalf("%s is %d bytes, BTF %s %d", goType, goType.Size(), typ, size)
	}
	s, ok := btf.UnderlyingType(typ).(*btf.Struct)
	if !ok {
		return
	}
	if goType.NumField() != len(s.Members) {
		t.Fatalf("%s has %d fields, BTF %s %d members", goType, goType.NumField(), s.Name, len(s.Members))
	}
	for i, member := range s.Members {
		f := goType.Field(i)
		memberSize, err := btf.Sizeof(member.Type)
		if err != nil {
			t.Fatal(err)
		}
		if int(f.Offset) != int(member.Offset.Bytes()) || int(f.Type.Size()) != memberSize {
			t.Errorf("%s.%s at offset %d size %d, BTF %s.%s at offset %d size %d",
				goType.Name(), f.Name, f.Offset, f.Type.Size(), s.Name, member.Name, member.Offset.Bytes(), memberSize)
		}
	}
}
