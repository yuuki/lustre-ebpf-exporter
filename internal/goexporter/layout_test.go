package goexporter

import (
	"encoding/binary"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// rawObserverEvent mirrors struct observer_event of the BPF program field for
// field, with the padding the C compiler inserts written out, so that
// encoding/binary reads and writes exactly the bytes the perf buffer carries.
// TestBPFStructLayoutsMatchSource checks it against the C definition; the fuzz
// targets use it as a decoder independent of parseObserverEvent.
type rawObserverEvent struct {
	Plane      uint8
	Op         uint8
	ErrnoClass uint8
	Pad        [5]byte
	UID        uint32
	PID        uint32
	MountIdx   uint32
	_          [4]byte // C pads duration_us to 8-byte alignment
	DurationUS uint64
	SizeBytes  uint64
	RequestPtr uint64
	Comm       [16]byte
}

// cField is one member of a C struct, at the offset natural alignment gives it.
type cField struct {
	name   string
	offset int
	size   int
}

var (
	cDefineRe = regexp.MustCompile(`(?m)^#define ([A-Z0-9_]+) ([0-9]+)$`)
	cMemberRe = regexp.MustCompile(`^(__u8|__u32|__u64|char)\s+([a-z_]+)(?:\[([A-Z0-9_]+)\])?;$`)
)

// parseCStruct returns the members and size of `struct name` in the BPF
// source. It understands the scalar types the shared structs use and lays them
// out with natural alignment, as clang does for the bpfel target without
// packing attributes (the source has none).
func parseCStruct(t *testing.T, source, name string) ([]cField, int) {
	t.Helper()
	defines := map[string]int{}
	for _, m := range cDefineRe.FindAllStringSubmatch(source, -1) {
		v, err := strconv.Atoi(m[2])
		if err != nil {
			t.Fatalf("parse #define %s: %v", m[1], err)
		}
		defines[m[1]] = v
	}
	body := regexp.MustCompile(`(?s)\nstruct ` + name + ` \{\n(.*?)\n\};`).FindStringSubmatch(source)
	if body == nil {
		t.Fatalf("struct %s not found in the BPF source", name)
	}
	scalarSize := map[string]int{"__u8": 1, "char": 1, "__u32": 4, "__u64": 8}
	var fields []cField
	offset, maxAlign := 0, 1
	for _, line := range strings.Split(body[1], "\n") {
		m := cMemberRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			t.Fatalf("struct %s: unsupported member %q", name, line)
		}
		align := scalarSize[m[1]]
		count := 1
		if m[3] != "" {
			n, err := strconv.Atoi(m[3])
			if err != nil {
				var ok bool
				if n, ok = defines[m[3]]; !ok {
					t.Fatalf("struct %s: unknown array length %s", name, m[3])
				}
			}
			count = n
		}
		offset = (offset + align - 1) / align * align
		fields = append(fields, cField{name: m[2], offset: offset, size: align * count})
		offset += align * count
		maxAlign = max(maxAlign, align)
	}
	return fields, (offset + maxAlign - 1) / maxAlign * maxAlign
}

// checkGoLayout fails unless the named fields of goType sit at the offsets and
// sizes of cFields, in order, and the type has the C size with no implicit
// padding (encoding/binary, which cilium/ebpf falls back to, writes none).
func checkGoLayout(t *testing.T, goType reflect.Type, cFields []cField, cSize int) {
	t.Helper()
	var named []reflect.StructField
	for i := range goType.NumField() {
		if f := goType.Field(i); f.Name != "_" {
			named = append(named, f)
		}
	}
	if len(named) != len(cFields) {
		t.Fatalf("%s has %d fields, the C struct %d", goType.Name(), len(named), len(cFields))
	}
	for i, f := range named {
		c := cFields[i]
		if int(f.Offset) != c.offset || int(f.Type.Size()) != c.size {
			t.Errorf("%s.%s at offset %d size %d, C %s at offset %d size %d",
				goType.Name(), f.Name, f.Offset, f.Type.Size(), c.name, c.offset, c.size)
		}
	}
	if int(goType.Size()) != cSize {
		t.Errorf("%s is %d bytes, the C struct %d", goType.Name(), goType.Size(), cSize)
	}
	if n := binary.Size(reflect.New(goType).Interface()); n != cSize {
		t.Errorf("%s encodes to %d bytes, the C struct is %d", goType.Name(), n, cSize)
	}
}

// TestBPFStructLayoutsMatchSource pins the binary contract between the BPF
// program and its Go decoders: the perf event that parseObserverEvent reads
// and the counter map keys and values that the drain path iterates.
func TestBPFStructLayoutsMatchSource(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("../bpf/lustre_ebpf_exporter.bpf.c")
	if err != nil {
		t.Fatalf("read BPF source: %v", err)
	}
	source := string(raw)
	for _, tc := range []struct {
		cName  string
		goType reflect.Type
	}{
		{"observer_event", reflect.TypeFor[rawObserverEvent]()},
		{"agg_key", reflect.TypeFor[bpfAggKey]()},
		{"counter_val", reflect.TypeFor[bpfCounterVal]()},
		{"error_agg_key", reflect.TypeFor[bpfErrorAggKey]()},
		{"error_counter_val", reflect.TypeFor[bpfErrorCounterVal]()},
	} {
		t.Run(tc.cName, func(t *testing.T) {
			fields, size := parseCStruct(t, source, tc.cName)
			checkGoLayout(t, tc.goType, fields, size)
		})
	}

	// parseObserverEvent decodes with literal offsets; they must be the
	// struct's.
	fields, size := parseCStruct(t, source, "observer_event")
	if size != 64 {
		t.Fatalf("observer_event is %d bytes, parseObserverEvent expects 64", size)
	}
	want := map[string][2]int{ // offset, size as read by parseObserverEvent
		"plane": {0, 1}, "op": {1, 1}, "errno_class": {2, 1},
		"uid": {8, 4}, "pid": {12, 4}, "mount_idx": {16, 4},
		"duration_us": {24, 8}, "size_bytes": {32, 8}, "request_ptr": {40, 8},
		"comm": {48, 16},
	}
	for _, f := range fields {
		w, ok := want[f.name]
		if !ok {
			continue
		}
		delete(want, f.name)
		if w[0] != f.offset || w[1] != f.size {
			t.Errorf("observer_event.%s at offset %d size %d, parseObserverEvent reads offset %d size %d",
				f.name, f.offset, f.size, w[0], w[1])
		}
	}
	for name := range want {
		t.Errorf("observer_event has no member %s, which parseObserverEvent reads", name)
	}
}
