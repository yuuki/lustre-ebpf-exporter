//go:build linux

package goexporter

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/goleak"

	"github.com/yuuki/lustre-ebpf-exporter/internal/bpf"
)

// newEmbeddedMap creates the named map of the embedded object, so that the
// kernel checks the Go keys and values against its real key and value sizes.
func newEmbeddedMap(t *testing.T, spec *ebpf.CollectionSpec, name string) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(spec.Maps[name])
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

// putPerCPU stores values spread over the first CPUs, as the BPF program's
// per-CPU increments leave them.
func putPerCPU[V any](t *testing.T, m *ebpf.Map, key any, perCPU ...V) {
	t.Helper()
	values := make([]V, ebpf.MustPossibleCPU())
	copy(values, perCPU)
	if err := m.Put(key, values); err != nil {
		t.Fatal(err)
	}
}

func aggKey(op, intent uint8, comm string) bpfAggKey {
	key := bpfAggKey{UID: 1001, Op: op, MountIdx: 0, ActorType: rawActorUser, Intent: intent}
	copy(key.Comm[:], comm)
	return key
}

// TestBPFCounterCollectorDrainsEmbeddedMaps fills the counter maps of the
// embedded object the way the BPF program does, including a comm that is not
// UTF-8, and checks that the drain goroutine sums them per CPU, empties the
// maps, keeps accumulating, drains once more when cancelled and then ends, and
// that every scrape succeeds. It needs the privileges that loading the object
// does, so it runs in the privileged CI step.
func TestBPFCounterCollectorDrainsEmbeddedMaps(t *testing.T) {
	requireEmbeddedObject(t)
	ignore := goleak.IgnoreCurrent()
	spec, err := bpf.LoadCollectionSpec()
	if err != nil {
		t.Fatal(err)
	}
	llite := newEmbeddedMap(t, spec, "llite_counters")
	rpc := newEmbeddedMap(t, spec, "rpc_counters")
	lliteErrors := newEmbeddedMap(t, spec, "llite_error_counters")
	rpcErrors := newEmbeddedMap(t, spec, "rpc_error_counters")

	fill := func() {
		readKey := aggKey(rawOpRead, rawIntentDataRead, "dd")
		putPerCPU(t, llite, &readKey, bpfCounterVal{OpsCount: 2, BytesSum: 100}, bpfCounterVal{OpsCount: 1, BytesSum: 50})
		evilKey := aggKey(rawOpLookup, rawIntentNamespaceRead, "\xffevil")
		putPerCPU(t, llite, &evilKey, bpfCounterVal{OpsCount: 1})
		waitKey := aggKey(rawOpQueueWait, rawIntentUnknown, "dd")
		putPerCPU(t, rpc, &waitKey, bpfCounterVal{OpsCount: 4})
		errKey := bpfErrorAggKey{UID: 1001, Op: rawOpOpen, Intent: rawIntentNamespaceRead, Reason: rawErrnoClassPerm}
		copy(errKey.Comm[:], "dd")
		putPerCPU(t, lliteErrors, &errKey, bpfErrorCounterVal{OpsCount: 1}, bpfErrorCounterVal{OpsCount: 1})
		rpcErrKey := bpfErrorAggKey{UID: 1001, ActorType: rawActorClientWorker, Intent: rawIntentUnknown, Reason: rawRPCEventResend}
		copy(rpcErrKey.Comm[:], "ptlrpcd_00_01")
		putPerCPU(t, rpcErrors, &rpcErrKey, bpfErrorCounterVal{OpsCount: 3})
	}
	c := NewBPFCounterCollector(llite, rpc, lliteErrors, rpcErrors,
		[]MountInfo{{Path: "/mnt/lustre", FSName: "fs"}}, testResolver(), testSlurmResolver(), NewProcessFilter(nil, false), false, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.StartDrain(ctx, time.Hour)

	fill()
	c.DrainOnce()
	for _, m := range []*ebpf.Map{llite, rpc, lliteErrors, rpcErrors} {
		if key, err := m.NextKeyBytes(nil); err != nil || key != nil {
			t.Fatalf("%v not emptied by the drain: next key %x, %v", m, key, err)
		}
	}
	fill()
	cancel() // the goroutine drains once more on its way out
	goleak.VerifyNone(t, ignore)

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got, err := gatherToText(families)
	if err != nil {
		t.Fatal(err)
	}
	const user = `uid="1001",username="testuser"`
	const mount = `fs="fs",mount="/mnt/lustre"`
	want := strings.Join([]string{
		"# HELP lustre_client_access_operations_total Aggregated llite access operation count",
		"# TYPE lustre_client_access_operations_total counter",
		`lustre_client_access_operations_total{access_intent="data_read",actor_type="user",` + mount + `,op="read",process="dd",` + user + `} 6`,
		`lustre_client_access_operations_total{access_intent="namespace_read",actor_type="user",` + mount + `,op="lookup",process="` + "\uFFFD" + `evil",` + user + `} 2`,
		"# HELP lustre_client_data_bytes_total Aggregated llite data volume in bytes",
		"# TYPE lustre_client_data_bytes_total counter",
		`lustre_client_data_bytes_total{access_intent="data_read",actor_type="user",` + mount + `,op="read",process="dd",` + user + `} 300`,
		"# HELP lustre_client_operation_errors_total Aggregated llite operation error count by errno class",
		"# TYPE lustre_client_operation_errors_total counter",
		`lustre_client_operation_errors_total{access_intent="namespace_read",actor_type="user",errno_class="perm",` + mount + `,op="open",process="dd",` + user + `} 4`,
		"# HELP lustre_client_rpc_errors_total Aggregated ptlrpc error/recovery event count",
		"# TYPE lustre_client_rpc_errors_total counter",
		`lustre_client_rpc_errors_total{actor_type="client_worker",event="resend",` + mount + `,process="ptlrpcd_00_01",` + user + `} 6`,
		"# HELP lustre_client_rpc_wait_operations_total Aggregated ptlrpc queue wait count",
		"# TYPE lustre_client_rpc_wait_operations_total counter",
		`lustre_client_rpc_wait_operations_total{actor_type="user",` + mount + `,op="queue_wait",process="dd",` + user + `} 8`,
	}, "\n") + "\n"
	if got != want {
		t.Fatalf("metrics:\n%s\nwant:\n%s", got, want)
	}
}
