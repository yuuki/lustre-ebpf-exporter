# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Lustre eBPF exporter — eBPF-backed Prometheus exporter that measures Lustre client activity (llite + PtlRPC) per-user/per-process on the client node. Two implementations coexist: a preferred Go CO-RE exporter and a legacy Python + bpftrace fallback.

## Build Commands

```bash
# Go exporter — Linux artifact build via Docker (recommended)
make docker-build-go-exporter

# Go exporter — native build (requires Linux with clang)
make generate-go-exporter   # BPF codegen via bpf2go
make build-go-exporter      # compile Go binary
make stage-go-exporter      # copy BPF .o to dist/

# Go unit tests (platform-independent logic only; BPF runtime is Linux-only)
go test ./...

# Run a single Go test
go test ./internal/goexporter -run TestAggregatorCollectsExpectedMetrics

# Python tests
pytest tests/test_observer_agent.py -q

# Lima E2E (requires full Lima Lustre environment)
bash ./e2e/lima/scripts/verify-observer-go.sh    # Go exporter
bash ./e2e/lima/scripts/verify-observer.sh        # legacy Python
```

## Architecture

### Observation Model (shared by both implementations)

Two planes of observation with identical semantic contracts:

1. **llite** — user-facing workload plane: kprobes on `ll_lookup_nd`, `ll_file_open`, `ll_file_read_iter`, `ll_file_write_iter`, `ll_fsync`. Classified as `metadata` or `data` ops.
2. **PtlRPC** — client-internal impact plane: optional kprobes on `ptlrpc_queue_wait`, `ptlrpc_send_new_req`, `__ptlrpc_free_req`. Degrades gracefully when probes are missing.

Actors are classified as `user`, `worker` (ptlrpcd\_\*), or `daemon`.

### Go Exporter (`cmd/` + `internal/goexporter/`)

Pipeline: **BPF perf events → Event parsing → Aggregator → PrometheusExporter**

- `internal/bpf/lustre_ebpf_exporter.bpf.c` — CO-RE BPF program. Events are 64-byte `observer_event` structs sent via perf buffer. Mount filtering is done kernel-side via `config_map`.
- `internal/goexporter/runtime_linux.go` — `linuxEventSource` loads the BPF collection, attaches kprobes (required + optional), reads perf events. Uses `loadCollectionWithOptionalPrograms` to retry without optional programs on load failure.
- `internal/goexporter/runtime_stub.go` — non-Linux build stub (returns error).
- `internal/goexporter/types.go` — `Event`, `AggregatedMetric`, raw event parsing. The 64-byte binary layout must stay in sync with the BPF C struct.
- `internal/goexporter/aggregate.go` — `Aggregator` consumes events, builds counters/histograms keyed by NUL-delimited metric name + sorted attributes.
- `internal/goexporter/prometheus.go` — maps internal OTel-style metric names (`lustre.client.access.operations`) to Prometheus families (`lustre_client_access_operations_total`).
- `internal/goexporter/mount.go` — resolves Lustre mount path to device major/minor via `/proc/mounts`.
- `internal/goexporter/runtime.go` — `Run()` orchestrates the tick-aggregate-export loop.

### Legacy Python Exporter (`lustre_client_observer/agent.py`)

Generates a bpftrace script at runtime, parses tab-delimited `EVENT` lines from stdout, aggregates windows, exports to Prometheus and/or OTLP. Entry via `tools/lustre_client_trace.sh`.

### Key Invariants

- The BPF event struct layout (64 bytes) and op/plane codes must match between `lustre_ebpf_exporter.bpf.c` and `types.go`.
- Metric attribute keys use OTel conventions internally (`user.id`, `process.name`, `lustre.actor.type`), mapped to Prometheus label names at export time.
- Label cardinality is constrained by design: no pid, path, or request pointer in exported labels.

## Commit Style

Short, scoped subjects: `fix: ...`, `build: ...`, `chore: ...`, `docs: ...`.
