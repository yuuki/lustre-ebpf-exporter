# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Lustre eBPF exporter — eBPF-backed Prometheus exporter that measures Lustre client activity (llite + PtlRPC) per-user/per-process on the client node. Two implementations coexist: a **first-class** Go CO-RE exporter under `cmd/`/`internal/`, and a **second-class** legacy Python + bpftrace fallback, now confined to `legacy/`.

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
go test ./internal/goexporter -run TestDirectObserveUpdatesHistogram

# Python tests (legacy path)
pytest legacy/tests/test_observer_agent.py -q

# BPF verifier check via Docker (macOS OK, requires Docker --privileged)
make verify-bpf

# Lima E2E (requires full Lima Lustre environment)
bash ./e2e/lima/scripts/verify-observer-go.sh    # Go exporter (first-class)
bash ./e2e/lima/scripts/verify-observer.sh        # legacy Python (second-class)
```

## Architecture

### Observation Model (shared by both implementations)

Two planes of observation with identical semantic contracts:

1. **llite** — user-facing workload plane: kprobes on `ll_lookup_nd`, `ll_file_open`, `ll_file_read_iter`, `ll_file_write_iter`, `ll_fsync`. Each op is classified by `lustre.access.intent`: `namespace_read`, `namespace_mutation`, `data_read`, `data_write`, `sync`.
2. **PtlRPC** — client-internal impact plane: optional kprobes on `ptlrpc_queue_wait`, `ptlrpc_send_new_req`, `__ptlrpc_free_req`. Degrades gracefully when probes are missing.

Actors are classified as `user`, `batch_job` (slurm/pbs/sge/lsf), `system_daemon`, or `client_worker` (ptlrpcd\_\*).

### Go Exporter (`cmd/` + `internal/goexporter/`)

Pipeline: **BPF perf events → immediate Prometheus update** (histograms/gauges) + **BPF counter maps → background drain → Custom Collector** (counters)

- `internal/bpf/lustre_ebpf_exporter.bpf.c` — CO-RE BPF program. Events are 64-byte `observer_event` structs sent via perf buffer. Mount filtering is done kernel-side via `config_map`.
- `internal/goexporter/runtime_linux.go` — `linuxEventSource` loads the BPF collection, attaches kprobes (required + optional), reads perf events. Uses `loadCollectionWithOptionalPrograms` to retry without optional programs on load failure.
- `internal/goexporter/runtime_stub.go` — non-Linux build stub (returns error).
- `internal/goexporter/types.go` — `Event`, `AggregatedMetric`, raw event parsing. The 64-byte binary layout must stay in sync with the BPF C struct.
- `internal/goexporter/aggregate.go` — `InflightTracker` wraps a Prometheus GaugeVec with zero-clamping for in-flight PtlRPC request tracking. Also provides Prometheus label builder functions.
- `internal/goexporter/bpf_counter_collector.go` — `BPFCounterCollector` implements `prometheus.Collector`. A background drain goroutine periodically reads BPF PERCPU_HASH counter maps and accumulates values in a Go-side map; `Collect()` returns them at scrape time.
- `internal/goexporter/prometheus.go` — `PrometheusExporter` serves histogram and gauge metrics directly (updated on event arrival). Counter metrics are provided by the registered `BPFCounterCollector`.
- `internal/goexporter/mount.go` — resolves Lustre mount path to device major/minor via `/proc/mounts`.
- `internal/goexporter/runtime.go` — `Run()` processes perf events in a select loop, updating Prometheus histograms/gauges immediately. No periodic flush timer.

### Legacy Python Exporter (`legacy/lustre_client_observer/agent.py`)

Second-class, frozen. Everything Python + bpftrace lives under `legacy/`:

- `legacy/lustre_client_observer/agent.py` — Python agent; generates a bpftrace script at runtime, parses tab-delimited `EVENT` lines from stdout, aggregates windows, exports to Prometheus and/or OTLP.
- `legacy/tools/lustre_client_trace.sh` — shell wrapper that is the entry point.
- `legacy/tools/lustre_client_observer.py` — Python CLI entry point.
- `legacy/tests/test_observer_agent.py` — unit tests for the legacy agent.
- `legacy/requirements-observer.txt` — Python dependencies.

Treat `legacy/` as read-only: bug fixes are welcome, but new features must target the Go exporter.

### Key Invariants

- The BPF event struct layout (64 bytes) and op/plane codes must match between `lustre_ebpf_exporter.bpf.c` and `types.go`.
- Metric attribute keys use OTel conventions internally (`user.id`, `process.name`, `lustre.actor.type`, `lustre.access.intent`), mapped to Prometheus label names at export time.
- Label cardinality is constrained by design: no pid, path, or request pointer in exported labels.

## Commit Style

Short, scoped subjects: `fix: ...`, `build: ...`, `chore: ...`, `docs: ...`.
