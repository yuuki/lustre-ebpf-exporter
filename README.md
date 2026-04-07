# lustre-ebpf-exporter

`lustre-ebpf-exporter` measures Lustre client activity continuously on the client node.
It uses `llite` as the primary observation plane for user-facing access activity and `PtlRPC`
as the secondary observation plane for client-internal wait behavior.

The repository currently contains two implementations:

- **First-class**: a Go-based Prometheus Exporter backed by eBPF CO-RE. This is the
  supported runtime and the only path that receives active development.
- **Second-class (legacy)**: a Python + `bpftrace` implementation, kept under
  [`legacy/`](legacy/) as a reference path and a temporary fallback for the handful of
  metrics the Go path does not yet emit. The legacy path is frozen and will be removed
  once the Go exporter reaches metric parity.

The project is aimed at answering questions such as:

- Which user or process is generating the most metadata traffic?
- Which user or process is generating the most data traffic?
- When did `ptlrpc_queue_wait` get worse?
- Did a heavy workload spike coincide with latency pain for others?

## Status

This repository is still an MVP.

What works today:

- Mount-scoped observation of llite entry activity.
- Per-user and per-process aggregation.
- Actor classification as `user`, `batch_job`, `system_daemon`, or `client_worker`.
- Prometheus export from both implementations.
- Lima-based E2E coverage for the Go exporter and the legacy Python path.

Important current limitation:

- The Go exporter currently emits llite operation counts, plus PtlRPC wait and inflight metrics when
  the relevant optional probes are available.
- The legacy Python path still provides llite latency and byte-volume metrics.
- The Go path does not currently emit llite latency and llite byte-volume metrics, because the
  llite completion correlation used in the current Linux E2E path is not yet robust enough to
  claim those values as production-quality.

If you need `lustre_client_access_duration_seconds` and `lustre_client_data_bytes_total` today,
use the legacy Python exporter.

## Observation Model

The design intentionally separates two planes:

1. `llite`
   This is the user-facing workload plane. It answers who touched Lustre and which operation class
   they requested. Observed via kprobes on `ll_lookup_nd`, `ll_file_open`, `ll_file_read_iter`,
   `ll_file_write_iter`, and `ll_fsync`.

2. `PtlRPC`
   This is the client-internal impact plane. It answers how much RPC wait occurred inside the
   Lustre client.

The `access_intent` label classifies operations into:

- `namespace_read`: `lookup`
- `namespace_mutation`: `open` (create path)
- `data_read`: `read`
- `data_write`: `write`
- `sync`: `fsync`

And actors are classified into:

- `user`: regular interactive or scripted processes
- `batch_job`: processes launched by Slurm, PBS, SGE, or LSF
- `system_daemon`: known system daemons and `*exporter` processes
- `client_worker`: `ptlrpcd_*` Lustre internal threads

## Repository Layout

First-class (Go exporter):

- `cmd/lustre-ebpf-exporter`
  Go CLI entrypoint for the supported exporter.
- `internal/bpf`
  CO-RE BPF program source and generated artifacts.
- `internal/goexporter`
  Go runtime, aggregation, mount resolution, and Prometheus export.
- `build/docker/go-exporter.Dockerfile`
  Docker build environment for Linux Go exporter artifacts.

Second-class (legacy Python + `bpftrace`):

- `legacy/lustre_client_observer/`
  Legacy Python agent (frozen).
- `legacy/tools/lustre_client_trace.sh`
  Compatibility wrapper for the Python implementation.
- `legacy/tools/lustre_client_observer.py`
  CLI entry point for the Python agent.
- `legacy/tests/test_observer_agent.py`
  Unit tests that cover the legacy Python agent.
- `legacy/requirements-observer.txt`
  Python dependencies for the legacy path.

Shared:

- `e2e/lima`
  Lima-based multi-VM Lustre test environment used by both paths.

## Metrics

The Prometheus metric family names are:

- `lustre_client_access_operations_total`
- `lustre_client_access_duration_seconds`
- `lustre_client_data_bytes_total`
- `lustre_client_rpc_wait_operations_total`
- `lustre_client_rpc_wait_duration_seconds`
- `lustre_client_inflight_requests`

Common labels are:

- `fs`
- `mount`
- `uid`
- `username`
- `process`
- `actor_type`
- `slurm_job_id`

Additional labels by family:

- llite workload metrics also use `access_intent` and `op`
- RPC wait metrics also use `op`

Label cardinality is intentionally constrained:

- `pid` is not exported
- `path` is not exported
- request pointers are not exported

### Metric Coverage by Implementation

Go CO-RE exporter:

- `lustre_client_access_operations_total`
- `lustre_client_rpc_wait_operations_total` when the relevant optional probes are available
- `lustre_client_rpc_wait_duration_seconds` when the relevant optional probes are available
- `lustre_client_inflight_requests` when request lifecycle probes are available

Legacy Python exporter:

- `lustre_client_access_operations_total`
- `lustre_client_access_duration_seconds`
- `lustre_client_data_bytes_total`
- `lustre_client_rpc_wait_operations_total`
- `lustre_client_rpc_wait_duration_seconds`
- `lustre_client_inflight_requests`

The Go exporter registers all Prometheus families, but the current aggregator only emits the
families that it can populate meaningfully.

## Quick Start

### First-class Path: Go CO-RE Exporter

Build Linux artifacts with Docker:

```bash
make docker-build-go-exporter
```

This produces:

- `dist/linux-amd64/lustre-ebpf-exporter`
- `dist/linux-amd64/lustre_ebpf_exporter.bpf.o`

Run the exporter (mount paths are auto-detected if `--mount` is omitted):

```bash
sudo ./dist/linux-amd64/lustre-ebpf-exporter \
  --mount /mnt/lustre \
  --web.listen-address :9108 \
  --web.telemetry-path /metrics
```

Then scrape:

```bash
curl http://127.0.0.1:9108/metrics
```

Useful flags:

- `--mount` (repeatable; auto-detected from `/proc/mounts` when omitted)
- `--drain-interval` (BPF counter map drain interval in seconds; default 5)
- `--duration`
- `--once`
- `--legacy-symbol-allow-missing`
- `--slurm-jobid` (enable Slurm job id resolution per pid)
- `--slurm-jobid-ttl`, `--slurm-jobid-negative-ttl`, `--slurm-jobid-verify-ttl`, `--slurm-jobid-cache-size`
- `--web.listen-address`
- `--web.telemetry-path`
- `--version`

The exporter follows the standard Prometheus exporter flag style for `--web.listen-address`
and `--web.telemetry-path`.

### Second-class Path: Legacy Python + bpftrace

> The legacy path lives under [`legacy/`](legacy/) and is frozen. Use it only when you
> need `lustre_client_access_duration_seconds` or `lustre_client_data_bytes_total`
> today; new work should target the Go exporter.

Run the compatibility wrapper:

```bash
sudo ./legacy/tools/lustre_client_trace.sh \
  --mount /mnt/lustre
```

By default it exposes Prometheus metrics on port `9108`.

Mirror the legacy exporter to OTLP as well:

```bash
sudo ./legacy/tools/lustre_client_trace.sh \
  --mount /mnt/lustre \
  --collector-endpoint http://127.0.0.1:4318/v1/metrics
```

Run the legacy exporter in local inspection mode:

```bash
sudo ./legacy/tools/lustre_client_trace.sh \
  --mount /mnt/lustre \
  --window-seconds 5 \
  --duration 30 \
  --dry-run
```

## Building

Native Go build:

```bash
make generate-go-exporter
make build-go-exporter
make stage-go-exporter
```

Recommended Linux artifact build:

```bash
make docker-build-go-exporter
```

Docker is the recommended build path because it produces the Linux binary and the matching BPF
object in a controlled environment.

## Requirements

Go exporter:

- Linux
- root privileges
- a working Lustre client mount
- a compatible prebuilt BPF object

Legacy Python exporter (second-class):

- Linux
- root privileges
- `bpftrace`
- Python 3.9 or later
- packages from `legacy/requirements-observer.txt`

## Verification

Go unit tests:

```bash
go test ./...
```

Python and repository static tests (legacy path lives under `legacy/tests/`):

```bash
pytest tests/test_lima_lustre_e2e.py legacy/tests/test_observer_agent.py -q
```

Lima E2E for the Go exporter:

```bash
bash ./e2e/lima/scripts/verify-observer-go.sh
```

Lima E2E for the legacy Python path:

```bash
bash ./e2e/lima/scripts/verify-observer.sh
```

For full Lima environment setup, see [e2e/lima/README.md](e2e/lima/README.md).

## Known Limitations

- The Go exporter currently prioritizes mount-scoped llite operation counting and PtlRPC wait
  visibility over full llite latency and byte accounting.
- Optional probes such as `ptlrpc_send_new_req` and `__ptlrpc_free_req` may be unavailable on a
  given Lustre build; the Go exporter degrades when that happens.
- The Linux E2E environment is based on Lustre 2.14 on Rocky 8, so behavior outside that matrix
  still needs broader validation.
- The project does not export file paths, inode numbers, PIDs, or request pointers as metric
  labels by design.

## Why Two Implementations?

The Python path was the fastest way to validate the observation model with `bpftrace`.
It now lives under [`legacy/`](legacy/) as a second-class implementation: frozen, kept
only for reference and for the narrow set of metrics the Go path does not yet emit.

The Go path is the first-class long-term runtime because it offers:

- a standard Prometheus exporter CLI
- a CO-RE-based deployment model
- cleaner packaging for production use
- a path toward retiring the legacy tracer once metric parity is good enough

Until the Go path reaches full metric parity, the legacy Python exporter remains the only
option when you need llite latency and byte-volume metrics. Once that gap closes the
`legacy/` tree is expected to be removed.
