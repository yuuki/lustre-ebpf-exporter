# lustre-ebpf-exporter

[![AI Generated](https://img.shields.io/badge/AI%20Generated-Claude-orange?logo=anthropic)](https://claude.ai/claude-code)
[![License](https://img.shields.io/github/license/yuuki/otel-lustre-tracer)](LICENSE)
[![GitHub Release](https://img.shields.io/github/v/release/yuuki/otel-lustre-tracer)](https://github.com/yuuki/otel-lustre-tracer/releases)
[![Go](https://img.shields.io/badge/Go-%3E%3D1.26-blue?logo=go)](https://go.dev)

`lustre-ebpf-exporter` measures Lustre client activity continuously on the client node.
It uses `llite` as the primary observation plane for user-facing access activity and `PtlRPC`
as the secondary observation plane for client-internal wait behavior.

The repository currently contains two implementations:

- **First-class**: a Go-based Prometheus Exporter backed by eBPF CO-RE. This is the
  supported runtime and the only path that receives active development.
- **Second-class (legacy)**: a frozen Python + `bpftrace` fallback under [`legacy/`](legacy/README.md).

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

The design intentionally separates three planes:

1. `llite`
   This is the user-facing workload plane. It answers who touched Lustre and which operation class
   they requested. Observed via kprobes on `ll_lookup_nd`, `ll_file_open`, `ll_file_read_iter`,
   `ll_file_write_iter`, and `ll_fsync`.

2. `PtlRPC`
   This is the client-internal impact plane. It answers how much RPC wait occurred inside the
   Lustre client.

3. `PCC` (Persistent Client Cache)
   This is the client-local cache plane. It answers how much I/O was served from the PCC cache
   layer and tracks attach/detach lifecycle events. Observed via optional kprobes on
   `pcc_file_read_iter`, `pcc_file_write_iter`, `pcc_file_open`, `pcc_lookup`, `pcc_fsync`,
   and attach/detach functions. All PCC probes degrade gracefully when the PCC module is not loaded.
   PCC metric collection is disabled by default and must be explicitly enabled with
   `--collector.pcc`.

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

Second-class (legacy Python + `bpftrace`): see [`legacy/`](legacy/README.md).

Shared:

- `e2e/lima`
  Lima-based multi-VM Lustre test environment used by both paths.

## Metrics

The Prometheus metric family names are:

- `lustre_client_access_operations_total`
- `lustre_client_access_duration_seconds`
- `lustre_client_data_bytes_total`
- `lustre_client_operation_errors_total`
- `lustre_client_rpc_wait_operations_total`
- `lustre_client_rpc_wait_duration_seconds`
- `lustre_client_rpc_errors_total`
- `lustre_client_inflight_requests`
- `lustre_client_pcc_operations_total`
- `lustre_client_pcc_operation_duration_seconds`
- `lustre_client_pcc_data_bytes_total`
- `lustre_client_pcc_operation_errors_total`
- `lustre_client_pcc_attach_total`
- `lustre_client_pcc_attach_failures_total`
- `lustre_client_pcc_detach_total`
- `lustre_client_pcc_layout_invalidations_total`

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
- llite error metrics also use `access_intent`, `op`, and `errno_class` (values: `timeout`, `notconn`, `perm`, `notfound`, `io`, `again`, `other`)
- RPC wait metrics also use `op`
- RPC error metrics also use `event` (values: `resend`, `restart`, `expire`, `notconn`)
- PCC I/O metrics use `access_intent` and `op` (same schema as llite)
- PCC error metrics use `access_intent`, `op`, and `errno_class`
- PCC attach metrics use `mode` (`ro`, `rw`) and `trigger` (`manual`, `auto`)
- PCC detach and invalidation metrics use the common labels only

Label cardinality is intentionally constrained:

- `pid` is not exported
- `path` is not exported
- request pointers are not exported

### Metric Coverage by Implementation

Go CO-RE exporter:

- `lustre_client_access_operations_total`
- `lustre_client_operation_errors_total` (llite VFS failures classified by errno_class; requires kretprobes)
- `lustre_client_rpc_wait_operations_total` when the relevant optional probes are available
- `lustre_client_rpc_wait_duration_seconds` when the relevant optional probes are available
- `lustre_client_rpc_errors_total` when the relevant optional probes are available (`ptlrpc_resend_req`, `ptlrpc_restart_req`, `ptlrpc_expire_one_request`, `ptlrpc_request_handle_notconn`)
- `lustre_client_inflight_requests` when request lifecycle probes are available
- `lustre_client_pcc_operations_total` when PCC module probes are available
- `lustre_client_pcc_operation_duration_seconds` when PCC module probes are available
- `lustre_client_pcc_data_bytes_total` when PCC module probes are available
- `lustre_client_pcc_operation_errors_total` when PCC module probes are available
- `lustre_client_pcc_attach_total` when PCC attach probes are available
- `lustre_client_pcc_attach_failures_total` when PCC attach probes are available
- `lustre_client_pcc_detach_total` when PCC lifecycle probes are available
- `lustre_client_pcc_layout_invalidations_total` when PCC lifecycle probes are available

The legacy Python exporter emits all six families; see [`legacy/`](legacy/README.md).

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

See [`legacy/README.md`](legacy/README.md).

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

Legacy Python exporter (second-class): see [`legacy/README.md`](legacy/README.md).

## Verification

Go unit tests:

```bash
go test ./...
```

Lima E2E for the Go exporter:

```bash
bash ./e2e/lima/scripts/verify-observer-go.sh
```

For the legacy Python path and full Lima environment setup, see [e2e/lima/README.md](e2e/lima/README.md).

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

The Python + `bpftrace` path was the fastest way to validate the observation model and is
kept under [`legacy/`](legacy/README.md) solely for the metrics the Go path does not yet
emit. Once metric parity is reached, `legacy/` will be removed.
