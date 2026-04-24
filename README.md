# lustre-ebpf-exporter

[![AI Generated](https://img.shields.io/badge/AI%20Generated-Claude-orange?logo=anthropic)](https://claude.ai/claude-code)
[![License](https://img.shields.io/github/license/yuuki/lustre-ebpf-exporter)](LICENSE)
[![GitHub Release](https://img.shields.io/github/v/release/yuuki/lustre-ebpf-exporter)](https://github.com/yuuki/lustre-ebpf-exporter/releases)
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

Common labels for counters and gauges are:

- `fs`
- `mount`
- `uid`
- `username`
- `process`
- `actor_type`
- `slurm_job_id`

Histogram families (`*_duration_seconds`) omit `process` by default to reduce
bucket cardinality. Set `--histogram-process-labels` to keep `process` on the
histogram family as well.

Additional labels by family:

- llite workload metrics also use `access_intent` and `op`
- llite error metrics also use `access_intent`, `op`, and `errno_class` (values: `timeout`, `notconn`, `perm`, `notfound`, `io`, `again`, `other`)
- RPC wait metrics also use `op`
- RPC error metrics also use `event` (values: `resend`, `restart`, `expire`, `notconn`)

Label cardinality is intentionally constrained:

- `pid` is not exported
- `path` is not exported
- request pointers are not exported
- `process` can be collapsed via `--process-allowlist` (static) or `--process-tail-trim-percent` (dynamic)

### Process Label Cardinality Control

On busy Lustre clients, hundreds of distinct process names can appear, inflating metric
cardinality. Five flags work together to keep the `process` label manageable.

#### `--histogram-process-labels` (histogram override)

By default, the histogram families `lustre_client_access_duration_seconds`
and `lustre_client_rpc_wait_duration_seconds` do not carry the `process` label.
This keeps `_bucket`, `_sum`, and `_count` series from multiplying by process name.

```bash
--histogram-process-labels
# Re-enable process on histogram families
```

#### `--process-allowlist` (static filtering)

A comma-separated list of process names to track individually. Every process not in the
list is collapsed to `"other"`. When set, dynamic tail-trimming is disabled entirely.

```bash
--process-allowlist "dd,python,rsync"
# Only dd, python, rsync appear as distinct process labels; everything else → "other"
```

Use this when you know exactly which processes matter.

#### `--process-tail-trim-percent` (dynamic filtering)

Dynamically identifies the bottom N% of processes by operation count in each drain cycle
and collapses them to `"other"`. The ranking is rebuilt every drain interval (default 5 s)
using only the ops from the previous cycle, so the trim set adapts to workload changes.

```bash
--process-tail-trim-percent 10
# Bottom 10% of processes by op count become "other"
```

Example: if four processes ran during a drain cycle with ops `dd=1000, python=500, bash=10, cat=5`,
a 50% trim would collapse the bottom two (`cat`, `bash`) to `"other"`, keeping `dd` and `python`
as distinct labels. Ties are broken alphabetically.

Set to 0 (the default) to disable.

#### `--process-tail-trim-hysteresis` (label churn prevention)

Controls how many consecutive drain cycles a process must remain in the trim candidate set
before it is actually trimmed. This prevents borderline processes from flapping between
their real name and `"other"` across successive scrapes.

```bash
--process-tail-trim-percent 10 --process-tail-trim-hysteresis 3
# A process must be in the bottom 10% for 3 consecutive cycles before being trimmed
```

If a process moves out of the trim candidate set in any cycle, its consecutive counter
resets to zero immediately. Default is 1 (trim on the first qualifying cycle).

#### `--process-name-strip-suffix` (numeric suffix normalization)

Many runtimes and thread pools append numeric identifiers to process names
(e.g. "Bun Pool 1", "Bun Pool 2", "worker-3", "thread_42"). Each numbered
variant becomes a distinct Prometheus label, causing cardinality explosion.

This flag strips the trailing separator+digits suffix, collapsing all
variants to a single canonical name:

```bash
--process-name-strip-suffix
# "Bun Pool 1", "Bun Pool 2", "Bun Pool 3" → "Bun Pool"
# "worker-3" → "worker"
# "thread_42" → "thread"
```

Recognised separators: space (` `), dash (`-`), underscore (`_`), colon (`:`).
Period is intentionally excluded so version-like names (`python3.11`, `go1.21`)
are not affected.

Stripping is applied **before** allowlist and tail-trim checks, so those
features operate on the normalized names. Disabled by default.

#### Priority

1. If `--process-name-strip-suffix` is set, trailing separator+digits suffixes are stripped first.
2. If `--process-allowlist` is set, it takes absolute priority and tail-trimming is skipped.
3. If `--process-tail-trim-percent` > 0 (and no allowlist), dynamic trimming applies.
4. If none are set, all process names pass through unchanged.

### Metric Coverage by Implementation

Go CO-RE exporter:

- `lustre_client_access_operations_total`
- `lustre_client_access_duration_seconds`
- `lustre_client_data_bytes_total`
- `lustre_client_operation_errors_total` (llite VFS failures classified by errno_class; requires kretprobes)
- `lustre_client_rpc_wait_operations_total` when the relevant optional probes are available
- `lustre_client_rpc_wait_duration_seconds` when the relevant optional probes are available
- `lustre_client_rpc_errors_total` when the relevant optional probes are available (`ptlrpc_resend_req`, `ptlrpc_restart_req`, `ptlrpc_expire_one_request`, `ptlrpc_request_handle_notconn`)
- `lustre_client_inflight_requests` when request lifecycle probes are available

The legacy Python exporter has its own metric coverage; see [`legacy/`](legacy/README.md).

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
- `--process-allowlist` (comma-separated list of process names to track; all others become `"other"`)
- `--process-tail-trim-percent` (dynamically trim the bottom N% of processes by operation count; default 0 = disabled)
- `--process-tail-trim-hysteresis` (consecutive drain cycles before trimming; default 1)
- `--process-name-strip-suffix` (strip trailing separator+digits from process names; default `false`)
- `--histogram-process-labels` (default `false`; when `false`, histogram families omit `process`)
- `--uid-labels` (default `true`; when `false`, drops `uid` and `username` labels and skips kernel-side `bpf_get_current_uid_gid()` — collapsing BPF PERCPU_HASH rows across users)
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
