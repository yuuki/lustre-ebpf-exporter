# lustre-ebpf-exporter

`lustre-ebpf-exporter` measures Lustre client activity continuously on the client node.
It uses `llite` as the primary observation plane for user-facing access activity and `PtlRPC`
as the secondary observation plane for client-internal wait behavior.

The repository currently contains two implementations:

- A preferred Go-based Prometheus Exporter backed by eBPF CO-RE.
- A legacy Python + `bpftrace` implementation kept as a fallback and reference path.

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
- Actor classification as `user`, `worker`, or `daemon`.
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
   they requested.

2. `PtlRPC`
   This is the client-internal impact plane. It answers how much RPC wait occurred inside the
   Lustre client.

The implementation also classifies operations into:

- `metadata`: `lookup`, `open`, `rename`, `unlink`, `mkdir`, `rmdir`
- `data`: `read`, `write`, `fsync`

And it classifies actors into:

- `user`
- `worker` for `ptlrpcd_*`
- `daemon` for known system daemons and `*exporter`

## Repository Layout

- `cmd/lustre-ebpf-exporter`
  Go CLI entrypoint for the preferred exporter.
- `internal/bpf`
  CO-RE BPF program source and generated artifacts.
- `internal/goexporter`
  Go runtime, aggregation, mount resolution, and Prometheus export.
- `lustre_client_observer`
  Legacy Python agent.
- `tools/lustre_client_trace.sh`
  Compatibility wrapper for the Python implementation.
- `e2e/lima`
  Lima-based multi-VM Lustre test environment.
- `build/docker/go-exporter.Dockerfile`
  Docker build environment for Linux Go exporter artifacts.

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
- `process`
- `actor_type`

Additional labels by family:

- llite workload metrics also use `access_class` and `op`
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

### Preferred Path: Go CO-RE Exporter

Build Linux artifacts with Docker:

```bash
make docker-build-go-exporter
```

This produces:

- `dist/linux-amd64/lustre-ebpf-exporter`
- `dist/linux-amd64/lustre_ebpf_exporter.bpf.o`

Run the exporter:

```bash
sudo ./dist/linux-amd64/lustre-ebpf-exporter \
  --mount /mnt/lustre \
  --web.listen-address :9108 \
  --web.telemetry-path /metrics \
  --bpf-object ./dist/linux-amd64/lustre_ebpf_exporter.bpf.o
```

Then scrape:

```bash
curl http://127.0.0.1:9108/metrics
```

Useful flags:

- `--mount`
- `--window-seconds`
- `--duration`
- `--once`
- `--bpf-object`
- `--legacy-symbol-allow-missing`
- `--web.listen-address`
- `--web.telemetry-path`

The exporter follows the standard Prometheus exporter flag style for `--web.listen-address`
and `--web.telemetry-path`.

### Legacy Path: Python + bpftrace

Run the compatibility wrapper:

```bash
sudo ./tools/lustre_client_trace.sh \
  --mount /mnt/lustre
```

By default it exposes Prometheus metrics on port `9108`.

Mirror the legacy exporter to OTLP as well:

```bash
sudo ./tools/lustre_client_trace.sh \
  --mount /mnt/lustre \
  --collector-endpoint http://127.0.0.1:4318/v1/metrics
```

Run the legacy exporter in local inspection mode:

```bash
sudo ./tools/lustre_client_trace.sh \
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

Legacy Python exporter:

- Linux
- root privileges
- `bpftrace`
- Python 3.9 or later
- packages from `requirements-observer.txt`

## Verification

Go unit tests:

```bash
go test ./...
```

Python and repository static tests:

```bash
pytest tests/test_lima_lustre_e2e.py tests/test_observer_agent.py -q
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
The Go path is the preferred long-term runtime because it offers:

- a standard Prometheus exporter CLI
- a CO-RE-based deployment model
- cleaner packaging for production use
- a path toward replacing the legacy tracer once metric parity is good enough

Until the Go path reaches full metric parity, the Python exporter remains the better choice when
you need llite latency and byte-volume metrics.
