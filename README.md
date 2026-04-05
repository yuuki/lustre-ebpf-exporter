# lustre-client-observer

`lustre-client-observer` is an MVP for continuous measurement of per-user and per-process Lustre client activity, using `llite` as the primary observation plane and `PtlRPC` as the secondary observation plane.

## Architecture

- Legacy path: `bpftrace` attaches to `ll_lookup_nd`, `ll_file_open`, `ll_file_read_iter`, `ll_file_write_iter`, `ll_fsync`, `ptlrpc_send_new_req`, `ptlrpc_queue_wait`, and `__ptlrpc_free_req`, and emits raw events that the Python agent aggregates.
- Preferred path: a Go CO-RE exporter loads a prebuilt eBPF object, reads normalized events over a ring buffer, aggregates over 10-second windows, and exposes a Prometheus Exporter.
- Both implementations classify events into `metadata` and `data`, assign `user|worker|daemon` actor types, and aggregate by uid and process name.
- The current MVP resolves the target Lustre mount to a `(major, minor)` device identity and filters llite/PTLRPC activity to the selected mount.

## Metrics

- `lustre_client_access_operations_total`
- `lustre_client_access_duration_seconds`
- `lustre_client_data_bytes_total`
- `lustre_client_rpc_wait_operations_total`
- `lustre_client_rpc_wait_duration_seconds`
- `lustre_client_inflight_requests`

Prometheus labels are `fs`, `mount`, `access_class`, `op`, `uid`, `process`, and `actor_type`. OTLP export, when enabled, continues to use the OTel-oriented internal names and resource attributes such as `service.name=lustre-client-observer`, `lustre.fs.name`, and `lustre.client.mount`.

## Usage

Run the legacy Python exporter:

```bash
tools/lustre_client_trace.sh \
  --mount /mnt/lustre \
  --prometheus-listen-address 0.0.0.0 \
  --prometheus-listen-port 9108
```

The exporter publishes metrics on `http://<host>:9108/metrics`.

Mirror the legacy Python exporter to an OTLP Collector as well:

```bash
tools/lustre_client_trace.sh \
  --mount /mnt/lustre \
  --prometheus-listen-address 0.0.0.0 \
  --prometheus-listen-port 9108 \
  --collector-endpoint http://127.0.0.1:4318/v1/metrics
```

Run in local verification mode only:

```bash
tools/lustre_client_trace.sh \
  --mount /mnt/lustre \
  --window-seconds 5 \
  --duration 30 \
  --dry-run
```

Run the preferred Go CO-RE exporter:

```bash
dist/linux-amd64/lustre-client-observer \
  --mount /mnt/lustre \
  --web.listen-address :9108 \
  --web.telemetry-path /metrics \
  --bpf-object dist/linux-amd64/lustre_client_observer.bpf.o
```

The Go exporter uses the standard Prometheus exporter style flags `--web.listen-address` and `--web.telemetry-path`.

For Lima-based verification, see [e2e/lima/README.md](/Users/y-tsubouchi/src/github.com/yuuki/otel-lustre-tracer/e2e/lima/README.md) and [verify-observer.sh](/Users/y-tsubouchi/src/github.com/yuuki/otel-lustre-tracer/e2e/lima/scripts/verify-observer.sh).
