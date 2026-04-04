# lustre-client-observer

`lustre-client-observer` is an MVP for continuous measurement of per-user and per-process Lustre client activity, using `llite` as the primary observation plane and `PtlRPC` as the secondary observation plane.

## Architecture

- `bpftrace` attaches to `ll_lookup_nd`, `ll_file_open`, `ll_file_read_iter`, `ll_file_write_iter`, `ll_fsync`, `ptlrpc_send_new_req`, `ptlrpc_queue_wait`, and `__ptlrpc_free_req`, and emits raw events.
- The Python agent aggregates over 10-second windows, classifies events into `metadata` and `data`, assigns `user|worker|daemon` actor types, and aggregates by uid and process name.
- The primary always-on signal is `OpenTelemetry Metrics`. The agent exports through `OTLP`. When no Collector is available, `--dry-run` prints aggregated JSON to stdout.
- The current MVP does not yet support mount-level filtering on the `llite/PTLRPC` side, so it assumes the client has exactly one Lustre mount in `/proc/mounts`. If multiple mounts are present, startup is rejected to avoid mislabeled time series.

## Metrics

- `lustre.client.access.operations`
- `lustre.client.access.duration`
- `lustre.client.data.bytes`
- `lustre.client.rpc.wait.operations`
- `lustre.client.rpc.wait.duration`
- `lustre.client.inflight.requests`

Common attributes are `user.id`, `process.name`, `lustre.access.class`, `lustre.access.op`, and `lustre.actor.type`. Resource attributes include `service.name=lustre-client-observer`, `lustre.fs.name`, and `lustre.client.mount`.

## Usage

Send to a Collector:

```bash
tools/lustre_client_trace.sh \
  --mount /mnt/lustre \
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

For Lima-based verification, see [e2e/lima/README.md](/Users/y-tsubouchi/src/github.com/yuuki/otel-lustre-tracer/e2e/lima/README.md) and [verify-observer.sh](/Users/y-tsubouchi/src/github.com/yuuki/otel-lustre-tracer/e2e/lima/scripts/verify-observer.sh).
