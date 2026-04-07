# Legacy Python + bpftrace Implementation

This directory holds the **second-class** implementation of `lustre-ebpf-exporter`:
a Python agent that drives `bpftrace` to emit per-event records, aggregates them, and
exports Prometheus (and optionally OTLP) metrics.

The **first-class** runtime is the Go CO-RE exporter under `cmd/lustre-ebpf-exporter`
and `internal/`. See the root [`README.md`](../README.md) for the supported path.

## Status

Frozen. This tree exists for two reasons only:

1. It still emits `lustre_client_access_duration_seconds` and
   `lustre_client_data_bytes_total`, which the Go exporter does not yet produce in a
   production-quality way.
2. It serves as a reference implementation for the observation model (llite + PtlRPC)
   and the bpftrace probe set.

Once the Go exporter reaches metric parity, this directory is expected to be removed
entirely. Do not add new features here. Bug fixes are accepted, but new work should
target the Go exporter.

## Layout

```
legacy/
├── README.md                       # this file
├── requirements-observer.txt       # Python runtime dependencies
├── lustre_client_observer/         # Python package (agent implementation)
│   ├── __init__.py
│   └── agent.py
├── tools/
│   ├── lustre_client_trace.sh      # shell entry point / compatibility wrapper
│   └── lustre_client_observer.py   # Python CLI entry point
└── tests/
    └── test_observer_agent.py      # unit tests for the legacy agent
```

The Lima-based E2E smoke test for this path lives outside `legacy/` and is invoked via
`e2e/lima/scripts/verify-observer.sh`, since it shares the Lima cluster definition with
the Go exporter E2E.

## Usage

Run the compatibility wrapper:

```bash
sudo ./legacy/tools/lustre_client_trace.sh \
  --mount /mnt/lustre
```

By default it exposes Prometheus metrics on port `9108`.

Mirror to OTLP:

```bash
sudo ./legacy/tools/lustre_client_trace.sh \
  --mount /mnt/lustre \
  --collector-endpoint http://127.0.0.1:4318/v1/metrics
```

Local inspection mode (aggregated JSON to stdout):

```bash
sudo ./legacy/tools/lustre_client_trace.sh \
  --mount /mnt/lustre \
  --window-seconds 5 \
  --duration 30 \
  --dry-run
```

## Requirements

- Linux
- root privileges
- `bpftrace`
- Python 3.9 or later
- packages from [`requirements-observer.txt`](requirements-observer.txt)

## Testing

```bash
pytest legacy/tests/test_observer_agent.py -q
```

The test is discoverable from the repository root; `legacy/` is added to `sys.path` by
the test module so that `from lustre_client_observer.agent import ...` resolves
correctly.
