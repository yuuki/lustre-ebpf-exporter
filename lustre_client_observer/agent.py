from __future__ import annotations

import argparse
import json
import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


LLITE_METADATA_OPS = {"lookup", "open", "rename", "unlink", "mkdir", "rmdir"}
LLITE_DATA_OPS = {"read", "write", "fsync"}
REQUIRED_TRACEABLE_SYMBOLS = {
    "ll_lookup_nd",
    "ll_file_open",
    "ll_file_read_iter",
    "ll_file_write_iter",
    "ll_fsync",
    "ptlrpc_queue_wait",
}
OPTIONAL_TRACEABLE_SYMBOLS = {
    "ptlrpc_send_new_req",
    "__ptlrpc_free_req",
}
DAEMON_NAMES = {
    "node_exporter",
    "sshd",
    "systemd",
    "systemd-journal",
    "dbus-daemon",
    "cron",
    "crond",
}


@dataclass(frozen=True)
class EventRecord:
    plane: str
    op: str
    uid: int
    pid: int
    comm: str
    duration_us: int
    size_bytes: int
    actor_type: str
    access_class: str | None
    request_ptr: str | None = None


@dataclass(frozen=True)
class AggregatedMetric:
    name: str
    value: int | list[int]
    unit: str
    metric_type: str
    attributes: dict[str, str]


def classify_actor_type(comm: str) -> str:
    if comm.startswith("ptlrpcd_"):
        return "worker"
    if comm in DAEMON_NAMES or comm.endswith("exporter"):
        return "daemon"
    return "user"


def access_class_for_op(op: str) -> str | None:
    if op in LLITE_METADATA_OPS:
        return "metadata"
    if op in LLITE_DATA_OPS:
        return "data"
    return None


def parse_event_line(line: str) -> EventRecord:
    parts = line.strip().split("\t")
    if len(parts) < 2 or parts[0] != "EVENT":
        raise ValueError(f"unsupported event line: {line.rstrip()}")

    fields: dict[str, str] = {}
    for item in parts[1:]:
        if "=" not in item:
            raise ValueError(f"malformed field: {item}")
        key, value = item.split("=", 1)
        fields[key] = value

    plane = fields["plane"]
    op = fields["op"]
    comm = fields["comm"]
    return EventRecord(
        plane=plane,
        op=op,
        uid=int(fields["uid"]),
        pid=int(fields["pid"]),
        comm=comm,
        duration_us=max(0, int(fields.get("duration_us", "0"))),
        size_bytes=max(0, int(fields.get("size_bytes", "0"))),
        actor_type=fields.get("actor_type", classify_actor_type(comm)),
        access_class=fields.get("access_class", access_class_for_op(op)),
        request_ptr=fields.get("request_ptr"),
    )


def validate_lustre_mount_selection(
    mount_path: str,
    mounts_text: str | None = None,
    realpath_fn: Any = os.path.realpath,
    stat_fn: Any = os.stat,
) -> None:
    _ = resolve_lustre_mount_identity(
        mount_path,
        mounts_text=mounts_text,
        realpath_fn=realpath_fn,
        stat_fn=stat_fn,
    )


def resolve_lustre_mount_identity(
    mount_path: str,
    mounts_text: str | None = None,
    realpath_fn: Any = os.path.realpath,
    stat_fn: Any = os.stat,
) -> tuple[int, int]:
    if mounts_text is None:
        mounts_text = Path("/proc/mounts").read_text()

    lustre_mounts: list[str] = []
    for line in mounts_text.splitlines():
        fields = line.split()
        if len(fields) < 3 or fields[2] != "lustre":
            continue
        lustre_mounts.append(fields[1])

    if not lustre_mounts:
        raise ValueError("no lustre mounts found in /proc/mounts")

    normalized_mount_path = realpath_fn(mount_path)
    normalized_lustre_mounts = [realpath_fn(item) for item in lustre_mounts]

    if normalized_mount_path not in normalized_lustre_mounts:
        raise ValueError(f"mount path is not a lustre mount: {mount_path}")

    device = int(stat_fn(normalized_mount_path).st_dev)
    return (os.major(device), os.minor(device))


def load_traceable_functions(text: str | None = None) -> set[str]:
    if text is None:
        for candidate in (
            "/sys/kernel/tracing/available_filter_functions",
            "/sys/kernel/debug/tracing/available_filter_functions",
        ):
            path = Path(candidate)
            if path.exists():
                text = path.read_text()
                break
        else:
            raise FileNotFoundError("available_filter_functions not found")

    functions: set[str] = set()
    for line in text.splitlines():
        if not line.strip():
            continue
        functions.add(line.split()[0])
    return functions


class EventWindowAggregator:
    def __init__(self) -> None:
        self._counter_values: dict[tuple[str, tuple[tuple[str, str], ...]], int] = defaultdict(int)
        self._histogram_values: dict[tuple[str, tuple[tuple[str, str], ...]], list[int]] = defaultdict(list)

    def consume(self, event: EventRecord) -> None:
        base_attributes = {
            "user.id": str(event.uid),
            "process.name": event.comm,
            "lustre.actor.type": event.actor_type,
        }

        if event.plane == "llite":
            if event.access_class is None:
                return
            llite_attributes = {
                **base_attributes,
                "lustre.access.class": event.access_class,
                "lustre.access.op": event.op,
            }
            self._add_counter("lustre.client.access.operations", 1, llite_attributes)
            if event.duration_us > 0:
                self._add_histogram("lustre.client.access.duration", event.duration_us, llite_attributes)
            if event.access_class == "data" and event.size_bytes > 0:
                self._add_counter("lustre.client.data.bytes", event.size_bytes, llite_attributes)
            return

        if event.plane != "ptlrpc":
            return

        rpc_attributes = {
            **base_attributes,
        }
        if event.op == "queue_wait":
            rpc_wait_attributes = {
                **rpc_attributes,
                "lustre.access.op": event.op,
            }
            self._add_counter("lustre.client.rpc.wait.operations", 1, rpc_wait_attributes)
            if event.duration_us > 0:
                self._add_histogram("lustre.client.rpc.wait.duration", event.duration_us, rpc_wait_attributes)
            return
        if event.op == "send_new_req":
            self._add_counter("lustre.client.inflight.requests", 1, rpc_attributes)
            return
        if event.op == "free_req":
            self._add_counter("lustre.client.inflight.requests", -1, rpc_attributes)

    def _add_counter(self, name: str, value: int, attributes: dict[str, str]) -> None:
        key = (name, tuple(sorted(attributes.items())))
        self._counter_values[key] += value

    def _add_histogram(self, name: str, value: int, attributes: dict[str, str]) -> None:
        key = (name, tuple(sorted(attributes.items())))
        self._histogram_values[key].append(value)

    def collect(self) -> list[AggregatedMetric]:
        metrics: list[AggregatedMetric] = []

        for (name, attribute_items), value in sorted(self._counter_values.items()):
            metric_type = "updowncounter" if name == "lustre.client.inflight.requests" else "counter"
            unit = "By" if name == "lustre.client.data.bytes" else "1"
            metrics.append(
                AggregatedMetric(
                    name=name,
                    value=value,
                    unit=unit,
                    metric_type=metric_type,
                    attributes=dict(attribute_items),
                )
            )

        for (name, attribute_items), values in sorted(self._histogram_values.items()):
            metrics.append(
                AggregatedMetric(
                    name=name,
                    value=list(values),
                    unit="us",
                    metric_type="histogram",
                    attributes=dict(attribute_items),
                )
            )

        self._counter_values.clear()
        self._histogram_values.clear()
        return metrics


def build_bpftrace_program(
    mount_path: str,
    target_major: int,
    target_minor: int,
    available_symbols: set[str] | None = None,
) -> str:
    if available_symbols is None:
        available_symbols = REQUIRED_TRACEABLE_SYMBOLS | OPTIONAL_TRACEABLE_SYMBOLS

    missing_required = sorted(REQUIRED_TRACEABLE_SYMBOLS - available_symbols)
    if missing_required:
        raise ValueError(f"required traceable functions are missing: {', '.join(missing_required)}")

    escaped_mount = mount_path.replace("\\", "\\\\").replace('"', '\\"')
    mount_filter = f"""  $target_major = (uint64){target_major};
  $target_minor = (uint64){target_minor};
  if (($dev >> 20) == $target_major && ($dev & 1048575) == $target_minor) {{"""
    sections = [
        f"""
BEGIN
{{
  printf("TRACE_START\\tmount={escaped_mount}\\n");
}}

kprobe:ll_lookup_nd
{{
  $dev = ((struct inode *)arg0)->i_sb->s_dev;
{mount_filter}
    @ll_lookup_start[tid] = nsecs;
    @ll_lookup_uid[tid] = uid;
    @ll_lookup_pid[tid] = pid;
    @ll_lookup_comm[tid] = comm;
    @selected_mount_tid[tid] = 1;
  }}
}}

kretprobe:ll_lookup_nd
/@ll_lookup_start[tid]/
{{
  printf("EVENT\\tplane=llite\\top=lookup\\tuid=%d\\tpid=%d\\tcomm=%s\\tduration_us=%llu\\tsize_bytes=0\\n",
    @ll_lookup_uid[tid], @ll_lookup_pid[tid], @ll_lookup_comm[tid], (nsecs - @ll_lookup_start[tid]) / 1000);
  delete(@ll_lookup_start[tid]);
  delete(@ll_lookup_uid[tid]);
  delete(@ll_lookup_pid[tid]);
  delete(@ll_lookup_comm[tid]);
  delete(@selected_mount_tid[tid]);
}}

kprobe:ll_file_open
{{
  $dev = ((struct inode *)arg0)->i_sb->s_dev;
{mount_filter}
    @ll_open_start[tid] = nsecs;
    @ll_open_uid[tid] = uid;
    @ll_open_pid[tid] = pid;
    @ll_open_comm[tid] = comm;
    @selected_mount_tid[tid] = 1;
  }}
}}

kretprobe:ll_file_open
/@ll_open_start[tid]/
{{
  printf("EVENT\\tplane=llite\\top=open\\tuid=%d\\tpid=%d\\tcomm=%s\\tduration_us=%llu\\tsize_bytes=0\\n",
    @ll_open_uid[tid], @ll_open_pid[tid], @ll_open_comm[tid], (nsecs - @ll_open_start[tid]) / 1000);
  delete(@ll_open_start[tid]);
  delete(@ll_open_uid[tid]);
  delete(@ll_open_pid[tid]);
  delete(@ll_open_comm[tid]);
  delete(@selected_mount_tid[tid]);
}}

kprobe:ll_file_read_iter
{{
  $dev = ((struct kiocb *)arg0)->ki_filp->f_inode->i_sb->s_dev;
{mount_filter}
    @ll_read_start[tid] = nsecs;
    @ll_read_uid[tid] = uid;
    @ll_read_pid[tid] = pid;
    @ll_read_comm[tid] = comm;
    @selected_mount_tid[tid] = 1;
  }}
}}

kretprobe:ll_file_read_iter
/@ll_read_start[tid]/
{{
  $bytes = retval > 0 ? retval : 0;
  printf("EVENT\\tplane=llite\\top=read\\tuid=%d\\tpid=%d\\tcomm=%s\\tduration_us=%llu\\tsize_bytes=%lld\\n",
    @ll_read_uid[tid], @ll_read_pid[tid], @ll_read_comm[tid], (nsecs - @ll_read_start[tid]) / 1000, $bytes);
  delete(@ll_read_start[tid]);
  delete(@ll_read_uid[tid]);
  delete(@ll_read_pid[tid]);
  delete(@ll_read_comm[tid]);
  delete(@selected_mount_tid[tid]);
}}

kprobe:ll_file_write_iter
{{
  $dev = ((struct kiocb *)arg0)->ki_filp->f_inode->i_sb->s_dev;
{mount_filter}
    @ll_write_start[tid] = nsecs;
    @ll_write_uid[tid] = uid;
    @ll_write_pid[tid] = pid;
    @ll_write_comm[tid] = comm;
    @selected_mount_tid[tid] = 1;
  }}
}}

kretprobe:ll_file_write_iter
/@ll_write_start[tid]/
{{
  $bytes = retval > 0 ? retval : 0;
  printf("EVENT\\tplane=llite\\top=write\\tuid=%d\\tpid=%d\\tcomm=%s\\tduration_us=%llu\\tsize_bytes=%lld\\n",
    @ll_write_uid[tid], @ll_write_pid[tid], @ll_write_comm[tid], (nsecs - @ll_write_start[tid]) / 1000, $bytes);
  delete(@ll_write_start[tid]);
  delete(@ll_write_uid[tid]);
  delete(@ll_write_pid[tid]);
  delete(@ll_write_comm[tid]);
  delete(@selected_mount_tid[tid]);
}}

kprobe:ll_fsync
{{
  $dev = ((struct file *)arg0)->f_inode->i_sb->s_dev;
{mount_filter}
    @ll_fsync_start[tid] = nsecs;
    @ll_fsync_uid[tid] = uid;
    @ll_fsync_pid[tid] = pid;
    @ll_fsync_comm[tid] = comm;
    @selected_mount_tid[tid] = 1;
  }}
}}

kretprobe:ll_fsync
/@ll_fsync_start[tid]/
{{
  printf("EVENT\\tplane=llite\\top=fsync\\tuid=%d\\tpid=%d\\tcomm=%s\\tduration_us=%llu\\tsize_bytes=0\\n",
    @ll_fsync_uid[tid], @ll_fsync_pid[tid], @ll_fsync_comm[tid], (nsecs - @ll_fsync_start[tid]) / 1000);
  delete(@ll_fsync_start[tid]);
  delete(@ll_fsync_uid[tid]);
  delete(@ll_fsync_pid[tid]);
  delete(@ll_fsync_comm[tid]);
  delete(@selected_mount_tid[tid]);
}}

kprobe:ptlrpc_queue_wait
/@tracked_req[arg0] || @selected_mount_tid[tid]/
{{
  @rpc_wait_start[tid] = nsecs;
  @rpc_wait_uid[tid] = uid;
  @rpc_wait_pid[tid] = pid;
  @rpc_wait_comm[tid] = comm;
  @rpc_wait_req[tid] = arg0;
  @tracked_req[arg0] = 1;
}}

kretprobe:ptlrpc_queue_wait
/@rpc_wait_start[tid]/
{{
  printf("EVENT\\tplane=ptlrpc\\top=queue_wait\\tuid=%d\\tpid=%d\\tcomm=%s\\tduration_us=%llu\\tsize_bytes=0\\trequest_ptr=0x%llx\\n",
    @rpc_wait_uid[tid], @rpc_wait_pid[tid], @rpc_wait_comm[tid], (nsecs - @rpc_wait_start[tid]) / 1000, @rpc_wait_req[tid]);
  delete(@rpc_wait_start[tid]);
  delete(@rpc_wait_uid[tid]);
  delete(@rpc_wait_pid[tid]);
  delete(@rpc_wait_comm[tid]);
  delete(@rpc_wait_req[tid]);
}}
""".strip()
    ]

    if "ptlrpc_send_new_req" in available_symbols:
        sections.append(
            """
kprobe:ptlrpc_send_new_req
/@selected_mount_tid[tid]/
{
  @tracked_req[arg0] = 1;
  printf("EVENT\\tplane=ptlrpc\\top=send_new_req\\tuid=%d\\tpid=%d\\tcomm=%s\\tduration_us=0\\tsize_bytes=0\\trequest_ptr=0x%llx\\n",
    uid, pid, comm, arg0);
}
""".strip()
        )

    if "__ptlrpc_free_req" in available_symbols:
        sections.append(
            """
kprobe:__ptlrpc_free_req
/@tracked_req[arg0]/
{
  printf("EVENT\\tplane=ptlrpc\\top=free_req\\tuid=%d\\tpid=%d\\tcomm=%s\\tduration_us=0\\tsize_bytes=0\\trequest_ptr=0x%llx\\n",
    uid, pid, comm, arg0);
  delete(@tracked_req[arg0]);
}
""".strip()
        )

    return "\n\n".join(sections)


def emit_metrics_json(metrics: list[AggregatedMetric], stream: Any) -> None:
    payload = [
        {
            "name": metric.name,
            "value": metric.value,
            "unit": metric.unit,
            "type": metric.metric_type,
            "attributes": metric.attributes,
        }
        for metric in metrics
    ]
    stream.write(json.dumps(payload, sort_keys=True) + "\n")
    stream.flush()


class OpenTelemetryMetricExporter:
    def __init__(self, endpoint: str, resource_attributes: dict[str, str]) -> None:
        from opentelemetry import metrics
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import Resource

        reader = PeriodicExportingMetricReader(
            OTLPMetricExporter(endpoint=endpoint),
            export_interval_millis=5000,
        )
        provider = MeterProvider(resource=Resource.create(resource_attributes), metric_readers=[reader])
        metrics.set_meter_provider(provider)
        self._provider = provider
        meter = metrics.get_meter("lustre-client-observer", "0.1.0")
        self._counters = {
            "lustre.client.access.operations": meter.create_counter(
                "lustre.client.access.operations",
                unit="1",
                description="Aggregated llite access operation count",
            ),
            "lustre.client.data.bytes": meter.create_counter(
                "lustre.client.data.bytes",
                unit="By",
                description="Aggregated llite data volume",
            ),
            "lustre.client.rpc.wait.operations": meter.create_counter(
                "lustre.client.rpc.wait.operations",
                unit="1",
                description="Aggregated ptlrpc queue wait count",
            ),
        }
        self._updown_counters = {
            "lustre.client.inflight.requests": meter.create_up_down_counter(
                "lustre.client.inflight.requests",
                unit="1",
                description="Net ptlrpc request lifecycle delta in the current window",
            ),
        }
        self._histograms = {
            "lustre.client.access.duration": meter.create_histogram(
                "lustre.client.access.duration",
                unit="us",
                description="Aggregated llite access latency",
            ),
            "lustre.client.rpc.wait.duration": meter.create_histogram(
                "lustre.client.rpc.wait.duration",
                unit="us",
                description="Aggregated ptlrpc wait latency",
            ),
        }

    def export(self, metrics: list[AggregatedMetric]) -> None:
        for metric in metrics:
            if metric.metric_type == "counter":
                self._counters[metric.name].add(int(metric.value), attributes=metric.attributes)
                continue
            if metric.metric_type == "updowncounter":
                self._updown_counters[metric.name].add(int(metric.value), attributes=metric.attributes)
                continue
            if metric.metric_type == "histogram":
                for value in metric.value:
                    self._histograms[metric.name].record(value, attributes=metric.attributes)

    def shutdown(self) -> None:
        self._provider.shutdown()


def default_resource_attributes(args: argparse.Namespace) -> dict[str, str]:
    host_name = socket.gethostname()
    return {
        "service.name": "lustre-client-observer",
        "service.version": args.service_version,
        "host.name": host_name,
        "host.id": args.host_id or host_name,
        "deployment.environment": args.deployment_environment,
        "lustre.fs.name": args.lustre_fs_name,
        "lustre.client.mount": args.mount,
    }


def _drain_stderr(stderr: Any) -> None:
    for line in iter(stderr.readline, ""):
        sys.stderr.write(line)
        sys.stderr.flush()


def run_observer(args: argparse.Namespace) -> int:
    aggregator = EventWindowAggregator()
    exporter: OpenTelemetryMetricExporter | None = None
    target_major, target_minor = resolve_lustre_mount_identity(args.mount)
    available_symbols = load_traceable_functions()
    if not args.dry_run:
        if not args.collector_endpoint:
            raise SystemExit("--collector-endpoint is required unless --dry-run is set")
        exporter = OpenTelemetryMetricExporter(
            endpoint=args.collector_endpoint,
            resource_attributes=default_resource_attributes(args),
        )

    program_file = tempfile.NamedTemporaryFile("w", suffix=".bt", delete=False)
    program_path = Path(program_file.name)
    try:
        program_file.write(
            build_bpftrace_program(
                args.mount,
                target_major=target_major,
                target_minor=target_minor,
                available_symbols=available_symbols,
            )
        )
        program_file.flush()
        program_file.close()

        process = subprocess.Popen(
            [args.bpftrace_path, "-q", str(program_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        assert process.stdout is not None
        assert process.stderr is not None

        stderr_thread = threading.Thread(target=_drain_stderr, args=(process.stderr,), daemon=True)
        stderr_thread.start()

        stop_requested = False

        def _handle_signal(signum: int, frame: Any) -> None:
            del signum, frame
            nonlocal stop_requested
            stop_requested = True

        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

        started_at = time.monotonic()
        next_flush_at = started_at + args.window_seconds

        while True:
            now = time.monotonic()
            timeout = max(0.0, min(1.0, next_flush_at - now))
            readable, _, _ = select.select([process.stdout], [], [], timeout)

            if readable:
                line = process.stdout.readline()
                if line == "":
                    break
                if line.startswith("EVENT\t"):
                    try:
                        aggregator.consume(parse_event_line(line))
                    except ValueError as exc:
                        print(f"warning: {exc}", file=sys.stderr)

            now = time.monotonic()
            if now >= next_flush_at:
                metrics = aggregator.collect()
                if metrics:
                    if args.dry_run:
                        emit_metrics_json(metrics, sys.stdout)
                    else:
                        assert exporter is not None
                        exporter.export(metrics)
                next_flush_at = now + args.window_seconds
                if args.once:
                    stop_requested = True

            if args.duration and now - started_at >= args.duration:
                stop_requested = True

            if stop_requested and process.poll() is None:
                process.send_signal(signal.SIGINT)

            if stop_requested and process.poll() is not None:
                break

        final_metrics = aggregator.collect()
        if final_metrics:
            if args.dry_run:
                emit_metrics_json(final_metrics, sys.stdout)
            else:
                assert exporter is not None
                exporter.export(final_metrics)

        return process.wait(timeout=5)
    finally:
        if exporter is not None:
            exporter.shutdown()
        try:
            program_path.unlink(missing_ok=True)
        except FileNotFoundError:
            pass


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Lustre client observer MVP")
    parser.add_argument("--mount", default="/mnt/lustre", help="Lustre client mount path")
    parser.add_argument("--duration", type=int, default=0, help="Stop after N seconds")
    parser.add_argument("--window-seconds", type=int, default=10, help="Aggregation window size")
    parser.add_argument("--collector-endpoint", default="", help="OTLP HTTP metrics endpoint")
    parser.add_argument("--dry-run", action="store_true", help="Print aggregated metrics as JSON lines")
    parser.add_argument("--once", action="store_true", help="Flush once and exit")
    parser.add_argument("--bpftrace-path", default=os.environ.get("BPFTRACE", "bpftrace"))
    parser.add_argument("--service-version", default="0.1.0")
    parser.add_argument("--deployment-environment", default="dev")
    parser.add_argument("--lustre-fs-name", default="lustrefs")
    parser.add_argument("--host-id", default="")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return run_observer(args)


if __name__ == "__main__":
    raise SystemExit(main())
