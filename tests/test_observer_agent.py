from __future__ import annotations

import os
import sys
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lustre_client_observer.agent import (
    AggregatedMetric,
    EventWindowAggregator,
    build_bpftrace_program,
    classify_actor_type,
    load_traceable_functions,
    parse_event_line,
    resolve_lustre_mount_identity,
    validate_lustre_mount_selection,
)


def test_classify_actor_type_distinguishes_worker_and_daemon() -> None:
    assert classify_actor_type("ptlrpcd_01_104") == "worker"
    assert classify_actor_type("node_exporter") == "daemon"
    assert classify_actor_type("bash") == "user"


def test_parse_llite_event_extracts_access_fields() -> None:
    event = parse_event_line(
        "EVENT\tplane=llite\top=read\tuid=1000\tcomm=python\tpid=4321\tduration_us=125\tsize_bytes=4096"
    )

    assert event.plane == "llite"
    assert event.op == "read"
    assert event.uid == 1000
    assert event.comm == "python"
    assert event.pid == 4321
    assert event.duration_us == 125
    assert event.size_bytes == 4096
    assert event.access_class == "data"
    assert event.actor_type == "user"


def test_parse_ptlrpc_event_infers_worker_actor() -> None:
    event = parse_event_line(
        "EVENT\tplane=ptlrpc\top=queue_wait\tuid=0\tcomm=ptlrpcd_00_01\tpid=99\tduration_us=80\trequest_ptr=0xffff"
    )

    assert event.plane == "ptlrpc"
    assert event.op == "queue_wait"
    assert event.actor_type == "worker"
    assert event.request_ptr == "0xffff"


def test_window_aggregator_sums_counts_bytes_and_durations() -> None:
    aggregator = EventWindowAggregator()
    aggregator.consume(
        parse_event_line(
            "EVENT\tplane=llite\top=write\tuid=1001\tcomm=dd\tpid=200\tduration_us=250\tsize_bytes=1048576"
        )
    )
    aggregator.consume(
        parse_event_line(
            "EVENT\tplane=llite\top=write\tuid=1001\tcomm=dd\tpid=200\tduration_us=500\tsize_bytes=524288"
        )
    )
    aggregator.consume(
        parse_event_line(
            "EVENT\tplane=ptlrpc\top=queue_wait\tuid=1001\tcomm=dd\tpid=200\tduration_us=75\trequest_ptr=0x1"
        )
    )

    metrics = aggregator.collect()

    assert AggregatedMetric(
        name="lustre.client.access.operations",
        value=2,
        unit="1",
        metric_type="counter",
        attributes={
            "user.id": "1001",
            "process.name": "dd",
            "lustre.access.class": "data",
            "lustre.access.op": "write",
            "lustre.actor.type": "user",
        },
    ) in metrics
    assert AggregatedMetric(
        name="lustre.client.data.bytes",
        value=1572864,
        unit="By",
        metric_type="counter",
        attributes={
            "user.id": "1001",
            "process.name": "dd",
            "lustre.access.class": "data",
            "lustre.access.op": "write",
            "lustre.actor.type": "user",
        },
    ) in metrics
    assert AggregatedMetric(
        name="lustre.client.rpc.wait.operations",
        value=1,
        unit="1",
        metric_type="counter",
        attributes={
            "user.id": "1001",
            "process.name": "dd",
            "lustre.actor.type": "user",
            "lustre.access.op": "queue_wait",
        },
    ) in metrics

    duration_metrics = [
        metric
        for metric in metrics
        if metric.name == "lustre.client.access.duration" and metric.attributes["process.name"] == "dd"
    ]
    assert len(duration_metrics) == 1
    assert duration_metrics[0].value == [250, 500]
    assert duration_metrics[0].unit == "us"
    assert duration_metrics[0].metric_type == "histogram"


def test_inflight_requests_uses_single_attribute_set_for_send_and_free() -> None:
    aggregator = EventWindowAggregator()
    aggregator.consume(
        parse_event_line(
            "EVENT\tplane=ptlrpc\top=send_new_req\tuid=1001\tcomm=dd\tpid=200\tduration_us=0\tsize_bytes=0\trequest_ptr=0x1"
        )
    )
    aggregator.consume(
        parse_event_line(
            "EVENT\tplane=ptlrpc\top=free_req\tuid=1001\tcomm=dd\tpid=200\tduration_us=0\tsize_bytes=0\trequest_ptr=0x1"
        )
    )

    metrics = aggregator.collect()

    assert AggregatedMetric(
        name="lustre.client.inflight.requests",
        value=0,
        unit="1",
        metric_type="updowncounter",
        attributes={
            "user.id": "1001",
            "process.name": "dd",
            "lustre.actor.type": "user",
        },
    ) in metrics


def test_validate_lustre_mount_selection_accepts_matching_mount_with_multiple_lustre_mounts() -> None:
    mounts_text = (
        "10.0.0.1@tcp:/fs1 /mnt/lustre1 lustre rw 0 0\n"
        "10.0.0.1@tcp:/fs2 /mnt/lustre2 lustre rw 0 0\n"
    )

    class FakeStat:
        st_dev = 1

    validate_lustre_mount_selection(
        "/mnt/lustre1",
        mounts_text=mounts_text,
        realpath_fn=lambda path: path,
        stat_fn=lambda path: FakeStat(),
    )


def test_validate_lustre_mount_selection_accepts_single_matching_mount() -> None:
    mounts_text = "10.0.0.1@tcp:/fs1 /mnt/lustre lustre rw 0 0\n"

    class FakeStat:
        st_dev = 1

    validate_lustre_mount_selection(
        "/mnt/lustre",
        mounts_text=mounts_text,
        realpath_fn=lambda path: path,
        stat_fn=lambda path: FakeStat(),
    )


def test_resolve_lustre_mount_identity_uses_major_minor_from_stat_device() -> None:
    class FakeStat:
        st_dev = 424242

    def fake_realpath(path: str) -> str:
        return path

    def fake_stat(path: str) -> FakeStat:
        assert path == "/mnt/lustre1"
        return FakeStat()

    mounts_text = (
        "10.0.0.1@tcp:/fs1 /mnt/lustre1 lustre rw 0 0\n"
        "10.0.0.1@tcp:/fs2 /mnt/lustre2 lustre rw 0 0\n"
    )

    assert (
        resolve_lustre_mount_identity(
            "/mnt/lustre1",
            mounts_text=mounts_text,
            realpath_fn=fake_realpath,
            stat_fn=fake_stat,
        )
        == (os.major(424242), os.minor(424242))
    )


def test_observer_cli_help_runs_from_tools_entrypoint() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools/lustre_client_observer.py"), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Lustre client observer MVP" in result.stdout


def test_load_traceable_functions_parses_function_names() -> None:
    functions = load_traceable_functions(
        text="ll_lookup_nd [lustre]\nptlrpc_queue_wait [ptlrpc]\n__x64_sys_read\n"
    )

    assert "ll_lookup_nd" in functions
    assert "ptlrpc_queue_wait" in functions
    assert "__x64_sys_read" in functions


def test_build_bpftrace_program_skips_missing_optional_ptlrpc_probes() -> None:
    program = build_bpftrace_program(
        "/mnt/lustre",
        target_major=977,
        target_minor=981636,
        available_symbols={
            "ll_lookup_nd",
            "ll_file_open",
            "ll_file_read_iter",
            "ll_file_write_iter",
            "ll_fsync",
            "ptlrpc_queue_wait",
        },
    )

    assert "kprobe:ptlrpc_queue_wait" in program
    assert "kprobe:ptlrpc_send_new_req" not in program
    assert "kprobe:__ptlrpc_free_req" not in program
    assert "@target_major" not in program
    assert "@target_minor" not in program
    assert "$target_major = (uint64)977;" in program
    assert "$target_minor = (uint64)981636;" in program
    assert "($dev >> 20) == $target_major" in program
    assert "($dev & 1048575) == $target_minor" in program
    assert "@selected_mount_tid[tid] = 1;" in program
    assert "@tracked_req[arg0] = 1;" in program
