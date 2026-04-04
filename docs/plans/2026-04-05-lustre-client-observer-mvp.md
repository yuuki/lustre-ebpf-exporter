# Lustre Client Observer MVP Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement an MVP for a resident observer that uses llite as the primary observation plane and PtlRPC as the secondary observation plane, and exports per-user and per-process frequency and latency through OTLP Metrics.

**Architecture:** `bpftrace` attaches to the minimum required llite/PtlRPC kprobe/kretprobe points and emits normalized raw events to stdout. The Python agent aggregates those events over 10-second windows, classifies them into metadata/data and actor types, buckets histogram data, and exports the result as OpenTelemetry Metrics. The existing Lima E2E environment is used to deploy the observer and run smoke verification, while static and unit tests lock down the expected behavior.

**Tech Stack:** Bash, bpftrace, Python 3, OpenTelemetry Python SDK, pytest

---

### Task 1: Add unit tests to lock down behavior

**Files:**
- Create: `tests/test_observer_agent.py`

**Step 1: Write the failing test**

```python
def test_parse_llite_event_extracts_actor_and_access_fields():
    ...

def test_window_aggregator_sums_counts_bytes_and_durations():
    ...
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_observer_agent.py -v`
Expected: FAIL with import error because the observer module does not exist yet.

**Step 3: Write minimal implementation**

Create the observer module skeleton with event parsing, aggregation state, actor classification, and metric record generation.

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_observer_agent.py -v`
Expected: PASS

### Task 2: Implement the bpftrace program and observer core

**Files:**
- Create: `tools/lustre_client_observer.py`
- Modify: `tools/lustre_client_trace.sh`

**Step 1: Write the failing test**

Add assertions that the shipped tracing script contains llite/PtlRPC probes and launches the Python observer.

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_lima_lustre_e2e.py -k observer -v`
Expected: FAIL because the current tracer only uses syscall tracepoints.

**Step 3: Write minimal implementation**

Implement:
- `bpftrace` program generation for `ll_lookup_nd`, `ll_file_open`, `ll_file_read_iter`, `ll_file_write_iter`, `ll_fsync`, `ptlrpc_queue_wait`, optional `ptlrpc_send_new_req`, `__ptlrpc_free_req`
- stdout event protocol with `type`, `op`, `uid`, `comm`, `duration_us`, `size_bytes`, `actor_type`
- Python observer CLI that launches `bpftrace`, aggregates windows, and exports OTLP metrics

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_lima_lustre_e2e.py -k observer -v`
Expected: PASS

### Task 3: Update Lima guest wiring and dependencies for the observer

**Files:**
- Modify: `e2e/lima/guest/client-setup.sh`
- Modify: `e2e/lima/scripts/verify-observer.sh`
- Create: `requirements-observer.txt`

**Step 1: Write the failing test**

Extend the static E2E tests to require Python/OpenTelemetry dependencies and observer smoke verification.

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_lima_lustre_e2e.py -v`
Expected: FAIL because the guest setup does not yet install observer runtime deps and smoke verify still expects the old raw syscall tracer.

**Step 3: Write minimal implementation**

Install runtime prerequisites, update smoke verify to run the observer in dry-run/stdout mode, and assert aggregated outputs or exported metric text.

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_lima_lustre_e2e.py -v`
Expected: PASS

### Task 4: Document usage

**Files:**
- Create: `README.md`

**Step 1: Write the failing test**

Extend static tests to require observer architecture and usage documentation.

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_lima_lustre_e2e.py -k readme -v`
Expected: FAIL because the repository root README is missing.

**Step 3: Write minimal implementation**

Document the MVP scope, metrics names, common attributes, runtime prerequisites, and Lima-based verification flow.

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_lima_lustre_e2e.py -k readme -v`
Expected: PASS

### Task 5: Full verification

**Files:**
- Verify only

**Step 1: Run targeted tests**

Run: `pytest tests/test_observer_agent.py tests/test_lima_lustre_e2e.py -v`
Expected: PASS

**Step 2: Review diff for unintended changes**

Run: `git diff --stat`
Expected: only observer-related files changed.
