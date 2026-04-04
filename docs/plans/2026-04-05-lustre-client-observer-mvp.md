# Lustre Client Observer MVP Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** llite を主観測面、PtlRPC を補助観測面とする常駐 observer の MVP を実装し、uid・process 単位の頻度と遅延を OTLP Metrics として送れるようにする。

**Architecture:** `bpftrace` は llite/PtlRPC の必要最小限の kprobe/kretprobe に attach し、stdout へ正規化済み raw event を出力する。Python エージェントはその出力を 10 秒窓で集約し、metadata/data 分類・actor 分類・Histogram bucket 化を行って OpenTelemetry Metrics として export する。既存 Lima E2E は observer の配備と smoke verify を担い、静的テストとユニットテストで仕様を固定する。

**Tech Stack:** Bash, bpftrace, Python 3, OpenTelemetry Python SDK, pytest

---

### Task 1: 仕様を固定するユニットテストを追加

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

### Task 2: bpftrace プログラムと observer 本体を実装

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

### Task 3: Lima guest 導線と依存関係を observer 用に更新

**Files:**
- Modify: `e2e/lima/guest/client-setup.sh`
- Modify: `e2e/lima/scripts/verify-observer.sh`
- Create: `requirements-observer.txt`

**Step 1: Write the failing test**

Extend E2E static tests to require Python/OpenTelemetry 依存と observer smoke verify.

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_lima_lustre_e2e.py -v`
Expected: FAIL because the guest setup does not yet install observer runtime deps and smoke verify still expects the old raw syscall tracer.

**Step 3: Write minimal implementation**

Install runtime prerequisites, update smoke verify to run the observer in dry-run/stdout mode, and assert aggregated outputs or exported metric text.

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_lima_lustre_e2e.py -v`
Expected: PASS

### Task 4: 利用手順を文書化

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

### Task 5: フル検証

**Files:**
- Verify only

**Step 1: Run targeted tests**

Run: `pytest tests/test_observer_agent.py tests/test_lima_lustre_e2e.py -v`
Expected: PASS

**Step 2: Review diff for unintended changes**

Run: `git diff --stat`
Expected: only observer-related files changed.
