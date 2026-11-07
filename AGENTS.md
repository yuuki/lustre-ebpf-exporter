# AGENTS.md

Guide for coding agents (and humans) working in this repository. `CLAUDE.md`
imports this file; keep the knowledge here. The user-facing documentation is
[README.md](README.md) (metrics, flags, cardinality controls, limitations).

## Overview and architecture

Lustre eBPF exporter: an eBPF-backed Prometheus exporter that measures Lustre
client activity (llite + PtlRPC) per user and per process on the client node.
It runs as root. Two implementations coexist:

- **First-class**: the Go CO-RE exporter under `cmd/` and `internal/`. All new
  work goes here.
- **Second-class**: the legacy Python + `bpftrace` fallback, confined to
  `legacy/` and frozen (bug fixes only; see [legacy/README.md](legacy/README.md)).
  It is kept only for llite latency and byte metrics the Go path does not yet
  produce in a production-quality way.

### Observation model (shared by both implementations)

1. **llite**, the user-facing workload plane. Required kprobes on
   `ll_lookup_nd`, `ll_file_open`, `ll_file_read_iter`, `ll_file_write_iter`,
   `ll_fsync`, plus required kretprobes on `__x64_sys_openat`, `__x64_sys_read`,
   `__x64_sys_write`, `__x64_sys_fsync` (and an optional one on
   `__x64_sys_openat2`) for return values. Optional kprobe+kretprobe pairs on
   `ll_file_release` (close), `ll_getattr`, `ll_xattr_get_common` (getxattr),
   `ll_xattr_set_common` (setxattr), `ll_mkdir`, `ll_mknod`, `ll_rename`,
   `ll_rmdir`, `ll_setattr`, `ll_statfs`, `ll_create_nd`, `ll_unlink`,
   `ll_link`, `ll_symlink`, `ll_listxattr`, `ll_get_inode_acl`, `ll_get_link`,
   `ll_iterate`. Each op is classified by `lustre.access.intent`:
   `namespace_read`, `namespace_mutation`, `data_read`, `data_write`, `sync`.
   The metadata probes assume Linux 5.12+ idmapped-mount inode_operation
   signatures for several probes (PARM2 holds the inode/dentry/path), with
   compatibility probes for some older Lustre 2.14-era symbols. On an
   unsupported signature a symbol may still attach while `s_dev` extraction
   fails, so it emits nothing. All metadata probes are optional and degrade
   gracefully.
2. **PtlRPC**, the client-internal impact plane. Optional probes on
   `ptlrpc_queue_wait` (kprobe+kretprobe), `ptlrpc_send_new_req`,
   `__ptlrpc_free_req`, and the error/recovery events `ptlrpc_resend_req`,
   `ptlrpc_restart_req`, `ptlrpc_expire_one_request`,
   `ptlrpc_request_handle_notconn`.

The probe lists live in `newEventSource` (`internal/goexporter/runtime_linux.go`).
A required program missing from the object fails startup; a required attach
fails it unless the error reports a missing symbol or
`--legacy-symbol-allow-missing` is set. `loadCollectionWithOptionalPrograms`
retries the load without the optional programs when the full collection is
rejected.

Actors are `user`, `batch_job` (slurm/pbs/sge/lsf), `system_daemon` or
`client_worker` (`ptlrpcd_*`). The BPF program classifies counter-map keys
(`classify_actor_type`, which has no `system_daemon` rule); the perf-event path
classifies in Go (`ClassifyActorType`, `classify.go`) from the unfiltered
process name.

### Go exporter data flow

```
kprobes ──> perf buffer `events` (64-byte observer_event) ──> readLoop ──> Run
        │     select loop ──> histograms / gauges / request counters (updated on arrival)
        └─> PERCPU_HASH counter maps ──> drain goroutine (every --drain-interval,
              read + delete) ──> Go-side accumulators ──> BPFCounterCollector.Collect (scrape)
```

- `internal/bpf/lustre_ebpf_exporter.bpf.c`: the CO-RE BPF program. Mount
  filtering is kernel-side through `config_map` (device numbers → mount index,
  at most 16 mounts). `const volatile uid_labels_enabled` is rewritten before
  load (`--uid-labels=false`). `internal/bpf/spec.go` loads the object that
  bpf2go embeds.
- `internal/goexporter/runtime_linux.go`: `linuxEventSource` loads the
  collection, writes the mount filter, attaches the probes, and runs `readLoop`.
  `runtime_stub.go` is the non-Linux stub (returns an error).
- `internal/goexporter/runtime.go`: `Run` resolves mounts, wires everything, and
  handles perf events in a select loop (no periodic flush timer).
- `internal/goexporter/types.go`: `Event`, `Config`, raw codes and
  `parseObserverEvent`; the Go mirrors of the BPF map keys and values.
- `internal/goexporter/bpf_counter_collector.go`: `BPFCounterCollector`, the
  drain goroutine and the `prometheus.Collector` for the counter families.
- `internal/goexporter/prometheus.go`: `PrometheusExporter` (registry, HTTP
  server, histograms, gauge, request counters) and the label-name builders;
  `aggregate.go` has the matching label-value builders and `InflightTracker`
  (zero-clamped in-flight gauge).
- `mount.go` resolves mount paths to device numbers via `/proc/mounts`;
  `procname.go` resolves a pid to `basename(argv[0])` (TTL cache, pid-reuse
  check); `process_filter.go` normalizes/allowlists process names;
  `username.go` caches uid → username; `slurm/` resolves pid → Slurm job id from
  `/proc/<pid>/environ` and `/proc/<pid>/cgroup` (`--slurm-jobid`).

## Directory layout

| Path | What |
|---|---|
| `cmd/lustre-ebpf-exporter/` | CLI entry point (flags, signals) |
| `cmd/bpf-verifier/` | Loads every program with the verifier log on; run by `make verify-bpf` |
| `internal/bpf/` | BPF C source, `spec.go`; bpf2go output (`*_bpfel.{go,o}`, gitignored) |
| `internal/goexporter/` | Runtime, decoding, aggregation, Prometheus export; `testdata/fuzz/` holds fuzz regression inputs |
| `internal/goexporter/slurm/` | Slurm job id resolver |
| `build/docker/` | Docker build (`go-exporter.Dockerfile`) and verifier (`bpf-verifier.Dockerfile`) images |
| `build/systemd/` | Unit and defaults file shipped in release archives |
| `e2e/lima/` | Lima multi-VM Lustre 2.14 environment (Rocky 8) for both implementations |
| `tests/test_lima_lustre_e2e.py` | Static checks of the Lima harness and repository files |
| `legacy/` | Frozen Python + bpftrace fallback |

## Build

```bash
make generate-go-exporter      # bpf2go codegen (Linux, clang, llvm-strip, libbpf headers)
make generate-go-exporter-all  # both amd64 and arm64 bindings (release builds)
make build-go-exporter         # dist/linux-amd64/lustre-ebpf-exporter (CGO_ENABLED=1)
make docker-build-go-exporter  # recommended Linux artifact build, in Docker
make docker-generate-go-exporter  # codegen in Docker (macOS)
make snapshot / make release-check  # GoReleaser
```

The bpf2go bindings are generated, not committed: every package importing
`internal/bpf` (only on Linux) fails to compile until they exist. The lint and
test targets below generate them when they are missing or older than the BPF
source. The object is embedded in the binary; no separate `.o` is installed.

## Test

| Command | What | Needs |
|---|---|---|
| `make test` (= `make test-go`) | unit tests (`go test ./...`) | on Linux, clang for the bindings; elsewhere the Linux-only code is skipped |
| `make test-race` | unit tests with `-race` | same |
| `make test-fuzz` | every `Fuzz*` target for `FUZZTIME` (30s); `FUZZ_PARALLEL=2` on a shared host | same |
| `make test-integration` | the goexporter tests as root (`sudo` unless root), race-enabled, with `LUSTRE_EBPF_REQUIRE_BPF=1` so that a BPF test cannot skip | root, kernel BTF; no Lustre |
| `make verify-bpf` | verifier run of every program, with the log, in a privileged container | Docker `--privileged` |
| `make bench` | benchmarks to `bench.txt` (gitignored); compare with `benchstat` | — |
| `bash ./e2e/lima/scripts/verify-observer-go.sh` | Go exporter E2E on a real Lustre client | full Lima Lustre environment |
| `bash ./e2e/lima/scripts/verify-observer.sh` | legacy E2E | same |
| `pytest legacy/tests/test_observer_agent.py -q` | legacy unit tests | `legacy/requirements-observer.txt` (e.g. `uvx --with-requirements legacy/requirements-observer.txt pytest ...`) |

Single test: `go test ./internal/goexporter -run TestDirectObserveUpdatesHistogram`.

- Tests that load the embedded object (`TestNewEventSource*`) or create its maps
  (`TestBPFCounterCollectorDrainsEmbeddedMaps`) call `requireEmbeddedObject` and
  skip without privileges; CI runs them as root with `make test-integration`.
  They fake the kprobe attaches, so the runner kernel's verifier is exercised
  but no probe is attached. Kprobe programs cannot be run with
  `BPF_PROG_TEST_RUN`; probe behaviour is only covered by the Lima E2E.
- Fuzz targets: `FuzzParseObserverEvent`, `FuzzProcessLabel`,
  `FuzzMountTable` (Linux), `FuzzDetectLustreMountsFromText`
  (`internal/goexporter`), `FuzzParseSlurmJobIDFromEnviron`,
  `FuzzParseSlurmJobIDFromCgroup`, `FuzzParseProcStatStarttime`
  (`slurm`). A failing input lands in `testdata/fuzz/<Target>/`; commit it as a
  regression seed with the fix.
- `goleak.VerifyTestMain` guards `internal/goexporter`: a test must stop every
  goroutine it starts (close the event source, `Shutdown` the exporter, cancel
  the drain context).
- Tests use fakes, not the host: `newProcNameResolver` and `slurm.Options`
  take file readers, mount parsing takes `realpath`/`stat` functions, and
  `readLoop` takes a `recordReader`.
- `tests/test_lima_lustre_e2e.py` (needs `pyyaml`) is not run in CI and has
  stale assertions (a removed `--bpf-object` flag and `stage-go-exporter`
  target, an old Go image tag, old source strings).

## Static analysis

```bash
make lint          # golangci-lint v2.15.0 (.golangci.yml) + go mod tidy -diff
make fmt           # golangci-lint fmt (gofmt)
make lint-actions  # actionlint + zizmor on .github/ (offline unless GH_TOKEN is set)
make vuln          # govulncheck ./...
make complexity    # cccc ranking (cccc.toml); CI tracks the scores with octocov
```

`GOOS=darwin go vet ./internal/goexporter/ ./cmd/lustre-ebpf-exporter/` checks
that the non-Linux stub still compiles. CodeQL (Go, Python) and govulncheck run
in `.github/workflows/security.yml`.

## Coding conventions

- Comments and docs in English; comments say why. Match the existing density.
- Logging: standard `log` for operational warnings (`warning: ...`), `log/slog`
  only for the debug hex dump. Never log per event outside the
  `LUSTRE_OBSERVER_DEBUG=1` / `LUSTRE_OBSERVER_DEBUG_HEX=1` switches.
- Errors: wrap with `%w`; hot-path lookups (username, process name, Slurm) never
  return errors and fall back to a default value.
- Label values from user-controlled sources (task comm, `argv[0]`, environment)
  are sanitized to valid UTF-8 at the source (`sanitizeComm`,
  `parseCmdlineName`, `parseSlurmJobIDFromEnviron`): Prometheus rejects invalid
  UTF-8, which fails the whole scrape.
- Metric attribute keys use OTel conventions internally (`user.id`,
  `process.name`, `lustre.actor.type`, `lustre.access.intent`) and map to the
  Prometheus label names at export time.
- Commits: short, scoped subjects: `fix: ...`, `build: ...`, `chore: ...`,
  `docs: ...`, `ci: ...`, `refactor: ...`.

## Compatibility contracts

Do not change these silently; call them out in the PR.

- **BPF ↔ Go binary layout**: `struct observer_event` (64 bytes, little-endian)
  ↔ `parseObserverEvent` and `rawObserverEvent` (test mirror); `agg_key`,
  `counter_val`, `error_agg_key`, `error_counter_val`, `mount_key` ↔
  `bpfAggKey`, `bpfCounterVal`, `bpfErrorAggKey`, `bpfErrorCounterVal`,
  `bpfMountKey`. `TestBPFStructLayoutsMatchSource` (C source) and
  `TestBPFMapLayoutsMatchBTF` (compiled BTF) enforce them.
- **Codes**: `OP_*`, `PLANE_*`, `ACTOR_*`, `INTENT_*`, `ERRNO_CLASS_*`,
  `RPC_EVENT_*` in the C source ↔ the `raw*` constants in `types.go`
  (`TestRawOpCodesMatchBPFDefinitions` checks the ops). Op codes 19–26 and plane
  code 3 (removed PCC support) stay reserved and rejected.
- **Map and variable names** the Go side looks up: `events`, `config_map`,
  `llite_counters`, `rpc_counters`, `llite_error_counters`,
  `rpc_error_counters`, `uid_labels_enabled`; program names in the probe lists.
  `config_map` holds 16 entries = `MaxMountPoints`.
- **Metric families** (README "Metrics"): `lustre_client_access_operations_total`,
  `_access_duration_seconds`, `_data_bytes_total`, `_operation_errors_total`,
  `_rpc_wait_operations_total`, `_rpc_wait_duration_seconds`,
  `_rpc_errors_total`, `_inflight_requests`, `_ptlrpc_requests_started_total`,
  `_ptlrpc_requests_completed_total` (all `lustre_client_` prefixed). Label sets
  and their order come from the `build*Labels` builders (`prometheus.go`) and
  the matching value builders (`aggregate.go`); `labels_test.go` pins them.
  `errno_class` and `event` values are closed sets.
- **Label cardinality**: never export pid, path, inode or request pointer
  labels. Histograms omit `process` unless `--histogram-process-labels`.
- **CLI flags** (`cmd/lustre-ebpf-exporter/main.go`, README "Useful flags") and
  the environment variables `LUSTRE_OBSERVER_DEBUG`, `LUSTRE_OBSERVER_DEBUG_HEX`.
- **Release artifacts**: `.goreleaser.yaml` archive names and contents, and the
  systemd unit in `build/systemd/`.

## Concurrency and resource management

- Goroutines: `readLoop` (owned by `linuxEventSource`; `Close` closes the perf
  reader and waits for it via `done`, then the event channel is closed), the
  drain goroutine (`StartDrain`; ends on context cancellation after a final
  drain), and the HTTP server goroutine (ended by `Shutdown`). `Run` returns on
  context cancellation, `--duration`, `--once` or a closed event channel.
- Locks: `BPFCounterCollector.mu` (drain takes the write lock, `Collect` the read
  lock), `InflightTracker.mu`, and the resolver caches' own mutexes.
  `resolveEventIdentity` runs outside every collector lock.
- The scrape path does no BPF syscalls and no `/proc` reads: `Collect` only
  reads the Go-side accumulators.
- `newEventSource` must close everything it opened on every error path
  (`TestNewEventSourceFailures` counts file descriptors).
- The perf channel holds 1024 events; when the consumer falls behind, the perf
  buffer overflows and lost samples are logged.

## Performance constraints

- The per-event path (decode, process name, filter, histogram observe) runs for
  every llite/PtlRPC event: no per-event syscalls on cache hits, no extra
  allocations, no logging. `bench_test.go` covers it; compare with `make bench`
  and `benchstat` before and after hot-path changes.
- BPF maps are bounded (`max_entries`); the Go-side accumulators grow with the
  label combinations seen. Keep label domains small.
- BPF program changes must keep passing the verifier on old and new kernels;
  `cccc.toml` excludes them from complexity tracking for that reason.

## Before opening a PR

1. `make check` (lint, lint-actions, test-race) passes.
2. `make test-integration` (root) when touching the BPF program, the runtime,
   map handling or the collector; `make verify-bpf` for BPF program changes.
3. `make test-fuzz` (or the relevant targets) when touching a parser or decoder.
4. `pytest legacy/tests/test_observer_agent.py -q` when fixing `legacy/`.
5. README updated for user-visible changes (metrics, labels, flags).

## Rules for AI agents

Forbidden:

- Disabling, skipping, deleting or weakening tests, lint rules or CI checks to
  get green (no `|| true`, `continue-on-error`, blanket excludes, loosened
  assertions). Report flaky tests as flaky.
- Editing generated files by hand (`internal/bpf/*_bpfel.*`); regenerate them.
- Adding features to `legacy/` (bug fixes only) or touching it beyond the fix.
- Adding dependencies without a written justification.
- Changing a compatibility contract above without calling it out.
- Loosening workflow `permissions`, unpinning actions, or adding
  `pull_request_target`.
- Committing secrets; rewriting history or force-pushing; tagging or publishing
  releases.

## Changes that need human review

Even when CI is green: `.github/workflows/`, `.goreleaser.yaml` and release
packaging; permissions and secrets; the BPF program and anything that loads or
attaches it (it runs in the kernel as root); parsers of data other processes
control (perf events, `/proc/<pid>/*`, `/proc/mounts`); the compatibility
contracts above; dependency additions; large refactors.
