# AGENTS.md

## Rules
- `legacy/` (Python + bpftrace) is frozen: bug fixes only, nothing beyond the fix; new work goes to the Go exporter (`cmd/`, `internal/`).
- Every `actor_type` label comes from Go's `ClassifyActorType` (counters classify the key's comm); C's `classify_actor_type` only fills the map key. Intent classification exists in C (`intent_for_op`) and Go (`intentForOp`): change both together.
- Per-event lookups (username, process name, Slurm) fall back to a default instead of returning an error; no per-event logging outside `LUSTRE_OBSERVER_DEBUG*`.
- `tests/test_lima_lustre_e2e.py` is not run in CI and has stale assertions.

## Compatibility contracts
- `struct observer_event` and map key/value structs (`internal/bpf/lustre_ebpf_exporter.bpf.c`) ↔ `parseObserverEvent` and the `bpf*` mirrors (`types.go`).
- `OP_*`, `PLANE_*`, `ACTOR_*`, `INTENT_*`, `ERRNO_CLASS_*`, `RPC_EVENT_*` ↔ the `raw*` constants in `internal/goexporter/types.go`.
- Map, variable and program names looked up in `internal/goexporter/runtime_linux.go`; the `config_map` size ↔ `MaxMountPoints`.
- Metric families, label sets and order: `build*Labels` (`prometheus.go`) ↔ the value builders (`aggregate.go`); `errno_class` and `event` are closed sets.
- CLI flags (`cmd/lustre-ebpf-exporter/main.go`), `LUSTRE_OBSERVER_DEBUG*`, release archives (`.goreleaser.yaml`) and `build/systemd/`.

## Before opening a pull request
- `make check`; also `make test-integration` (root) for the BPF program, the runtime, map handling or the collector.
- BPF program: also `make verify-bpf` and, where available, `bash ./e2e/lima/scripts/verify-observer-go.sh`, the only test that runs the probes.
- Parser or decoder: `make test-fuzz`; per-event path: `make bench` before and after.
- Linux-only code or its stub: `GOOS=darwin go vet ./internal/goexporter/ ./cmd/lustre-ebpf-exporter/`.
- A `legacy/` fix: `pytest legacy/tests/test_observer_agent.py -q`.

## Git conventions
- Branches: `<type>/<issue>-<summary>` (`<type>/<summary>` without an issue); tools' `agent/*`, `claude/*`, `copilot/*`, `dependabot/*` keep their names.
- Commits and PR titles: Conventional Commits 1.0.0, types `feat` `fix` `perf` `refactor` `test` `docs` `build` `ci` `chore` `revert`; scopes: `bpf`, `goexporter`, `slurm`, `bpf-verifier`, `legacy`, `e2e`.
