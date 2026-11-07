# AGENTS.md

This file holds only what the code does not show: the rules, contracts and
policies for changing lustre-ebpf-exporter.

## Rules the code does not show

- New work goes to the Go CO-RE exporter (`cmd/`, `internal/`). `legacy/`
  (Python + bpftrace) is frozen: bug fixes only, nothing beyond the fix.
- Cardinality: never export pid, path, inode or request-pointer labels; keep
  label domains small (the Go-side accumulators keep every combination seen).
- Make label values from user-controlled sources (task comm, `argv[0]`,
  environment) valid UTF-8 where they are read (`sanitizeComm`,
  `parseCmdlineName`, `parseSlurmJobIDFromEnviron`): one invalid value fails
  the whole scrape.
- Per-event path: no syscalls on cache hits, no extra allocations, no logging
  outside the `LUSTRE_OBSERVER_DEBUG*` switches; lookups (username, process
  name, Slurm) fall back to a default instead of returning errors.
- The scrape (`Collect`) does no BPF syscalls and no `/proc` reads;
  `resolveEventIdentity` runs outside every collector lock.
- Actor and intent classification exist in C (`classify_actor_type`,
  `intent_for_op`) and in Go (`ClassifyActorType`, `intentForOp`): change
  both sides together (only the Go side has a `system_daemon` rule).
- English for code, comments, docs and commit messages.

## Compatibility contracts

Call any change out in the pull request.

- BPF ↔ Go layout: `struct observer_event` and the map key/value structs in
  `internal/bpf/lustre_ebpf_exporter.bpf.c` ↔ `parseObserverEvent` and the
  `bpf*` mirrors in `internal/goexporter/types.go`.
- Codes (`OP_*`, `PLANE_*`, `ACTOR_*`, `INTENT_*`, `ERRNO_CLASS_*`,
  `RPC_EVENT_*`) ↔ the `raw*` constants in `types.go`.
- Map, variable and program names looked up in
  `internal/goexporter/runtime_linux.go`; `config_map` size ↔ `MaxMountPoints`.
- Metric families and label sets and order: `build*Labels` (`prometheus.go`)
  ↔ the value builders (`aggregate.go`); `errno_class` and `event` values
  are closed sets.
- CLI flags (`cmd/lustre-ebpf-exporter/main.go`), `LUSTRE_OBSERVER_DEBUG*`.
- Release artifacts: `.goreleaser.yaml` archives and `build/systemd/`.

## Before opening a pull request

- `make check`.
- BPF program, runtime, map handling or collector: `make test-integration`
  (root). BPF program: also `make verify-bpf` and, where available, the Lima
  E2E (`bash ./e2e/lima/scripts/verify-observer-go.sh`), the only test that
  runs the probes.
- Parser or decoder: `make test-fuzz`; commit crashers as regression seeds.
- Per-event path: `make bench` before and after, compared with `benchstat`.
- Linux-only code or its stub:
  `GOOS=darwin go vet ./internal/goexporter/ ./cmd/lustre-ebpf-exporter/`.
- `legacy/` fix: `pytest legacy/tests/test_observer_agent.py -q`.
- Metrics, labels or flags: README updated.

## Git conventions

Branches: `<type>/<issue>-<summary>`, or `<type>/<summary>` without an issue
(`fix/166-connect-errors`, `feat/qp-counters`). `<type>` is a commit type
below; `<summary>` is 2–5 lowercase ASCII words joined by `-`. Branches named
by tools keep their names (`agent/*`, `claude/*`, `copilot/*`,
`dependabot/*`). Never push to the default branch.

Commits follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):

    <type>(<scope>)!: <subject>

    <body>

    <footer>

- `type`: `feat` (new user-visible behaviour), `fix` (bug fix), `perf`,
  `refactor` (no behaviour change), `test`, `docs`, `build` (build system,
  dependencies, packaging), `ci` (workflows), `chore` (anything else, e.g.
  `chore(release): prepare v1.2.3`), `revert`.
- `scope`: optional; the package or area changed: `bpf`, `goexporter`,
  `slurm`, `bpf-verifier`, `legacy`, `e2e`.
- `!` and a `BREAKING CHANGE: <what changed and how to migrate>` footer for
  any change to a compatibility contract above.
- `subject`: imperative, lower case (except identifiers), no final period,
  at most 72 characters including the prefix.
- `body`: why the change is needed and what it affects, wrapped at 72
  columns; required unless the subject says everything.
- `footer`: `Fixes #N` / `Refs #N`, `BREAKING CHANGE:`, trailers such as
  `Co-Authored-By:`.
- One logical change per commit; regenerated files go in the commit that
  changes their source. Pull request titles use the same format (they become
  the squash commit).

## Forbidden

- Disabling, skipping, deleting or weakening tests, lint rules or CI checks
  to get green (`|| true`, `continue-on-error`, blanket excludes, loosened
  assertions). Report flaky tests as flaky.
- Editing the generated `internal/bpf/*_bpfel.*` by hand; regenerate them.
- Adding dependencies without a written justification.
- Changing a compatibility contract without calling it out.
- Loosening workflow `permissions`, unpinning actions or adding
  `pull_request_target`.
- Committing secrets, rewriting history, force-pushing, tagging or publishing
  releases.

## Needs human review

Even with green CI: `.github/workflows/`, `.goreleaser.yaml` and release
packaging; permissions and secrets; the BPF program and anything that loads
or attaches it (it runs in the kernel as root); parsers of data other
processes control (perf events, `/proc/<pid>/*`, `/proc/mounts`); the
compatibility contracts; dependency additions; large refactors.

## Environment notes

- On Linux, plain `go build`/`go test` fail until a make target has
  generated the uncommitted bpf2go bindings (clang, llvm-strip, libbpf).
- `tests/test_lima_lustre_e2e.py` is not run in CI and has stale assertions.
- With `GH_TOKEN` set but the GitHub API unreachable, run
  `env -u GH_TOKEN make check`.
