# Contributing to lustre-ebpf-exporter

Thanks for helping. The [README](README.md) describes what the exporter
measures and how to run it; [AGENTS.md](AGENTS.md) is the full guide to the
code, every make target and the compatibility contracts, for people and coding
agents alike.

## Proposing a change

- Report bugs and propose features in
  [GitHub issues](https://github.com/yuuki/lustre-ebpf-exporter/issues).
  Include the exporter version, the kernel and Lustre client versions, the
  command line and the relevant log lines. Report security issues privately as
  described in [SECURITY.md](SECURITY.md).
- New work targets the Go exporter (`cmd/`, `internal/`). `legacy/` is frozen:
  bug fixes only.
- Keep pull requests small and focused, and explain why the change is needed.
  Changes to metric names, labels, flags or the BPF event layout are
  compatibility changes: say so in the description.

## Before you open a pull request

On Linux with clang, llvm and the libbpf headers installed:

```bash
make check             # golangci-lint, go mod tidy, actionlint + zizmor, race tests
make test-integration  # as root: BPF loading tests (when touching BPF or the runtime)
```

Add tests for behaviour changes; run `make test-fuzz` when you touch a parser.
AGENTS.md lists what else to run for which change.

## Style

- Code comments and documentation in English.
- Commit subjects are short and scoped: `fix: ...`, `build: ...`, `ci: ...`,
  `docs: ...`, `refactor: ...`, `chore: ...`.
- AI-assisted contributions are welcome, but a human must review them before
  they are submitted.
