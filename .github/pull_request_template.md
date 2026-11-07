## What and why

<!-- What does this change, and which issue does it address (Closes #...)? -->

## How it was tested

<!-- Unit, fuzz and race tests, `make test-integration` (root), `make verify-bpf`, the Lima E2E, manual checks. -->

## Checklist

- [ ] `make check` passes (and `make test-integration` as root for changes to
      the BPF program, the runtime or the counter maps).
- [ ] Behaviour changes come with tests; parser changes keep the fuzz targets
      passing (`make test-fuzz`).
- [ ] README (metrics, labels, flags) and AGENTS.md are updated where needed.
- [ ] Public contracts (metric names and labels, CLI flags, the BPF event and
      map layouts) are unchanged, or the change is called out above.
- [ ] AI-assisted changes have been reviewed by a human.
