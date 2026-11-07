# Security policy

lustre-ebpf-exporter runs as root on Lustre client nodes. It loads eBPF
programs into the kernel and attaches them to Lustre and syscall functions,
reads `/proc/mounts` and the `/proc/<pid>/` files (`cmdline`, `stat`, `environ`,
`cgroup`) of every process that touches a monitored mount, and serves the
resulting metrics over unauthenticated HTTP (`:9108` by default). Process
names, Slurm job ids and other values that unprivileged users control become
metric labels, so a local user is part of the threat model. Security issues are
taken seriously.

Examples of what is in scope: a way for an unprivileged local user to crash or
stall the exporter, make its scrapes fail, read memory or files through it, or
influence what the BPF programs do; BPF programs that can fault, leak kernel
memory or be rejected in a way that disables monitoring silently; information
in the metrics beyond the documented labels (README "Metrics"). By design the
metrics expose usernames, uids, process names and Slurm job ids to whoever can
reach the listen address; restrict it with `--web.listen-address` and the
firewall rather than reporting this as a vulnerability. The frozen Python
fallback under `legacy/` receives security fixes too.

## Supported versions

Security fixes are made on the `main` branch and released in the next version.
Only the latest release is supported.

## Reporting a vulnerability

Please do **not** open a public issue, pull request or discussion.

Report the vulnerability privately with GitHub's
[private vulnerability reporting](https://github.com/yuuki/lustre-ebpf-exporter/security/advisories/new)
(the "Report a vulnerability" button of the Security tab). If that is not
possible, contact the author privately via the contact information on
https://github.com/yuuki.

Please include the exporter version (`lustre-ebpf-exporter --version`), the
kernel and Lustre client versions, the command line, what an attacker controls
(a local unprivileged process, the network path to the metrics port, a Lustre
server, ...), and the impact, with steps to reproduce if you can. You should
receive an answer within a few weeks; the project is maintained on a
best-effort basis.

## Verifying releases

Each release publishes a `checksums.txt` (SHA-256) next to its archives; check a
download against it before installing.
