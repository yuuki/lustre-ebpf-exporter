#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: lustre_client_trace.sh [--mount /mnt/lustre] [--duration 15]

Trace client-side Lustre access on a mounted path using syscall tracepoints.
Outputs one line per event:
  EVENT<TAB><op><TAB>pid=...<TAB>uid=...<TAB>comm=...<TAB>...
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "required command not found: $1" >&2
    exit 1
  }
}

regex_escape() {
  printf '%s' "$1" | sed -e 's/[][(){}.^$?+*|]/\\&/g' -e 's/\//\\\//g'
}

mount_path="/mnt/lustre"
duration=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mount)
      mount_path="$2"
      shift 2
      ;;
    --duration)
      duration="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

require_cmd bpftrace

if [[ ! -d "${mount_path}" ]]; then
  echo "mount path does not exist: ${mount_path}" >&2
  exit 1
fi

trace_root="/sys/kernel/debug/tracing"
if [[ ! -d "${trace_root}" ]]; then
  mkdir -p /sys/kernel/debug
  mount -t tracefs nodev /sys/kernel/debug/tracing 2>/dev/null || true
fi

program_file="$(mktemp)"
cleanup() {
  rm -f "${program_file}"
}
trap cleanup EXIT

cat >"${program_file}" <<EOF
BEGIN
{
  printf("TRACE_START\\tmount=${mount_path}\\n");
}

tracepoint:syscalls:sys_enter_openat
{
  @open_path[tid] = str(args->filename);
  @open_seen[tid] = 1;
}

tracepoint:syscalls:sys_enter_open
{
  @open_path[tid] = str(args->filename);
  @open_seen[tid] = 1;
}

tracepoint:syscalls:sys_exit_openat
/@open_seen[tid]/
{
  \$path = @open_path[tid];
  if (args->ret >= 0 && strncmp(\$path, "${mount_path}", ${#mount_path}) == 0) {
    @fd_path[pid, args->ret] = \$path;
    @fd_seen[pid, args->ret] = 1;
    printf("EVENT\\topen\\tpid=%d\\tuid=%d\\tcomm=%s\\tfd=%d\\tret=%d\\tpath=%s\\n",
      pid, uid, comm, args->ret, args->ret, \$path);
  }
  delete(@open_path[tid]);
  delete(@open_seen[tid]);
}

tracepoint:syscalls:sys_exit_open
/@open_seen[tid]/
{
  \$path = @open_path[tid];
  if (args->ret >= 0 && strncmp(\$path, "${mount_path}", ${#mount_path}) == 0) {
    @fd_path[pid, args->ret] = \$path;
    @fd_seen[pid, args->ret] = 1;
    printf("EVENT\\topen\\tpid=%d\\tuid=%d\\tcomm=%s\\tfd=%d\\tret=%d\\tpath=%s\\n",
      pid, uid, comm, args->ret, args->ret, \$path);
  }
  delete(@open_path[tid]);
  delete(@open_seen[tid]);
}

tracepoint:syscalls:sys_enter_write
/@fd_seen[pid, args->fd]/
{
  @write_start[tid] = nsecs;
  @write_fd[tid] = args->fd;
  @write_count[tid] = args->count;
}

tracepoint:syscalls:sys_exit_write
/@write_start[tid]/
{
  \$fd = @write_fd[tid];
  \$path = @fd_path[pid, \$fd];
  printf("EVENT\\twrite\\tpid=%d\\tuid=%d\\tcomm=%s\\tfd=%d\\tret=%d\\tcount=%d\\tlat_us=%llu\\tpath=%s\\n",
    pid, uid, comm, \$fd, args->ret, @write_count[tid], (nsecs - @write_start[tid]) / 1000, \$path);
  delete(@write_start[tid]);
  delete(@write_fd[tid]);
  delete(@write_count[tid]);
}

tracepoint:syscalls:sys_enter_read
/@fd_seen[pid, args->fd]/
{
  @read_start[tid] = nsecs;
  @read_fd[tid] = args->fd;
  @read_count[tid] = args->count;
}

tracepoint:syscalls:sys_exit_read
/@read_start[tid]/
{
  \$fd = @read_fd[tid];
  \$path = @fd_path[pid, \$fd];
  printf("EVENT\\tread\\tpid=%d\\tuid=%d\\tcomm=%s\\tfd=%d\\tret=%d\\tcount=%d\\tlat_us=%llu\\tpath=%s\\n",
    pid, uid, comm, \$fd, args->ret, @read_count[tid], (nsecs - @read_start[tid]) / 1000, \$path);
  delete(@read_start[tid]);
  delete(@read_fd[tid]);
  delete(@read_count[tid]);
}

tracepoint:syscalls:sys_enter_close
/@fd_seen[pid, args->fd]/
{
  @close_fd[tid] = args->fd;
}

tracepoint:syscalls:sys_exit_close
/@close_fd[tid]/
{
  \$fd = @close_fd[tid];
  \$path = @fd_path[pid, \$fd];
  printf("EVENT\\tclose\\tpid=%d\\tuid=%d\\tcomm=%s\\tfd=%d\\tret=%d\\tpath=%s\\n",
    pid, uid, comm, \$fd, args->ret, \$path);
  if (args->ret == 0) {
    delete(@fd_path[pid, \$fd]);
    delete(@fd_seen[pid, \$fd]);
  }
  delete(@close_fd[tid]);
}
EOF

if [[ -n "${duration}" ]]; then
  bpftrace -q "${program_file}" &
  tracer_pid=$!
  sleep "${duration}"
  kill -INT "${tracer_pid}" 2>/dev/null || true
  wait "${tracer_pid}" || true
  exit 0
fi

exec bpftrace -q "${program_file}"
