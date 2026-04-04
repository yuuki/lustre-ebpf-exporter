#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib.sh"

trace_file="/tmp/lustre-trace.log"
trace_err="/tmp/lustre-trace.err"
smoke_file="${CLIENT_MOUNTPOINT}/observer-smoke.bin"

log "verifying minimal client-side observer"
guest_run "${CLIENT_INSTANCE}" /bin/bash -lc "sudo bash -lc '
set -euo pipefail
rm -f ${trace_file} ${trace_err} ${smoke_file}
stdbuf -oL $(guest_repo_root)/tools/lustre_client_trace.sh \
  --mount ${CLIENT_MOUNTPOINT} \
  --window-seconds 5 \
  --duration 30 \
  --dry-run > ${trace_file} 2> ${trace_err} &
tracer_pid=\$!
trap \"kill -INT \${tracer_pid} 2>/dev/null || true; wait \${tracer_pid} || true\" EXIT
sleep 5
dd if=/dev/zero of=${smoke_file} bs=1M count=4 conv=fsync status=none
sync
cat ${smoke_file} >/dev/null
rm -f ${smoke_file}
for _ in \$(seq 1 15); do
  if grep -Fq \"lustre.client.access.operations\" ${trace_file}; then
    break
  fi
  sleep 1
done
kill -INT \${tracer_pid} 2>/dev/null || true
wait \${tracer_pid} || true
grep -F \"lustre.client.access.operations\" ${trace_file}
grep -F \"lustre.client.access.duration\" ${trace_file}
grep -F \"lustre.client.data.bytes\" ${trace_file}
if ! grep -Eq \"\\\"lustre.access.op\\\": \\\"write\\\"\" ${trace_file}; then
  grep -Eq \"\\\"lustre.access.op\\\": \\\"read\\\"\" ${trace_file}
fi
grep -Eq \"\\\"process.name\\\": \\\"[^\\\"]+\\\"\" ${trace_file}
'"
