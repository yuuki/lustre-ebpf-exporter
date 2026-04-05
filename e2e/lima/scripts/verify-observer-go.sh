#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib.sh"

metrics_file="/tmp/lustre-go-observer.metrics"
smoke_file="${CLIENT_MOUNTPOINT}/observer-go-smoke.bin"
binary_path="$(guest_repo_root)/dist/linux-amd64/lustre-client-observer"
bpf_object_path="$(guest_repo_root)/dist/linux-amd64/lustre_client_observer.bpf.o"

log "verifying Go CO-RE client-side observer"
guest_run "${CLIENT_INSTANCE}" /bin/bash -lc "sudo bash -lc '
set -euo pipefail
test -x ${binary_path}
test -f ${bpf_object_path}
rm -f ${metrics_file} ${smoke_file}
stdbuf -oL ${binary_path} \
  --mount ${CLIENT_MOUNTPOINT} \
  --web.listen-address :9108 \
  --web.telemetry-path /metrics \
  --bpf-object ${bpf_object_path} &
tracer_pid=\$!
trap \"kill -INT \${tracer_pid} 2>/dev/null || true; wait \${tracer_pid} || true\" EXIT
sleep 5
dd if=/dev/zero of=${smoke_file} bs=1M count=4 conv=fsync status=none
sync
cat ${smoke_file} >/dev/null
rm -f ${smoke_file}
for _ in \$(seq 1 15); do
  if curl -fsS http://127.0.0.1:9108/metrics > ${metrics_file}; then
    break
  fi
  sleep 1
done
grep -F \"lustre_client_access_operations_total\" ${metrics_file}
grep -F \"lustre_client_access_duration_seconds\" ${metrics_file}
grep -F \"lustre_client_data_bytes_total\" ${metrics_file}
'"
