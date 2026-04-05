#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib.sh"

metrics_file="/tmp/lustre-go-observer.metrics"
log_file="/tmp/lustre-go-observer.log"
smoke_file="${CLIENT_MOUNTPOINT}/observer-go-smoke.bin"
binary_path="$(guest_repo_root)/dist/linux-amd64/lustre-ebpf-exporter"
bpf_object_path="$(guest_repo_root)/dist/linux-amd64/lustre_ebpf_exporter.bpf.o"

log "verifying Go CO-RE client-side observer"
guest_run "${CLIENT_INSTANCE}" sudo bash <<EOF
set -euo pipefail
test -x "${binary_path}"
test -f "${bpf_object_path}"
pkill -f "${binary_path}" || true
for _ in \$(seq 1 20); do
  if ! pgrep -f "${binary_path}" >/dev/null 2>&1 && ! ss -ltn | grep -F ':9108' >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
rm -f "${metrics_file}" "${log_file}" "${smoke_file}"
nohup "${binary_path}" \
  --mount "${CLIENT_MOUNTPOINT}" \
  --window-seconds 2 \
  --web.listen-address :9108 \
  --web.telemetry-path /metrics \
  --bpf-object "${bpf_object_path}" \
  >"${log_file}" 2>&1 &
tracer_pid=\$!
trap 'kill -INT \${tracer_pid} 2>/dev/null || true; wait \${tracer_pid} || true' EXIT
sleep 5
dd if=/dev/zero of="${smoke_file}" bs=1M count=4 conv=fsync status=none
sync
cat "${smoke_file}" >/dev/null
rm -f "${smoke_file}"
for _ in \$(seq 1 20); do
  if curl -fsS http://127.0.0.1:9108/metrics > "${metrics_file}"; then
    if grep -Fq "lustre_client_access_operations_total" "${metrics_file}"; then
      break
    fi
  fi
  sleep 1
done
grep -F "lustre_client_access_operations_total" "${metrics_file}"
if grep -F 'process=""' "${metrics_file}" >/dev/null; then
  echo "unexpected empty process label in Go exporter metrics" >&2
  exit 1
fi
cat "${log_file}" >/dev/null
EOF
