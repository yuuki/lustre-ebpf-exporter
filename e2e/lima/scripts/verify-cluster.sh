#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib.sh"

log "verifying server exports"
guest_run "${SERVER_INSTANCE}" /bin/bash -lc "sudo mount | grep -q ' ${SERVER_MDT_MOUNTPOINT} ' && sudo mount | grep -q ' ${SERVER_OST_MOUNTPOINT} '"

log "verifying client mount"
guest_run "${CLIENT_INSTANCE}" /bin/bash -lc "sudo mount | grep -q ' ${CLIENT_MOUNTPOINT} '"

log "running smoke IO on client"
guest_run "${CLIENT_INSTANCE}" /bin/bash -lc "sudo bash -lc 'set -euo pipefail; cd ${CLIENT_MOUNTPOINT}; dd if=/dev/zero of=smoke.bin bs=1M count=8 status=none; sync; ls -lh smoke.bin; rm -f smoke.bin'"

log "dumping Lustre capacity"
guest_run "${CLIENT_INSTANCE}" /bin/bash -lc "sudo lfs df -h ${CLIENT_MOUNTPOINT}"
