#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib.sh"

GUEST_REPO_ROOT="$(guest_repo_root)"
COMMON_SCRIPT="${GUEST_REPO_ROOT}/e2e/lima/guest/common.sh"
SERVER_SCRIPT="${GUEST_REPO_ROOT}/e2e/lima/guest/server-setup.sh"
CLIENT_SCRIPT="${GUEST_REPO_ROOT}/e2e/lima/guest/client-setup.sh"
reboot_requested_rc=194

wait_for_instance_ready() {
  local instance="$1"
  local attempt

  for attempt in $(seq 1 120); do
    if guest_run "${instance}" /bin/bash -lc "test -d \"${GUEST_REPO_ROOT}\"" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done

  echo "timed out waiting for ${instance} guest mount to become ready" >&2
  return 1
}

restart_instance_for_kernel_switch() {
  local instance="$1"
  log "restarting ${instance} to boot into the configured Lustre kernel"
  limactl stop --tty=false "${instance}"
  limactl start --tty=false "${instance}"
  wait_for_instance_ready "${instance}"
}

wait_for_instance_reboot() {
  local instance="$1"
  local saw_disconnect=0
  local attempt

  for attempt in $(seq 1 120); do
    if guest_run "${instance}" /bin/true >/dev/null 2>&1; then
      if [[ "${saw_disconnect}" -eq 1 ]]; then
        wait_for_instance_ready "${instance}"
        return 0
      fi
    else
      saw_disconnect=1
    fi
    sleep 2
  done

  if [[ "${saw_disconnect}" -eq 0 ]]; then
    wait_for_instance_ready "${instance}"
    return $?
  fi

  echo "timed out waiting for ${instance} to reboot" >&2
  return 1
}

run_guest_setup_with_reboot_retry() {
  local instance="$1"
  shift
  local rc=0
  local attempt

  wait_for_instance_ready "${instance}"

  for attempt in 1 2 3; do
    set +e
    guest_sudo_env_run "${instance}" "$@"
    rc=$?
    set -e

    if [[ "${rc}" -eq 0 ]]; then
      return 0
    fi

    if [[ "${rc}" -ne "${reboot_requested_rc}" ]]; then
      return "${rc}"
    fi

    log "${instance} requested reboot to activate Lustre kernel"
    restart_instance_for_kernel_switch "${instance}"
  done

  echo "${instance} exceeded reboot retry limit" >&2
  return 1
}

log "bootstrapping server"
run_guest_setup_with_reboot_retry \
  "${SERVER_INSTANCE}" \
  LUSTRE_SERVER_REPO_BASE="${SERVER_REPO_BASE}" \
  LUSTRE_CLIENT_REPO_BASE="${CLIENT_REPO_BASE}" \
  E2FSPROGS_REPO_BASE="${E2FSPROGS_REPO_BASE}" \
  FS_NAME="${FS_NAME}" \
  MDT_INDEX="${MDT_INDEX}" \
  OST_INDEX="${OST_INDEX}" \
  SERVER_HOST_ALIAS="${SERVER_HOST_ALIAS}" \
  SERVER_MDT_MOUNTPOINT="${SERVER_MDT_MOUNTPOINT}" \
  SERVER_OST_MOUNTPOINT="${SERVER_OST_MOUNTPOINT}" \
  SERVER_MDT_BLOCK_DEVICE="${SERVER_MDT_BLOCK_DEVICE}" \
  SERVER_OST_BLOCK_DEVICE="${SERVER_OST_BLOCK_DEVICE}" \
  SERVER_MDT_LOOP_IMAGE="${SERVER_MDT_LOOP_IMAGE}" \
  SERVER_OST_LOOP_IMAGE="${SERVER_OST_LOOP_IMAGE}" \
  SERVER_MDT_LOOP_SIZE_GB="${SERVER_MDT_LOOP_SIZE_GB}" \
  SERVER_OST_LOOP_SIZE_GB="${SERVER_OST_LOOP_SIZE_GB}" \
  COMMON_SCRIPT="${COMMON_SCRIPT}" \
  /bin/bash "${SERVER_SCRIPT}"

SERVER_IP="$(instance_ip "${SERVER_INSTANCE}")"
if [[ -z "${SERVER_IP}" ]]; then
  echo "failed to determine server IP" >&2
  exit 1
fi
log "server IP: ${SERVER_IP}"

log "bootstrapping client"
run_guest_setup_with_reboot_retry \
  "${CLIENT_INSTANCE}" \
  LUSTRE_SERVER_REPO_BASE="${SERVER_REPO_BASE}" \
  LUSTRE_CLIENT_REPO_BASE="${CLIENT_REPO_BASE}" \
  LUSTRE_KERNEL_VERSION="${LUSTRE_KERNEL_VERSION}" \
  FS_NAME="${FS_NAME}" \
  CLIENT_MOUNTPOINT="${CLIENT_MOUNTPOINT}" \
  SERVER_HOST_ALIAS="${SERVER_HOST_ALIAS}" \
  SERVER_IP="${SERVER_IP}" \
  COMMON_SCRIPT="${COMMON_SCRIPT}" \
  /bin/bash "${CLIENT_SCRIPT}"
