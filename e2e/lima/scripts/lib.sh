#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
CONFIG_FILE="${E2E_DIR}/config/lustre-2.14.0.env"

if [[ ! -f "${CONFIG_FILE}" ]]; then
  echo "missing config file: ${CONFIG_FILE}" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "${CONFIG_FILE}"

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

template_path() {
  local relpath="$1"
  printf '%s/%s\n' "${REPO_ROOT}" "${relpath}"
}

guest_repo_root() {
  printf '%s\n' "${REPO_ROOT}"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "required command not found: $1" >&2
    exit 1
  }
}

validate_yaml_template() {
  local template="$1"
  python3 - "$template" <<'PY'
from pathlib import Path
import sys
import yaml

path = Path(sys.argv[1])
doc = yaml.safe_load(path.read_text())
required = ["minimumLimaVersion", "vmType", "arch"]
missing = [key for key in required if key not in doc]
if missing:
    raise SystemExit(f"{path}: missing required keys: {', '.join(missing)}")
PY
}

ensure_lima_disk() {
  local disk_name="$1"
  local disk_size="$2"

  if limactl disk list | awk 'NR > 1 {print $1}' | grep -qx "${disk_name}"; then
    log "disk already exists: ${disk_name}"
    return 0
  fi

  log "creating disk ${disk_name} (${disk_size})"
  limactl disk create "${disk_name}" --size "${disk_size}"
}

start_instance() {
  local instance="$1"
  local template="$2"
  log "starting ${instance}"
  if limactl list | awk 'NR > 1 {print $1}' | grep -qx "${instance}"; then
    limactl start --tty=false "${instance}"
    return 0
  fi

  limactl start --tty=false --name "${instance}" "$(template_path "${template}")"
}

delete_instance_if_exists() {
  local instance="$1"
  if limactl list | awk 'NR > 1 {print $1}' | grep -qx "${instance}"; then
    log "deleting instance ${instance}"
    limactl delete --force "${instance}"
  fi
}

delete_disk_if_exists() {
  local disk_name="$1"
  if limactl disk list | awk 'NR > 1 {print $1}' | grep -qx "${disk_name}"; then
    log "deleting disk ${disk_name}"
    limactl disk delete "${disk_name}"
  fi
}

guest_run() {
  local instance="$1"
  shift
  limactl shell "${instance}" "$@"
}

guest_sudo_env_run() {
  local instance="$1"
  shift
  limactl shell "${instance}" sudo env "$@"
}

instance_ip() {
  local instance="$1"
  limactl shell "${instance}" /bin/bash -lc \
    "ip -4 -o addr show scope global | awk '{print \$4}' | cut -d/ -f1 | head -n1"
}
