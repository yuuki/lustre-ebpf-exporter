#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib.sh"

require_cmd limactl
require_cmd python3

log "validating YAML templates"
validate_yaml_template "$(template_path "${SERVER_TEMPLATE}")"
validate_yaml_template "$(template_path "${CLIENT_TEMPLATE}")"

ensure_lima_disk "${SERVER_DISK_MDT}" "${SERVER_DISK_MDT_SIZE}"
ensure_lima_disk "${SERVER_DISK_OST}" "${SERVER_DISK_OST_SIZE}"

start_instance "${SERVER_INSTANCE}" "${SERVER_TEMPLATE}"
start_instance "${CLIENT_INSTANCE}" "${CLIENT_TEMPLATE}"

"${SCRIPT_DIR}/provision-hosts.sh"
"${SCRIPT_DIR}/verify-cluster.sh"
"${SCRIPT_DIR}/verify-observer.sh"
