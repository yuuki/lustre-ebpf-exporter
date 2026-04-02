#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib.sh"

delete_instance_if_exists "${CLIENT_INSTANCE}"
delete_instance_if_exists "${SERVER_INSTANCE}"

delete_disk_if_exists "${SERVER_DISK_OST}"
delete_disk_if_exists "${SERVER_DISK_MDT}"
