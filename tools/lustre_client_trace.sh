#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: lustre_client_trace.sh [--mount /mnt/lustre] [--duration 15] [--window-seconds 10]
                             [--collector-endpoint http://collector:4318/v1/metrics]
                             [--dry-run]

Compatibility wrapper for the Python-based Lustre client observer MVP.
By default it exports OTLP metrics. Use --dry-run to print aggregated JSON metrics.
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "required command not found: $1" >&2
    exit 1
  }
}

find_python() {
  if command -v python3.9 >/dev/null 2>&1; then
    printf '%s\n' "python3.9"
    return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    printf '%s\n' "python3"
    return 0
  fi
  return 1
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

mount_path="/mnt/lustre"
duration=""
window_seconds=""
collector_endpoint=""
dry_run=0
observer_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mount)
      mount_path="$2"
      observer_args+=("$1" "$2")
      shift 2
      ;;
    --duration)
      duration="$2"
      observer_args+=("$1" "$2")
      shift 2
      ;;
    --window-seconds)
      window_seconds="$2"
      observer_args+=("$1" "$2")
      shift 2
      ;;
    --collector-endpoint)
      collector_endpoint="$2"
      observer_args+=("$1" "$2")
      shift 2
      ;;
    --dry-run)
      dry_run=1
      observer_args+=("$1")
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      observer_args+=("$1")
      shift
      ;;
  esac
done

require_cmd bpftrace
python_cmd="$(find_python)" || {
  echo "required command not found: python3.9 or python3" >&2
  exit 1
}

if [[ ! -d "${mount_path}" ]]; then
  echo "mount path does not exist: ${mount_path}" >&2
  exit 1
fi

if [[ "${dry_run}" -eq 0 && -z "${collector_endpoint}" ]]; then
  echo "--collector-endpoint is required unless --dry-run is set" >&2
  exit 1
fi

export PYTHONPATH="${repo_root}${PYTHONPATH:+:${PYTHONPATH}}"
exec "${python_cmd}" "${repo_root}/lustre_client_observer/agent.py" "${observer_args[@]}"
