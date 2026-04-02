#!/usr/bin/env bash
set -euo pipefail

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "this script must run as root" >&2
    exit 1
  fi
}

log() {
  printf '[guest %s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

primary_interface() {
  local iface
  iface="$(ip -4 route show default | awk '{print $5; exit}')"
  if [[ -z "${iface}" ]]; then
    echo "failed to detect primary interface" >&2
    exit 1
  fi
  printf '%s\n' "${iface}"
}

primary_ipv4() {
  local iface="$1"
  ip -4 -o addr show dev "${iface}" | awk '{print $4}' | cut -d/ -f1 | head -n1
}

ensure_base_deps() {
  log "installing base dependencies"
  dnf install -y \
    dnf-plugins-core \
    e2fsprogs \
    iproute \
    kmod \
    rsync \
    util-linux
}

installed_lustre_kernel() {
  rpm -q kernel-core --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | grep 'el8_lustre' | sort -V | tail -n1 || true
}

ensure_lustre_kernel_active() {
  local target_kernel
  target_kernel="$(installed_lustre_kernel)"
  if [[ -z "${target_kernel}" || "$(uname -r)" == "${target_kernel}" ]]; then
    return 0
  fi

  log "switching default kernel to ${target_kernel} and requesting host-side restart"
  grubby --set-default "/boot/vmlinuz-${target_kernel}"
  exit 194
}

ensure_selinux_disabled() {
  local current_mode
  current_mode="$(getenforce 2>/dev/null || true)"

  if [[ "${current_mode}" == "Disabled" ]] && grep -Eq '^SELINUX=disabled$' /etc/selinux/config; then
    return 0
  fi

  log "disabling SELinux and requesting host-side restart"
  if grep -q '^SELINUX=' /etc/selinux/config; then
    sed -ri 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
  else
    printf 'SELINUX=disabled\n' >>/etc/selinux/config
  fi
  grubby --update-kernel=DEFAULT --args=selinux=0
  exit 194
}

write_repo_file() {
  local repo_path="$1"
  local repo_id="$2"
  local baseurl="$3"

  cat >"${repo_path}" <<EOF
[${repo_id}]
name=${repo_id}
baseurl=${baseurl}
enabled=1
gpgcheck=0
repo_gpgcheck=0
skip_if_unavailable=0
EOF
}

configure_lnet() {
  local iface="$1"
  mkdir -p /etc/modprobe.d
  cat >/etc/modprobe.d/lustre-lnet.conf <<EOF
options lnet networks=tcp(${iface})
EOF
}

ensure_lustre_module_loaded() {
  modprobe lustre
}

ensure_lnet_ready() {
  modprobe lnet
  modprobe ksocklnd || true
  lctl network up || true
}

ensure_hosts_entry() {
  local ip_addr="$1"
  local hostname="$2"
  if grep -Eq "[[:space:]]${hostname}([[:space:]]|\$)" /etc/hosts; then
    sed -i "s/^.*[[:space:]]${hostname}\$/$(printf '%s %s' "${ip_addr}" "${hostname}" | sed 's/[&/]/\\&/g')/" /etc/hosts
  else
    printf '%s %s\n' "${ip_addr}" "${hostname}" >>/etc/hosts
  fi
}

ensure_data_disk_mounted() {
  local block_device="$1"
  local mountpoint="$2"
  local fs_type="${3:-ext4}"
  local uuid

  mkdir -p "${mountpoint}"

  if [[ -z "$(blkid -s TYPE -o value "${block_device}" 2>/dev/null || true)" ]]; then
    log "formatting ${block_device} as ${fs_type}"
    mkfs."${fs_type}" -F "${block_device}"
  fi

  uuid="$(blkid -s UUID -o value "${block_device}")"
  ensure_fstab_entry "UUID=${uuid}" "${mountpoint}" "${fs_type}" defaults
  systemctl daemon-reload

  if ! mountpoint -q "${mountpoint}"; then
    mount "${mountpoint}"
  fi
}

ensure_loop_device() {
  local image_path="$1"
  local size_gb="$2"
  local loopdev

  mkdir -p "$(dirname "${image_path}")"
  if [[ ! -f "${image_path}" ]]; then
    truncate -s "${size_gb}G" "${image_path}"
  fi

  loopdev="$(losetup -j "${image_path}" | awk -F: 'NR==1{print $1}')"
  if [[ -z "${loopdev}" ]]; then
    loopdev="$(losetup --find --show "${image_path}")"
  fi
  printf '%s\n' "${loopdev}"
}

ensure_fstab_entry() {
  local spec="$1"
  local mountpoint="$2"
  local fstype="$3"
  local options="$4"

  mkdir -p "$(dirname "${mountpoint}")"
  mkdir -p "${mountpoint}"
  if ! grep -Fq "${mountpoint} ${fstype}" /etc/fstab; then
    printf '%s %s %s %s 0 0\n' "${spec}" "${mountpoint}" "${fstype}" "${options}" >>/etc/fstab
  fi
}
