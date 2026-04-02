#!/usr/bin/env bash
set -euo pipefail

# shellcheck disable=SC1090
source "${COMMON_SCRIPT}"

require_root

write_repo_file /etc/yum.repos.d/lustre-server.repo lustre-server "${LUSTRE_SERVER_REPO_BASE}"
write_repo_file /etc/yum.repos.d/lustre-client.repo lustre-client "${LUSTRE_CLIENT_REPO_BASE}"
ensure_base_deps

log "installing Lustre client kernel"
dnf install -y \
  "kernel-core-${LUSTRE_KERNEL_VERSION}" \
  "kernel-modules-${LUSTRE_KERNEL_VERSION}" \
  "kernel-modules-extra-${LUSTRE_KERNEL_VERSION}"
ensure_lustre_kernel_active

log "installing Lustre client packages"
if rpm -q lustre-client >/dev/null 2>&1 && { rpm -q kmod-lustre-client >/dev/null 2>&1 || rpm -q lustre-client-dkms >/dev/null 2>&1; }; then
  log "Lustre client userspace and kernel packages are already installed"
elif rpm -q lustre-client-dkms >/dev/null 2>&1; then
  log "lustre-client-dkms is already installed; installing userspace package only"
  dnf install -y lustre-client
elif ! dnf install -y \
  lustre-client \
  kmod-lustre-client; then
  log "prebuilt kmod install failed; falling back to lustre-client-dkms"
  /usr/bin/crb enable
  dnf install -y epel-release
  dnf install -y \
    expect \
    python2 \
    libyaml-devel \
    zlib-devel \
    gcc \
    make \
    perl \
    elfutils-libelf-devel \
    "kernel-devel-${LUSTRE_KERNEL_VERSION}" \
    dkms \
    lustre-client-dkms \
    lustre-client
fi

iface="$(primary_interface)"
configure_lnet "${iface}"
ensure_hosts_entry "${SERVER_IP}" "${SERVER_HOST_ALIAS}"
ensure_lustre_module_loaded
ensure_lnet_ready

mkdir -p "${CLIENT_MOUNTPOINT}"
ensure_fstab_entry "${SERVER_IP}@tcp:/${FS_NAME}" "${CLIENT_MOUNTPOINT}" lustre defaults,_netdev

if ! mountpoint -q "${CLIENT_MOUNTPOINT}"; then
  mount "${CLIENT_MOUNTPOINT}"
fi

log "client setup completed"
