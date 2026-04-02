#!/usr/bin/env bash
set -euo pipefail

# shellcheck disable=SC1090
source "${COMMON_SCRIPT}"

require_root

write_repo_file /etc/yum.repos.d/lustre-server.repo lustre-server "${LUSTRE_SERVER_REPO_BASE}"
write_repo_file /etc/yum.repos.d/e2fsprogs-wc.repo e2fsprogs-wc "${E2FSPROGS_REPO_BASE}"
ensure_base_deps

log "installing Lustre server packages"
dnf remove -y \
  lustre-all-dkms \
  lustre-ldiskfs-dkms \
  lustre-client-dkms \
  zfs-dkms \
  zfs \
  kmod-lustre-osd-zfs \
  lustre-osd-zfs-mount \
  libzfs4 \
  libzpool4 \
  libnvpair3 \
  libuutil3 || true

dnf install -y \
  lustre \
  kmod-lustre \
  kmod-lustre-osd-ldiskfs \
  lustre-osd-ldiskfs-mount
ensure_lustre_kernel_active
ensure_selinux_disabled

ensure_data_disk_mounted "${SERVER_MDT_BLOCK_DEVICE}" /mnt/lima-mdt
ensure_data_disk_mounted "${SERVER_OST_BLOCK_DEVICE}" /mnt/lima-ost

iface="$(primary_interface)"
ip_addr="$(primary_ipv4 "${iface}")"

configure_lnet "${iface}"
ensure_hosts_entry "${ip_addr}" "${SERVER_HOST_ALIAS}"
ensure_lustre_module_loaded
modprobe ldiskfs

mdt_loop="$(ensure_loop_device "${SERVER_MDT_LOOP_IMAGE}" "${SERVER_MDT_LOOP_SIZE_GB}")"
ost_loop="$(ensure_loop_device "${SERVER_OST_LOOP_IMAGE}" "${SERVER_OST_LOOP_SIZE_GB}")"

mkdir -p "${SERVER_MDT_MOUNTPOINT}" "${SERVER_OST_MOUNTPOINT}"

if ! blkid "${mdt_loop}" | grep -q 'TYPE="lustre"'; then
  log "formatting MDT ${mdt_loop}"
  mkfs.lustre --reformat --fsname="${FS_NAME}" --mgs --mdt --index="${MDT_INDEX}" "${mdt_loop}"
fi

if ! blkid "${ost_loop}" | grep -q 'TYPE="lustre"'; then
  log "formatting OST ${ost_loop}"
  mkfs.lustre --reformat --fsname="${FS_NAME}" --ost --mgsnode="${ip_addr}@tcp" --index="${OST_INDEX}" "${ost_loop}"
fi

ensure_fstab_entry "${mdt_loop}" "${SERVER_MDT_MOUNTPOINT}" lustre defaults,_netdev
ensure_fstab_entry "${ost_loop}" "${SERVER_OST_MOUNTPOINT}" lustre defaults,_netdev

if ! mountpoint -q "${SERVER_MDT_MOUNTPOINT}"; then
  mount "${SERVER_MDT_MOUNTPOINT}"
fi

ensure_lnet_ready

if ! mountpoint -q "${SERVER_OST_MOUNTPOINT}"; then
  mount "${SERVER_OST_MOUNTPOINT}"
fi

log "server setup completed"
