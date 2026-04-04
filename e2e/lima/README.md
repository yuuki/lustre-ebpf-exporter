# Lima Lustre 2.14.0 E2E Environment

This directory contains templates and setup scripts for a minimal Lustre 2.14.0 E2E environment on Lima.

Important assumptions:

- Public Lustre 2.14.0 RPMs are published for the `el8.3` line.
- Because of that, the earlier `Rocky Linux 9.6 + Lustre 2.14.0` idea is unsupported as-is.
- This initial E2E setup validates Lustre 2.14.0 on `Rocky 8 / x86_64` under Lima.
- On Apple Silicon, this runs as `qemu + x86_64 emulation`, so VM boot and DKMS builds are slower.
- The templates install `fuse-sshfs` during system provisioning so the host workspace can be exposed to the guest through reverse-sshfs.

## Topology

- `lustre-e2e-server`
  - Rocky 8 / x86_64
  - MGS + MDT + OSS + OST consolidated onto one node
  - The `mdt` and `ost` Lima extra disks are exposed to the guest as `/dev/vdb` and `/dev/vdc`, formatted as ext4, mounted at `/mnt/lima-mdt` and `/mnt/lima-ost`, then used to host loopback images for `mkfs.lustre`
- `lustre-e2e-client`
  - Rocky 8 / x86_64
  - Installs the Lustre client and mounts `lustrefs` at `/mnt/lustre`
- Network
  - Lima `user-v2`
  - VM-to-VM connectivity is available, so the client can connect to the server `@tcp` NID

## Usage

```bash
./e2e/lima/scripts/up.sh
./e2e/lima/scripts/verify-cluster.sh
./e2e/lima/scripts/destroy.sh
```

`up.sh` runs the following steps in order:

1. Validate the Lima templates
2. Create the `mdt` / `ost` extra disks
3. Start the server VM
4. Start the client VM
5. Build the Lustre server side
6. Mount Lustre on the client side
7. smoke verify

## Notes

- This configuration is a minimal E2E setup optimized for reproducing `Lustre 2.14.0 on Lima` first.
- The server switches to the Lustre-provided kernel and forces `SELinux=disabled`, which may require up to two host-side restarts. This follows the Whamcloud walkthrough assumptions.
- Both server and client prefer prebuilt `kmod-*` packages over DKMS.
- If Rocky 9.6 validation is required, it is safer to split that into a separate profile using Lustre 2.16 or newer.
