from __future__ import annotations

import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def read_text(relpath: str) -> str:
    return (ROOT / relpath).read_text()


def read_yaml(relpath: str) -> dict:
    return yaml.safe_load(read_text(relpath))


def test_expected_lima_e2e_files_exist() -> None:
    expected = [
        "README.md",
        "requirements-observer.txt",
        "e2e/lima/README.md",
        "e2e/lima/config/lustre-2.14.0.env",
        "e2e/lima/templates/lustre-server.yaml",
        "e2e/lima/templates/lustre-client.yaml",
        "e2e/lima/scripts/up.sh",
        "e2e/lima/scripts/destroy.sh",
        "e2e/lima/scripts/provision-hosts.sh",
        "e2e/lima/scripts/verify-cluster.sh",
        "e2e/lima/scripts/verify-observer.sh",
        "e2e/lima/scripts/verify-observer-go.sh",
        "e2e/lima/guest/common.sh",
        "e2e/lima/guest/server-setup.sh",
        "e2e/lima/guest/client-setup.sh",
        "tools/lustre_client_observer.py",
        "tools/lustre_client_trace.sh",
        "cmd/lustre-client-observer/main.go",
        "internal/bpf/lustre_client_observer.bpf.c",
        "Makefile",
        "go.mod",
    ]

    for relpath in expected:
        assert (ROOT / relpath).exists(), relpath


def test_server_template_uses_x86_64_qemu_and_vm_to_vm_network() -> None:
    server = read_yaml("e2e/lima/templates/lustre-server.yaml")

    assert server["vmType"] == "qemu"
    assert server["arch"] == "x86_64"
    assert server["networks"] == [{"lima": "user-v2"}]
    assert server["mountType"] == "reverse-sshfs"
    provision = server["provision"]
    assert provision[0]["mode"] == "system"
    assert "dnf install -y fuse-sshfs" in provision[0]["script"]
    additional_disks = server["additionalDisks"]
    assert {"name": "mdt", "format": True, "fsType": "ext4"} in additional_disks
    assert {"name": "ost", "format": True, "fsType": "ext4"} in additional_disks


def test_client_template_uses_x86_64_qemu_and_vm_to_vm_network() -> None:
    client = read_yaml("e2e/lima/templates/lustre-client.yaml")

    assert client["vmType"] == "qemu"
    assert client["arch"] == "x86_64"
    assert client["networks"] == [{"lima": "user-v2"}]
    assert client["mountType"] == "reverse-sshfs"
    provision = client["provision"]
    assert provision[0]["mode"] == "system"
    assert "dnf install -y fuse-sshfs" in provision[0]["script"]


def test_lustre_version_and_el8_repo_urls_are_pinned() -> None:
    config = read_text("e2e/lima/config/lustre-2.14.0.env")

    assert "LUSTRE_VERSION=2.14.0" in config
    assert "LUSTRE_DISTRO_SUFFIX=el8.3" in config
    assert "LUSTRE_KERNEL_VERSION=4.18.0-240.1.1.el8_lustre.x86_64" in config
    assert "SERVER_REPO_BASE=https://downloads.whamcloud.com/public/lustre/lustre-2.14.0/el8.3/server" in config
    assert "CLIENT_REPO_BASE=https://downloads.whamcloud.com/public/lustre/lustre-2.14.0/el8.3/client" in config
    assert "E2FSPROGS_REPO_BASE=https://downloads.whamcloud.com/public/e2fsprogs/1.45.6.wc5/el8" in config
    assert "SERVER_MDT_BLOCK_DEVICE=/dev/vdb" in config
    assert "SERVER_OST_BLOCK_DEVICE=/dev/vdc" in config
    assert "/RPMS/x86_64" not in config


def test_up_script_brings_up_server_then_client_then_verifies() -> None:
    script = read_text("e2e/lima/scripts/up.sh")

    assert "${SERVER_INSTANCE}" in script
    assert "${CLIENT_INSTANCE}" in script
    assert "start_instance" in script
    assert "validate_yaml_template" in script
    assert "provision-hosts.sh" in script
    assert "verify-cluster.sh" in script
    assert script.index("${SERVER_INSTANCE}") < script.index("${CLIENT_INSTANCE}")


def test_readme_documents_rocky96_incompatibility_and_supported_path() -> None:
    readme = read_text("e2e/lima/README.md")

    assert "Rocky Linux 9.6" in readme
    assert "Lustre 2.14.0" in readme
    assert "unsupported" in readme
    assert "Rocky 8" in readme
    assert "SELinux" in readme


def test_common_guest_setup_installs_only_kmod_runtime_dependencies() -> None:
    common = read_text("e2e/lima/guest/common.sh")

    assert "dnf-plugins-core" in common
    assert "e2fsprogs" in common
    assert "iproute" in common
    assert "kmod" in common
    assert "util-linux" in common
    assert "epel-release" not in common
    assert "config-manager --set-enabled powertools" not in common
    assert "config-manager --set-enabled PowerTools" not in common
    assert 'kernel-devel-"$(uname -r)"' not in common
    assert "dkms" not in common
    assert "gcc" not in common
    assert "make" not in common
    assert "perl" not in common


def test_common_guest_setup_can_reboot_into_lustre_kernel() -> None:
    common = read_text("e2e/lima/guest/common.sh")

    assert "installed_lustre_kernel" in common
    assert "ensure_lustre_kernel_active" in common
    assert "ensure_selinux_disabled" in common
    assert "ensure_lustre_module_loaded" in common
    assert "ensure_lnet_ready" in common
    assert "ensure_data_disk_mounted" in common
    assert "grubby --set-default" in common
    assert "grubby --update-kernel=DEFAULT --args=selinux=0" in common
    assert "exit 194" in common
    assert "systemctl --no-block reboot" not in common


def test_server_package_install_prefers_prebuilt_kmods() -> None:
    server = read_text("e2e/lima/guest/server-setup.sh")

    install_block = "dnf install -y \\\n  lustre \\\n  kmod-lustre \\\n  kmod-lustre-osd-ldiskfs \\\n  lustre-osd-ldiskfs-mount"

    assert install_block in server
    assert "dnf remove -y" in server
    assert 'ensure_selinux_disabled' in server
    assert 'ensure_data_disk_mounted "${SERVER_MDT_BLOCK_DEVICE}" /mnt/lima-mdt' in server
    assert 'ensure_data_disk_mounted "${SERVER_OST_BLOCK_DEVICE}" /mnt/lima-ost' in server
    assert "lustre-osd-zfs-mount" in server
    assert "zfs-dkms" in server
    assert "lustre-ldiskfs-dkms" not in install_block


def test_server_mounts_mdt_before_bringing_lnet_online() -> None:
    server = read_text("e2e/lima/guest/server-setup.sh")

    assert 'mount "${SERVER_MDT_MOUNTPOINT}"' in server
    assert "ensure_lnet_ready" in server
    assert server.index('mount "${SERVER_MDT_MOUNTPOINT}"') < server.index("ensure_lnet_ready")


def test_client_package_install_prefers_prebuilt_kmods_with_dkms_fallback() -> None:
    client = read_text("e2e/lima/guest/client-setup.sh")

    assert 'write_repo_file /etc/yum.repos.d/lustre-server.repo lustre-server "${LUSTRE_SERVER_REPO_BASE}"' in client
    kernel_install_block = (
        'dnf install -y \\\n'
        '  "kernel-core-${LUSTRE_KERNEL_VERSION}" \\\n'
        '  "kernel-modules-${LUSTRE_KERNEL_VERSION}" \\\n'
        '  "kernel-modules-extra-${LUSTRE_KERNEL_VERSION}"'
    )
    assert kernel_install_block in client
    assert client.index(kernel_install_block) < client.index("log \"installing Lustre client packages\"")
    assert client.index('ensure_lustre_kernel_active') < client.index("log \"installing Lustre client packages\"")

    prebuilt_install_block = (
        'elif ! dnf install -y \\\n'
        '  lustre-client \\\n'
        '  kmod-lustre-client; then'
    )
    installed_skip_block = (
        'if rpm -q lustre-client >/dev/null 2>&1 && { rpm -q kmod-lustre-client >/dev/null 2>&1 || rpm -q lustre-client-dkms >/dev/null 2>&1; }; then\n'
        '  log "Lustre client userspace and kernel packages are already installed"\n'
        'elif rpm -q lustre-client-dkms >/dev/null 2>&1; then\n'
        '  log "lustre-client-dkms is already installed; installing userspace package only"\n'
        '  dnf install -y lustre-client'
    )
    dkms_fallback_block = (
        '  /usr/bin/crb enable\n'
        '  dnf install -y epel-release\n'
        '  dnf install -y \\\n'
        '    expect \\\n'
        '    python2 \\\n'
        '    libyaml-devel \\\n'
        '    zlib-devel \\\n'
        '    gcc \\\n'
        '    make \\\n'
        '    perl \\\n'
        '    elfutils-libelf-devel \\\n'
        '    "kernel-devel-${LUSTRE_KERNEL_VERSION}" \\\n'
        '    dkms \\\n'
        '    lustre-client-dkms \\\n'
        '    lustre-client\n'
        'fi'
    )

    assert installed_skip_block in client
    assert prebuilt_install_block in client
    assert dkms_fallback_block in client
    assert 'dnf install -y \\\n  bpftrace \\\n  python39 \\\n  python39-pip' in client
    assert 'python3.9 -m pip install --upgrade pip' in client
    assert 'python3.9 -m pip install -r "${REPO_ROOT}/requirements-observer.txt"' in client


def test_client_observer_bpftrace_program_targets_llite_and_ptlrpc() -> None:
    from lustre_client_observer.agent import build_bpftrace_program

    program = build_bpftrace_program("/mnt/lustre", target_major=1, target_minor=2)

    assert 'printf("TRACE_START\\tmount=/mnt/lustre\\n");' in program
    assert "@target_major" not in program
    assert "@target_minor" not in program
    assert "$target_major = (uint64)1;" in program
    assert "$target_minor = (uint64)2;" in program
    assert "kprobe:ll_lookup_nd" in program
    assert "kretprobe:ll_lookup_nd" in program
    assert "kprobe:ll_file_open" in program
    assert "kretprobe:ll_file_read_iter" in program
    assert "kretprobe:ll_file_write_iter" in program
    assert "kprobe:ll_fsync" in program
    assert "kprobe:ptlrpc_send_new_req" in program
    assert "kprobe:ptlrpc_queue_wait" in program
    assert "kretprobe:ptlrpc_queue_wait" in program
    assert "kprobe:__ptlrpc_free_req" in program
    assert 'plane=llite' in program
    assert 'plane=ptlrpc' in program


def test_client_observer_wrapper_executes_python_agent() -> None:
    script = read_text("tools/lustre_client_trace.sh")

    assert "lustre_client_observer/agent.py" in script
    assert "python3.9" in script
    assert "python3" in script
    assert "--prometheus-listen-address" in script
    assert "--prometheus-listen-port" in script
    assert "--collector-endpoint" in script
    assert "--dry-run" in script


def test_go_exporter_cli_uses_standard_prometheus_web_flags() -> None:
    main = read_text("cmd/lustre-client-observer/main.go")

    assert '"--web.listen-address"' not in main
    assert '"web.listen-address"' in main
    assert '"web.telemetry-path"' in main
    assert '"--mount"' not in main
    assert '"mount"' in main
    assert '"bpf-object"' in main
    assert '"legacy-symbol-allow-missing"' in main
    assert "DurationVar" not in main
    assert "IntVar(&windowSeconds" in main
    assert "IntVar(&durationSeconds" in main
    assert "syscall.SIGTERM" in main


def test_makefile_wires_bpf2go_build_and_stage_targets() -> None:
    makefile = read_text("Makefile")

    assert "github.com/cilium/ebpf/cmd/bpf2go" in makefile
    assert "generate-go-exporter" in makefile
    assert "build-go-exporter" in makefile
    assert "stage-go-exporter" in makefile
    assert "dist/$(GOOS)-$(GOARCH)" in makefile
    assert "lustreclientobserver_bpfel.o" in makefile


def test_go_verify_script_scrapes_prometheus_metrics() -> None:
    script = read_text("e2e/lima/scripts/verify-observer-go.sh")

    assert "curl -fsS http://127.0.0.1:9108/metrics" in script
    assert "--web.listen-address :9108" in script
    assert "--web.telemetry-path /metrics" in script
    assert "--bpf-object" in script
    assert "lustre_client_access_operations_total" in script
    assert "lustre_client_access_duration_seconds" in script
    assert "lustre_client_data_bytes_total" in script


def test_go_runtime_keeps_required_probes_strict_and_optional_degraded() -> None:
    runtime_linux = read_text("internal/goexporter/runtime_linux.go")

    assert "source.attachAll(required, false)" in runtime_linux
    assert "source.attachAll(optional, false)" in runtime_linux
    assert "if s.started" in runtime_linux


def test_go_bpf_source_uses_core_access_and_signed_retvals() -> None:
    source = read_text("internal/bpf/lustre_client_observer.bpf.c")

    assert "preserve_access_index" in source
    assert "__builtin_preserve_access_index" in source
    assert "long bytes = PT_REGS_RC(ctx);" in source
    assert "(__u64)bytes" in source


def test_verify_observer_script_runs_aggregated_observer_dry_run() -> None:
    script = read_text("e2e/lima/scripts/verify-observer.sh")

    assert "lustre_client_trace.sh" in script
    assert "--dry-run" in script
    assert "lustre.client.access.operations" in script
    assert "lustre.client.access.duration" in script
    assert "lustre.client.data.bytes" in script
    assert "if ! grep -Eq" in script
    assert "trace.log" in script
    assert "lustre.client.rpc.wait.duration" not in script
    assert "lustre.client.rpc.wait.operations" not in script


def test_root_readme_documents_observer_architecture() -> None:
    readme = read_text("README.md")

    assert "lustre-client-observer" in readme
    assert "llite" in readme
    assert "PtlRPC" in readme
    assert "Prometheus Exporter" in readme
    assert "lustre_client_access_operations_total" in readme
    assert "lustre_client_rpc_wait_duration_seconds" in readme
    assert "Go CO-RE" in readme
    assert "web.listen-address" in readme


def test_provision_hosts_retries_guest_setup_after_kernel_switch_reboot() -> None:
    script = read_text("e2e/lima/scripts/provision-hosts.sh")

    assert "run_guest_setup_with_reboot_retry" in script
    assert "restart_instance_for_kernel_switch" in script
    assert "reboot_requested_rc=194" in script
    assert 'test -d \\"${GUEST_REPO_ROOT}\\"' in script
    assert 'limactl stop --tty=false "${instance}"' in script
    assert 'limactl start --tty=false "${instance}"' in script
    assert 'LUSTRE_SERVER_REPO_BASE="${SERVER_REPO_BASE}"' in script
    assert 'LUSTRE_KERNEL_VERSION="${LUSTRE_KERNEL_VERSION}"' in script
    assert '"${SERVER_INSTANCE}"' in script
    assert '"${CLIENT_INSTANCE}"' in script
