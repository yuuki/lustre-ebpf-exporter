package goexporter

//go:generate sh -c "cd ../bpf && BPF_CFLAGS=${BPF_CFLAGS:--I. -D__TARGET_ARCH_x86} go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -go-package bpf lustreclientobserver ./lustre_client_observer.bpf.c -- ${BPF_CFLAGS:--I. -D__TARGET_ARCH_x86}"
//go:generate sh -c "cd ../bpf && BPF_CFLAGS=${BPF_CFLAGS:--I. -D__TARGET_ARCH_arm64} go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target arm64 -go-package bpf lustreclientobserver ./lustre_client_observer.bpf.c -- ${BPF_CFLAGS:--I. -D__TARGET_ARCH_arm64}"
