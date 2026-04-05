//go:build linux

package goexporter

//go:generate sh -c "cd ../bpf && go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -go-package bpf lustreclientobserver ./lustre_client_observer.bpf.c -- -I."
//go:generate sh -c "cd ../bpf && go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target arm64 -go-package bpf lustreclientobserver ./lustre_client_observer.bpf.c -- -I."
