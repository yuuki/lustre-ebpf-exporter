GO ?= go
GOFLAGS ?=
GOOS ?= linux
GOARCH ?= amd64
BPF_CLANG ?= clang
BPF2GO ?= $(GO) run github.com/cilium/ebpf/cmd/bpf2go
DIST_DIR ?= dist/$(GOOS)-$(GOARCH)
EXPORTER_BIN ?= $(DIST_DIR)/lustre-client-observer
BPF_OBJECT ?= $(DIST_DIR)/lustre_client_observer.bpf.o

.PHONY: generate-go-exporter
generate-go-exporter:
	cd internal/bpf && $(BPF2GO) -cc $(BPF_CLANG) -target $(GOARCH) -go-package bpf lustreclientobserver ./lustre_client_observer.bpf.c -- -I.

.PHONY: build-go-exporter
build-go-exporter:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build $(GOFLAGS) -o $(EXPORTER_BIN) ./cmd/lustre-client-observer

.PHONY: stage-go-exporter
stage-go-exporter:
	mkdir -p $(DIST_DIR)
	cp internal/bpf/lustreclientobserver_bpfel.o $(BPF_OBJECT)

.PHONY: test-go
test-go:
	$(GO) test ./...
