GO ?= go
GOFLAGS ?=
GOOS ?= linux
GOARCH ?= amd64
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS ?= -X main.version=$(VERSION) -X main.commit=$(COMMIT)
BPF_CLANG ?= clang
BPF2GO ?= $(GO) run github.com/cilium/ebpf/cmd/bpf2go
ifeq ($(GOARCH),amd64)
BPF_TARGET_ARCH ?= x86
else ifeq ($(GOARCH),arm64)
BPF_TARGET_ARCH ?= arm64
endif
BPF_CFLAGS ?= -I. -D__TARGET_ARCH_$(BPF_TARGET_ARCH)
DIST_DIR ?= dist/$(GOOS)-$(GOARCH)
EXPORTER_BIN ?= $(DIST_DIR)/lustre-ebpf-exporter
DOCKER_BUILDER_IMAGE ?= lustre-ebpf-exporter-go-builder
DOCKERFILE_GO_EXPORTER ?= build/docker/go-exporter.Dockerfile

.PHONY: generate-go-exporter
generate-go-exporter:
	cd internal/bpf && $(BPF2GO) -cc $(BPF_CLANG) -target $(GOARCH) -go-package bpf lustreebpfexporter ./lustre_ebpf_exporter.bpf.c -- $(BPF_CFLAGS)

.PHONY: build-go-exporter
build-go-exporter:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -ldflags '$(LDFLAGS)' $(GOFLAGS) -o $(EXPORTER_BIN) ./cmd/lustre-ebpf-exporter

.PHONY: test-go
test-go:
	$(GO) test ./...

.PHONY: docker-build-go-exporter
docker-build-go-exporter:
	mkdir -p $(DIST_DIR)
	docker build \
		-f $(DOCKERFILE_GO_EXPORTER) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--target export \
		--output type=local,dest=$(DIST_DIR) \
		.

DOCKERFILE_BPF_VERIFIER ?= build/docker/bpf-verifier.Dockerfile
BPF_VERIFIER_IMAGE ?= lustre-bpf-verifier

.PHONY: verify-bpf
verify-bpf:
	docker build -f $(DOCKERFILE_BPF_VERIFIER) -t $(BPF_VERIFIER_IMAGE) .
	docker run --rm --privileged $(BPF_VERIFIER_IMAGE)

INSTALL_BIN_DIR ?= /usr/local/bin
SYSTEMD_UNIT_DIR ?= /etc/systemd/system
DEFAULT_ENV_DIR ?= /etc/default

.PHONY: install
install:
	install -m 755 $(EXPORTER_BIN) $(INSTALL_BIN_DIR)/lustre-ebpf-exporter
	install -m 644 build/systemd/lustre-ebpf-exporter.service $(SYSTEMD_UNIT_DIR)/lustre-ebpf-exporter.service
	install -m 644 build/systemd/lustre-ebpf-exporter.default $(DEFAULT_ENV_DIR)/lustre-ebpf-exporter
	systemctl daemon-reload
