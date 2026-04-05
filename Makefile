GO ?= go
GOFLAGS ?=
GOOS ?= linux
GOARCH ?= amd64
BPF_CLANG ?= clang
BPF2GO ?= $(GO) run github.com/cilium/ebpf/cmd/bpf2go
ifeq ($(GOARCH),amd64)
BPF_TARGET_ARCH ?= x86
else ifeq ($(GOARCH),arm64)
BPF_TARGET_ARCH ?= arm64
endif
BPF_CFLAGS ?= -I. -D__TARGET_ARCH_$(BPF_TARGET_ARCH)
DIST_DIR ?= dist/$(GOOS)-$(GOARCH)
EXPORTER_BIN ?= $(DIST_DIR)/lustre-client-observer
BPF_OBJECT ?= $(DIST_DIR)/lustre_client_observer.bpf.o
DOCKER_BUILDER_IMAGE ?= lustre-client-observer-go-builder
DOCKERFILE_GO_EXPORTER ?= build/docker/go-exporter.Dockerfile

.PHONY: generate-go-exporter
generate-go-exporter:
	cd internal/bpf && $(BPF2GO) -cc $(BPF_CLANG) -target $(GOARCH) -go-package bpf lustreclientobserver ./lustre_client_observer.bpf.c -- $(BPF_CFLAGS)

.PHONY: build-go-exporter
build-go-exporter:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build $(GOFLAGS) -o $(EXPORTER_BIN) ./cmd/lustre-client-observer

.PHONY: stage-go-exporter
stage-go-exporter:
	mkdir -p $(DIST_DIR)
	obj="$$(find internal/bpf -maxdepth 1 -type f -name 'lustreclientobserver*.o' | head -n1)"; \
	test -n "$${obj}" && cp "$${obj}" $(BPF_OBJECT)

.PHONY: test-go
test-go:
	$(GO) test ./...

.PHONY: docker-build-go-exporter
docker-build-go-exporter:
	mkdir -p $(DIST_DIR)
	docker build \
		-f $(DOCKERFILE_GO_EXPORTER) \
		--target export \
		--output type=local,dest=$(DIST_DIR) \
		.
