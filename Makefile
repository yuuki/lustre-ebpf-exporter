GO ?= go
GOFLAGS ?=
GOOS ?= linux
GOARCH ?= amd64
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS ?= -X main.version=$(VERSION) -X main.commit=$(COMMIT)
BPF_CLANG ?= clang
BPF2GO_STRIP ?= $(shell command -v llvm-strip 2>/dev/null || echo /opt/homebrew/opt/llvm/bin/llvm-strip)
BPF2GO ?= $(GO) run github.com/cilium/ebpf/cmd/bpf2go
ifeq ($(GOARCH),amd64)
BPF_TARGET_ARCH ?= x86
BPF_LIBC_TRIPLE ?= x86_64-linux-gnu
else ifeq ($(GOARCH),arm64)
BPF_TARGET_ARCH ?= arm64
BPF_LIBC_TRIPLE ?= aarch64-linux-gnu
endif
BPF_CFLAGS ?= -I. -I/usr/include/$(BPF_LIBC_TRIPLE) -D__TARGET_ARCH_$(BPF_TARGET_ARCH)
DIST_DIR ?= dist/$(GOOS)-$(GOARCH)
EXPORTER_BIN ?= $(DIST_DIR)/lustre-ebpf-exporter
DOCKER_BUILDER_IMAGE ?= lustre-ebpf-exporter-go-builder
DOCKERFILE_GO_EXPORTER ?= build/docker/go-exporter.Dockerfile

# Tool versions. CI pins the same versions (.github/workflows); bump together.
GOLANGCI_LINT_VERSION   ?= v2.15.0
GOVULNCHECK_VERSION     ?= v1.9.0
ACTIONLINT_VERSION      ?= v1.7.12
ZIZMOR_VERSION          ?= 1.32.0
GH_ACTIONS_LOCK_VERSION ?= v0.4.1
FUZZTIME                ?= 30s
# Empty means one fuzzing worker per CPU; set FUZZ_PARALLEL=2 on a shared host.
FUZZ_PARALLEL           ?=
BENCH_COUNT             ?= 6

# `go run pkg@version` ignores go.mod, so a go older than go.mod's would build
# the analyzers with an older toolchain, which then refuse or fail to type-check
# this module: build them with the toolchain go.mod selects.
GO_TOOLCHAIN = $(shell $(GO) env GOVERSION)
GOLANGCI_LINT ?= GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
GOVULNCHECK ?= GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
ACTIONLINT ?= GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)
# uvx or pipx (preinstalled on GitHub-hosted runners) runs the pinned zizmor.
ZIZMOR ?= $(if $(shell command -v uvx 2>/dev/null),uvx zizmor@$(ZIZMOR_VERSION),pipx run zizmor==$(ZIZMOR_VERSION))
# gh-actions-lock (the `gh actions-lock` extension) runs through `go run` too.
GH_ACTIONS_LOCK ?= GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run github.com/github/gh-actions-lock/cmd/gh-actions-lock@$(GH_ACTIONS_LOCK_VERSION)
# The privileged tests run as root: through sudo unless make already is root.
SUDO ?= $(if $(filter 0,$(shell id -u)),,sudo)
INTEGRATION_TEST_BIN ?= dist/test/goexporter.test

# The bpf2go bindings are gitignored, and every package that imports
# internal/bpf needs them to compile, so the lint and test targets generate them
# when they are missing or older than the BPF source. They are generated for
# GOARCH (amd64 unless set), which must be the host's architecture for tests.
# Only Linux builds compile internal/bpf, so elsewhere nothing is generated.
BPF_BINDINGS := internal/bpf/lustreebpfexporter_$(BPF_TARGET_ARCH)_bpfel.go
BPF_PREREQ := $(if $(filter Linux,$(shell uname -s)),$(BPF_BINDINGS))

$(BPF_BINDINGS): internal/bpf/lustre_ebpf_exporter.bpf.c
	$(MAKE) generate-go-exporter

# GOOS= GOARCH= keep the bpf2go host binary (compiled by `go run`) at the
# runner's native arch even when GOARCH is set for the BPF target arch
# selection downstream.
.PHONY: generate-go-exporter
generate-go-exporter:
	cd internal/bpf && GOOS= GOARCH= $(BPF2GO) -cc $(BPF_CLANG) -strip $(BPF2GO_STRIP) -target $(GOARCH) -go-package bpf lustreebpfexporter ./lustre_ebpf_exporter.bpf.c -- $(BPF_CFLAGS)

# Each goarch picks up the embedded .o tagged for it via //go:build amd64 vs
# //go:build arm64, so both must be regenerated before a multi-arch build.
.PHONY: generate-go-exporter-all
generate-go-exporter-all:
	$(MAKE) generate-go-exporter GOARCH=amd64
	$(MAKE) generate-go-exporter GOARCH=arm64

# docker-generate-go-exporter: run BPF codegen inside Docker (use this on macOS)
.PHONY: docker-generate-go-exporter
docker-generate-go-exporter:
	docker build -f $(DOCKERFILE_GO_EXPORTER) --target codegen -t lustre-ebpf-exporter-codegen .
	docker run --rm -v $(CURDIR)/internal/bpf:/out lustre-ebpf-exporter-codegen \
		sh -c 'cp /src/internal/bpf/lustreebpfexporter_*.go /src/internal/bpf/lustreebpfexporter_*.o /out/'

.PHONY: build-go-exporter
build-go-exporter:
	CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -ldflags '$(LDFLAGS)' $(GOFLAGS) -o $(EXPORTER_BIN) ./cmd/lustre-ebpf-exporter

.PHONY: test-go
test-go: $(BPF_PREREQ)
	$(GO) test ./...

# Standard name for the unit tests.
.PHONY: test
test: test-go

# The local pre-PR gate: what the required CI jobs check without root.
.PHONY: check
check: lint lint-actions test-race

# golangci-lint (linters and formatters per .golangci.yml) and go.mod tidiness.
.PHONY: lint
lint: $(BPF_PREREQ)
	$(GOLANGCI_LINT) run
	$(GO) mod tidy -diff

# Apply the formatters of .golangci.yml.
.PHONY: fmt
fmt:
	$(GOLANGCI_LINT) fmt

# Lint (actionlint) and audit (zizmor) the GitHub Actions workflows. zizmor
# runs its online audits only with GH_TOKEN set.
# gh-actions-lock checks that .github/workflows/actions.lock pins every
# action the workflows use; with GH_TOKEN it also verifies each pin upstream.
.PHONY: lint-actions
lint-actions:
	$(ACTIONLINT)
	$(ZIZMOR) $(if $(GH_TOKEN),,--offline) .
	$(GH_ACTIONS_LOCK) $(if $(GH_TOKEN),--verify,--verify-local)

# Pin the actions in .github/workflows/actions.lock after a `uses:` changed,
# then review the diff. Needs a GitHub token (GH_TOKEN or `gh auth login`).
.PHONY: lock-actions
lock-actions:
	$(GH_ACTIONS_LOCK)

# Unit tests with the race detector.
.PHONY: test-race
test-race: $(BPF_PREREQ)
	$(GO) test -race ./...

# Run every fuzz target for FUZZTIME. The listing is assigned first so that a
# package that fails to compile stops the loop instead of looking target-less.
.PHONY: test-fuzz
test-fuzz: $(BPF_PREREQ)
	@set -e; for pkg in $$($(GO) list ./...); do \
		listed=$$($(GO) test -list '^Fuzz' $$pkg); \
		for f in $$(printf '%s\n' "$$listed" | grep '^Fuzz' || true); do \
			echo "== $$pkg $$f"; \
			$(GO) test -run='^$$' -fuzz="^$$f\$$" -fuzztime=$(FUZZTIME) $(if $(FUZZ_PARALLEL),-parallel=$(FUZZ_PARALLEL)) $$pkg; \
		done; \
	done

# The goexporter tests as root, race-enabled. The tests that load the embedded
# BPF object (it must pass the verifier of the running kernel, which needs BTF)
# or create its maps skip without privileges; LUSTRE_EBPF_REQUIRE_BPF=1 turns
# such a skip into a failure. No Lustre is needed: the kprobe attaches are
# faked.
.PHONY: test-integration
test-integration: $(BPF_PREREQ)
	mkdir -p $(dir $(INTEGRATION_TEST_BIN))
	$(GO) test -race -c -o $(INTEGRATION_TEST_BIN) ./internal/goexporter
	cd internal/goexporter && $(SUDO) LUSTRE_EBPF_REQUIRE_BPF=1 $(abspath $(INTEGRATION_TEST_BIN)) -test.count=1

# Benchmarks; compare runs with benchstat.
.PHONY: bench
bench: $(BPF_PREREQ)
	$(GO) test -run='^$$' -bench=. -benchmem -count=$(BENCH_COUNT) ./... | tee bench.txt

# Known vulnerabilities reachable from the code.
.PHONY: vuln
vuln: $(BPF_PREREQ)
	$(GOVULNCHECK) ./...

# Rank the most complex functions with cccc (https://github.com/moznion/cccc);
# what is analyzed is configured in cccc.toml.
.PHONY: complexity
complexity:
	cccc --table --top-cognitive 20 .

GORELEASER ?= goreleaser

.PHONY: snapshot
snapshot:
	$(GORELEASER) release --snapshot --clean --skip=publish

.PHONY: release-check
release-check:
	$(GORELEASER) check

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
