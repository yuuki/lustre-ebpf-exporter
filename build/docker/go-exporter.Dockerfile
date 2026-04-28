# Stage 1: Go module cache
FROM golang:1.26.2-bookworm AS deps

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

# Stage 2: BPF codegen (clang + bpf2go)
FROM deps AS codegen

ENV BPF_CFLAGS="-I. -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86"

RUN apt-get update \
 && apt-get install -y --no-install-recommends clang libbpf-dev libelf-dev linux-libc-dev llvm make \
 && rm -rf /var/lib/apt/lists/*

COPY Makefile ./
COPY internal/bpf ./internal/bpf

RUN make generate-go-exporter GOOS=linux GOARCH=amd64

# Stage 3: Go binary build
FROM deps AS builder

ARG VERSION=dev
ARG COMMIT=unknown

RUN apt-get update \
 && apt-get install -y --no-install-recommends libbpf-dev libelf-dev linux-libc-dev \
 && rm -rf /var/lib/apt/lists/*

COPY Makefile ./
COPY cmd ./cmd
COPY internal ./internal

# Replace host-side stubs with clang-compiled BPF artifacts from codegen stage
COPY --from=codegen /src/internal/bpf/lustreebpfexporter_*.go ./internal/bpf/
COPY --from=codegen /src/internal/bpf/lustreebpfexporter_*.o  ./internal/bpf/

RUN make build-go-exporter GOOS=linux GOARCH=amd64 \
    LDFLAGS="-X main.version=${VERSION} -X main.commit=${COMMIT}"

# Stage 4: Export artifact to local filesystem (used with --output type=local)
FROM scratch AS export

COPY --from=builder /src/dist/linux-amd64/lustre-ebpf-exporter /
