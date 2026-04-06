FROM golang:1.26.1-bookworm AS builder

ENV BPF_CFLAGS="-I. -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86"

RUN apt-get update \
 && apt-get install -y --no-install-recommends clang libbpf-dev libelf-dev linux-libc-dev llvm make \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY go.mod go.sum Makefile ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal

RUN make generate-go-exporter GOOS=linux GOARCH=amd64
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bpf-verifier ./cmd/bpf-verifier

FROM debian:bookworm-slim
COPY --from=builder /bpf-verifier /bpf-verifier
ENTRYPOINT ["/bpf-verifier"]
