FROM golang:1.26.1-bookworm AS builder

ENV PATH=/usr/local/go/bin:/go/bin:${PATH}
ENV BPF_CFLAGS="-I. -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86"

RUN apt-get update \
 && apt-get install -y --no-install-recommends clang libbpf-dev libelf-dev linux-libc-dev llvm make \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY go.mod go.sum Makefile ./
COPY cmd ./cmd
COPY internal ./internal

RUN make generate-go-exporter GOOS=linux GOARCH=amd64
RUN make build-go-exporter GOOS=linux GOARCH=amd64
RUN make stage-go-exporter GOOS=linux GOARCH=amd64

RUN mkdir -p /out \
 && cp dist/linux-amd64/lustre-client-observer /out/lustre-client-observer \
 && cp dist/linux-amd64/lustre_client_observer.bpf.o /out/lustre_client_observer.bpf.o

FROM scratch AS export

COPY --from=builder /out/ /
