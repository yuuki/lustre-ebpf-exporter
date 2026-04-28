package goexporter

// BPF bindings are generated via the Makefile target `generate-go-exporter`
// (or `generate-go-exporter-all` for multi-arch). The bpf2go invocation lives
// there to keep CFLAGS, strip options, and per-arch include paths in one
// place. Do not add `go:generate` directives here.
