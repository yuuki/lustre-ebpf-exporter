//go:build linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	objPath := flag.String("obj", "", "path to BPF object file")
	flag.Parse()

	if *objPath == "" {
		fmt.Fprintln(os.Stderr, "usage: bpf-verifier -obj <path>")
		os.Exit(2)
	}

	if err := run(*objPath); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}

func run(objPath string) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load spec from %s: %w", objPath, err)
	}

	names := make([]string, 0, len(spec.Programs))
	for name := range spec.Programs {
		names = append(names, name)
	}
	sort.Strings(names)

	fmt.Printf("Verifying %d BPF programs from %s\n", len(names), objPath)
	for _, name := range names {
		fmt.Printf("  %-40s %s\n", name, spec.Programs[name].Type)
	}
	fmt.Println()

	col, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     ebpf.LogLevelBranch,
			LogSizeStart: 10 << 20,
		},
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("verifier rejected program:\n%+v", ve)
		}
		return fmt.Errorf("load collection: %w", err)
	}
	col.Close()

	fmt.Printf("OK: all %d programs passed BPF verifier\n", len(names))
	return nil
}
