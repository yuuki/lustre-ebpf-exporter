//go:build linux

package slurm

import "os"

// defaultFSReader returns the platform-default /proc reader.
// Used to install sane defaults into Options if the caller left them nil.
func defaultFSReader() FSReader {
	return os.ReadFile
}

// NewDefault constructs a Resolver with /proc-backed readers. Any FSReader
// already set in opts is preserved; nil readers are filled with os.ReadFile.
func NewDefault(opts Options) *Resolver {
	rd := defaultFSReader()
	if opts.ReadEnviron == nil {
		opts.ReadEnviron = rd
	}
	if opts.ReadCgroup == nil {
		opts.ReadCgroup = rd
	}
	if opts.ReadStat == nil {
		opts.ReadStat = rd
	}
	return New(opts)
}
