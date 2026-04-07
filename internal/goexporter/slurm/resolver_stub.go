//go:build !linux

package slurm

import "errors"

// errNotSupported is returned by the non-linux FSReader stubs so that
// Resolve() collapses to JobInfo{} on unsupported platforms.
var errNotSupported = errors.New("slurm: /proc reads are only supported on linux")

func stubReader(_ string) ([]byte, error) { return nil, errNotSupported }

// NewDefault constructs a Resolver whose readers always fail. Resolve()
// will therefore always return JobInfo{}, which is acceptable because
// this build target is used only for non-Linux development (tests of
// platform-independent logic).
func NewDefault(opts Options) *Resolver {
	if opts.ReadEnviron == nil {
		opts.ReadEnviron = stubReader
	}
	if opts.ReadCgroup == nil {
		opts.ReadCgroup = stubReader
	}
	if opts.ReadStat == nil {
		opts.ReadStat = stubReader
	}
	return New(opts)
}
