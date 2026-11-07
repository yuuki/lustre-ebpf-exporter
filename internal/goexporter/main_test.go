package goexporter

import (
	"testing"

	"go.uber.org/goleak"
)

// The package starts goroutines (the perf read loop, the counter drain loop and
// the metrics server); every test must leave none of them running.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
