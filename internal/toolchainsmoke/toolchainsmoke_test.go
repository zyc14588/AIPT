package toolchainsmoke

import (
	"runtime"
	"strings"
	"testing"
)

// TestToolchainVersionLock is the B001 toolchain smoke test: it proves the
// `go test` machinery runs, and asserts the executing Go toolchain stays
// inside the pinned 1.26.x series (go.mod pins go 1.26.x with the exact
// toolchain go1.26.5).
func TestToolchainVersionLock(t *testing.T) {
	v := runtime.Version()
	if !strings.HasPrefix(v, "go1.26") {
		t.Fatalf("toolchain drift: runtime.Version()=%q, want go1.26.x", v)
	}
	if runtime.Compiler != "gc" {
		t.Fatalf("unexpected compiler %q, want gc", runtime.Compiler)
	}
}
