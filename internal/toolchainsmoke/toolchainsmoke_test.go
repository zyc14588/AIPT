package toolchainsmoke

import (
	"runtime"
	"testing"
)

// TestToolchainVersionLock is the B001 toolchain smoke test, evolved by the
// AIPT-M0-B003 security requalification: it proves the `go test` machinery
// runs, and asserts the executing Go toolchain is EXACTLY go1.26.6 (go.mod
// pins go 1.26.x with the exact toolchain go1.26.6, the AIPT-M0-B003 security
// requalification of the B001-qualified go1.26.5). The CI workflow installs
// the exact Go 1.26.6 toolchain, so any other runtime version is drift.
func TestToolchainVersionLock(t *testing.T) {
	v := runtime.Version()
	if v != "go1.26.6" {
		t.Fatalf("toolchain drift: runtime.Version()=%q, want exactly go1.26.6", v)
	}
	if runtime.Compiler != "gc" {
		t.Fatalf("unexpected compiler %q, want gc", runtime.Compiler)
	}
}
