package toolchainsmoke

import (
	"runtime"
	"testing"
)

// TestToolchainVersionLock remains the exact-version B001 smoke test.
// B003 qualified Go1.26.6 historically; Q018 qualified the current Go1.26.9.
// Q019 synchronizes this assertion with that current pin. Every other runtime
// version remains drift; historical sources keep their original assertion.
func TestToolchainVersionLock(t *testing.T) {
	v := runtime.Version()
	if v != "go1.26.9" {
		t.Fatalf("toolchain drift: runtime.Version()=%q, want exactly go1.26.9", v)
	}
	if runtime.Compiler != "gc" {
		t.Fatalf("unexpected compiler %q, want gc", runtime.Compiler)
	}
}
