// Package toolchainsmoke proves — and proves nothing else — that the pinned
// Go toolchain recorded in tools/toolchain.lock.json can compile and run
// tests for this repository.
//
// AIPT-M0-B001 deliberately contains no runtime, Core, Launcher, Schema,
// JSON-RPC, Adapter, or DB business code, and no third-party Go runtime
// dependency. This package was the only Go package in the B001 candidate;
// the AIPT-M0-B002 iteration-5 dependency-free Go protocol consumer
// (internal/protocol) joined it as the second Go package. This package
// remains exactly the B001 toolchain smoke test — it never gains protocol,
// runtime, or business behavior.
package toolchainsmoke
