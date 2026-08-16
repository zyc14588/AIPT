// Package toolchainsmoke proves — and proves nothing else — that the pinned
// Go toolchain recorded in tools/toolchain.lock.json can compile and run
// tests for this repository.
//
// AIPT-M0-B001 deliberately contains no runtime, Core, Launcher, Schema,
// JSON-RPC, Adapter, or DB business code, and no third-party Go runtime
// dependency. This package is the only Go package in the B001 candidate.
package toolchainsmoke
