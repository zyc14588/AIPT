// Package launcher implements the AIPT fail-closed runtime shell.
// It owns the immutable launch-gate order, wires the shared configuration to
// PostgreSQL and the B003 forward-only migration runner, and performs bounded
// reverse cleanup. B004 implements MODEL and HARNESS; the production path
// still stops at IPC and never skips ahead to claim runtime readiness.
package launcher
