// Package launcher implements the AIPT-M0-B004 fail-closed runtime shell.
// It owns the immutable launch-gate order, wires the shared configuration to
// PostgreSQL and the B003 forward-only migration runner, and performs bounded
// reverse cleanup. The production path always stops at the first mandatory
// unimplemented gate (MODEL); it never skips ahead to claim runtime readiness.
package launcher
