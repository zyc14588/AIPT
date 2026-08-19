package postgres

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// ErrMigrationChecksumDrift is the exported sentinel for migration checksum
// drift. Its error text is the stable code AIPT_MIGRATION_CHECKSUM_DRIFT so
// callers can match it without parsing messages; it is also matched via
// errors.Is by *MigrationChecksumDriftError.
var ErrMigrationChecksumDrift = errors.New("AIPT_MIGRATION_CHECKSUM_DRIFT")

// MigrationChecksumDriftError is the typed, errors.Is-compatible error that
// reports a SHA-256 checksum drift for one migration: the on-disk SQL bytes no
// longer hash to the checksum recorded when the migration was applied. Version
// is the numeric migration version, Expected is the recorded [32]byte SHA-256
// and Actual is the SHA-256 of the current file bytes.
type MigrationChecksumDriftError struct {
	Version  int64
	Expected [32]byte
	Actual   [32]byte
}

// Error implements error and always embeds the stable drift code.
func (e *MigrationChecksumDriftError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: migration version %d checksum drift: expected %x, actual %x",
		ErrMigrationChecksumDrift, e.Version, e.Expected, e.Actual)
}

// Is makes *MigrationChecksumDriftError match the exported sentinel through
// errors.Is, independent of the carried version and checksums.
func (e *MigrationChecksumDriftError) Is(target error) bool {
	return target == ErrMigrationChecksumDrift
}

// ErrLedgerCursorMismatch is the exported sentinel for an append whose locked
// stream cursor does not match the actual ledger_events tail. Its error text
// is the stable code AIPT_LEDGER_CURSOR_MISMATCH so callers can match it
// without parsing messages; it is also matched via errors.Is by
// *LedgerCursorMismatchError.
var ErrLedgerCursorMismatch = errors.New("AIPT_LEDGER_CURSOR_MISMATCH")

// LedgerCursorMismatchError is the typed, errors.Is-compatible error reported
// when the ledger_streams cursor and the actual ledger_events tail disagree.
// StreamID is the affected stream, CursorSequence and CursorHash are the
// locked cursor values (CursorHash is nil for the empty cursor), and
// TailSequence, TailHash, and TailPresent describe the actual tail (TailHash
// is nil and TailPresent is false when the stream has no tail row at all).
type LedgerCursorMismatchError struct {
	StreamID       string
	CursorSequence int64
	CursorHash     *[32]byte
	TailSequence   int64
	TailHash       *[32]byte
	TailPresent    bool
}

// Error implements error and always embeds the stable mismatch code.
func (e *LedgerCursorMismatchError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: stream %q cursor (sequence %d, hash %s) does not match the actual ledger tail (present %t, sequence %d, hash %s)",
		ErrLedgerCursorMismatch, e.StreamID, e.CursorSequence, formatLedgerHash(e.CursorHash),
		e.TailPresent, e.TailSequence, formatLedgerHash(e.TailHash))
}

// Is makes *LedgerCursorMismatchError match the exported sentinel through
// errors.Is, independent of the carried stream, sequences, and hashes.
func (e *LedgerCursorMismatchError) Is(target error) bool {
	return target == ErrLedgerCursorMismatch
}

// ErrLedgerSequenceExhausted is the exported sentinel for an append rejected
// because the stream cursor already holds the maximum positive BIGINT
// sequence, so no further event can be appended. Its error text is the stable
// code AIPT_LEDGER_SEQUENCE_EXHAUSTED; it is also matched via errors.Is by
// *LedgerSequenceExhaustedError.
var ErrLedgerSequenceExhausted = errors.New("AIPT_LEDGER_SEQUENCE_EXHAUSTED")

// LedgerSequenceExhaustedError is the typed, errors.Is-compatible error
// reported when the next append sequence would overflow the positive signed
// int64/BIGINT domain. StreamID is the affected stream and Sequence is the
// exhausted cursor sequence (math.MaxInt64).
type LedgerSequenceExhaustedError struct {
	StreamID string
	Sequence int64
}

// Error implements error and always embeds the stable exhaustion code.
func (e *LedgerSequenceExhaustedError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: stream %q cursor is at the maximum positive BIGINT sequence %d; no further event can be appended",
		ErrLedgerSequenceExhausted, e.StreamID, e.Sequence)
}

// Is makes *LedgerSequenceExhaustedError match the exported sentinel through
// errors.Is, independent of the carried stream and sequence.
func (e *LedgerSequenceExhaustedError) Is(target error) bool {
	return target == ErrLedgerSequenceExhausted
}

// formatLedgerHash renders a 32-byte ledger hash deterministically as
// lowercase hex for error messages; a nil hash renders as "nil".
func formatLedgerHash(h *[32]byte) string {
	if h == nil {
		return "nil"
	}
	return hex.EncodeToString(h[:])
}
