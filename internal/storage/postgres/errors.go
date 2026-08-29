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

// ErrLedgerExpectedSequence is the stable optimistic-concurrency rejection
// returned when an append's expected authoritative sequence is stale.
var ErrLedgerExpectedSequence = errors.New("AIPT_LEDGER_EXPECTED_SEQUENCE")

// LedgerExpectedSequenceError reports the expected and actual locked cursor.
// It contains identities and sequence numbers only; no payload, DSN, or
// credential can enter this error surface.
type LedgerExpectedSequenceError struct {
	StreamID string
	Expected int64
	Actual   int64
}

func (e *LedgerExpectedSequenceError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: stream %q expected sequence %d, actual %d",
		ErrLedgerExpectedSequence, e.StreamID, e.Expected, e.Actual)
}

func (e *LedgerExpectedSequenceError) Is(target error) bool {
	return target == ErrLedgerExpectedSequence
}

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

// ErrLedgerStreamNotFound is the exported sentinel for a VerifyStream run that
// cannot find the stream it was asked to verify. Its error text is the stable
// code AIPT_LEDGER_STREAM_NOT_FOUND so callers can match it without parsing
// messages; it is also matched via errors.Is by *LedgerStreamNotFoundError.
var ErrLedgerStreamNotFound = errors.New("AIPT_LEDGER_STREAM_NOT_FOUND")

// LedgerStreamNotFoundError is the typed, errors.Is-compatible error reported
// when the ledger stream identified by StreamID does not exist, so there is no
// chain to verify.
type LedgerStreamNotFoundError struct {
	StreamID string
}

// Error implements error and always embeds the stable not-found code.
func (e *LedgerStreamNotFoundError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: stream %q not found", ErrLedgerStreamNotFound, e.StreamID)
}

// Is makes *LedgerStreamNotFoundError match the exported sentinel through
// errors.Is, independent of the carried stream.
func (e *LedgerStreamNotFoundError) Is(target error) bool {
	return target == ErrLedgerStreamNotFound
}

// ErrLedgerSequenceGap is the exported sentinel for a VerifyStream run that
// finds the events of a stream are not contiguous from sequence 1. Its error
// text is the stable code AIPT_LEDGER_SEQUENCE_GAP so callers can match it
// without parsing messages; it is also matched via errors.Is by
// *LedgerSequenceGapError.
var ErrLedgerSequenceGap = errors.New("AIPT_LEDGER_SEQUENCE_GAP")

// LedgerSequenceGapError is the typed, errors.Is-compatible error reported
// when verifying a stream skips a sequence: Expected is the sequence the next
// event must carry and Actual is the sequence of the event actually found.
type LedgerSequenceGapError struct {
	StreamID string
	Expected int64
	Actual   int64
}

// Error implements error and always embeds the stable gap code.
func (e *LedgerSequenceGapError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: stream %q sequence gap: expected %d, actual %d",
		ErrLedgerSequenceGap, e.StreamID, e.Expected, e.Actual)
}

// Is makes *LedgerSequenceGapError match the exported sentinel through
// errors.Is, independent of the carried stream and sequences.
func (e *LedgerSequenceGapError) Is(target error) bool {
	return target == ErrLedgerSequenceGap
}

// ErrLedgerPrevHashMismatch is the exported sentinel for a VerifyStream run
// whose recomputed event hash does not match the recorded event, because the
// recorded previous-event hash differs from the expected one. Its error text
// is the stable code AIPT_LEDGER_PREV_HASH_MISMATCH so callers can match it
// without parsing messages; it is also matched via errors.Is by
// *LedgerPrevHashMismatchError.
var ErrLedgerPrevHashMismatch = errors.New("AIPT_LEDGER_PREV_HASH_MISMATCH")

// LedgerPrevHashMismatchError is the typed, errors.Is-compatible error
// reported when an event's recorded previous-event hash does not match the
// expected digest of the preceding event. Sequence is the verified event's
// sequence, Expected is the derived previous-event hash and Actual is the hash
// recorded on the event (both nil-safe).
type LedgerPrevHashMismatchError struct {
	StreamID string
	Sequence int64
	Expected *[32]byte
	Actual   *[32]byte
}

// Error implements error and always embeds the stable mismatch code.
func (e *LedgerPrevHashMismatchError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: stream %q sequence %d previous hash mismatch: expected %s, actual %s",
		ErrLedgerPrevHashMismatch, e.StreamID, e.Sequence, formatLedgerHash(e.Expected), formatLedgerHash(e.Actual))
}

// Is makes *LedgerPrevHashMismatchError match the exported sentinel through
// errors.Is, independent of the carried stream, sequence, and hashes.
func (e *LedgerPrevHashMismatchError) Is(target error) bool {
	return target == ErrLedgerPrevHashMismatch
}

// ErrLedgerPayloadHashMismatch is the exported sentinel for a VerifyStream run
// whose recomputed event hash does not match the recorded event, because the
// recorded payload hash differs from the payload stored with the event. Its
// error text is the stable code AIPT_LEDGER_PAYLOAD_HASH_MISMATCH so callers
// can match it without parsing messages; it is also matched via errors.Is by
// *LedgerPayloadHashMismatchError.
var ErrLedgerPayloadHashMismatch = errors.New("AIPT_LEDGER_PAYLOAD_HASH_MISMATCH")

// LedgerPayloadHashMismatchError is the typed, errors.Is-compatible error
// reported when an event's recorded payload hash does not match the SHA-256 of
// its stored canonical payload. Sequence is the verified event's sequence,
// Expected is the digest of the stored payload and Actual is the payload hash
// recorded on the event (both nil-safe).
type LedgerPayloadHashMismatchError struct {
	StreamID string
	Sequence int64
	Expected *[32]byte
	Actual   *[32]byte
}

// Error implements error and always embeds the stable mismatch code.
func (e *LedgerPayloadHashMismatchError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: stream %q sequence %d payload hash mismatch: expected %s, actual %s",
		ErrLedgerPayloadHashMismatch, e.StreamID, e.Sequence, formatLedgerHash(e.Expected), formatLedgerHash(e.Actual))
}

// Is makes *LedgerPayloadHashMismatchError match the exported sentinel through
// errors.Is, independent of the carried stream, sequence, and hashes.
func (e *LedgerPayloadHashMismatchError) Is(target error) bool {
	return target == ErrLedgerPayloadHashMismatch
}

// ErrLedgerEventHashMismatch is the exported sentinel for a VerifyStream run
// whose recomputed versioned event hash does not match the event hash recorded
// on the event. Its error text is the stable code AIPT_LEDGER_EVENT_HASH_MISMATCH
// so callers can match it without parsing messages; it is also matched via
// errors.Is by *LedgerEventHashMismatchError.
var ErrLedgerEventHashMismatch = errors.New("AIPT_LEDGER_EVENT_HASH_MISMATCH")

// LedgerEventHashMismatchError is the typed, errors.Is-compatible error
// reported when an event's recorded versioned event hash does not match the
// digest recomputed from the event's own fields. Sequence is the verified
// event's sequence, Expected is the recomputed digest and Actual is the event
// hash recorded on the event (both nil-safe).
type LedgerEventHashMismatchError struct {
	StreamID string
	Sequence int64
	Expected *[32]byte
	Actual   *[32]byte
}

// Error implements error and always embeds the stable mismatch code.
func (e *LedgerEventHashMismatchError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: stream %q sequence %d event hash mismatch: expected %s, actual %s",
		ErrLedgerEventHashMismatch, e.StreamID, e.Sequence, formatLedgerHash(e.Expected), formatLedgerHash(e.Actual))
}

// Is makes *LedgerEventHashMismatchError match the exported sentinel through
// errors.Is, independent of the carried stream, sequence, and hashes.
func (e *LedgerEventHashMismatchError) Is(target error) bool {
	return target == ErrLedgerEventHashMismatch
}

// ErrLedgerMalformedHash is the exported sentinel for a VerifyStream run that
// reads a hash column that is neither NULL nor exactly 32 bytes. Its error
// text is the stable code AIPT_LEDGER_MALFORMED_HASH so callers can match it
// without parsing messages; it is also matched via errors.Is by
// *LedgerMalformedHashError.
var ErrLedgerMalformedHash = errors.New("AIPT_LEDGER_MALFORMED_HASH")

// LedgerMalformedHashError is the typed, errors.Is-compatible error reported
// when a ledger hash column holds an impossible value. Field names the
// malformed hash column, IsNull reports whether the value was SQL NULL, and
// ByteLength reports the byte length of the value when it was not NULL.
type LedgerMalformedHashError struct {
	StreamID   string
	Sequence   int64
	Field      string
	IsNull     bool
	ByteLength int
}

// Error implements error and always embeds the stable malformed code.
func (e *LedgerMalformedHashError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: stream %q sequence %d malformed hash at field %s: is null %t, byte length %d",
		ErrLedgerMalformedHash, e.StreamID, e.Sequence, e.Field, e.IsNull, e.ByteLength)
}

// Is makes *LedgerMalformedHashError match the exported sentinel through
// errors.Is, independent of the carried stream, sequence, field, and value.
func (e *LedgerMalformedHashError) Is(target error) bool {
	return target == ErrLedgerMalformedHash
}

// formatLedgerHash renders a 32-byte ledger hash deterministically as
// lowercase hex for error messages; a nil hash renders as "nil".
func formatLedgerHash(h *[32]byte) string {
	if h == nil {
		return "nil"
	}
	return hex.EncodeToString(h[:])
}
