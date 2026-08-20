// This file defines the versioned ledger hash-chain encoding contract for the
// PostgreSQL storage layer. It is pure and database-free: it specifies the
// exact preimage layout of a ledger block under the literal domain
// AIPT_LEDGER_V1, validates every input field before any allocation or
// encoding, and provides the unexported encoding and hashing helpers that later
// package files (the Append and Verify paths) build on.
//
// The preimage commits only to the block content fields below. committed_at is
// deliberately excluded: the digest must not change when a block is re-applied
// or migrated, only when its content changes.
package postgres

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"
)

// HashDomain is the literal versioned domain that opens every ledger block
// preimage. It is part of the exact encoding contract: changing it changes
// every digest, so the domain is pinned here rather than taken from callers.
const HashDomain = "AIPT_LEDGER_V1"

// ErrInvalidLedgerHashInput is the exported sentinel for invalid versioned
// ledger hash-chain input. Its error text is the stable code
// AIPT_INVALID_LEDGER_HASH_INPUT so callers can match it without parsing
// messages; it is also matched via errors.Is by *LedgerHashInputError.
var ErrInvalidLedgerHashInput = errors.New("AIPT_INVALID_LEDGER_HASH_INPUT")

// LedgerHashInputError is the typed, errors.Is-compatible error that reports
// one rejected hash input field. Field is the contract field name ("", when
// the whole input is rejected) and Detail is a deterministic explanation.
type LedgerHashInputError struct {
	Field  string
	Detail string
}

// Error implements error and always embeds the stable rejection code.
func (e *LedgerHashInputError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Field != "" {
		return fmt.Sprintf("%s at field %s: %s", ErrInvalidLedgerHashInput, e.Field, e.Detail)
	}
	return fmt.Sprintf("%s: %s", ErrInvalidLedgerHashInput, e.Detail)
}

// Is makes *LedgerHashInputError match the exported sentinel through
// errors.Is, independent of the carried field and detail.
func (e *LedgerHashInputError) Is(target error) bool {
	return target == ErrInvalidLedgerHashInput
}

// ledgerHashInput is the versioned ledger hash-chain input. StreamID and
// EventID are the stream and event identifiers, Sequence is the strictly
// positive stream sequence number, stored as an int64 so it exactly shares
// PostgreSQL BIGINT's representable domain, EventType is the event type,
// PayloadHash is the raw 32-byte SHA-256 digest of the payload bytes
// (computed by the caller), and PrevHash is the previous block's digest —
// nil for the genesis block, which has no previous hash.
type ledgerHashInput struct {
	StreamID    string
	Sequence    int64
	EventID     string
	EventType   string
	PayloadHash [32]byte
	PrevHash    *[32]byte
}

// validateLedgerHashInput fails closed on any input that cannot be encoded as
// a versioned preimage: the domain and every textual field must be nonempty
// valid UTF-8 whose byte length fits a uint32 big-endian length prefix, and
// the sequence must be positive. PayloadHash and PrevHash are fixed 32-byte
// values and need no validation. Validation runs before any allocation or
// encoding, so invalid input never reaches the hash.
func validateLedgerHashInput(domain string, in ledgerHashInput) error {
	if err := validateTextField("domain", domain); err != nil {
		return err
	}
	if err := validateTextField("stream_id", in.StreamID); err != nil {
		return err
	}
	if err := validateTextField("event_id", in.EventID); err != nil {
		return err
	}
	if err := validateTextField("event_type", in.EventType); err != nil {
		return err
	}
	if in.Sequence <= 0 {
		return &LedgerHashInputError{Field: "sequence", Detail: "must be positive"}
	}
	return nil
}

// validateTextField rejects a textual preimage field that is empty, not valid
// UTF-8, or too long for the uint32 big-endian length prefix. The length bound
// is checked first so an impossibly long field fails before any UTF-8 scan.
func validateTextField(field, value string) error {
	if err := validateByteLength(field, len(value)); err != nil {
		return err
	}
	if value == "" {
		return &LedgerHashInputError{Field: field, Detail: "must be nonempty"}
	}
	if !utf8.ValidString(value) {
		return &LedgerHashInputError{Field: field, Detail: "must be valid UTF-8"}
	}
	return nil
}

// validateByteLength is the pure uint32 length-prefix bound guard: a field of
// n bytes is representable only when n fits in a uint32 big-endian length
// prefix. It is factored out so the impossible-length rejection can be
// exercised without allocating a >4GiB string.
func validateByteLength(field string, n int) error {
	if uint64(n) > math.MaxUint32 {
		return &LedgerHashInputError{Field: field, Detail: "byte length exceeds the uint32 length-prefix bound"}
	}
	return nil
}

// encodeLedgerPreimage builds the exact versioned preimage bytes for the given
// domain and input:
//
//	uint32 BE len(domain)     || domain UTF-8 bytes
//	uint32 BE len(stream_id)  || stream_id UTF-8 bytes
//	uint64 BE sequence
//	uint32 BE len(event_id)   || event_id UTF-8 bytes
//	uint32 BE len(event_type) || event_type UTF-8 bytes
//	payload hash (raw 32 bytes)
//	0x00, or 0x01 || previous hash (raw 32 bytes)
//
// The domain is a parameter so tests can prove the domain literal is bound
// into the digest; hashLedgerBlock pins it to HashDomain. committed_at is not
// part of the preimage. Input is validated before any allocation or encoding.
func encodeLedgerPreimage(domain string, in ledgerHashInput) ([]byte, error) {
	if err := validateLedgerHashInput(domain, in); err != nil {
		return nil, err
	}

	size := 4 + len(domain) + 4 + len(in.StreamID) + 8 + 4 + len(in.EventID) + 4 + len(in.EventType) + 32 + 1
	if in.PrevHash != nil {
		size += 32
	}
	preimage := make([]byte, 0, size)

	preimage = appendLengthPrefixed(preimage, domain)
	preimage = appendLengthPrefixed(preimage, in.StreamID)

	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], uint64(in.Sequence))
	preimage = append(preimage, seq[:]...)

	preimage = appendLengthPrefixed(preimage, in.EventID)
	preimage = appendLengthPrefixed(preimage, in.EventType)

	preimage = append(preimage, in.PayloadHash[:]...)

	if in.PrevHash == nil {
		preimage = append(preimage, 0)
	} else {
		preimage = append(preimage, 1)
		preimage = append(preimage, in.PrevHash[:]...)
	}
	return preimage, nil
}

// appendLengthPrefixed appends a uint32 big-endian byte-length prefix followed
// by the UTF-8 bytes of s. The caller must have validated s through
// validateLedgerHashInput (nonempty valid UTF-8, byte length ≤ MaxUint32), so
// the uint32 conversion is lossless.
func appendLengthPrefixed(dst []byte, s string) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s)))
	dst = append(dst, lenBuf[:]...)
	return append(dst, s...)
}

// hashLedgerBlock computes the SHA-256 digest of the versioned AIPT_LEDGER_V1
// preimage for in, validating the input first so invalid fields fail closed
// before any hashing. It is the unexported entry point the Append and Verify
// paths use to commit a ledger block to its digest.
func hashLedgerBlock(in ledgerHashInput) ([32]byte, error) {
	preimage, err := encodeLedgerPreimage(HashDomain, in)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(preimage), nil
}
