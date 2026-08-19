package postgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
)

// ---- versioned ledger hash-chain contract vectors ----

// ledgerHashVector is a reusable, package-level fixed vector for the versioned
// ledger hash-chain contract: the exact input fields, the expected complete
// preimage hex, and the expected SHA-256 digest hex. Both hex constants are
// independent expected values computed offline (never through the
// implementation under test); later same-package SQL integration tests can
// reuse the records as ground truth for Append/Verify.
type ledgerHashVector struct {
	name        string
	input       ledgerHashInput
	preimageHex string
	digestHex   string
}

// mustDecode32 hex-decodes an exactly 32-byte constant, panicking at package
// initialization so a typo in a hard-coded vector fails the test binary
// immediately.
func mustDecode32(s string) [32]byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		panic(fmt.Sprintf("mustDecode32: %q is not an exactly 32-byte hex constant: %v", s, err))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

// The three vectors form a real chain: the chained block's PrevHash is the
// genesis digest and the Unicode block's PrevHash is the chained digest, so a
// later integration test can append exactly these three blocks in order.
var (
	// ledgerGenesisVector is the genesis block: no previous hash, ASCII fields.
	ledgerGenesisVector = ledgerHashVector{
		name: "genesis",
		input: ledgerHashInput{
			StreamID:    "game-events",
			Sequence:    1,
			EventID:     "evt-0001",
			EventType:   "ledger.appended",
			PayloadHash: mustDecode32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
		},
		preimageHex: "0000000e414950545f4c45444745525f56310000000b67616d652d6576656e74730000000000000001000000086576742d303030310000000f6c65646765722e617070656e646564000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00",
		digestHex:   "53b0b541ef1ecbc3242e65d0270b8907615ec65de72c7e0e25913a4d83894358",
	}

	// genesisDigest is the genesis block's digest, decoded from its vector and
	// reused as the chained block's previous hash.
	genesisDigest = mustDecode32(ledgerGenesisVector.digestHex)

	// ledgerChainedVector is the second block: previous hash present, ASCII
	// fields, PrevHash equal to the genesis digest.
	ledgerChainedVector = ledgerHashVector{
		name: "chained",
		input: ledgerHashInput{
			StreamID:    "game-events",
			Sequence:    2,
			EventID:     "evt-0002",
			EventType:   "state.applied",
			PayloadHash: mustDecode32("20406080a0c0e00001030507090b0d0f11131517191b1d1f21232527292b2d2f"),
			PrevHash:    &genesisDigest,
		},
		preimageHex: "0000000e414950545f4c45444745525f56310000000b67616d652d6576656e74730000000000000002000000086576742d303030320000000d73746174652e6170706c69656420406080a0c0e00001030507090b0d0f11131517191b1d1f21232527292b2d2f0153b0b541ef1ecbc3242e65d0270b8907615ec65de72c7e0e25913a4d83894358",
		digestHex:   "e993c740471db9c6f1aba0391898d44b933858be6f8d711ed60295493dbf6070",
	}

	// chainedDigest is the chained block's digest, decoded from its vector and
	// reused as the Unicode block's previous hash.
	chainedDigest = mustDecode32(ledgerChainedVector.digestHex)

	// ledgerUnicodeVector is the third block: previous hash present and
	// non-ASCII (CJK) stream/event identifiers and event type.
	ledgerUnicodeVector = ledgerHashVector{
		name: "unicode",
		input: ledgerHashInput{
			StreamID:    "游戏事件流",
			Sequence:    3,
			EventID:     "事件-0003",
			EventType:   "状态.已应用",
			PayloadHash: mustDecode32("7f8f9fafbfcfdfeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0001020304050607"),
			PrevHash:    &chainedDigest,
		},
		preimageHex: "0000000e414950545f4c45444745525f56310000000fe6b8b8e6888fe4ba8be4bbb6e6b58100000000000000030000000be4ba8be4bbb62d3030303300000010e78ab6e680812ee5b7b2e5ba94e794a87f8f9fafbfcfdfeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060701e993c740471db9c6f1aba0391898d44b933858be6f8d711ed60295493dbf6070",
		digestHex:   "e8663d2cdd1eef8b8b175640d3e3fe7c947cd804c81e50d861230239097cb749",
	}

	// ledgerHashVectors lists every fixed vector in chain order.
	ledgerHashVectors = []ledgerHashVector{
		ledgerGenesisVector,
		ledgerChainedVector,
		ledgerUnicodeVector,
	}
)

func TestHashDomainLiteral(t *testing.T) {
	if HashDomain != "AIPT_LEDGER_V1" {
		t.Fatalf("HashDomain = %q, want the literal AIPT_LEDGER_V1", HashDomain)
	}
}

func TestHashVectorsFormChain(t *testing.T) {
	if ledgerGenesisVector.input.PrevHash != nil {
		t.Error("genesis PrevHash must be nil")
	}
	if got := *ledgerChainedVector.input.PrevHash; got != genesisDigest {
		t.Errorf("chained PrevHash = %x, want genesis digest %x", got, genesisDigest)
	}
	if got := *ledgerUnicodeVector.input.PrevHash; got != chainedDigest {
		t.Errorf("unicode PrevHash = %x, want chained digest %x", got, chainedDigest)
	}
}

// checkVectorPreimageStructure independently parses a decoded preimage
// constant back into its structural fields and compares every part against the
// vector input, proving the constant has the exact documented layout: four
// uint32 length-prefixed UTF-8 fields, a big-endian uint64 sequence, a raw
// 32-byte payload hash, and an explicit 0-or-1 previous-hash marker with
// nothing after it (in particular, no timestamp).
func checkVectorPreimageStructure(t *testing.T, v ledgerHashVector, preimage []byte) {
	t.Helper()
	off := 0
	readLenPrefixed := func(want string) {
		t.Helper()
		if off+4 > len(preimage) {
			t.Fatalf("preimage truncated at byte %d reading a length prefix", off)
		}
		n := binary.BigEndian.Uint32(preimage[off : off+4])
		off += 4
		if int(n) > len(preimage)-off {
			t.Fatalf("preimage truncated at byte %d reading a %d-byte field", off, int(n))
		}
		got := string(preimage[off : off+int(n)])
		off += int(n)
		if got != want {
			t.Errorf("length-prefixed field = %q, want %q", got, want)
		}
	}

	readLenPrefixed("AIPT_LEDGER_V1")
	readLenPrefixed(v.input.StreamID)

	if off+8 > len(preimage) {
		t.Fatalf("preimage truncated at byte %d reading the sequence", off)
	}
	if seq := binary.BigEndian.Uint64(preimage[off : off+8]); seq != uint64(v.input.Sequence) {
		t.Errorf("sequence = %d, want %d", seq, v.input.Sequence)
	}
	off += 8

	readLenPrefixed(v.input.EventID)
	readLenPrefixed(v.input.EventType)

	if off+32 > len(preimage) {
		t.Fatalf("preimage truncated at byte %d reading the payload hash", off)
	}
	if got := preimage[off : off+32]; !bytes.Equal(got, v.input.PayloadHash[:]) {
		t.Errorf("payload hash = %x, want %x", got, v.input.PayloadHash)
	}
	off += 32

	if off >= len(preimage) {
		t.Fatalf("preimage truncated at byte %d reading the marker", off)
	}
	marker := preimage[off]
	off++
	if v.input.PrevHash == nil {
		if marker != 0 {
			t.Errorf("marker = %d, want 0 for absent previous hash", marker)
		}
	} else {
		if marker != 1 {
			t.Errorf("marker = %d, want 1 for present previous hash", marker)
		}
		if off+32 > len(preimage) {
			t.Fatalf("preimage truncated at byte %d reading the previous hash", off)
		}
		if got := preimage[off : off+32]; !bytes.Equal(got, v.input.PrevHash[:]) {
			t.Errorf("previous hash = %x, want %x", got, v.input.PrevHash)
		}
		off += 32
	}
	if off != len(preimage) {
		t.Errorf("preimage has %d trailing bytes after the marker section; the layout allows none", len(preimage)-off)
	}
}

func TestHashLedgerBlockVectors(t *testing.T) {
	for _, v := range ledgerHashVectors {
		t.Run(v.name, func(t *testing.T) {
			preimage, err := hex.DecodeString(v.preimageHex)
			if err != nil {
				t.Fatalf("decode preimageHex: %v", err)
			}
			digest, err := hex.DecodeString(v.digestHex)
			if err != nil {
				t.Fatalf("decode digestHex: %v", err)
			}

			// Independently decode the preimage constant field by field and
			// compare every part against the vector input.
			checkVectorPreimageStructure(t, v, preimage)

			// The encoded preimage must be byte-for-byte identical to the
			// independent constant.
			got, err := encodeLedgerPreimage(HashDomain, v.input)
			if err != nil {
				t.Fatalf("encodeLedgerPreimage: %v", err)
			}
			if !bytes.Equal(got, preimage) {
				t.Errorf("preimage = %x, want %x", got, preimage)
			}

			// The digest must be exactly the independent constant.
			gotDigest, err := hashLedgerBlock(v.input)
			if err != nil {
				t.Fatalf("hashLedgerBlock: %v", err)
			}
			var wantDigest [32]byte
			copy(wantDigest[:], digest)
			if gotDigest != wantDigest {
				t.Errorf("digest = %x, want %x", gotDigest, wantDigest)
			}

			// Independent cross-check: SHA-256 of the decoded preimage constant
			// must equal the decoded digest constant (stdlib only, no
			// implementation-under-test involvement).
			if sum := sha256.Sum256(preimage); sum != wantDigest {
				t.Errorf("sha256(preimageHex) = %x, want digestHex %x", sum, wantDigest)
			}

			// The preimage length must match the structural layout exactly:
			// four length-prefixed fields, an 8-byte sequence, a raw 32-byte
			// payload hash, a 1-byte marker, and the 32 prev bytes only when
			// present. Any extra field (for example a timestamp) would break
			// this length.
			wantLen := 4 + len("AIPT_LEDGER_V1") + 4 + len(v.input.StreamID) + 8 +
				4 + len(v.input.EventID) + 4 + len(v.input.EventType) + 32 + 1
			if v.input.PrevHash != nil {
				wantLen += 32
			}
			if len(preimage) != wantLen {
				t.Errorf("preimage length = %d, want %d (layout without timestamp)", len(preimage), wantLen)
			}
		})
	}
}

func TestHashLedgerBlockMaxInt64Sequence(t *testing.T) {
	// The sequence field is an int64 sharing PostgreSQL BIGINT's
	// representable domain: the maximum positive value must encode losslessly
	// as the big-endian bytes 0x7fffffffffffffff.
	in := ledgerGenesisVector.input
	in.Sequence = math.MaxInt64

	preimage, err := encodeLedgerPreimage(HashDomain, in)
	if err != nil {
		t.Fatalf("encodeLedgerPreimage(MaxInt64 sequence): %v", err)
	}
	off := 4 + len(HashDomain) + 4 + len(in.StreamID)
	if off+8 > len(preimage) {
		t.Fatalf("preimage truncated at byte %d reading the sequence", off)
	}
	seqBytes := preimage[off : off+8]
	if want := "7fffffffffffffff"; hex.EncodeToString(seqBytes) != want {
		t.Errorf("sequence bytes = %x, want %s", seqBytes, want)
	}
	if _, err := hashLedgerBlock(in); err != nil {
		t.Fatalf("hashLedgerBlock(MaxInt64 sequence): %v", err)
	}
}

// ---- sensitivity: every bound field plus domain and prev presence/bytes ----

func TestHashSensitivity(t *testing.T) {
	base := ledgerGenesisVector.input
	canonical, err := hashLedgerBlock(base)
	if err != nil {
		t.Fatalf("hashLedgerBlock(base): %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*ledgerHashInput)
	}{
		{"stream_id", func(m *ledgerHashInput) { m.StreamID += "-alt" }},
		{"sequence", func(m *ledgerHashInput) { m.Sequence++ }},
		{"event_id", func(m *ledgerHashInput) { m.EventID += "-alt" }},
		{"event_type", func(m *ledgerHashInput) { m.EventType += "-alt" }},
		{"payload_hash", func(m *ledgerHashInput) { m.PayloadHash[0] ^= 0x01 }},
		{"prev_added", func(m *ledgerHashInput) { m.PrevHash = &[32]byte{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := base
			tc.mutate(&mutated)
			got, err := hashLedgerBlock(mutated)
			if err != nil {
				t.Fatalf("hashLedgerBlock(mutated): %v", err)
			}
			if got == canonical {
				t.Errorf("digest %x must change when %s changes", canonical, tc.name)
			}
		})
	}
}

func TestHashSensitivityDomain(t *testing.T) {
	base := ledgerGenesisVector.input

	canonical, err := hashLedgerBlock(base)
	if err != nil {
		t.Fatalf("hashLedgerBlock(base): %v", err)
	}

	// Encode the same input under a different (still valid) domain and hash the
	// preimage with the stdlib directly: the digest must change, proving the
	// domain literal is bound into the preimage.
	mutated, err := encodeLedgerPreimage("AIPT_LEDGER_V2", base)
	if err != nil {
		t.Fatalf("encodeLedgerPreimage(AIPT_LEDGER_V2): %v", err)
	}
	if got := sha256.Sum256(mutated); got == canonical {
		t.Error("digest must change when the domain changes")
	}
}

func TestHashSensitivityPrevPresence(t *testing.T) {
	// Removing the previous hash from the chained block flips the marker byte
	// (0x01 -> 0x00) and drops the prev bytes: the digest must change.
	chained := ledgerChainedVector.input
	withPrev, err := hashLedgerBlock(chained)
	if err != nil {
		t.Fatalf("hashLedgerBlock(chained): %v", err)
	}
	withoutPrev := chained
	withoutPrev.PrevHash = nil
	got, err := hashLedgerBlock(withoutPrev)
	if err != nil {
		t.Fatalf("hashLedgerBlock(withoutPrev): %v", err)
	}
	if got == withPrev {
		t.Error("digest must change when the previous hash is dropped")
	}

	// Adding a previous hash to the genesis block flips the marker byte
	// (0x00 -> 0x01) and adds prev bytes: the digest must change.
	genesis := ledgerGenesisVector.input
	genesisDigest, err := hashLedgerBlock(genesis)
	if err != nil {
		t.Fatalf("hashLedgerBlock(genesis): %v", err)
	}
	withAdded := genesis
	withAdded.PrevHash = &[32]byte{}
	gotAdded, err := hashLedgerBlock(withAdded)
	if err != nil {
		t.Fatalf("hashLedgerBlock(withAdded): %v", err)
	}
	if gotAdded == genesisDigest {
		t.Error("digest must change when a previous hash is added")
	}
}

func TestHashSensitivityPrevBytes(t *testing.T) {
	chained := ledgerChainedVector.input
	canonical, err := hashLedgerBlock(chained)
	if err != nil {
		t.Fatalf("hashLedgerBlock(chained): %v", err)
	}

	// Flip one byte of the previous hash: the marker stays 0x01 but the prev
	// bytes change, so the digest must change.
	mutated := chained
	prev := *mutated.PrevHash
	prev[0] ^= 0x01
	mutated.PrevHash = &prev
	got, err := hashLedgerBlock(mutated)
	if err != nil {
		t.Fatalf("hashLedgerBlock(mutated): %v", err)
	}
	if got == canonical {
		t.Error("digest must change when a previous-hash byte changes")
	}
}

// ---- invalid input: fail closed before hashing ----

func TestHashLedgerBlockRejectsInvalidInput(t *testing.T) {
	base := ledgerGenesisVector.input

	cases := []struct {
		name   string
		mutate func(*ledgerHashInput)
	}{
		{"empty stream_id", func(m *ledgerHashInput) { m.StreamID = "" }},
		{"empty event_id", func(m *ledgerHashInput) { m.EventID = "" }},
		{"empty event_type", func(m *ledgerHashInput) { m.EventType = "" }},
		{"non-UTF8 stream_id", func(m *ledgerHashInput) { m.StreamID = "\xff\xfe" }},
		{"non-UTF8 event_id", func(m *ledgerHashInput) { m.EventID = "\xff\xfe" }},
		{"non-UTF8 event_type", func(m *ledgerHashInput) { m.EventType = "\xff\xfe" }},
		{"zero sequence", func(m *ledgerHashInput) { m.Sequence = 0 }},
		{"negative sequence", func(m *ledgerHashInput) { m.Sequence = -1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := base
			tc.mutate(&mutated)
			_, err := hashLedgerBlock(mutated)
			if err == nil {
				t.Fatal("invalid input must fail closed before hashing")
			}
			if !errors.Is(err, ErrInvalidLedgerHashInput) {
				t.Errorf("error = %v, want errors.Is(ErrInvalidLedgerHashInput)", err)
			}
			var typed *LedgerHashInputError
			if !errors.As(err, &typed) {
				t.Errorf("error = %v, want recoverable via errors.As", err)
			}
		})
	}
}

func TestEncodeLedgerPreimageRejectsInvalidDomain(t *testing.T) {
	base := ledgerGenesisVector.input
	for name, domain := range map[string]string{
		"empty":    "",
		"non-UTF8": "\xff\xfe",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := encodeLedgerPreimage(domain, base)
			if err == nil {
				t.Fatal("invalid domain must be rejected")
			}
			if !errors.Is(err, ErrInvalidLedgerHashInput) {
				t.Errorf("error = %v, want errors.Is(ErrInvalidLedgerHashInput)", err)
			}
		})
	}
}

func TestLedgerHashInputErrorCarriesField(t *testing.T) {
	// Every rejection is deterministic: the typed error carries the exact
	// contract field name and a stable detail, matchable without parsing the
	// message text.
	_, err := hashLedgerBlock(ledgerHashInput{StreamID: "", Sequence: 1, EventID: "evt-1", EventType: "ledger.appended"})
	if err == nil {
		t.Fatal("empty stream_id must be rejected")
	}
	var typed *LedgerHashInputError
	if !errors.As(err, &typed) {
		t.Fatalf("error = %v, want recoverable via errors.As", err)
	}
	if typed.Field != "stream_id" {
		t.Errorf("typed.Field = %q, want %q", typed.Field, "stream_id")
	}
	if !strings.Contains(typed.Detail, "nonempty") {
		t.Errorf("typed.Detail = %q, want it to mention nonempty", typed.Detail)
	}
	if !strings.Contains(err.Error(), "AIPT_INVALID_LEDGER_HASH_INPUT") {
		t.Errorf("Error() = %q, want it to embed the stable rejection code", err)
	}
}

func TestValidateByteLengthRejectsUint32Overflow(t *testing.T) {
	// A field longer than MaxUint32 bytes cannot be represented by the uint32
	// big-endian length prefix. The pure guard is exercised directly with the
	// boundary value instead of allocating a >4GiB string.
	if strconv.IntSize < 64 {
		t.Skip("uint32 overflow bound requires a 64-bit int")
	}
	tooLong := int(int64(math.MaxUint32) + 1)
	if err := validateByteLength("stream_id", tooLong); err == nil {
		t.Fatal("byte length beyond MaxUint32 must be rejected")
	} else if !errors.Is(err, ErrInvalidLedgerHashInput) {
		t.Errorf("error = %v, want errors.Is(ErrInvalidLedgerHashInput)", err)
	}
	if err := validateByteLength("stream_id", math.MaxUint32); err != nil {
		t.Errorf("byte length exactly MaxUint32 must be accepted, got %v", err)
	}
}
