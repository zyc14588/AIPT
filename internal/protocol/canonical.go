package protocol

// Deterministic canonical JSON / SHA-256, byte-compatible with the
// independent Node protocol-assets oracle:
//
//	canonicalJson(v): arrays keep order, object keys are sorted recursively,
//	and JSON.stringify produces compact output with no insignificant
//	whitespace. The oracle hashes SHA-256 over that string (lowercase hex).
//
// CanonicalJSON accepts supplied JSON bytes, enforces every strict parsing
// rule (duplicate keys, trailing input, unsafe integers, negative zero,
// non-finite/overflowing numbers) BEFORE hashing, and returns the canonical
// compact representation. Object keys are sorted by JavaScript default sort
// order (UTF-16 code units), and number formatting follows the ES6
// JSON.stringify algorithm (Go's encoding/json float encoder is ES6-exact),
// so the output is byte-identical to the Node oracle for every input.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// CanonicalJSON returns the canonical compact JSON representation of data:
// object keys sorted recursively (JavaScript UTF-16 code unit order), arrays
// in order, no insignificant whitespace, finite/lossless numbers. It rejects
// duplicate keys, trailing input, unsafe integer rounding, negative zero,
// and non-finite/overflowing numeric input with typed contract errors.
func CanonicalJSON(data []byte) (string, error) {
	root, err := parseStrictJSON(data)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	writeCanonical(&b, root)
	return b.String(), nil
}

// CanonicalSHA256 returns the lowercase-hex SHA-256 digest of the canonical
// JSON representation of data, matching the Node canonical representation.
func CanonicalSHA256(data []byte) (string, error) {
	canon, err := CanonicalJSON(data)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canon))
	return hex.EncodeToString(sum[:]), nil
}

func writeCanonical(b *strings.Builder, n *jsonNode) {
	switch n.kind {
	case kindNull:
		b.WriteString("null")
	case kindBool:
		if n.boolVal {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case kindString:
		b.WriteString(quoteJSONUnits(n.units))
	case kindNumber:
		if n.isInt {
			b.WriteString(strconv.FormatInt(n.ival, 10))
		} else {
			// encoding/json marshals float64 with the exact ES6
			// JSON.stringify number algorithm (same thresholds, same
			// exponent cleanup), so this matches Node byte for byte.
			out, _ := json.Marshal(n.fval)
			b.Write(out)
		}
	case kindArray:
		b.WriteByte('[')
		for i, item := range n.arr {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonical(b, item)
		}
		b.WriteByte(']')
	case kindObject:
		members := make([]jsonMember, len(n.members))
		copy(members, n.members)
		sort.SliceStable(members, func(i, j int) bool {
			return compareUnits(members[i].key, members[j].key) < 0
		})
		b.WriteByte('{')
		for i, m := range members {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(quoteJSONUnits(m.key))
			b.WriteByte(':')
			writeCanonical(b, m.val)
		}
		b.WriteByte('}')
	}
}

// compareUnits compares two UTF-16 code-unit sequences lexicographically,
// matching JavaScript's default Array.prototype.sort() order (lone
// surrogates included, exactly like the JS strings they represent).
func compareUnits(a, b []uint16) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

// quoteJSONUnits renders a UTF-16 code-unit sequence as a JSON string
// exactly like Node's JSON.stringify: control characters use the
// \b \f \n \r \t short escapes, other controls use lowercase \u00xx, valid
// surrogate pairs recombine into their Unicode scalar, and lone high/low
// surrogates serialize as Node's lowercase \uXXXX escape (never as U+FFFD).
// No HTML escaping is applied.
func quoteJSONUnits(u []uint16) string {
	const hexDigits = "0123456789abcdef"
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(u); i++ {
		c := u[i]
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			switch {
			case c < 0x20:
				b.WriteString(`\u00`)
				b.WriteByte(hexDigits[c>>4])
				b.WriteByte(hexDigits[c&0xf])
			case c >= 0xD800 && c <= 0xDBFF && i+1 < len(u) && u[i+1] >= 0xDC00 && u[i+1] <= 0xDFFF:
				// Valid surrogate pair: recombine into the scalar.
				b.WriteRune(utf16.DecodeRune(rune(c), rune(u[i+1])))
				i++
			case c >= 0xD800 && c <= 0xDFFF:
				// Lone surrogate: Node serializes the lowercase \uXXXX
				// escape and never a replacement character.
				b.WriteString(`\u`)
				b.WriteByte(hexDigits[c>>12])
				b.WriteByte(hexDigits[(c>>8)&0xf])
				b.WriteByte(hexDigits[(c>>4)&0xf])
				b.WriteByte(hexDigits[c&0xf])
			default:
				b.WriteRune(rune(c))
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
