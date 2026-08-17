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
		b.WriteString(quoteJSONString(n.str))
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
			return compareUTF16(members[i].key, members[j].key) < 0
		})
		b.WriteByte('{')
		for i, m := range members {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(quoteJSONString(m.key))
			b.WriteByte(':')
			writeCanonical(b, m.val)
		}
		b.WriteByte('}')
	}
}

// compareUTF16 compares two strings by their UTF-16 code unit sequences,
// matching JavaScript's default Array.prototype.sort() order.
func compareUTF16(a, b string) int {
	ascii := true
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] >= 0x80 || b[i] >= 0x80 {
			ascii = false
			break
		}
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	if ascii {
		switch {
		case len(a) < len(b):
			return -1
		case len(a) > len(b):
			return 1
		}
		return 0
	}
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			if ua[i] < ub[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(ua) < len(ub):
		return -1
	case len(ua) > len(ub):
		return 1
	}
	return 0
}

// quoteJSONString renders s as a JSON string exactly like Node's
// JSON.stringify: control characters use the \b \f \n \r \t short escapes,
// other controls use lowercase \u00xx, and no HTML escaping is applied.
func quoteJSONString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
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
			if r < 0x20 {
				b.WriteString(`\u00`)
				const hexDigits = "0123456789abcdef"
				b.WriteByte(hexDigits[byte(r)>>4])
				b.WriteByte(hexDigits[byte(r)&0xf])
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
