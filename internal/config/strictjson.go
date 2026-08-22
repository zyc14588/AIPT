package config

// Strict, lossless JSON parsing (Go standard library only). This package
// implements its own recursive-descent JSON parser instead of relying on
// encoding/json's Decoder because the frozen config contract requires
// guarantees the generic decoder does not provide:
//
//   - duplicate object member names are rejected at ANY nesting depth
//     (encoding/json silently keeps the last occurrence);
//   - trailing values after the top-level document are rejected;
//   - integer values that overflow int64 are rejected instead of silently
//     rounding;
//   - non-finite / overflowing numbers (1e999) are rejected instead of
//     decoded as +Inf;
//   - every parsed node keeps its exact member/value structure, so typed
//     decoding walks raw parsed nodes and never re-parses attacker input.
//
// The parser follows RFC 8259 exactly: whitespace is only space/tab/CR/LF,
// strings carry only the JSON escapes (with \u surrogate pairs decoded), and
// invalid UTF-8 is rejected. Unknown-field values still have to be
// syntactically valid JSON because the whole document is parsed before any
// typed member is read.

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

type jsonKind uint8

const (
	kindNull jsonKind = iota
	kindBool
	kindString
	kindNumber
	kindArray
	kindObject
)

// jsonNode is one parsed JSON value. For strings, sval holds the decoded Go
// string; for numbers, isInt/ival hold exact int64 integers and fval holds
// the float64 view of non-integer numbers. start/end span the raw text in
// data.
type jsonNode struct {
	kind    jsonKind
	start   int
	end     int
	data    []byte
	sval    string
	boolVal bool
	isInt   bool
	ival    int64
	fval    float64
	arr     []*jsonNode
	members []jsonMember
}

type jsonMember struct {
	key string
	val *jsonNode
}

// member returns the value node of the given key, or nil when absent.
func (n *jsonNode) member(key string) *jsonNode {
	if n.kind != kindObject {
		return nil
	}
	for _, m := range n.members {
		if m.key == key {
			return m.val
		}
	}
	return nil
}

// strictJSONParser is the strict parser.
type strictJSONParser struct {
	data []byte
	pos  int
}

const maxJSONDepth = 512

// parseStrictJSON parses exactly one JSON value and enforces every strict
// rule above. It returns the parsed tree.
func parseStrictJSON(data []byte) (*jsonNode, error) {
	p := &strictJSONParser{data: data}
	p.skipWS()
	if p.pos >= len(p.data) {
		return nil, newConfigError(ReasonJSONMalformed, "$", "empty input")
	}
	n, err := p.parseValue(0, "$")
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.pos != len(p.data) {
		return nil, newConfigError(ReasonJSONTrailing, "$",
			fmt.Sprintf("trailing data after the top-level value at byte %d", p.pos))
	}
	return n, nil
}

func (p *strictJSONParser) skipWS() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *strictJSONParser) parseValue(depth int, path string) (*jsonNode, error) {
	if p.pos >= len(p.data) {
		return nil, newConfigError(ReasonJSONMalformed, path, "unexpected end of input")
	}
	if depth > maxJSONDepth {
		return nil, newConfigError(ReasonJSONMalformed, path, "JSON nesting too deep")
	}
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.parseObject(depth, path)
	case c == '[':
		return p.parseArray(depth, path)
	case c == '"':
		return p.parseString(path)
	case c == 't':
		return p.parseLiteral("true", true, path)
	case c == 'f':
		return p.parseLiteral("false", false, path)
	case c == 'n':
		return p.parseLiteral("null", false, path)
	case c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumber(path)
	default:
		return nil, newConfigError(ReasonJSONMalformed, path,
			fmt.Sprintf("unexpected byte %q", c))
	}
}

// valueDelimiterOK reports whether the byte following a scalar value is a
// legal delimiter (whitespace, ',', ']', '}', or end of input).
func (p *strictJSONParser) valueDelimiterOK() bool {
	if p.pos >= len(p.data) {
		return true
	}
	switch p.data[p.pos] {
	case ' ', '\t', '\n', '\r', ',', ']', '}':
		return true
	}
	return false
}

func (p *strictJSONParser) parseLiteral(lit string, val bool, path string) (*jsonNode, error) {
	start := p.pos
	for i := 0; i < len(lit); i++ {
		if p.pos >= len(p.data) || p.data[p.pos] != lit[i] {
			return nil, newConfigError(ReasonJSONMalformed, path,
				fmt.Sprintf("malformed literal at byte %d", start))
		}
		p.pos++
	}
	if !p.valueDelimiterOK() {
		return nil, newConfigError(ReasonJSONMalformed, path,
			fmt.Sprintf("malformed literal at byte %d", start))
	}
	kind := kindBool
	if lit == "null" {
		kind = kindNull
	}
	return &jsonNode{kind: kind, start: start, end: p.pos, data: p.data, boolVal: val}, nil
}

// parseString parses a JSON string starting at the current '"' and returns a
// node carrying the decoded value. \u escapes (surrogate pairs included) are
// decoded; lone surrogates decode to U+FFFD exactly like encoding/json, and
// invalid UTF-8 and raw control characters are rejected.
func (p *strictJSONParser) parseString(path string) (*jsonNode, error) {
	start := p.pos
	p.pos++ // consume '"'
	var sb strings.Builder
	for {
		if p.pos >= len(p.data) {
			return nil, newConfigError(ReasonJSONMalformed, path, "unterminated string")
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			p.pos++
			return &jsonNode{kind: kindString, start: start, end: p.pos, data: p.data, sval: sb.String()}, nil
		case c == '\\':
			p.pos++
			if p.pos >= len(p.data) {
				return nil, newConfigError(ReasonJSONMalformed, path, "unterminated string escape")
			}
			switch esc := p.data[p.pos]; esc {
			case '"', '\\', '/':
				sb.WriteByte(esc)
				p.pos++
			case 'b':
				sb.WriteByte('\b')
				p.pos++
			case 'f':
				sb.WriteByte('\f')
				p.pos++
			case 'n':
				sb.WriteByte('\n')
				p.pos++
			case 'r':
				sb.WriteByte('\r')
				p.pos++
			case 't':
				sb.WriteByte('\t')
				p.pos++
			case 'u':
				if p.pos+4 >= len(p.data) {
					return nil, newConfigError(ReasonJSONMalformed, path, "truncated \\u escape")
				}
				r1, ok := hex4(p.data[p.pos+1 : p.pos+5])
				if !ok {
					return nil, newConfigError(ReasonJSONMalformed, path, "invalid \\u escape")
				}
				p.pos += 5
				if r1 >= 0xD800 && r1 <= 0xDBFF {
					// Possible high surrogate: look for a following low
					// surrogate pair.
					if p.pos+5 < len(p.data) && p.data[p.pos] == '\\' && p.data[p.pos+1] == 'u' {
						r2, ok := hex4(p.data[p.pos+2 : p.pos+6])
						if !ok {
							return nil, newConfigError(ReasonJSONMalformed, path, "invalid \\u escape")
						}
						if r2 >= 0xDC00 && r2 <= 0xDFFF {
							sb.WriteRune(utf16.DecodeRune(rune(r1), rune(r2)))
							p.pos += 6
							continue
						}
					}
					sb.WriteRune(utf8.RuneError) // lone high surrogate
					continue
				}
				if r1 >= 0xDC00 && r1 <= 0xDFFF {
					sb.WriteRune(utf8.RuneError) // lone low surrogate
					continue
				}
				sb.WriteRune(rune(r1))
			default:
				return nil, newConfigError(ReasonJSONMalformed, path,
					fmt.Sprintf("invalid string escape \\%c at byte %d", esc, p.pos))
			}
		case c < 0x20:
			return nil, newConfigError(ReasonJSONMalformed, path,
				fmt.Sprintf("raw control character 0x%02x inside string at byte %d", c, p.pos))
		default:
			r, size := utf8.DecodeRune(p.data[p.pos:])
			if r == utf8.RuneError && size == 1 {
				return nil, newConfigError(ReasonJSONMalformed, path, "string carries invalid UTF-8")
			}
			sb.Write(p.data[p.pos : p.pos+size])
			p.pos += size
		}
	}
}

func hex4(b []byte) (rune, bool) {
	if len(b) != 4 {
		return 0, false
	}
	v := 0
	for _, c := range b {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= int(c - '0')
		case c >= 'a' && c <= 'f':
			v |= int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v |= int(c-'A') + 10
		default:
			return 0, false
		}
	}
	return rune(v), true
}

// configJSONPath prevents attacker-controlled object member names from being
// reflected into errors while preserving useful paths for contract members.
func configJSONPath(parent, key string) string {
	switch key {
	case "schema", "profile", "database", "evidence", "dsn", "identity", "namespace", "ping_timeout_ms":
		return parent + "/" + key
	default:
		return parent + "/<unknown>"
	}
}

// parseNumber parses a JSON number with the exact RFC 8259 grammar and
// enforces strictness: integer literals must fit int64, non-integer literals
// must parse to a finite float64 (overflow to infinity is rejected).
func (p *strictJSONParser) parseNumber(path string) (*jsonNode, error) {
	start := p.pos
	if p.data[p.pos] == '-' {
		p.pos++
		if p.pos >= len(p.data) {
			return nil, newConfigError(ReasonJSONMalformed, path, "truncated number")
		}
	}
	// Integer part.
	switch {
	case p.data[p.pos] == '0':
		p.pos++
	case p.data[p.pos] >= '1' && p.data[p.pos] <= '9':
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
	default:
		return nil, newConfigError(ReasonJSONMalformed, path,
			fmt.Sprintf("malformed number at byte %d", start))
	}
	isInt := true
	// Fraction.
	if p.pos < len(p.data) && p.data[p.pos] == '.' {
		isInt = false
		p.pos++
		if p.pos >= len(p.data) || p.data[p.pos] < '0' || p.data[p.pos] > '9' {
			return nil, newConfigError(ReasonJSONMalformed, path,
				fmt.Sprintf("malformed number fraction at byte %d", start))
		}
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
	}
	// Exponent.
	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		isInt = false
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		if p.pos >= len(p.data) || p.data[p.pos] < '0' || p.data[p.pos] > '9' {
			return nil, newConfigError(ReasonJSONMalformed, path,
				fmt.Sprintf("malformed number exponent at byte %d", start))
		}
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
	}
	if !p.valueDelimiterOK() {
		return nil, newConfigError(ReasonJSONMalformed, path,
			fmt.Sprintf("malformed number at byte %d", start))
	}
	raw := string(p.data[start:p.pos])
	if isInt {
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil, newConfigError(ReasonJSONUnsafeInteger, path,
				"integer outside the int64 range")
		}
		return &jsonNode{kind: kindNumber, start: start, end: p.pos, data: p.data, isInt: true, ival: v}, nil
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return nil, newConfigError(ReasonJSONNonFiniteNumber, path,
			"number overflows the IEEE-754 double range")
	}
	return &jsonNode{kind: kindNumber, start: start, end: p.pos, data: p.data, fval: f}, nil
}

func (p *strictJSONParser) parseObject(depth int, path string) (*jsonNode, error) {
	start := p.pos
	p.pos++ // consume '{'
	p.skipWS()
	n := &jsonNode{kind: kindObject, start: start, data: p.data}
	seen := make(map[string]bool, 8)
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		n.end = p.pos
		return n, nil
	}
	for {
		p.skipWS()
		if p.pos >= len(p.data) {
			return nil, newConfigError(ReasonJSONMalformed, path, "unterminated object")
		}
		if p.data[p.pos] != '"' {
			return nil, newConfigError(ReasonJSONMalformed, path,
				fmt.Sprintf("expected object member name at byte %d", p.pos))
		}
		keyNode, err := p.parseString(path)
		if err != nil {
			return nil, err
		}
		key := keyNode.sval
		if seen[key] {
			return nil, newConfigError(ReasonJSONDuplicateKey, configJSONPath(path, key),
				"duplicate object member")
		}
		seen[key] = true
		p.skipWS()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return nil, newConfigError(ReasonJSONMalformed, path,
				"expected ':' after object member")
		}
		p.pos++
		p.skipWS()
		val, err := p.parseValue(depth+1, configJSONPath(path, key))
		if err != nil {
			return nil, err
		}
		n.members = append(n.members, jsonMember{key: key, val: val})
		p.skipWS()
		if p.pos >= len(p.data) {
			return nil, newConfigError(ReasonJSONMalformed, path, "unterminated object")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			n.end = p.pos
			return n, nil
		default:
			return nil, newConfigError(ReasonJSONMalformed, path,
				fmt.Sprintf("expected ',' or '}' at byte %d", p.pos))
		}
	}
}

func (p *strictJSONParser) parseArray(depth int, path string) (*jsonNode, error) {
	start := p.pos
	p.pos++ // consume '['
	p.skipWS()
	n := &jsonNode{kind: kindArray, start: start, data: p.data}
	idx := 0
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		n.end = p.pos
		return n, nil
	}
	for {
		p.skipWS()
		val, err := p.parseValue(depth+1, fmt.Sprintf("%s/%d", path, idx))
		if err != nil {
			return nil, err
		}
		n.arr = append(n.arr, val)
		idx++
		p.skipWS()
		if p.pos >= len(p.data) {
			return nil, newConfigError(ReasonJSONMalformed, path, "unterminated array")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			n.end = p.pos
			return n, nil
		default:
			return nil, newConfigError(ReasonJSONMalformed, path,
				fmt.Sprintf("expected ',' or ']' at byte %d", p.pos))
		}
	}
}
