package protocol

// Strict, lossless JSON parsing. This package implements its own
// recursive-descent JSON parser (standard library only) instead of
// encoding/json's Decoder because the wire contract requires guarantees the
// generic decoder does not provide:
//
//   - duplicate object member names are rejected at ANY nesting depth
//     (encoding/json silently keeps the last occurrence);
//   - integer values outside the cross-language safe range
//     [-9007199254740991, 9007199254740991] are rejected instead of
//     silently rounded;
//   - negative zero (-0, -0.0, -0e0) is rejected;
//   - non-finite / overflowing numbers (1e999) are rejected instead of
//     decoded as +Inf;
//   - trailing values after the top-level document are rejected;
//   - every parsed node keeps its exact raw byte span, so arbitrary JSON
//     fields are carried as json.RawMessage — never interface{} followed by
//     unchecked coercion.
//
// The parser follows RFC 8259 exactly: whitespace is only space/tab/CR/LF,
// strings carry only the JSON escapes, and invalid UTF-8 is rejected.

import (
	"encoding/json"
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

// jsonNode is one parsed JSON value. For strings, str holds the decoded
// value; for numbers, isInt/ival hold exact safe integers and fval holds the
// float64 view of non-integer numbers. start/end span the raw text in data.
type jsonNode struct {
	kind    jsonKind
	start   int
	end     int
	data    []byte
	str     string
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

// raw returns the exact raw JSON text of the node as a fresh json.RawMessage.
func (n *jsonNode) raw() json.RawMessage {
	return json.RawMessage(append([]byte(nil), n.data[n.start:n.end]...))
}

// float64Value returns the numeric value of a number node.
func (n *jsonNode) float64Value() float64 {
	if n.isInt {
		return float64(n.ival)
	}
	return n.fval
}

// hasMember reports whether an object node carries the given key.
func (n *jsonNode) hasMember(key string) bool {
	if n.kind != kindObject {
		return false
	}
	for _, m := range n.members {
		if m.key == key {
			return true
		}
	}
	return false
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

// strictJSONParser is the lossless strict parser.
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
		return nil, newContractError(ReasonJSONMalformed, "$", "empty input")
	}
	n, err := p.parseValue(0, "$")
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.pos != len(p.data) {
		return nil, newContractError(ReasonJSONTrailing, "$",
			fmt.Sprintf("trailing data after the top-level value at byte %d", p.pos))
	}
	return n, nil
}

// ValidateJSON strictly validates exactly one JSON document: it rejects
// malformed input, trailing values, duplicate member names at any depth,
// unsafe integers, negative zero, and non-finite/overflowing numbers.
// It returns nil for a strictly valid document.
func ValidateJSON(data []byte) error {
	_, err := parseStrictJSON(data)
	return err
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
		return nil, newContractError(ReasonJSONMalformed, path, "unexpected end of input")
	}
	if depth > maxJSONDepth {
		return nil, newContractError(ReasonJSONMalformed, path, "JSON nesting too deep")
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
		return p.parseNull(path)
	case c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumber(path)
	default:
		return nil, newContractError(ReasonJSONMalformed, path,
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
			return nil, newContractError(ReasonJSONMalformed, path,
				fmt.Sprintf("malformed literal at byte %d", start))
		}
		p.pos++
	}
	if !p.valueDelimiterOK() {
		return nil, newContractError(ReasonJSONMalformed, path,
			fmt.Sprintf("malformed literal at byte %d", start))
	}
	return &jsonNode{kind: kindBool, start: start, end: p.pos, data: p.data, boolVal: val}, nil
}

func (p *strictJSONParser) parseNull(path string) (*jsonNode, error) {
	start := p.pos
	for i := 0; i < 4; i++ {
		if p.pos >= len(p.data) || p.data[p.pos] != "null"[i] {
			return nil, newContractError(ReasonJSONMalformed, path,
				fmt.Sprintf("malformed literal at byte %d", start))
		}
		p.pos++
	}
	if !p.valueDelimiterOK() {
		return nil, newContractError(ReasonJSONMalformed, path,
			fmt.Sprintf("malformed literal at byte %d", start))
	}
	return &jsonNode{kind: kindNull, start: start, end: p.pos, data: p.data}, nil
}

// parseString parses a JSON string starting at the current '"' and returns a
// node carrying the decoded value.
func (p *strictJSONParser) parseString(path string) (*jsonNode, error) {
	start := p.pos
	p.pos++ // consume '"'
	contentStart := p.pos
	for {
		if p.pos >= len(p.data) {
			return nil, newContractError(ReasonJSONMalformed, path, "unterminated string")
		}
		c := p.data[p.pos]
		if c == '"' {
			content := p.data[contentStart:p.pos]
			if !utf8.Valid(content) {
				return nil, newContractError(ReasonJSONMalformed, path, "string carries invalid UTF-8")
			}
			decoded, err := unescapeJSONString(content)
			if err != nil {
				return nil, newContractError(ReasonJSONMalformed, path, err.Error())
			}
			p.pos++
			return &jsonNode{kind: kindString, start: start, end: p.pos, data: p.data, str: decoded}, nil
		}
		if c == '\\' {
			if p.pos+1 >= len(p.data) {
				return nil, newContractError(ReasonJSONMalformed, path, "unterminated string escape")
			}
			switch esc := p.data[p.pos+1]; esc {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				p.pos += 2
			case 'u':
				if p.pos+6 > len(p.data) {
					return nil, newContractError(ReasonJSONMalformed, path, "truncated \\u escape")
				}
				for _, b := range p.data[p.pos+2 : p.pos+6] {
					if !isHex(b) {
						return nil, newContractError(ReasonJSONMalformed, path,
							fmt.Sprintf("invalid \\u escape at byte %d", p.pos))
					}
				}
				p.pos += 6
			default:
				return nil, newContractError(ReasonJSONMalformed, path,
					fmt.Sprintf("invalid string escape \\%c at byte %d", esc, p.pos+1))
			}
			continue
		}
		if c < 0x20 {
			return nil, newContractError(ReasonJSONMalformed, path,
				fmt.Sprintf("raw control character 0x%02x inside string at byte %d", c, p.pos))
		}
		p.pos++
	}
}

func isHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func hex4(b []byte) rune {
	v := 0
	for _, c := range b {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= int(c - '0')
		case c >= 'a' && c <= 'f':
			v |= int(c-'a') + 10
		default:
			v |= int(c-'A') + 10
		}
	}
	return rune(v)
}

// unescapeJSONString decodes the raw content of a JSON string (without the
// surrounding quotes). Escapes are validated by the caller's scan; this
// function handles surrogate pairs exactly like encoding/json (lone
// surrogates decode to U+FFFD).
func unescapeJSONString(raw []byte) (string, error) {
	var b strings.Builder
	i := 0
	for i < len(raw) {
		c := raw[i]
		if c != '\\' {
			b.WriteByte(c)
			i++
			continue
		}
		esc := raw[i+1]
		switch esc {
		case '"':
			b.WriteByte('"')
		case '\\':
			b.WriteByte('\\')
		case '/':
			b.WriteByte('/')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'u':
			r1 := hex4(raw[i+2 : i+6])
			i += 6
			if r1 >= 0xD800 && r1 <= 0xDBFF {
				// High surrogate: pair with a following \uXXXX low surrogate.
				if i+6 <= len(raw) && raw[i] == '\\' && raw[i+1] == 'u' {
					r2 := hex4(raw[i+2 : i+6])
					if r2 >= 0xDC00 && r2 <= 0xDFFF {
						b.WriteRune(utf16.DecodeRune(r1, r2))
						i += 6
						continue
					}
				}
				b.WriteRune(utf8.RuneError)
				continue
			}
			if r1 >= 0xDC00 && r1 <= 0xDFFF {
				// Lone low surrogate.
				b.WriteRune(utf8.RuneError)
				continue
			}
			b.WriteRune(r1)
			continue
		default:
			return "", fmt.Errorf("invalid string escape \\%c", esc)
		}
		i += 2
	}
	return b.String(), nil
}

// parseNumber parses a JSON number with the exact RFC 8259 grammar and
// enforces cross-language safety: integer literals must lie inside
// [SafeIntegerMin, SafeIntegerMax], negative zero is rejected, and
// non-integer literals must parse to a finite float64 (underflow to zero is
// accepted, overflow to infinity is rejected).
func (p *strictJSONParser) parseNumber(path string) (*jsonNode, error) {
	start := p.pos
	if p.data[p.pos] == '-' {
		p.pos++
		if p.pos >= len(p.data) {
			return nil, newContractError(ReasonJSONMalformed, path, "truncated number")
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
		return nil, newContractError(ReasonJSONMalformed, path,
			fmt.Sprintf("malformed number at byte %d", start))
	}
	isInt := true
	// Fraction.
	if p.pos < len(p.data) && p.data[p.pos] == '.' {
		isInt = false
		p.pos++
		if p.pos >= len(p.data) || p.data[p.pos] < '0' || p.data[p.pos] > '9' {
			return nil, newContractError(ReasonJSONMalformed, path,
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
			return nil, newContractError(ReasonJSONMalformed, path,
				fmt.Sprintf("malformed number exponent at byte %d", start))
		}
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
	}
	if !p.valueDelimiterOK() {
		return nil, newContractError(ReasonJSONMalformed, path,
			fmt.Sprintf("malformed number at byte %d", start))
	}
	raw := p.data[start:p.pos]
	neg := raw[0] == '-'
	digits := raw
	if neg {
		digits = raw[1:]
	}
	if isInt {
		if neg && string(digits) == "0" {
			return nil, newContractError(ReasonJSONNegativeZero, path, "negative zero is not a canonical JSON value")
		}
		var v int64
		for _, d := range digits {
			digit := int64(d - '0')
			if v > (math.MaxInt64-digit)/10 {
				return nil, newContractError(ReasonJSONUnsafeInteger, path,
					"integer outside the cross-language safe range [-9007199254740991, 9007199254740991]")
			}
			v = v*10 + digit
		}
		if neg {
			v = -v
		}
		if v < SafeIntegerMin || v > SafeIntegerMax {
			return nil, newContractError(ReasonJSONUnsafeInteger, path,
				"integer outside the cross-language safe range [-9007199254740991, 9007199254740991]")
		}
		return &jsonNode{kind: kindNumber, start: start, end: p.pos, data: p.data, isInt: true, ival: v}, nil
	}
	f, err := strconv.ParseFloat(string(raw), 64)
	if err != nil {
		if math.IsInf(f, 0) || math.IsNaN(f) {
			return nil, newContractError(ReasonJSONNonFiniteNumber, path,
				"number overflows the IEEE-754 double range")
		}
		if f == 0 {
			// Underflow to zero: identical to Node's JSON.parse behavior.
			return &jsonNode{kind: kindNumber, start: start, end: p.pos, data: p.data, fval: 0}, nil
		}
		return nil, newContractError(ReasonJSONMalformed, path, "malformed number")
	}
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return nil, newContractError(ReasonJSONNonFiniteNumber, path,
			"number overflows the IEEE-754 double range")
	}
	if f == 0 && math.Signbit(f) {
		return nil, newContractError(ReasonJSONNegativeZero, path, "negative zero is not a canonical JSON value")
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
			return nil, newContractError(ReasonJSONMalformed, path, "unterminated object")
		}
		if p.data[p.pos] != '"' {
			return nil, newContractError(ReasonJSONMalformed, path,
				fmt.Sprintf("expected object member name at byte %d", p.pos))
		}
		keyNode, err := p.parseString(path)
		if err != nil {
			return nil, err
		}
		key := keyNode.str
		if seen[key] {
			return nil, newContractError(ReasonJSONDuplicateKey, path+"/"+key,
				fmt.Sprintf("duplicate object member %q", key))
		}
		seen[key] = true
		p.skipWS()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return nil, newContractError(ReasonJSONMalformed, path,
				fmt.Sprintf("expected ':' after object member %q", key))
		}
		p.pos++
		p.skipWS()
		val, err := p.parseValue(depth+1, path+"/"+key)
		if err != nil {
			return nil, err
		}
		n.members = append(n.members, jsonMember{key: key, val: val})
		p.skipWS()
		if p.pos >= len(p.data) {
			return nil, newContractError(ReasonJSONMalformed, path, "unterminated object")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			n.end = p.pos
			return n, nil
		default:
			return nil, newContractError(ReasonJSONMalformed, path,
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
			return nil, newContractError(ReasonJSONMalformed, path, "unterminated array")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			n.end = p.pos
			return n, nil
		default:
			return nil, newContractError(ReasonJSONMalformed, path,
				fmt.Sprintf("expected ',' or ']' at byte %d", p.pos))
		}
	}
}
