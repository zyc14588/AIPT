package protocol

// RequestID is the JSON-RPC request/response id. It preserves whether the id
// was a JSON string or a JSON number (the JSON type) and the exact value, and
// round-trips verbatim through marshal/unmarshal. Request/response id
// equality compares BOTH value and JSON type.
//
// Accepted values, per the canonical schema ($defs/request_id):
//   - a JSON string of 1..128 characters (non-empty, no bound on content);
//   - a JSON number whose mathematical value is an integer inside the
//     inclusive cross-language safe range [SafeIntegerMin, SafeIntegerMax].
//
// String ids are kept as their canonical quoted JSON text — the exact
// JavaScript string value rendered exactly like Node's JSON.stringify
// (iteration 5C). Lone UTF-16 surrogate code units therefore survive
// parsing, marshal as the lowercase \uXXXX escape, and stay distinct from
// U+FFFD under Equal: distinct string values always carry distinct canonical
// texts, while escape-spelling variants of the same value (a valid surrogate
// pair vs its literal scalar, "\u0061" vs "a") canonicalize to the same text
// and compare equal. The representation is an immutable Go string: callers
// can never mutate a backing slice and are never handed one.
//
// Rejected: null, booleans, arrays, objects, empty/oversize strings,
// non-integers, negative zero, and integers outside the inclusive bounds.
// Numbers are never silently rounded: out-of-range integers are rejected
// while they still have their exact digits.

import (
	"math"
	"strconv"
	"unicode/utf8"
)

// RequestIDKind is the JSON type of a request/response id.
type RequestIDKind uint8

const (
	// IDString marks a string id.
	IDString RequestIDKind = iota + 1
	// IDNumber marks an integer id.
	IDNumber
)

// RequestID preserves the JSON type and exact value of a request id. The
// unexported fields keep the value immutable: str holds the canonical quoted
// JSON text of a string id (its exact JavaScript string value), and num holds
// the integer value of a number id. Zero-value ids carry no JSON type and
// fail MarshalJSON closed.
type RequestID struct {
	kind RequestIDKind
	str  string
	num  int64
}

// NewStringID builds a string RequestID, validating the 1..128 character
// bound and UTF-8 validity. s must be a valid UTF-8 Go string: caller bytes
// that are not valid UTF-8 are not a faithful JSON string boundary and are
// rejected deterministically with ReasonIDInvalid — nothing is replaced or
// rewritten.
func NewStringID(s string) (RequestID, error) {
	if s == "" {
		return RequestID{}, newContractError(ReasonIDInvalid, "$", "request id string must not be empty")
	}
	if !utf8.ValidString(s) {
		return RequestID{}, newContractError(ReasonIDInvalid, "$", "request id string carries invalid UTF-8")
	}
	units := stringToUnits(s)
	if unitsCharCount(units) > MaxRequestIDStringLength {
		return RequestID{}, newContractError(ReasonIDInvalid, "$",
			"request id string exceeds 128 characters")
	}
	return RequestID{kind: IDString, str: quoteJSONUnits(units)}, nil
}

// NewNumberID builds an integer RequestID, validating the inclusive
// cross-language safe-integer bounds.
func NewNumberID(n int64) (RequestID, error) {
	if n < SafeIntegerMin || n > SafeIntegerMax {
		return RequestID{}, newContractError(ReasonIDInvalid, "$",
			"request id integer outside the cross-language safe range [-9007199254740991, 9007199254740991]")
	}
	return RequestID{kind: IDNumber, num: n}, nil
}

// Kind returns the preserved JSON type of the id.
func (id RequestID) Kind() RequestIDKind {
	return id.kind
}

// String returns the Go string view of the id: the decimal form for number
// ids, and the Go Unicode (UTF-8) view for string ids. For string ids it is
// deliberately NOT the exact wire value: lone UTF-16 surrogate code units
// cannot be represented in valid Go UTF-8 and appear as U+FFFD here. Equal
// and MarshalJSON always preserve the exact JSON string value, lone
// surrogates included; String is only the lossy Go view.
func (id RequestID) String() string {
	switch id.kind {
	case IDString:
		node, err := parseStrictJSON([]byte(id.str))
		if err != nil || node.kind != kindString {
			// Unreachable: str is always produced by quoteJSONUnits and is
			// therefore always one strictly valid JSON string.
			return ""
		}
		return unitsToGoString(node.units)
	case IDNumber:
		return strconv.FormatInt(id.num, 10)
	}
	return ""
}

// Int64 returns the integer value of the id and true when the id is a number.
func (id RequestID) Int64() (int64, bool) {
	if id.kind != IDNumber {
		return 0, false
	}
	return id.num, true
}

// Equal reports whether two ids carry the same value AND the same JSON type.
// String values compare by their exact JavaScript string value: lone
// surrogate units never equal U+FFFD, a valid escaped surrogate pair equals
// the literal scalar, and alternate escape spellings of the same value
// compare equal (canonical quoted texts are compared, and distinct string
// values always carry distinct canonical texts).
func (id RequestID) Equal(other RequestID) bool {
	if id.kind != other.kind {
		return false
	}
	switch id.kind {
	case IDString:
		return id.str == other.str
	case IDNumber:
		return id.num == other.num
	}
	return false
}

// MarshalJSON renders the id with its preserved JSON type. String ids emit
// their stored canonical quoted JSON text — the exact Node-compatible
// JavaScript string value: lone surrogates as lowercase \uXXXX escapes,
// valid surrogate pairs as their scalar, control characters as short
// escapes.
func (id RequestID) MarshalJSON() ([]byte, error) {
	switch id.kind {
	case IDString:
		return []byte(id.str), nil
	case IDNumber:
		return []byte(strconv.FormatInt(id.num, 10)), nil
	}
	return nil, newContractError(ReasonIDInvalid, "$", "request id carries no JSON type")
}

// UnmarshalJSON strictly decodes a request id from a single JSON value,
// preserving type and exact value and rejecting everything outside the
// string/integer contract.
func (id *RequestID) UnmarshalJSON(data []byte) error {
	root, err := parseStrictJSON(data)
	if err != nil {
		return err
	}
	decoded, err := requestIDFromNode(root, "$")
	if err != nil {
		return err
	}
	*id = decoded
	return nil
}

// requestIDFromNode validates a parsed node as a request id.
func requestIDFromNode(n *jsonNode, path string) (RequestID, error) {
	switch n.kind {
	case kindString:
		if len(n.units) == 0 {
			return RequestID{}, newContractError(ReasonIDInvalid, path, "request id string must not be empty")
		}
		if unitsCharCount(n.units) > MaxRequestIDStringLength {
			return RequestID{}, newContractError(ReasonIDInvalid, path,
				"request id string exceeds 128 characters")
		}
		return RequestID{kind: IDString, str: quoteJSONUnits(n.units)}, nil
	case kindNumber:
		var v int64
		if n.isInt {
			v = n.ival
		} else {
			f := n.fval
			if math.Trunc(f) != f {
				return RequestID{}, newContractError(ReasonIDInvalid, path, "request id must be an integer, not a fraction")
			}
			if f < float64(SafeIntegerMin) || f > float64(SafeIntegerMax) {
				return RequestID{}, newContractError(ReasonIDInvalid, path,
					"request id integer outside the cross-language safe range [-9007199254740991, 9007199254740991]")
			}
			v = int64(f)
		}
		if v < SafeIntegerMin || v > SafeIntegerMax {
			return RequestID{}, newContractError(ReasonIDInvalid, path,
				"request id integer outside the cross-language safe range [-9007199254740991, 9007199254740991]")
		}
		return RequestID{kind: IDNumber, num: v}, nil
	default:
		return RequestID{}, newContractError(ReasonIDInvalid, path,
			"request id must be a string or an integer (null, booleans, arrays and objects are rejected)")
	}
}
