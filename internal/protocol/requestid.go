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
// Rejected: null, booleans, arrays, objects, empty/oversize strings,
// non-integers, negative zero, and integers outside the inclusive bounds.
// Numbers are never silently rounded: out-of-range integers are rejected
// while they still have their exact digits.

import (
	"math"
	"strconv"
)

// RequestIDKind is the JSON type of a request/response id.
type RequestIDKind uint8

const (
	// IDString marks a string id.
	IDString RequestIDKind = iota + 1
	// IDNumber marks an integer id.
	IDNumber
)

// RequestID preserves the JSON type and exact value of a request id.
type RequestID struct {
	kind RequestIDKind
	str  string
	num  int64
}

// NewStringID builds a string RequestID, validating the 1..128 character
// bound.
func NewStringID(s string) (RequestID, error) {
	if s == "" {
		return RequestID{}, newContractError(ReasonIDInvalid, "$", "request id string must not be empty")
	}
	if len([]rune(s)) > MaxRequestIDStringLength {
		return RequestID{}, newContractError(ReasonIDInvalid, "$",
			"request id string exceeds 128 characters")
	}
	return RequestID{kind: IDString, str: s}, nil
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

// String returns the string value of the id. It is valid for both kinds.
func (id RequestID) String() string {
	return id.str
}

// Int64 returns the integer value of the id and true when the id is a number.
func (id RequestID) Int64() (int64, bool) {
	if id.kind != IDNumber {
		return 0, false
	}
	return id.num, true
}

// Equal reports whether two ids carry the same value AND the same JSON type.
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

// MarshalJSON renders the id with its preserved JSON type.
func (id RequestID) MarshalJSON() ([]byte, error) {
	switch id.kind {
	case IDString:
		return []byte(quoteJSONString(id.str)), nil
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
		if n.str == "" {
			return RequestID{}, newContractError(ReasonIDInvalid, path, "request id string must not be empty")
		}
		if len([]rune(n.str)) > MaxRequestIDStringLength {
			return RequestID{}, newContractError(ReasonIDInvalid, path,
				"request id string exceeds 128 characters")
		}
		return RequestID{kind: IDString, str: n.str}, nil
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
