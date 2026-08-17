package protocol_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zyc14588/AIPT/internal/protocol"
)

func TestRequestIDStringRoundTripPreservesTypeAndValue(t *testing.T) {
	id, err := protocol.NewStringID("minimal-v1-arithmetic-request-1")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `"minimal-v1-arithmetic-request-1"` {
		t.Fatalf("string id must marshal as a JSON string, got %s", data)
	}
	var back protocol.RequestID
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if !back.Equal(id) || back.Kind() != protocol.IDString || back.String() != id.String() {
		t.Fatalf("string id round-trip drifted: %+v != %+v", back, id)
	}
}

func TestRequestIDNumberRoundTripPreservesTypeAndValue(t *testing.T) {
	for _, n := range []int64{0, 1, 42, -32000, protocol.SafeIntegerMin, protocol.SafeIntegerMax} {
		id, err := protocol.NewNumberID(n)
		if err != nil {
			t.Fatalf("NewNumberID(%d): %v", n, err)
		}
		data, err := json.Marshal(id)
		if err != nil {
			t.Fatal(err)
		}
		if !jsonNumberEqual(string(data), n) {
			t.Fatalf("number id %d must marshal as a JSON number, got %s", n, data)
		}
		var back protocol.RequestID
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatalf("round-trip unmarshal of %d: %v", n, err)
		}
		if !back.Equal(id) || back.Kind() != protocol.IDNumber {
			t.Fatalf("number id round-trip drifted for %d", n)
		}
		if got, ok := back.Int64(); !ok || got != n {
			t.Fatalf("number id value drifted: %d (ok=%v) != %d", got, ok, n)
		}
	}
}

func jsonNumberEqual(marshaled string, n int64) bool {
	var f float64
	return json.Unmarshal([]byte(marshaled), &f) == nil && f == float64(n)
}

func int64ToString(n int64) string {
	data, _ := json.Marshal(n)
	return string(data)
}

func TestRequestIDAcceptsBothInclusiveSafeIntegerBoundaries(t *testing.T) {
	for _, n := range []int64{protocol.SafeIntegerMin, protocol.SafeIntegerMax} {
		var id protocol.RequestID
		err := json.Unmarshal([]byte(int64ToString(n)), &id)
		if err != nil {
			t.Fatalf("inclusive boundary %d must be accepted: %v", n, err)
		}
		if got, ok := id.Int64(); !ok || got != n {
			t.Fatalf("boundary id %d drifted to %d", n, got)
		}
	}
}

func TestRequestIDRejectsIntegersOutsideBounds(t *testing.T) {
	// Integer literals outside the inclusive bound are rejected at the strict
	// JSON layer (never silently rounded); float-form literals whose value
	// escapes the bound are rejected at the id gate.
	for _, n := range []int64{protocol.SafeIntegerMin - 1, protocol.SafeIntegerMax + 1} {
		var id protocol.RequestID
		err := json.Unmarshal([]byte(int64ToString(n)), &id)
		wantReason(t, err, protocol.ReasonJSONUnsafeInteger)
	}
	var id protocol.RequestID
	wantReason(t, json.Unmarshal([]byte(`9.007199254740992e15`), &id), protocol.ReasonIDInvalid)
	wantReason(t, json.Unmarshal([]byte(`-9.007199254740992e15`), &id), protocol.ReasonIDInvalid)
}

func TestRequestIDRejectsEmptyString(t *testing.T) {
	var id protocol.RequestID
	wantReason(t, json.Unmarshal([]byte(`""`), &id), protocol.ReasonIDInvalid)
}

func TestRequestIDRejectsOversizeString(t *testing.T) {
	var id protocol.RequestID
	oversize := `"` + strings.Repeat("x", 129) + `"`
	wantReason(t, json.Unmarshal([]byte(oversize), &id), protocol.ReasonIDInvalid)
	// Exactly 128 characters is accepted.
	exact := `"` + strings.Repeat("x", 128) + `"`
	if err := json.Unmarshal([]byte(exact), &id); err != nil {
		t.Fatalf("128-character string id must be accepted: %v", err)
	}
}

func TestRequestIDRejectsNullBooleanArrayObject(t *testing.T) {
	for _, doc := range []string{`null`, `true`, `false`, `[1]`, `{"a":1}`, `[]`, `{}`} {
		var id protocol.RequestID
		if err := json.Unmarshal([]byte(doc), &id); err == nil {
			t.Fatalf("id %s must be rejected", doc)
		}
	}
}

func TestRequestIDRejectsNonIntegerNumbers(t *testing.T) {
	for _, doc := range []string{`1.5`, `0.1`, `-2.5`, `1e-2`, `3.14159`, `1.0000000000000002`} {
		var id protocol.RequestID
		wantReason(t, json.Unmarshal([]byte(doc), &id), protocol.ReasonIDInvalid)
	}
}

func TestRequestIDAcceptsIntegerValuedNumberLiterals(t *testing.T) {
	// Node's JSON.parse reads 1e2 / 1.0 as integer-valued doubles; the value
	// is an exact safe integer and must be preserved without rounding.
	cases := map[string]int64{`1e2`: 100, `1.0`: 1, `42.0`: 42, `0e0`: 0}
	for doc, want := range cases {
		var id protocol.RequestID
		if err := json.Unmarshal([]byte(doc), &id); err != nil {
			t.Fatalf("integer-valued literal %s must be accepted: %v", doc, err)
		}
		if got, ok := id.Int64(); !ok || got != want {
			t.Fatalf("literal %s must decode to %d, got %d", doc, want, got)
		}
	}
}

func TestRequestIDRejectsNegativeZero(t *testing.T) {
	for _, doc := range []string{`-0`, `-0.0`, `-0e5`} {
		var id protocol.RequestID
		wantReason(t, json.Unmarshal([]byte(doc), &id), protocol.ReasonJSONNegativeZero)
	}
}

func TestRequestIDEqualityComparesValueAndJSONType(t *testing.T) {
	strOne, _ := protocol.NewStringID("1")
	numOne, _ := protocol.NewNumberID(1)
	numTwo, _ := protocol.NewNumberID(2)
	if strOne.Equal(numOne) {
		t.Fatal(`string "1" must not equal number 1 (JSON type is part of identity)`)
	}
	if numOne.Equal(numTwo) {
		t.Fatal("number 1 must not equal number 2")
	}
	if !numOne.Equal(numOne) {
		t.Fatal("identical ids must be equal")
	}
	strA, _ := protocol.NewStringID("a")
	strB, _ := protocol.NewStringID("a")
	if !strA.Equal(strB) {
		t.Fatal("identical string ids must be equal")
	}
}

func TestRequestIDUnmarshalRejectsTrailingValues(t *testing.T) {
	// Call UnmarshalJSON directly: encoding/json's top-level Unmarshal
	// performs its own trailing check before dispatching to this method.
	var id protocol.RequestID
	wantReason(t, id.UnmarshalJSON([]byte(`42 43`)), protocol.ReasonJSONTrailing)
	wantReason(t, id.UnmarshalJSON([]byte(`"a" "b"`)), protocol.ReasonJSONTrailing)
	wantReason(t, id.UnmarshalJSON([]byte(`{} {}`)), protocol.ReasonJSONTrailing)
}

func TestRequestIDUnmarshalRejectsDuplicateKeys(t *testing.T) {
	var id protocol.RequestID
	wantReason(t, json.Unmarshal([]byte(`{"a":1,"a":2}`), &id), protocol.ReasonJSONDuplicateKey)
}

func TestRequestIDUnsafeNumberLiteralNeverRounds(t *testing.T) {
	// 9007199254740993 as a float literal rounds to ...992 in a double; the
	// parser must reject the integer literal with the unsafe-integer reason
	// and the float form at the id gate — never silently accept a rounded
	// value.
	var id protocol.RequestID
	wantReason(t, json.Unmarshal([]byte(`9007199254740993`), &id), protocol.ReasonJSONUnsafeInteger)
	wantReason(t, json.Unmarshal([]byte(`9007199254740993.0`), &id), protocol.ReasonIDInvalid)
}

func TestNewStringIDAndNewNumberIDValidation(t *testing.T) {
	if _, err := protocol.NewStringID(""); err == nil {
		t.Fatal("NewStringID must reject empty strings")
	}
	if _, err := protocol.NewStringID(strings.Repeat("x", 129)); err == nil {
		t.Fatal("NewStringID must reject oversize strings")
	}
	if _, err := protocol.NewNumberID(protocol.SafeIntegerMax + 1); err == nil {
		t.Fatal("NewNumberID must reject integers above the inclusive bound")
	}
	if _, err := protocol.NewNumberID(protocol.SafeIntegerMin - 1); err == nil {
		t.Fatal("NewNumberID must reject integers below the inclusive bound")
	}
	if _, err := protocol.NewNumberID(protocol.SafeIntegerMin); err != nil {
		t.Fatalf("NewNumberID must accept the inclusive minimum: %v", err)
	}
	if _, err := protocol.NewNumberID(protocol.SafeIntegerMax); err != nil {
		t.Fatalf("NewNumberID must accept the inclusive maximum: %v", err)
	}
}
