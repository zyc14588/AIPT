package protocol_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/zyc14588/AIPT/internal/protocol"
)

func TestValidateJSONAcceptsLosslessValues(t *testing.T) {
	docs := []string{
		`null`, `true`, `false`, `0`, `-1`, `9007199254740991`, `-9007199254740991`,
		`3.14`, `1e-7`, `1e21`, `""`, `"a\tb\n\"c\" \u00e9"`, `[]`, `{}`,
		`[1,2,{"a":null}]`, `{"a":{"b":[true,false]}}`,
	}
	for _, doc := range docs {
		if err := protocol.ValidateJSON([]byte(doc)); err != nil {
			t.Fatalf("ValidateJSON(%s) rejected a lossless document: %v", doc, err)
		}
	}
}

func TestValidateJSONRejectsEmptyInput(t *testing.T) {
	wantReason(t, protocol.ValidateJSON(nil), protocol.ReasonJSONMalformed)
	wantReason(t, protocol.ValidateJSON([]byte("")), protocol.ReasonJSONMalformed)
	wantReason(t, protocol.ValidateJSON([]byte("   \n\t ")), protocol.ReasonJSONMalformed)
}

func TestValidateJSONRejectsMalformedDocuments(t *testing.T) {
	docs := []string{
		`{`, `[`, `{"a"`, `{"a":`, `{"a":1`, `[1,`, `"abc`, `"ab\x"`,
		`tru`, `nul`, `fals`, `01`, `1.`, `1.e5`, `1.2.3`, `1e`, `1e+`,
		`+1`, `.5`, `-`, `{a:1}`, `{'a':1}`, `[1 2]`, `{"a" 1}`, `{"a":1,}`,
		`[,1]`, `[1,]`, `{"a":01}`, `truex`, `nullx`, "\"a\x01b\"", "\"a\xff\"",
	}
	for _, doc := range docs {
		if err := protocol.ValidateJSON([]byte(doc)); err == nil {
			t.Fatalf("ValidateJSON(%q) accepted malformed input", doc)
		}
	}
}

func TestValidateJSONRejectsTrailingValues(t *testing.T) {
	docs := []string{
		`{} {}`, `1 2`, `[1][2]`, `null true`, `{"a":1} {"b":2}`, `"x" "y"`,
		`{}x`, `{}[]`, `{"a":1}junk`,
	}
	for _, doc := range docs {
		wantReason(t, protocol.ValidateJSON([]byte(doc)), protocol.ReasonJSONTrailing)
	}
}

func TestValidateJSONRejectsDuplicateTopLevelKeys(t *testing.T) {
	wantReason(t, protocol.ValidateJSON([]byte(`{"a":1,"a":2}`)), protocol.ReasonJSONDuplicateKey)
	wantReason(t, protocol.ValidateJSON([]byte(`{"a":1,"b":2,"a":3}`)), protocol.ReasonJSONDuplicateKey)
}

func TestValidateJSONRejectsDuplicateNestedKeys(t *testing.T) {
	docs := []string{
		`{"outer":{"a":1,"a":2}}`,
		`{"outer":[{"a":1,"a":2}]}`,
		`{"a":{"b":{"c":1,"c":2}}}`,
		`{"arr":[1,{"dup":1,"dup":2}]}`,
	}
	for _, doc := range docs {
		wantReason(t, protocol.ValidateJSON([]byte(doc)), protocol.ReasonJSONDuplicateKey)
	}
}

func TestValidateJSONRejectsEscapedDuplicateKeys(t *testing.T) {
	// "a" and "\u0061" decode to the same member name.
	wantReason(t, protocol.ValidateJSON([]byte(`{"a":1,"\u0061":2}`)), protocol.ReasonJSONDuplicateKey)
}

func TestValidateJSONRejectsUnsafeIntegers(t *testing.T) {
	docs := []string{
		`9007199254740992`, `-9007199254740992`, `9223372036854775807`,
		`-9223372036854775808`, `99999999999999999999999999`,
		`{"deep":{"n":9007199254740992}}`, `[9007199254740993]`,
	}
	for _, doc := range docs {
		wantReason(t, protocol.ValidateJSON([]byte(doc)), protocol.ReasonJSONUnsafeInteger)
	}
}

func TestValidateJSONAcceptsSafeIntegerBoundaries(t *testing.T) {
	for _, doc := range []string{`9007199254740991`, `-9007199254740991`, `0`, `-32000`} {
		if err := protocol.ValidateJSON([]byte(doc)); err != nil {
			t.Fatalf("ValidateJSON(%s) rejected a safe integer: %v", doc, err)
		}
	}
}

func TestValidateJSONRejectsNegativeZero(t *testing.T) {
	docs := []string{`-0`, `-0.0`, `-0e0`, `-0E5`, `-0.0e10`, `{"n":-0}`, `[-0.00]`}
	for _, doc := range docs {
		wantReason(t, protocol.ValidateJSON([]byte(doc)), protocol.ReasonJSONNegativeZero)
	}
}

func TestValidateJSONRejectsNonFiniteNumbers(t *testing.T) {
	docs := []string{`1e999`, `-1e999`, `1e309`, `{"n":-1.8e3080}`, `[2e1024]`}
	for _, doc := range docs {
		wantReason(t, protocol.ValidateJSON([]byte(doc)), protocol.ReasonJSONNonFiniteNumber)
	}
}

func TestCanonicalJSONSortsKeysRecursively(t *testing.T) {
	in := `{"z":1,"a":{"y":2,"x":[3,{"b":4,"a":5}]}}`
	want := `{"a":{"x":[3,{"a":5,"b":4}],"y":2},"z":1}`
	got, err := protocol.CanonicalJSON([]byte(in))
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if got != want {
		t.Fatalf("canonical JSON mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestCanonicalJSONArraysKeepOrderAndNoWhitespace(t *testing.T) {
	in := " [ 1 , 2 , 3 ] "
	got, err := protocol.CanonicalJSON([]byte(in))
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if got != `[1,2,3]` {
		t.Fatalf("canonical JSON mismatch: got %s", got)
	}
}

func TestCanonicalJSONIsDeterministicAcrossInsertionOrder(t *testing.T) {
	a := `{"first":1,"second":{"x":1,"y":2},"third":[1,2,3]}`
	b := `{"third":[1,2,3],"second":{"y":2,"x":1},"first":1}`
	ca, err := protocol.CanonicalJSON([]byte(a))
	if err != nil {
		t.Fatal(err)
	}
	cb, err := protocol.CanonicalJSON([]byte(b))
	if err != nil {
		t.Fatal(err)
	}
	if ca != cb {
		t.Fatalf("canonicalization is not deterministic across insertion order:\n %s\n %s", ca, cb)
	}
}

func TestCanonicalJSONNumberFormattingMatchesNode(t *testing.T) {
	// Spot checks against Node's JSON.stringify(number) output.
	cases := map[string]string{
		`0.0000001`:             `1e-7`,
		`1e-7`:                  `1e-7`,
		`0.000001`:              `0.000001`,
		`1e20`:                  `100000000000000000000`,
		`1e21`:                  `1e+21`,
		`0.1`:                   `0.1`,
		`0.30000000000000004`:   `0.30000000000000004`,
		`1e308`:                 `1e+308`,
		`5e-324`:                `5e-324`,
		`1.2345678901234568e20`: `123456789012345680000`,
		`1.0`:                   `1`,
		`100.0`:                 `100`,
		`-2.5e-8`:               `-2.5e-8`,
		`9007199254740991`:      `9007199254740991`,
	}
	for in, want := range cases {
		got, err := protocol.CanonicalJSON([]byte(in))
		if err != nil {
			t.Fatalf("CanonicalJSON(%s): %v", in, err)
		}
		if got != want {
			t.Fatalf("canonical number formatting mismatch for %s: got %s, want %s (Node)", in, got, want)
		}
	}
}

func TestCanonicalJSONStringEscapingMatchesNode(t *testing.T) {
	in := `{"c":"\u0000\u0007\u0008\u0009\u000a\u000b\u000c\u000d\u001f\"\\\/\u00e9\u4e2d"}`
	want := "{\"c\":\"\\u0000\\u0007\\b\\t\\n\\u000b\\f\\r\\u001f\\\"\\\\/é中\"}"
	got, err := protocol.CanonicalJSON([]byte(in))
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if got != want {
		t.Fatalf("canonical string escaping mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestCanonicalJSONSortsByJavaScriptUTF16Order(t *testing.T) {
	// U+1F600 (surrogate D83D DE00) sorts BEFORE U+E000 in UTF-16, which is
	// the JavaScript default sort order — not Go byte order.
	in := `{"\ue000":1,"\ud83d\ude00":2}`
	got, err := protocol.CanonicalJSON([]byte(in))
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	want := "{\"\U0001F600\":2,\"\uE000\":1}"
	if got != want {
		t.Fatalf("UTF-16 key order mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestCanonicalSHA256KnownVector(t *testing.T) {
	got, err := protocol.CanonicalSHA256([]byte(`{"b":1,"a":2}`))
	if err != nil {
		t.Fatalf("CanonicalSHA256: %v", err)
	}
	sum := sha256.Sum256([]byte(`{"a":2,"b":1}`))
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("canonical SHA-256 mismatch: got %s, want %s", got, want)
	}
}

func TestCanonicalJSONRejectsDuplicateKeys(t *testing.T) {
	_, err := protocol.CanonicalJSON([]byte(`{"a":1,"a":2}`))
	wantReason(t, err, protocol.ReasonJSONDuplicateKey)
	_, err = protocol.CanonicalSHA256([]byte(`{"a":{"b":1,"b":2}}`))
	wantReason(t, err, protocol.ReasonJSONDuplicateKey)
}

func TestCanonicalJSONRejectsTrailingInput(t *testing.T) {
	_, err := protocol.CanonicalJSON([]byte(`{"a":1} trailing`))
	wantReason(t, err, protocol.ReasonJSONTrailing)
	_, err = protocol.CanonicalSHA256([]byte(`1 2`))
	wantReason(t, err, protocol.ReasonJSONTrailing)
}

func TestCanonicalJSONRejectsUnsafeIntegers(t *testing.T) {
	_, err := protocol.CanonicalJSON([]byte(`{"n":9007199254740992}`))
	wantReason(t, err, protocol.ReasonJSONUnsafeInteger)
	_, err = protocol.CanonicalSHA256([]byte(`9007199254740993`))
	wantReason(t, err, protocol.ReasonJSONUnsafeInteger)
}

func TestCanonicalJSONRejectsNegativeZero(t *testing.T) {
	_, err := protocol.CanonicalJSON([]byte(`-0`))
	wantReason(t, err, protocol.ReasonJSONNegativeZero)
	_, err = protocol.CanonicalSHA256([]byte(`{"n":-0.0}`))
	wantReason(t, err, protocol.ReasonJSONNegativeZero)
}

func TestCanonicalJSONRejectsNonFiniteNumbers(t *testing.T) {
	_, err := protocol.CanonicalJSON([]byte(`1e999`))
	wantReason(t, err, protocol.ReasonJSONNonFiniteNumber)
}

func TestCanonicalJSONRejectsMalformed(t *testing.T) {
	if _, err := protocol.CanonicalJSON([]byte(`{"a"`)); err == nil {
		t.Fatal("CanonicalJSON accepted malformed input")
	}
	if _, err := protocol.CanonicalSHA256(nil); err == nil {
		t.Fatal("CanonicalSHA256 accepted empty input")
	}
}

func TestCanonicalJSONHandlesNestedMixedValues(t *testing.T) {
	in := `{"nested":[{"k":"v"},null,true,false,-1,0,2.5,[]]}`
	want := `{"nested":[{"k":"v"},null,true,false,-1,0,2.5,[]]}`
	got, err := protocol.CanonicalJSON([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if strings.ContainsAny(got, " \t\n\r") {
		t.Fatalf("canonical JSON carries insignificant whitespace: %q", got)
	}
}
