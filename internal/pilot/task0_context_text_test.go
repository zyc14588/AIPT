package pilot

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zyc14588/AIPT/internal/protocol"
)

func TestTask0GMContextTextRetainsTypesDelimitersAndUnicode(t *testing.T) {
	rows := []any{}
	for i := 0; i < 12; i++ {
		rows = append(rows, map[string]any{"NON_CANON_REPEATED_FIELD": "NON_CANON_REPEATED_STRING", "index": i,
			"empty": "", "null": nil, "array": []any{}, "object": map[string]any{}, "false": false, "true": true,
			"numeric_string": "9007199254740993", "reserved": []string{"_", "T", "F", "null", "true", "false", "^0", "#0:", "中文🙂\n{}[]:,"}})
	}
	input, _ := json.Marshal(map[string]any{"NON_CANON_ROWS": rows, "": "EMPTY_KEY", "中文:key": "UTF8_KEY", "large_integer": json.Number("9007199254740991")})
	canonical, err := protocol.CanonicalJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := task0EncodeGMView(input)
	if err != nil || len(encoded) >= len(canonical) || !bytes.Contains(encoded, []byte(task0GMTextEncoding)) {
		t.Fatal("meaningful lossless packing rejected", err)
	}
	decoded, err := task0DecodeGMView(encoded)
	if err != nil || !bytes.Equal(decoded, []byte(canonical)) {
		t.Fatal("values, types or exact text changed", err)
	}
	for i := 0; i < 8; i++ {
		again, err := task0EncodeGMView(input)
		if err != nil || !bytes.Equal(again, encoded) {
			t.Fatal("unstable dictionary tie/order")
		}
	}
}

func TestTask0GMContextTextUsesOriginalWhenEnvelopeCostsMore(t *testing.T) {
	raw := json.RawMessage(`{"NON_CANON":true}`)
	got, err := task0EncodeGMView(raw)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("expanded a small context", err)
	}
}

func TestTask0GMContextTextRejectsAmbiguousOrTruncatedRecords(t *testing.T) {
	for _, text := range []string{
		`{a:_,a:T}`, `{a:_,#1:a:T}`, `{^0:T,a:F}`, `{a:^1}`, `{a:^00}`, `{a:^}`, `{a:#00:}`,
		`{a:#4:中}`, `{a:#2:中}`, `{a:#9999999:x}`, `{a:T,}`, `{a:[T,]}`, `{a:T}x`, `{a:01}`, `{a:1e}`,
		`{a:}`, `{a:"untyped quoted string"}`, `{a:NOT A WORD}`, `[]`, `null`, strings.Repeat("[", 130) + strings.Repeat("]", 130),
	} {
		t.Run(text, func(t *testing.T) {
			raw, _ := json.Marshal(task0GMTextView{task0GMTextEncoding, task0GMTextLegend, []string{"a"}, text})
			if _, err := task0DecodeGMView(raw); err == nil {
				t.Fatal("ambiguous representation accepted")
			}
		})
	}
	for _, mutation := range []string{"duplicate_pool", "null_pool", "foreign_codec", "foreign_legend", "case_alias", "unknown_field"} {
		t.Run(mutation, func(t *testing.T) {
			v := task0GMTextView{task0GMTextEncoding, task0GMTextLegend, []string{}, "{a:T}"}
			switch mutation {
			case "duplicate_pool":
				v.Strings = []string{"a", "a"}
			case "null_pool":
				v.Strings = nil
			case "foreign_codec":
				v.Encoding += "-other"
			case "foreign_legend":
				v.Legend += "-other"
			}
			raw, _ := json.Marshal(v)
			if mutation == "case_alias" {
				raw = bytes.Replace(raw, []byte(`"encoding"`), []byte(`"Encoding"`), 1)
			}
			if mutation == "unknown_field" {
				raw = append([]byte(`{"unknown":true,`), raw[1:]...)
			}
			if _, err := task0DecodeGMView(raw); err == nil {
				t.Fatal("foreign envelope accepted")
			}
		})
	}
}
