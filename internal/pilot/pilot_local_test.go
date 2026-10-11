package pilot

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// These receipts describe a synthetic request only; no model or runtime code
// executes, and the chain itself never authenticates its claimed producer.
func nonCanonCompletedNativeProof(t *testing.T, mutate func([]NativeInputReceipt)) []byte {
	t.Helper()
	items := make([]NativeInputReceipt, 3)
	for i := range items {
		items[i] = NativeInputReceipt{Schema: "aipt.private.b007-final-native-input-proof/v1", Sequence: i + 1,
			ClosureSHA256: strings.Repeat("a", 64), NativeSHA256: strings.Repeat("b", 64), RequestSHA256: strings.Repeat("c", 64), RequestBytes: 123,
			ResponseSHA256: inputSHA(nil)}
	}
	items[0].Event = "COUNT_REQUEST_INTENT"
	items[1].Event = "COUNT_PASS_GENERATION_INTENT"
	items[1].InputTokens = 321
	items[2].Event = "GENERATION_COMPLETED_WITH_BOUNDED_USAGE"
	items[2].InputTokens = 321
	items[2].OutputTokens = 32
	items[2].ResponseSHA256 = inputSHA([]byte("NON_CANON_TEST_SSE_ONLY"))
	if mutate != nil {
		mutate(items)
	}
	previous := strings.Repeat("0", 64)
	var out []byte
	for i := range items {
		items[i].PreviousSHA256 = previous
		b, e := json.Marshal(items[i])
		if e != nil {
			t.Fatal(e)
		}
		b = append(b, '\n')
		out = append(out, b...)
		previous = inputSHA(b)
	}
	return out
}

func TestNativeProofRejectsContradictionsEvenWithRecomputedChain(t *testing.T) {
	check := func(b []byte) error {
		return validateCompletedNativeProof(b, strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64))
	}
	valid := nonCanonCompletedNativeProof(t, nil)
	if check(valid) != nil {
		t.Fatal("synthetic complete bounded proof rejected")
	}
	mutations := map[string]func([]NativeInputReceipt){
		"counter-only-no-generation":   func(r []NativeInputReceipt) { r[2].Event = "COUNT_PASS_GENERATION_INTENT" },
		"changing-request-size":        func(r []NativeInputReceipt) { r[2].RequestBytes++ },
		"changing-request-digest":      func(r []NativeInputReceipt) { r[2].RequestSHA256 = strings.Repeat("d", 64) },
		"changing-native-generation":   func(r []NativeInputReceipt) { r[2].NativeSHA256 = strings.Repeat("d", 64) },
		"changing-closure":             func(r []NativeInputReceipt) { r[2].ClosureSHA256 = strings.Repeat("d", 64) },
		"input-disagreement":           func(r []NativeInputReceipt) { r[2].InputTokens++ },
		"oversized-input":              func(r []NativeInputReceipt) { r[1].InputTokens = 8193; r[2].InputTokens = 8193 },
		"output-over-budget":           func(r []NativeInputReceipt) { r[2].OutputTokens = 1025 },
		"null-equivalent-empty-output": func(r []NativeInputReceipt) { r[2].ResponseSHA256 = inputSHA(nil) },
		"wrong-sequence":               func(r []NativeInputReceipt) { r[1].Sequence = 3 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			if check(nonCanonCompletedNativeProof(t, mutate)) == nil {
				t.Fatal("contradictory completed proof admitted")
			}
		})
	}
	for name, body := range map[string][]byte{"missing-final-newline": valid[:len(valid)-1], "extra-newline": append(append([]byte{}, valid...), '\n'), "missing-generation": valid[:strings.LastIndex(string(valid[:len(valid)-1]), "\n")+1], "broken-chain": []byte(strings.Replace(string(valid), `"previous_sha256":"`+inputSHA(valid[:strings.IndexByte(string(valid), '\n')+1]), `"previous_sha256":"`+strings.Repeat("d", 64), 1))} {
		t.Run(name, func(t *testing.T) {
			if check(body) == nil {
				t.Fatal("incomplete or broken chain admitted")
			}
		})
	}
}

func TestPreparedLocalMissingAcceptanceCannotStartOrExposeProof(t *testing.T) {
	for _, digest := range []string{"", strings.Repeat("a", 64)} {
		if grant, e := decodeAcceptedPilotLocalGrant([]byte(`{}`), digest, strings.Repeat("b", 64), nil, nil); e == nil || grant != nil {
			t.Fatal("caller digest accepted absent full binding")
		}
	}
	if s, e := openPreparedPilotLocal(context.Background(), nil, nil); e == nil || s != nil {
		t.Fatal("missing acceptance launched preparation")
	}
	s := &preparedPilotLocal{}
	if b, e := s.readNativeProof(context.Background()); e == nil || b != nil {
		t.Fatal("unready session exposed origin-less proof")
	}
	if e := s.retire(); e != nil || !s.revoked {
		t.Fatal("failed setup did not revoke admission", e)
	}
	if b, e := s.readNativeProof(context.Background()); e == nil || b != nil {
		t.Fatal("retired session exposed proof")
	}
}
