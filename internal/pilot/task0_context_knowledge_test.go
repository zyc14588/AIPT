package pilot

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestTask0ContextKnowledgeSelectionRetainsExactNeededTruthAndRegistry(t *testing.T) {
	raw := json.RawMessage(`{"NON_CANON_SEEN":{"observation":"正文🙂","truth":true},"NON_CANON_UNSEEN":{"observation":"另一条","truth":false}}`)
	original := bytes.Clone(raw)
	got, err := task0NeededKnowledgeFact(raw, "NON_CANON_SEEN")
	if err != nil || !bytes.Equal(got, []byte(`{"observation":"正文🙂","truth":true}`)) || !bytes.Equal(raw, original) {
		t.Fatal("selected fact or full original registry changed", err)
	}
	got[0] = '!'
	if !bytes.Equal(raw, original) {
		t.Fatal("shared mutable source bytes")
	}
	for _, id := range []string{"T0-NOTE-1", "T0-NOTE-10", "T0-NOTE-99"} {
		if fact, err := task0NeededKnowledgeFact(raw, id); err != nil || fact != nil {
			t.Fatal("pollution note invented a source truth entry")
		}
	}
	for _, id := range []string{"", "NON_CANON_UNKNOWN", "T0-NOTE-0", "T0-NOTE-01", "T0-NOTE-100", "t0-note-1"} {
		if _, err := task0NeededKnowledgeFact(raw, id); err == nil {
			t.Fatal("unknown source fact admitted", id)
		}
	}
	for _, raw := range []json.RawMessage{json.RawMessage(`null`), json.RawMessage(`[]`), json.RawMessage(`{"NON_CANON_SEEN":null}`)} {
		if _, err := task0NeededKnowledgeFact(raw, "NON_CANON_SEEN"); err == nil {
			t.Fatal("missing truth registry admitted")
		}
	}
}
