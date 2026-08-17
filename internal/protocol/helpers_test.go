package protocol_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/zyc14588/AIPT/internal/protocol"
)

// The Go tests consume the SAME repository files as the accepted TypeScript
// SDK and the independent Node protocol-assets oracle — the canonical schema
// and the shared minimal fixture — by path. Any drift in those files fails
// these tests; there is deliberately no second Go-only fixture truth.

const (
	// schemaPath is the single canonical wire authority (read-only).
	schemaPath = "../../schemas/protocol/v1/aipt-protocol.schema.json"
	// fixtureDir is the single shared generic fixture (read-only).
	fixtureDir = "../../testdata/protocol/v1/minimal-fixture"
)

func readRepoFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("repository file %s is unreadable (drift fails closed): %v", path, err)
	}
	return data
}

func readFixture(t *testing.T, rel string) []byte {
	t.Helper()
	return readRepoFile(t, filepath.Join(fixtureDir, rel))
}

func readSchema(t *testing.T) []byte {
	t.Helper()
	return readRepoFile(t, schemaPath)
}

func mustDecodeState(t *testing.T, data []byte) *protocol.State {
	t.Helper()
	s, err := protocol.DecodeState(data)
	if err != nil {
		t.Fatalf("DecodeState: %v", err)
	}
	return s
}

func mustDecodeSeatSet(t *testing.T, data []byte) *protocol.SeatSet {
	t.Helper()
	s, err := protocol.DecodeSeatSet(data)
	if err != nil {
		t.Fatalf("DecodeSeatSet: %v", err)
	}
	return s
}

func mustDecodeProjection(t *testing.T, data []byte) *protocol.Projection {
	t.Helper()
	p, err := protocol.DecodeProjection(data)
	if err != nil {
		t.Fatalf("DecodeProjection: %v", err)
	}
	return p
}

func mustDecodeManifest(t *testing.T, data []byte) *protocol.Manifest {
	t.Helper()
	m, err := protocol.DecodeManifest(data)
	if err != nil {
		t.Fatalf("DecodeManifest: %v", err)
	}
	return m
}

func mustDecodeTransition(t *testing.T, data []byte) *protocol.StateTransition {
	t.Helper()
	tr, err := protocol.DecodeStateTransition(data)
	if err != nil {
		t.Fatalf("DecodeStateTransition: %v", err)
	}
	return tr
}

// mustMarshal canonicalizes a typed value through encoding/json for
// JSONEqual comparisons.
func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

// wantReason asserts err is a typed contract error carrying exactly reason.
func wantReason(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a contract error with reason %s, got nil", reason)
	}
	if got := protocol.ContractReason(err); got != reason {
		t.Fatalf("expected contract reason %s, got %s (%v)", reason, got, err)
	}
}

// wantNoReason asserts err is nil.
func wantNoReason(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("expected success, got contract error: %v", err)
	}
}
