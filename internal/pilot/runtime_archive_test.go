package pilot

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
)

func nonCanonFlatCapsule(t *testing.T, mutation string) ([]byte, string) {
	t.Helper()
	body := nonCanonCodeELF("")
	m := nonCanonCodeManifest(body)
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	identity := inputSHA(raw)
	base := nonCanonCodeELF("")
	payload := append(append(append([]byte{}, base...), raw...), body...)
	var trailer [capsuleTrailerBytes]byte
	copy(trailer[:32], capsuleTrailerMagic)
	binary.LittleEndian.PutUint64(trailer[32:40], uint64(len(base)))
	binary.LittleEndian.PutUint64(trailer[40:48], uint64(len(raw)))
	sum, _ := hex.DecodeString(identity)
	copy(trailer[48:], sum)
	switch mutation {
	case "bad_magic":
		trailer[0] ^= 1
	case "overflow_base":
		binary.LittleEndian.PutUint64(trailer[32:40], ^uint64(0))
	case "oversized_manifest":
		binary.LittleEndian.PutUint64(trailer[40:48], 4<<20+1)
	case "wrong_manifest_digest":
		trailer[48] ^= 1
	case "changed_code":
		payload[len(base)+len(raw)] ^= 1
	case "extra_unlisted_payload":
		payload = append(payload, []byte("NON_CANON_UNLISTED_TRAILING_PAYLOAD")...)
	case "short_code":
		payload = payload[:len(payload)-1]
	case "changed_manifest":
		payload[len(base)] ^= 1
	}
	return append(payload, trailer[:]...), identity
}

func holdNonCanonFlatCapsule(t *testing.T, body []byte) *os.File {
	t.Helper()
	p := t.TempDir() + "/non_canon_helper_payload"
	if err := os.WriteFile(p, body, 0600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	f, err := sealedCodeSnapshot(source, int64(len(body)), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestEmbeddedCapsuleExactHeldBytesAndRetirement(t *testing.T) {
	body, expected := nonCanonFlatCapsule(t, "")
	f := holdNonCanonFlatCapsule(t, body)
	c, err := OpenEmbeddedCodeCapsule(f, expected)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	asset, err := c.Descriptor("server_fixture")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(asset)
	_ = asset.Close()
	if err != nil || !bytes.Equal(got, nonCanonCodeELF("")) {
		t.Fatal("embedded immutable bytes changed", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Descriptor("server_fixture"); !errors.Is(err, ErrCodeCapsule) {
		t.Fatal("retired embedded capsule reopened", err)
	}
}

func TestEmbeddedCapsuleRejectsUnheldAndAmbiguousEnvelope(t *testing.T) {
	for _, mutation := range []string{"bad_magic", "overflow_base", "oversized_manifest", "wrong_manifest_digest", "changed_code", "extra_unlisted_payload", "short_code", "changed_manifest", "wrong_expected", "unsealed_source"} {
		t.Run(mutation, func(t *testing.T) {
			body, expected := nonCanonFlatCapsule(t, mutation)
			f := holdNonCanonFlatCapsule(t, body)
			if mutation == "wrong_expected" {
				expected = inputSHA([]byte("NON_CANON_DIFFERENT_TRUSTED_BINDING"))
			}
			if mutation == "unsealed_source" {
				p := t.TempDir() + "/mutable_source"
				if err := os.WriteFile(p, body, 0600); err != nil {
					t.Fatal(err)
				}
				var err error
				f, err = os.Open(p)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
			}
			if c, err := OpenEmbeddedCodeCapsule(f, expected); c != nil || !errors.Is(err, ErrCodeCapsule) {
				if c != nil {
					_ = c.Close()
				}
				t.Fatal("unheld or ambiguous capsule accepted", err)
			}
		})
	}
}
