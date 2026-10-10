package pilot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestColdCapsuleConstructionRejectsMismatchedOriginsBeforeOutput(t *testing.T) {
	body := nonCanonCodeELF("")
	m := nonCanonCodeManifest(body)
	raw, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "NON_CANON_ELF_SHAPED_DATA")
	if e = os.WriteFile(path, body, 0600); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	for _, kind := range []string{"valid", "base-digest", "manifest-digest", "missing-asset", "extra-unlisted-asset", "cancelled", "changed-code"} {
		t.Run(kind, func(t *testing.T) {
			baseSHA, manifestSHA := inputSHA(body), inputSHA(raw)
			sources := map[string]*os.File{"server_fixture": f}
			ctx := context.Background()
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			var out bytes.Buffer
			switch kind {
			case "base-digest":
				baseSHA = strings.Repeat("a", 64)
			case "manifest-digest":
				manifestSHA = strings.Repeat("b", 64)
			case "missing-asset":
				delete(sources, "server_fixture")
			case "extra-unlisted-asset":
				sources["unlisted"] = f
			case "cancelled":
				cancel()
			case "changed-code":
				other := append([]byte{}, body...)
				other[len(other)-1] ^= 1
				p := filepath.Join(t.TempDir(), "NON_CANON_CHANGED_ASSET")
				if e = os.WriteFile(p, other, 0600); e != nil {
					t.Fatal(e)
				}
				changed, e := os.Open(p)
				if e != nil {
					t.Fatal(e)
				}
				defer changed.Close()
				sources["server_fixture"] = changed
			}
			built, e := BuildPreparedRuntimeCapsule(ctx, f, baseSHA, raw, manifestSHA, sources, &out)
			if kind != "valid" {
				if !errors.Is(e, ErrCodeCapsule) || out.Len() != 0 || built.HelperSHA256 != "" {
					t.Fatal("mismatched cold artifact produced a usable identity", e, out.Len())
				}
				return
			}
			if e != nil || built.HelperSHA256 != inputSHA(out.Bytes()) || built.HelperBytes != int64(out.Len()) || built.AssetCount != 1 {
				t.Fatal("cold artifact digest", built, e)
			}
			held := holdNonCanonFlatCapsule(t, out.Bytes())
			c, e := OpenEmbeddedCodeCapsule(held, manifestSHA)
			if e != nil {
				t.Fatal("cold artifact not parseable", e)
			}
			defer c.Close()
			if c.Identity() != manifestSHA {
				t.Fatal("cold artifact lost externally supplied manifest identity")
			}
		})
	}
}
