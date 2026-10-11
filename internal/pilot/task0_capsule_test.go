package pilot

import (
	"io"
	"os"
	"testing"
)

// NON_CANON malformed source data. The private accepted-source integration
// separately checks repeated admission of the complete unchanged 47 assets.
func TestTask0CapsuleRejectedManifestPreservesSharedDescriptorCursor(t *testing.T) {
	body := []byte(`{"non_canon_manifest":true}`)
	f, err := task0SealedBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	c := &HeldCodeCapsule{identity: inputSHA([]byte("NON_CANON")), files: map[string]*os.File{task0SourceAsset(task0ManifestPath): f}}
	defer c.Close()
	for _, offset := range []int64{0, 7, int64(len(body))} {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		for count := 0; count < 2; count++ {
			if validateTask0Capsule(c) == nil {
				t.Fatal("malformed manifest accepted")
			}
			cursor, err := f.Seek(0, io.SeekCurrent)
			if err != nil || cursor != offset {
				t.Fatal("rejected verification changed another reader's shared cursor")
			}
		}
	}
}
