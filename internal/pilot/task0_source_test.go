package pilot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zyc14588/AIPT/internal/protocol"
	"github.com/zyc14588/AIPT/internal/runcore"
)

// NON_CANON source-reader fixture. Its expectations only enter the private
// verification helper. They never replace the exported loader's compile-time
// Owner identities, and the fixture has no runtime/model grant.
func prototypeSourceReaderFixture(t *testing.T) (string, []byte, []byte, prototypeInputExpectations) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	entries := make([]pinnedInput, 45)
	for i := range entries {
		name := fmt.Sprintf("fixture/input-%02d.json", i)
		data := []byte(fmt.Sprintf(`{"non_canon_source":%d}`, i))
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
		entries[i] = pinnedInput{Path: name, Bytes: len(data), SHA256: inputSHA(data)}
	}
	old := map[string]any{"schema": "aipt.public.b007-task0-input-annex/v1", "decision_id": "B007-TASK0-SUPPLEMENTAL-INPUT-ANNEX-Q003=A", "preserved_base_files": entries[:5], "supplemental_inputs": entries[5:17], "supplemental_input_count": 12}
	retained, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	m := prototypeSourceManifest{Schema: "unregistered.task0-prototype-package/v2", PackageID: "NON-CANON-source-reader", Lifecycle: "PROTOTYPE", Canonical: false,
		SourceBaseline:            prototypeSourceBaseline{Repository: "zyc14588/UNREGISTERED", Commit: "fe0965977447caf8cd7b6e58252bc1b991b7cc6f", Tree: "34597e79c586fb034256daa32d67640692ec589d"},
		ContainingRevisionBinding: "EXTERNAL_ACCEPTED_COMMIT_TREE_AND_DIGEST_REQUIRED", Entries: entries}
	mraw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := protocol.CanonicalJSON(mraw)
	if err != nil {
		t.Fatal(err)
	}
	expected := prototypeInputExpectations{AuthoritySHA: strings.Repeat("a", 64), RetainedAnnexSHA: inputSHA(retained), AdoptionReviewSHA: strings.Repeat("b", 64), CIEvidenceSHA: strings.Repeat("c", 64),
		SourcePackage: runcore.SourcePackageBinding{PackageID: m.PackageID, Schema: m.Schema, Repository: "fixture/non-canon", Commit: strings.Repeat("1", 40), Tree: strings.Repeat("2", 40), CanonicalSHA256: inputSHA([]byte(canonical))}}
	a := prototypeInputAnnex{Schema: "aipt.public.b007-task0-prototype-input-annex/v2", DecisionID: "AIPT-MVP-B007-OWNER-Q009",
		AuthorityPath: "docs/pilot/authorities/task0-prototype-source-successor-q009.json", AuthoritySHA256: expected.AuthoritySHA,
		RetainedQ003AuthoritySHA: Task0InputAuthoritySHA, RetainedQ003AnnexSHA: expected.RetainedAnnexSHA,
		SourceAdoptionReviewSHA: expected.AdoptionReviewSHA, OnlineCIEvidenceSHA: expected.CIEvidenceSHA, SourcePackage: expected.SourcePackage, SourceManifest: m,
		RuntimeReady: false, QualificationEligible: false}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	expected.AnnexSHA = inputSHA(raw)
	return root, raw, retained, expected
}

func TestPrototypeSourceClosureHoldsAllBytesAndPreservesSeventeen(t *testing.T) {
	root, raw, retained, expected := prototypeSourceReaderFixture(t)
	a, files, err := loadPrototypeInputClosure(root, raw, retained, expected)
	if err != nil || len(files) != 45 || a.SourcePackage != expected.SourcePackage {
		t.Fatal("synthetic source closure rejected", err)
	}
	name := a.SourceManifest.Entries[0].Path
	held := append([]byte(nil), files[name]...)
	if err := os.WriteFile(filepath.Join(root, name), []byte(`{"changed":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if string(files[name]) != string(held) {
		t.Fatal("opened source follows later path replacement")
	}
	if _, _, err := loadPrototypeInputClosure(root, raw, retained, expected); err == nil {
		t.Fatal("changed source bytes accepted")
	}
	if _, err := LoadTask0PrototypeInputs(root, raw, retained); err == nil {
		t.Fatal("synthetic source expectations reached the Owner-pinned exported loader")
	}
}

func TestPrototypeSourceClosureRejectsSemanticAndCanonicalSubstitution(t *testing.T) {
	cases := map[string]func(*prototypeInputAnnex){
		"different_authority":  func(a *prototypeInputAnnex) { a.AuthoritySHA256 = strings.Repeat("d", 64) },
		"different_review":     func(a *prototypeInputAnnex) { a.SourceAdoptionReviewSHA = strings.Repeat("d", 64) },
		"different_ci":         func(a *prototypeInputAnnex) { a.OnlineCIEvidenceSHA = strings.Repeat("d", 64) },
		"different_commit":     func(a *prototypeInputAnnex) { a.SourcePackage.Commit = strings.Repeat("3", 40) },
		"runtime_grant":        func(a *prototypeInputAnnex) { a.RuntimeReady = true },
		"qualification_grant":  func(a *prototypeInputAnnex) { a.QualificationEligible = true },
		"canon_promotion":      func(a *prototypeInputAnnex) { a.SourceManifest.Canonical = true },
		"wrong_count":          func(a *prototypeInputAnnex) { a.SourceManifest.Entries = a.SourceManifest.Entries[:44] },
		"same_count_duplicate": func(a *prototypeInputAnnex) { a.SourceManifest.Entries[1] = a.SourceManifest.Entries[0] },
		"unsorted_entries": func(a *prototypeInputAnnex) {
			a.SourceManifest.Entries[0], a.SourceManifest.Entries[1] = a.SourceManifest.Entries[1], a.SourceManifest.Entries[0]
		},
		"traversal":                    func(a *prototypeInputAnnex) { a.SourceManifest.Entries[0].Path = "../outside.json" },
		"different_retained_authority": func(a *prototypeInputAnnex) { a.RetainedQ003AuthoritySHA = strings.Repeat("d", 64) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			root, raw, retained, expected := prototypeSourceReaderFixture(t)
			var a prototypeInputAnnex
			if err := json.Unmarshal(raw, &a); err != nil {
				t.Fatal(err)
			}
			mutate(&a)
			raw, err := json.Marshal(a)
			if err != nil {
				t.Fatal(err)
			}
			// Rehashing the outer envelope cannot alter its independently pinned
			// inner source/review/CI/retention or semantic policy.
			expected.AnnexSHA = inputSHA(raw)
			if _, _, err := loadPrototypeInputClosure(root, raw, retained, expected); err == nil {
				t.Fatal("substitution accepted")
			}
		})
	}
	for _, name := range []string{"case_alias", "duplicate_key", "unknown_field"} {
		t.Run(name, func(t *testing.T) {
			root, raw, retained, expected := prototypeSourceReaderFixture(t)
			s := string(raw)
			switch name {
			case "case_alias":
				s = strings.Replace(s, `"runtime_ready"`, `"RUNTIME_READY"`, 1)
			case "duplicate_key":
				s = strings.Replace(s, `"runtime_ready":false`, `"runtime_ready":false,"runtime_ready":false`, 1)
			case "unknown_field":
				s = strings.TrimSuffix(s, "}") + `,"bypass":false}`
			}
			expected.AnnexSHA = inputSHA([]byte(s))
			if _, _, err := loadPrototypeInputClosure(root, []byte(s), retained, expected); err == nil {
				t.Fatal("ambiguous control JSON accepted")
			}
		})
	}
}

func TestPrototypeSourceClosureRejectsChangedRetainedInputWithFreshDigests(t *testing.T) {
	root, raw, retained, expected := prototypeSourceReaderFixture(t)
	var a prototypeInputAnnex
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"non_canon_changed_original":true}`)
	e := &a.SourceManifest.Entries[0]
	e.Bytes, e.SHA256 = len(data), inputSHA(data)
	if err := os.WriteFile(filepath.Join(root, e.Path), data, 0600); err != nil {
		t.Fatal(err)
	}
	mraw, _ := json.Marshal(a.SourceManifest)
	canonical, err := protocol.CanonicalJSON(mraw)
	if err != nil {
		t.Fatal(err)
	}
	a.SourcePackage.CanonicalSHA256 = inputSHA([]byte(canonical))
	expected.SourcePackage = a.SourcePackage
	raw, _ = json.Marshal(a)
	expected.AnnexSHA = inputSHA(raw)
	if _, _, err := loadPrototypeInputClosure(root, raw, retained, expected); err == nil {
		t.Fatal("original seventeen rewritten despite retained annex")
	}
}

func TestPrototypeSourceClosureRejectsUnheldFileObjects(t *testing.T) {
	for _, kind := range []string{"file_symlink", "root_symlink", "hardlink", "public_file", "public_directory", "missing_file"} {
		t.Run(kind, func(t *testing.T) {
			root, raw, retained, expected := prototypeSourceReaderFixture(t)
			file := filepath.Join(root, "fixture/input-00.json")
			switch kind {
			case "file_symlink":
				if err := os.Rename(file, file+".held"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(file+".held", file); err != nil {
					t.Fatal(err)
				}
			case "root_symlink":
				alias := root + "-alias"
				if err := os.Symlink(root, alias); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Remove(alias) })
				root = alias
			case "hardlink":
				if err := os.Link(file, file+".alias"); err != nil {
					t.Fatal(err)
				}
			case "public_file":
				if err := os.Chmod(file, 0644); err != nil {
					t.Fatal(err)
				}
			case "public_directory":
				if err := os.Chmod(filepath.Dir(file), 0755); err != nil {
					t.Fatal(err)
				}
			case "missing_file":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := loadPrototypeInputClosure(root, raw, retained, expected); err == nil {
				t.Fatal("unheld source file accepted")
			}
		})
	}
}
