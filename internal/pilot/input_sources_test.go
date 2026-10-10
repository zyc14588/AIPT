package pilot

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func pinnedFixture(t *testing.T) (string, []pinnedInput) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "inputs")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	content := []byte(`{"synthetic_non_canon_input":true}`)
	if err := os.WriteFile(filepath.Join(root, "sub", "one.json"), content, 0600); err != nil {
		t.Fatal(err)
	}
	return root, []pinnedInput{{"sub/one.json", inputSHA(content), len(content)}}
}

func TestPinnedInputHeldBytesAndFailClosedFileIdentity(t *testing.T) {
	for _, kind := range []string{"valid", "changed", "missing", "file_symlink", "directory_symlink", "hardlink", "public_mode", "unsafe_path", "duplicate", "wrong_size", "directory_mode", "duplicate_json_keys"} {
		t.Run(kind, func(t *testing.T) {
			root, items := pinnedFixture(t)
			file := filepath.Join(root, "sub", "one.json")
			switch kind {
			case "changed":
				_ = os.WriteFile(file, []byte(`{"changed":true}`), 0600)
			case "missing":
				_ = os.Remove(file)
			case "file_symlink":
				_ = os.Rename(file, file+".old")
				_ = os.Symlink("one.json.old", file)
			case "directory_symlink":
				_ = os.Rename(filepath.Join(root, "sub"), filepath.Join(root, "old"))
				_ = os.Symlink("old", filepath.Join(root, "sub"))
			case "hardlink":
				_ = os.Link(file, file+".second")
			case "public_mode":
				_ = os.Chmod(file, 0644)
			case "unsafe_path":
				items[0].Path = "sub/../sub/one.json"
			case "duplicate":
				items = append(items, items[0])
			case "wrong_size":
				items[0].Bytes++
			case "directory_mode":
				_ = os.Chmod(filepath.Join(root, "sub"), 0755)
			case "duplicate_json_keys":
				content := []byte(`{"x":1,"x":2}`)
				_ = os.WriteFile(file, content, 0600)
				items[0].SHA256 = inputSHA(content)
				items[0].Bytes = len(content)
			}
			files, err := loadPinnedInputs(root, items)
			if kind != "valid" {
				if !errors.Is(err, ErrInput) {
					t.Fatalf("unsafe %s accepted: %v", kind, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, []byte(`{"later_replacement":true}`), 0600); err != nil {
				t.Fatal(err)
			}
			if inputSHA(files[items[0].Path]) != items[0].SHA256 {
				t.Fatal("held bytes changed after disk replacement")
			}
		})
	}
}

func syntheticMappings() []visibilityMapping {
	makeJSON := func(id, locator, label string, principals []string) visibilityMapping {
		encoded, _ := json.Marshal(locator)
		return visibilityMapping{ID: id, Source: mappingSource{Path: Task0CharactersPath, Locator: encoded, Type: "json_path"}, Label: label, RemoteAllowed: true, Principals: principals}
	}
	stats := makeJSON("stats-1", "characters.alpha", "PUBLIC", []string{"GM", "ALL_PLAYERS"})
	stats.Source.Scope.Fields = []string{"name", "attribute"}
	return []visibilityMapping{
		stats,
		makeJSON("secret-1", "characters.alpha.secret", "TABLE_HIDDEN_REMOTE_ALLOWED", []string{"GM", "CHARACTER:UNR-CHAR-0001"}),
		makeJSON("secret-2", "characters.beta.secret", "TABLE_HIDDEN_REMOTE_ALLOWED", []string{"GM", "CHARACTER:UNR-CHAR-0002"}),
		makeJSON("clue-1", "characters.alpha.discovery_clues", "TABLE_HIDDEN_REMOTE_ALLOWED", []string{"GM"}),
		{ID: "handout", Source: mappingSource{Path: "handout.md", Locator: json.RawMessage(`null`), Type: "whole_file"}, Label: "UNRELEASED_REMOTE_ALLOWED", RemoteAllowed: true, Principals: []string{"GM", "ALL_PLAYERS"}},
	}
}

func syntheticInputSources(t *testing.T, mappings []visibilityMapping) *InputSources {
	t.Helper()
	registry := map[string]any{"aipt_schema": "aipt.visibility.v1", "policy": map[string]any{"taxonomy": map[string]any{
		"labels":         []string{"PUBLIC", "UNRELEASED_REMOTE_ALLOWED", "TABLE_HIDDEN_REMOTE_ALLOWED", "LOCAL_ONLY_SECRET", "HUMAN_PRIVATE_DATA", "CREDENTIAL_SECRET"},
		"remote_allowed": map[string]bool{"PUBLIC": true, "UNRELEASED_REMOTE_ALLOWED": true, "TABLE_HIDDEN_REMOTE_ALLOWED": true, "LOCAL_ONLY_SECRET": false, "HUMAN_PRIVATE_DATA": false, "CREDENTIAL_SECRET": false},
	}}, "mappings": mappings}
	encoded, _ := json.Marshal(registry)
	files := map[string][]byte{Task0VisibilityPath: encoded, Task0CharactersPath: []byte(`{"characters":{"alpha":{"name":"synthetic alpha","attribute":40,"secret":"OWNER_ONLY_NON_CANON_SECRET","discovery_clues":["GM_ONLY_NON_CANON_CLUE"]},"beta":{"secret":"OTHER_PLAYER_NON_CANON_SECRET"}}}`), "handout.md": []byte("SYNTHETIC_UNRELEASED_HANDOUT\n")}
	s, err := compileInputSources(files)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRoleProjectionPreventsOwnClueOtherSecretAndEarlyRelease(t *testing.T) {
	s := syntheticInputSources(t, syntheticMappings())
	for _, principal := range []string{"CHARACTER:UNR-CHAR-0001", "CHARACTER:UNR-CHAR-0002", "CHARACTER:UNR-CHAR-0003", "CHARACTER:UNR-CHAR-0004"} {
		projection, err := s.Project(principal, []string{"stats-1"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(projection)
		if strings.Contains(string(body), "SECRET") || strings.Contains(string(body), "CLUE") {
			t.Fatal("public stats expose private source")
		}
	}
	own, err := s.Project("CHARACTER:UNR-CHAR-0001", []string{"secret-1"}, nil)
	if err != nil || !strings.Contains(own[0].Content, "OWNER_ONLY") {
		t.Fatal("own-secret projection rejected", err)
	}
	for _, ids := range [][]string{{"secret-2"}, {"clue-1"}, {"handout"}, {"unknown-source"}, {"stats-1", "secret-2"}, {"stats-1", "stats-1"}} {
		if data, err := s.Project("CHARACTER:UNR-CHAR-0001", ids, nil); !errors.Is(err, ErrInput) || data != nil {
			t.Fatalf("unauthorized projection accepted: %v", ids)
		}
	}
	if _, err := s.Project("GM", []string{"secret-1", "secret-2", "clue-1", "handout"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Project("CHARACTER:UNR-CHAR-0001", []string{"handout"}, map[string]bool{"handout": true}); err != nil {
		t.Fatal(err)
	}
	for _, principal := range []string{"ALL_PLAYERS", "seat-01", "CHARACTER:UNR-CHAR-0005", "SYSTEM_INTERNAL"} {
		if _, err := s.Project(principal, []string{"stats-1"}, nil); !errors.Is(err, ErrInput) {
			t.Fatal("invalid runtime principal accepted", principal)
		}
	}
}

func TestUnclassifiedForbiddenAndConflictingRegistryMappingsReject(t *testing.T) {
	for _, kind := range []string{"unknown_label", "missing_label", "forbidden_data", "hidden_all_players", "wrong_remote", "duplicate_id", "unknown_principal", "overlap_permission"} {
		t.Run(kind, func(t *testing.T) {
			m := syntheticMappings()
			switch kind {
			case "unknown_label":
				m[0].Label = "UNCLASSIFIED"
			case "missing_label":
				m[0].Label = ""
			case "forbidden_data":
				m[0].Label = "HUMAN_PRIVATE_DATA"
				m[0].RemoteAllowed = false
			case "hidden_all_players":
				m[1].Principals = append(m[1].Principals, "ALL_PLAYERS")
			case "wrong_remote":
				m[0].RemoteAllowed = false
			case "duplicate_id":
				m[1].ID = m[0].ID
			case "unknown_principal":
				m[0].Principals = []string{"seat-01"}
			case "overlap_permission":
				m = append(m, visibilityMapping{ID: "conflict", Source: mappingSource{Path: "handout.md", Locator: json.RawMessage(`null`), Type: "whole_file"}, Label: "TABLE_HIDDEN_REMOTE_ALLOWED", RemoteAllowed: true, Principals: []string{"GM"}})
			}
			registry := map[string]any{"aipt_schema": "aipt.visibility.v1", "policy": map[string]any{"taxonomy": map[string]any{"labels": []string{"PUBLIC", "UNRELEASED_REMOTE_ALLOWED", "TABLE_HIDDEN_REMOTE_ALLOWED", "LOCAL_ONLY_SECRET", "HUMAN_PRIVATE_DATA", "CREDENTIAL_SECRET"}, "remote_allowed": map[string]bool{"PUBLIC": true, "UNRELEASED_REMOTE_ALLOWED": true, "TABLE_HIDDEN_REMOTE_ALLOWED": true, "LOCAL_ONLY_SECRET": false, "HUMAN_PRIVATE_DATA": false, "CREDENTIAL_SECRET": false}}}, "mappings": m}
			encoded, _ := json.Marshal(registry)
			if _, err := compileInputSources(map[string][]byte{Task0VisibilityPath: encoded, "handout.md": []byte("synthetic\n"), Task0CharactersPath: []byte(`{"characters":{"alpha":{"name":"a","attribute":40,"secret":"s","discovery_clues":[]},"beta":{"secret":"b"}}}`)}); !errors.Is(err, ErrInput) {
				t.Fatal("invalid registry accepted", err)
			}
		})
	}
}

func TestMarkdownProjectionStripsGMColumnAndBindsOriginalRanges(t *testing.T) {
	document := []byte("# synthetic non-canon\n\n## Sheet\n| Fact | GM notes |\n| --- | --- |\n| PUBLIC_MARKER | HIDDEN_MARKER |\n\n## Later\nnot included\n")
	locator, _ := json.Marshal("## Sheet")
	m := visibilityMapping{ID: "sheet", Source: mappingSource{Type: "markdown_heading", Locator: locator}}
	m.Source.Scope.ExcludeColumns = []string{"GM notes"}
	f, err := resolveInputFragment(document, m)
	if err != nil || strings.Contains(f.content, "HIDDEN_MARKER") || strings.Contains(f.content, "Later") || !strings.Contains(f.content, "PUBLIC_MARKER") || !strings.Contains(string(document[f.start:f.end]), "HIDDEN_MARKER") {
		t.Fatal("invalid column projection/range", err)
	}
	m.Source.Type = "markdown_table_column"
	m.Source.Scope.ExcludeColumns = nil
	m.Source.Locator, _ = json.Marshal("## Sheet / GM notes")
	f, err = resolveInputFragment(document, m)
	if err != nil || strings.Contains(f.content, "PUBLIC_MARKER") || !strings.Contains(f.content, "HIDDEN_MARKER") {
		t.Fatal("GM-only column projection wrong", err)
	}
	if _, _, err := markdownSection(append(document, []byte("## Sheet\nsecond\n")...), "## Sheet", false); !errors.Is(err, ErrInput) {
		t.Fatal("ambiguous heading accepted")
	}
	if _, err := projectMarkdownColumns(string(document), []string{"missing-column"}, ""); !errors.Is(err, ErrInput) {
		t.Fatal("unresolved exclusion accepted")
	}
}

func TestRealFixedInputProjectionOptionalPrivateAcceptance(t *testing.T) {
	privateRoot := os.Getenv("AIPT_B007_PRIVATE_INPUT_ROOT")
	if privateRoot == "" {
		t.Skip("private exact game bodies are deliberately absent from public CI")
	}
	annex, err := os.ReadFile("../../docs/pilot/inputs/task0-input-annex-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := LoadTask0Inputs(privateRoot, annex)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.files) != 17 {
		t.Fatal("approved source inventory incomplete")
	}
	for _, id := range []string{"premades-secret-0001", "premades-secret-0002", "premades-secret-0003", "premades-secret-0004"} {
		for n, principal := range []string{"CHARACTER:UNR-CHAR-0001", "CHARACTER:UNR-CHAR-0002", "CHARACTER:UNR-CHAR-0003", "CHARACTER:UNR-CHAR-0004"} {
			_, err := s.Project(principal, []string{id}, nil)
			if (id[len(id)-1] == '1'+byte(n)) != (err == nil) {
				t.Fatal("exact-source character secret routing failed", id, principal)
			}
		}
	}
	for _, principal := range []string{"CHARACTER:UNR-CHAR-0001", "CHARACTER:UNR-CHAR-0002", "CHARACTER:UNR-CHAR-0003", "CHARACTER:UNR-CHAR-0004"} {
		for _, id := range []string{"intel-pack-001", "gm-screen-001", "stage3-scene-S1", "premades-clues-0001", "premades-trigger-0001", "rks-gm-notes-column", "handouts-visitor-notice"} {
			if _, err := s.Project(principal, []string{id}, nil); !errors.Is(err, ErrInput) {
				t.Fatal("exact-source unauthorized material accepted", id, principal)
			}
		}
	}
	gm, err := s.Project("GM", []string{"stage3-scene-S1", "stage3-scene-S2", "stage3-scene-S3", "stage3-scene-S4", "stage3-scene-S5", "stage3-scene-S6", "stage3-scene-S7", "stage3-scene-S8", "intel-pack-001", "gm-screen-001"}, nil)
	if err != nil || len(gm) != 10 {
		t.Fatal("complete Task0 GM source projection missing", err)
	}
	if len(s.fragments) == 0 || !slices.ContainsFunc(gm, func(p ProjectedInput) bool { return p.ByteStart >= 0 && p.ByteEnd > p.ByteStart }) {
		t.Fatal("source range bindings missing")
	}
}
