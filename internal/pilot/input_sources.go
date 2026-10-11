package pilot

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"slices"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/zyc14588/AIPT/internal/protocol"
)

const (
	Task0InputAuthoritySHA = "ee801db456897f11429238c3ffdbc08cca2a7d40009ea3ad1adee658eafc63e5"
	Task0InputAnnexSHA     = "5f4ecf19c84a384245071c3f23f491a8c1fe4c8dcae0326a7123a3d6000566f5"
	Task0VisibilityPath    = "aipt/p0-b001/visibility.json"
	Task0CharactersPath    = "aipt/p0-b000/premades-v2.json"
)

var ErrInput = errors.New("B007 fixed input identity or role projection rejected")

type pinnedInput struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

// InputSources holds verified bytes, never repository locators or live paths.
// Model contexts can only request a classified fragment ID, not a file.
type InputSources struct {
	files     map[string][]byte
	fragments map[string]inputFragment
}

type mappingSource struct {
	Path    string          `json:"path"`
	Locator json.RawMessage `json:"locator"`
	Type    string          `json:"locator_type"`
	Scope   struct {
		Fields         []string `json:"fields"`
		HeadingOnly    bool     `json:"heading_only"`
		ExcludeColumns []string `json:"exclude_columns"`
	} `json:"scope"`
}
type visibilityMapping struct {
	ID            string        `json:"id"`
	Source        mappingSource `json:"source"`
	Label         string        `json:"label"`
	RemoteAllowed bool          `json:"remote_allowed"`
	Principals    []string      `json:"principals"`
}
type inputFragment struct {
	mapping visibilityMapping
	content string
	start   int
	end     int
}

type ProjectedInput struct {
	ID             string          `json:"id"`
	SourcePath     string          `json:"source_path"`
	SourceSHA256   string          `json:"source_sha256"`
	Selector       json.RawMessage `json:"selector"`
	Classification string          `json:"classification"`
	Content        string          `json:"content"`
	ContentSHA256  string          `json:"content_sha256"`
	// Ranges bind the original source before any declared column projection.
	ByteStart int `json:"byte_start"`
	ByteEnd   int `json:"byte_end"`
}

func inputSHA(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

// LoadTask0Inputs requires the exact Owner-approved public annex and private
// regular source blobs. Neither an updated checkout nor a different manifest
// can silently add an input or rewrite the accepted original package.
func LoadTask0Inputs(privateRoot string, annex []byte) (*InputSources, error) {
	if inputSHA(annex) != Task0InputAnnexSHA {
		return nil, ErrInput
	}
	var manifest struct {
		Schema     string        `json:"schema"`
		Decision   string        `json:"decision_id"`
		Base       []pinnedInput `json:"preserved_base_files"`
		Additional []pinnedInput `json:"supplemental_inputs"`
		Count      int           `json:"supplemental_input_count"`
	}
	if _, err := protocol.CanonicalJSON(annex); err != nil || json.Unmarshal(annex, &manifest) != nil || manifest.Schema != "aipt.public.b007-task0-input-annex/v1" || manifest.Decision != "B007-TASK0-SUPPLEMENTAL-INPUT-ANNEX-Q003=A" || len(manifest.Base) != 5 || len(manifest.Additional) != 12 || manifest.Count != 12 {
		return nil, ErrInput
	}
	files, err := loadPinnedInputs(privateRoot, append(manifest.Base, manifest.Additional...))
	if err != nil {
		return nil, ErrInput
	}
	return compileInputSources(files)
}

func validInputPath(name string) bool {
	return name != "" && name == path.Clean(name) && !strings.HasPrefix(name, "/") && name != "." && !strings.Contains(name, "\\") && !slices.Contains(strings.Split(name, "/"), "..")
}

func privateInputFile(rootFD int, name string) ([]byte, error) {
	parts := strings.Split(name, "/")
	current, err := syscall.Dup(rootFD)
	if err != nil {
		return nil, ErrInput
	}
	defer func() { _ = syscall.Close(current) }()
	for _, segment := range parts[:len(parts)-1] {
		next, err := syscall.Openat(current, segment, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, ErrInput
		}
		_ = syscall.Close(current)
		current = next
		var st syscall.Stat_t
		if syscall.Fstat(current, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0700 {
			return nil, ErrInput
		}
	}
	fd, err := syscall.Openat(current, parts[len(parts)-1], syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrInput
	}
	f := os.NewFile(uintptr(fd), "verified B007 input")
	defer f.Close()
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0600 || st.Nlink != 1 || st.Size <= 0 || st.Size > 4<<20 {
		return nil, ErrInput
	}
	data, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	if err != nil || len(data) != int(st.Size) || !utf8.Valid(data) {
		return nil, ErrInput
	}
	return data, nil
}

func loadPinnedInputs(privateRoot string, items []pinnedInput) (map[string][]byte, error) {
	fd, err := syscall.Open(privateRoot, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrInput
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0700 {
		return nil, ErrInput
	}
	files := make(map[string][]byte, len(items))
	for _, item := range items {
		if !validInputPath(item.Path) || !digest(item.SHA256) || files[item.Path] != nil {
			return nil, ErrInput
		}
		data, err := privateInputFile(fd, item.Path)
		if err != nil || inputSHA(data) != item.SHA256 || item.Bytes != 0 && len(data) != item.Bytes {
			return nil, ErrInput
		}
		if strings.HasSuffix(item.Path, ".json") {
			if _, err := protocol.CanonicalJSON(data); err != nil {
				return nil, ErrInput
			}
		}
		files[item.Path] = data
	}
	return files, nil
}

func validPrincipal(p string) bool {
	return slices.Contains([]string{"GM", "ALL_PLAYERS", "CHARACTER:UNR-CHAR-0001", "CHARACTER:UNR-CHAR-0002", "CHARACTER:UNR-CHAR-0003", "CHARACTER:UNR-CHAR-0004"}, p)
}

func compileInputSources(files map[string][]byte) (*InputSources, error) {
	var registry struct {
		Schema string `json:"aipt_schema"`
		Policy struct {
			Taxonomy struct {
				Labels []string        `json:"labels"`
				Remote map[string]bool `json:"remote_allowed"`
			} `json:"taxonomy"`
		} `json:"policy"`
		Mappings []visibilityMapping `json:"mappings"`
	}
	if json.Unmarshal(files[Task0VisibilityPath], &registry) != nil || registry.Schema != "aipt.visibility.v1" {
		return nil, ErrInput
	}
	labels := []string{"CREDENTIAL_SECRET", "HUMAN_PRIVATE_DATA", "LOCAL_ONLY_SECRET", "PUBLIC", "TABLE_HIDDEN_REMOTE_ALLOWED", "UNRELEASED_REMOTE_ALLOWED"}
	slices.Sort(registry.Policy.Taxonomy.Labels)
	if !slices.Equal(registry.Policy.Taxonomy.Labels, labels) || len(registry.Policy.Taxonomy.Remote) != len(labels) {
		return nil, ErrInput
	}
	for _, label := range labels {
		expected := slices.Contains([]string{"PUBLIC", "TABLE_HIDDEN_REMOTE_ALLOWED", "UNRELEASED_REMOTE_ALLOWED"}, label)
		if registry.Policy.Taxonomy.Remote[label] != expected {
			return nil, ErrInput
		}
	}
	s := &InputSources{files: files, fragments: map[string]inputFragment{}}
	seen := map[string]bool{}
	for _, m := range registry.Mappings {
		if m.ID == "" || seen[m.ID] || !validInputPath(m.Source.Path) || !slices.Contains(labels, m.Label) || !registry.Policy.Taxonomy.Remote[m.Label] || !m.RemoteAllowed || len(m.Principals) == 0 || m.Label == "TABLE_HIDDEN_REMOTE_ALLOWED" && slices.Contains(m.Principals, "ALL_PLAYERS") {
			return nil, ErrInput
		}
		seen[m.ID] = true
		ps := map[string]bool{}
		for _, p := range m.Principals {
			if !validPrincipal(p) || ps[p] {
				return nil, ErrInput
			}
			ps[p] = true
		}
		content, included := files[m.Source.Path]
		if !included {
			continue
		} // Other repository files remain out of B007 scope.
		fragment, err := resolveInputFragment(content, m)
		if err != nil {
			return nil, ErrInput
		}
		// Equal-specificity intersections cannot silently change permissions.
		for _, old := range s.fragments {
			if old.mapping.Source.Path == m.Source.Path && old.mapping.Source.Type == m.Source.Type && fragment.start >= 0 && old.start >= 0 && fragment.start < old.end && old.start < fragment.end && (old.mapping.Label != m.Label || !slices.Equal(old.mapping.Principals, m.Principals)) {
				return nil, ErrInput
			}
		}
		s.fragments[m.ID] = fragment
	}
	return s, nil
}

// Project rejects the entire request on one unauthorized/missing fragment.
// releases is trusted committed game state; a model cannot authorize release.
func (s *InputSources) Project(principal string, ids []string, releases map[string]bool) ([]ProjectedInput, error) {
	if s == nil || !validPrincipal(principal) || principal == "ALL_PLAYERS" || len(ids) > 32 {
		return nil, ErrInput
	}
	seen := map[string]bool{}
	result := make([]ProjectedInput, 0, len(ids))
	for _, id := range ids {
		fragment, exists := s.fragments[id]
		m := fragment.mapping
		allowed := slices.Contains(m.Principals, principal) || principal != "GM" && slices.Contains(m.Principals, "ALL_PLAYERS")
		if !exists || seen[id] || !allowed || m.Label == "UNRELEASED_REMOTE_ALLOWED" && principal != "GM" && !releases[id] {
			return nil, ErrInput
		}
		seen[id] = true
		result = append(result, ProjectedInput{ID: id, SourcePath: m.Source.Path, SourceSHA256: inputSHA(s.files[m.Source.Path]), Selector: append(json.RawMessage(nil), m.Source.Locator...), Classification: m.Label, Content: fragment.content, ContentSHA256: inputSHA([]byte(fragment.content)), ByteStart: fragment.start, ByteEnd: fragment.end})
	}
	return result, nil
}

func resolveInputFragment(data []byte, m visibilityMapping) (inputFragment, error) {
	f := inputFragment{mapping: m, start: -1, end: -1}
	var locator string
	switch m.Source.Type {
	case "whole_file":
		if len(m.Source.Scope.Fields) != 0 || len(m.Source.Scope.ExcludeColumns) != 0 || m.Source.Scope.HeadingOnly {
			return f, ErrInput
		}
		f.content, f.start, f.end = string(data), 0, len(data)
	case "json_path":
		if json.Unmarshal(m.Source.Locator, &locator) != nil || locator == "" {
			return f, ErrInput
		}
		var selected any
		if json.Unmarshal(data, &selected) != nil {
			return f, ErrInput
		}
		for _, key := range strings.Split(locator, ".") {
			object, ok := selected.(map[string]any)
			if !ok {
				return f, ErrInput
			}
			selected, ok = object[key]
			if !ok {
				return f, ErrInput
			}
		}
		if len(m.Source.Scope.Fields) > 0 {
			object, ok := selected.(map[string]any)
			if !ok {
				return f, ErrInput
			}
			projection := map[string]any{}
			for _, key := range m.Source.Scope.Fields {
				value, ok := object[key]
				if !ok || projection[key] != nil {
					return f, ErrInput
				}
				projection[key] = value
			}
			selected = projection
		}
		encoded, err := json.Marshal(selected)
		if err != nil {
			return f, ErrInput
		}
		f.content, err = protocol.CanonicalJSON(encoded)
		if err != nil {
			return f, ErrInput
		}
	case "markdown_heading", "markdown_table_column":
		if json.Unmarshal(m.Source.Locator, &locator) != nil {
			return f, ErrInput
		}
		heading := locator
		column := ""
		if m.Source.Type == "markdown_table_column" {
			var ok bool
			heading, column, ok = strings.Cut(locator, " / ")
			if !ok || column == "" {
				return f, ErrInput
			}
		}
		start, end, err := markdownSection(data, heading, m.Source.Scope.HeadingOnly)
		if err != nil {
			return f, ErrInput
		}
		f.start, f.end, f.content = start, end, string(data[start:end])
		if column != "" || len(m.Source.Scope.ExcludeColumns) > 0 {
			f.content, err = projectMarkdownColumns(f.content, m.Source.Scope.ExcludeColumns, column)
			if err != nil {
				return f, ErrInput
			}
		}
		if m.Source.Path == "campaign/rules/mechanics-fine-v1.md" && m.ID == "mf-A" {
			// The fixed registry explicitly requires these design-only columns
			// to be stripped from player distribution. Strip for GM too so a
			// shared PUBLIC fragment can never carry the excluded metadata.
			f.content = stripDesignAnnotations(f.content)
		}
	case "markdown_preamble":
		var lines struct {
			Start int `json:"start_line"`
			End   int `json:"end_line"`
		}
		if json.Unmarshal(m.Source.Locator, &lines) != nil || lines.Start != 1 || lines.End < 1 {
			return f, ErrInput
		}
		parts := bytes.SplitAfter(data, []byte("\n"))
		limit := 0
		for limit < len(parts) && !bytes.HasPrefix(parts[limit], []byte("## ")) {
			limit++
		}
		for limit > 0 && len(bytes.TrimSpace(parts[limit-1])) == 0 {
			limit--
		}
		if lines.End != limit {
			return f, ErrInput
		}
		f.start, f.end = 0, len(bytes.Join(parts[:limit], nil))
		f.content = string(data[:f.end])
	default:
		return f, ErrInput
	}
	return f, nil
}

func headingLevel(line string) int {
	for i, c := range line {
		if c != '#' {
			if c == ' ' && i > 0 && i <= 6 {
				return i
			}
			return 0
		}
	}
	return 0
}

func markdownSection(data []byte, heading string, only bool) (int, int, error) {
	level := headingLevel(heading)
	if level == 0 {
		return 0, 0, ErrInput
	}
	start, end, offset, found := -1, len(data), 0, 0
	for _, line := range bytes.SplitAfter(data, []byte("\n")) {
		text := strings.TrimRight(string(line), "\r\n")
		if text == heading {
			found++
			if found == 1 {
				start = offset
				if only {
					end = offset + len(line)
				}
			}
		} else if start >= 0 && end == len(data) && headingLevel(text) > 0 && headingLevel(text) <= level {
			end = offset
		}
		offset += len(line)
	}
	if found != 1 || start < 0 || end <= start {
		return 0, 0, ErrInput
	}
	return start, end, nil
}

func markdownCells(line string) ([]string, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") || strings.Contains(line, "\\|") {
		return nil, false
	}
	cells := strings.Split(strings.TrimSuffix(strings.TrimPrefix(line, "|"), "|"), "|")
	for i := range cells {
		cells[i] = strings.TrimSpace(cells[i])
	}
	return cells, true
}

func projectMarkdownColumns(section string, exclude []string, only string) (string, error) {
	lines := strings.SplitAfter(section, "\n")
	var result strings.Builder
	var columns []int
	found := map[string]bool{}
	table := false
	for _, line := range lines {
		cells, row := markdownCells(line)
		if !row {
			table = false
			if only == "" {
				result.WriteString(line)
			}
			continue
		}
		if !table {
			columns = nil
			for index, column := range cells {
				if slices.Contains(exclude, column) {
					found[column] = true
					continue
				}
				if only == "" || column == only {
					columns = append(columns, index)
				}
				if column == only && only != "" {
					found[only] = true
				}
			}
			table = true
		}
		if len(columns) == 0 {
			if only == "" {
				return "", ErrInput
			}
			continue
		}
		selected := make([]string, 0, len(columns))
		for _, index := range columns {
			if index >= len(cells) {
				return "", ErrInput
			}
			selected = append(selected, cells[index])
		}
		result.WriteString("| " + strings.Join(selected, " | ") + " |\n")
	}
	for _, column := range exclude {
		if !found[column] {
			return "", ErrInput
		}
	}
	if only != "" && !found[only] {
		return "", ErrInput
	}
	return result.String(), nil
}

func stripDesignAnnotations(section string) string {
	var result strings.Builder
	for _, line := range strings.SplitAfter(section, "\n") {
		plain := strings.ReplaceAll(strings.TrimSpace(line), "**", "")
		if strings.HasPrefix(plain, "- 锚点：") || strings.HasPrefix(plain, "- 收敛：") || strings.HasPrefix(plain, "- 收敛断言") {
			continue
		}
		result.WriteString(line)
	}
	return result.String()
}
