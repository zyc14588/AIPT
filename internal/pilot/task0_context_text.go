package pilot

import (
	"bytes"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/zyc14588/AIPT/internal/protocol"
)

const task0GMTextEncoding = "GM_JSON_TEXT_V1"
const task0GMTextLegend = "{}[] JSON; words=strings; #N:text=N UTF8 bytes; ^N=s[N]; _=null,T=true,F=false"

type task0GMTextView struct {
	Encoding string   `json:"encoding"`
	Legend   string   `json:"legend"`
	Strings  []string `json:"s"`
	Value    string   `json:"value"`
}

// This readable representation removes repeated JSON quoting, not facts.
// Names and prose remain text. A short string table holds exact repeated
// names/text; byte-counted strings preserve delimiters, empty strings, UTF8,
// newlines and literal scalar-looking strings without an escape convention.
// Only the already authorized GM fact uses it. Its complete canonical input
// must round trip on every invocation, before the new fact is hashed.
func task0EncodeGMView(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) < 2 || len(raw) > 1<<20 || !utf8.Valid(raw) {
		return nil, ErrTask0
	}
	canonical, err := protocol.CanonicalJSON(raw)
	var view map[string]any
	d := json.NewDecoder(strings.NewReader(canonical))
	d.UseNumber()
	if err != nil || d.Decode(&view) != nil || view == nil {
		return nil, ErrTask0
	}
	type occurrence struct{ keys, values int }
	counts := map[string]occurrence{}
	nodes := 0
	var count func(any, int) error
	count = func(v any, depth int) error {
		nodes++
		if depth > 128 || nodes > 65536 {
			return ErrTask0
		}
		switch v := v.(type) {
		case map[string]any:
			for k, child := range v {
				c := counts[k]
				c.keys++
				counts[k] = c
				if err := count(child, depth+1); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range v {
				if err := count(child, depth+1); err != nil {
					return err
				}
			}
		case string:
			c := counts[v]
			c.values++
			counts[v] = c
		}
		return nil
	}
	if count(view, 0) != nil {
		return nil, ErrTask0
	}
	quotedSize := func(s string) int { b, _ := json.Marshal(s); return len(b) }
	weight := func(s string) int {
		c := counts[s]
		return c.keys*len(task0GMTextLiteral(s, true)) + c.values*len(task0GMTextLiteral(s, false)) - quotedSize(s)
	}
	candidates := make([]string, 0, len(counts))
	for s := range counts {
		candidates = append(candidates, s)
	}
	slices.SortFunc(candidates, func(a, b string) int {
		if x, y := weight(a), weight(b); x != y {
			return y - x
		}
		return strings.Compare(a, b)
	})
	pool := []string{}
	references := map[string]string{}
	for _, s := range candidates {
		c := counts[s]
		ref := "^" + strconv.Itoa(len(pool))
		gain := c.keys*(len(task0GMTextLiteral(s, true))-len(ref)) + c.values*(len(task0GMTextLiteral(s, false))-len(ref)) - quotedSize(s) - 1
		if gain > 0 && len(pool) < 4096 {
			references[s] = ref
			pool = append(pool, s)
		}
	}
	var b strings.Builder
	literal := func(s string, key bool) {
		if ref, ok := references[s]; ok {
			b.WriteString(ref)
		} else {
			b.WriteString(task0GMTextLiteral(s, key))
		}
	}
	var write func(any)
	write = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			b.WriteByte('{')
			for i, k := range keys {
				if i != 0 {
					b.WriteByte(',')
				}
				literal(k, true)
				b.WriteByte(':')
				write(v[k])
			}
			b.WriteByte('}')
		case []any:
			b.WriteByte('[')
			for i, child := range v {
				if i != 0 {
					b.WriteByte(',')
				}
				write(child)
			}
			b.WriteByte(']')
		case string:
			literal(v, false)
		case nil:
			b.WriteByte('_')
		case bool:
			if v {
				b.WriteByte('T')
			} else {
				b.WriteByte('F')
			}
		case json.Number:
			b.WriteString(string(v))
		}
	}
	write(view)
	encoded, err := json.Marshal(task0GMTextView{task0GMTextEncoding, task0GMTextLegend, pool, b.String()})
	compact, ce := protocol.CanonicalJSON(encoded)
	if err != nil || ce != nil {
		return nil, ErrTask0
	}
	decoded, err := task0DecodeGMView(json.RawMessage(compact))
	if err != nil || !bytes.Equal(decoded, []byte(canonical)) {
		return nil, ErrTask0
	}
	if len(compact) >= len(canonical) {
		return json.RawMessage(canonical), nil
	}
	return json.RawMessage(compact), nil
}

func task0GMTextWord(s string) bool {
	if s == "" || !(s[0] >= 'A' && s[0] <= 'Z' || s[0] >= 'a' && s[0] <= 'z' || s[0] == '_') {
		return false
	}
	for _, c := range []byte(s)[1:] {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("_@./-", rune(c))) {
			return false
		}
	}
	return true
}

func task0GMTextLiteral(s string, key bool) string {
	if task0GMTextWord(s) && (key || s != "_" && s != "T" && s != "F") {
		return s
	}
	return "#" + strconv.Itoa(len(s)) + ":" + s
}

type task0GMTextParser struct {
	raw        string
	pool       []string
	pos, nodes int
}

func (p *task0GMTextParser) take(c byte) bool {
	if p.pos >= len(p.raw) || p.raw[p.pos] != c {
		return false
	}
	p.pos++
	return true
}

func (p *task0GMTextParser) integer() (int, error) {
	start := p.pos
	for p.pos < len(p.raw) && p.raw[p.pos] >= '0' && p.raw[p.pos] <= '9' {
		p.pos++
	}
	if p.pos == start || p.pos-start > 7 || p.pos-start > 1 && p.raw[start] == '0' {
		return 0, ErrTask0
	}
	n, err := strconv.Atoi(p.raw[start:p.pos])
	if err != nil {
		return 0, ErrTask0
	}
	return n, nil
}

func (p *task0GMTextParser) text() (string, error) {
	if p.take('^') {
		n, err := p.integer()
		if err != nil || n >= len(p.pool) {
			return "", ErrTask0
		}
		return p.pool[n], nil
	}
	if p.take('#') {
		n, err := p.integer()
		if err != nil || !p.take(':') || n > len(p.raw)-p.pos {
			return "", ErrTask0
		}
		s := p.raw[p.pos : p.pos+n]
		p.pos += n
		if !utf8.ValidString(s) {
			return "", ErrTask0
		}
		return s, nil
	}
	start := p.pos
	for p.pos < len(p.raw) && !strings.ContainsRune(":,{}[]", rune(p.raw[p.pos])) {
		p.pos++
	}
	s := p.raw[start:p.pos]
	if !task0GMTextWord(s) {
		return "", ErrTask0
	}
	return s, nil
}

func (p *task0GMTextParser) value(depth int) (any, error) {
	p.nodes++
	if depth > 128 || p.nodes > 65536 || p.pos >= len(p.raw) {
		return nil, ErrTask0
	}
	if p.take('{') {
		v := map[string]any{}
		if p.take('}') {
			return v, nil
		}
		for {
			k, err := p.text()
			if err != nil || !p.take(':') {
				return nil, ErrTask0
			}
			if _, duplicate := v[k]; duplicate {
				return nil, ErrTask0
			}
			child, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			v[k] = child
			if p.take('}') {
				return v, nil
			}
			if !p.take(',') {
				return nil, ErrTask0
			}
		}
	}
	if p.take('[') {
		v := []any{}
		if p.take(']') {
			return v, nil
		}
		for {
			child, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			v = append(v, child)
			if p.take(']') {
				return v, nil
			}
			if !p.take(',') {
				return nil, ErrTask0
			}
		}
	}
	if p.raw[p.pos] == '^' || p.raw[p.pos] == '#' {
		return p.text()
	}
	start := p.pos
	for p.pos < len(p.raw) && !strings.ContainsRune(",}]", rune(p.raw[p.pos])) {
		p.pos++
	}
	token := p.raw[start:p.pos]
	switch token {
	case "_":
		return nil, nil
	case "T":
		return true, nil
	case "F":
		return false, nil
	}
	if task0GMTextWord(token) {
		return token, nil
	}
	var n any
	d := json.NewDecoder(strings.NewReader(token))
	d.UseNumber()
	if !json.Valid([]byte(token)) || d.Decode(&n) != nil {
		return nil, ErrTask0
	}
	if number, ok := n.(json.Number); ok {
		return number, nil
	}
	return nil, ErrTask0
}

// This private decoder validates only the trusted encoder's representation.
// It is not an action, patch, tool, or model-output input surface.
func task0DecodeGMView(raw json.RawMessage) (json.RawMessage, error) {
	var v task0GMTextView
	if decodeFrozenJSON(raw, 1<<20, &v) != nil || v.Encoding != task0GMTextEncoding || v.Legend != task0GMTextLegend || v.Strings == nil || len(v.Strings) > 4096 || !utf8.ValidString(v.Value) {
		return nil, ErrTask0
	}
	seen := map[string]bool{}
	for _, s := range v.Strings {
		if !utf8.ValidString(s) || seen[s] {
			return nil, ErrTask0
		}
		seen[s] = true
	}
	p := task0GMTextParser{raw: v.Value, pool: v.Strings}
	decoded, err := p.value(0)
	if _, ok := decoded.(map[string]any); err != nil || !ok || p.pos != len(p.raw) {
		return nil, ErrTask0
	}
	body, err := json.Marshal(decoded)
	canonical, ce := protocol.CanonicalJSON(body)
	if err != nil || ce != nil || len(canonical) > 1<<20 {
		return nil, ErrTask0
	}
	return json.RawMessage(canonical), nil
}
