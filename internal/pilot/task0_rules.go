package pilot

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/zyc14588/AIPT/internal/runcore"
)

const task0MachineRulesPath = "aipt/p0-b002/machine-rules.json"

var ErrRule = errors.New("B007 fixed rule or deterministic resolution rejected")

type RuleCitation struct {
	Path         string `json:"path"`
	Locator      string `json:"locator"`
	LocatorType  string `json:"locator_type"`
	SourceSHA256 string `json:"source_sha256"`
}
type machineRule struct {
	ID         string            `json:"rule_id"`
	Lifecycle  string            `json:"lifecycle_status"`
	Canonical  bool              `json:"canonical"`
	Status     string            `json:"status"`
	Primary    RuleCitation      `json:"primary_source"`
	Supporting []RuleCitation    `json:"supporting_sources"`
	Resolution []json.RawMessage `json:"resolution"`
}

type Task0Rules struct {
	catalog                                                                        map[string]machineRule
	characters                                                                     map[string]task0Character
	skillAttributes                                                                map[string]string
	modifierMin, modifierMax, criticalDivisor, costOffset, costMax, catastropheMin int
	pressureWarning, pollutionWarning, alarmWarning                                int
	pressureCap, fatigueCap, pollutionCap, planCap, patrolSegments                 int
	moveMinutes, actionMinutes, reconMinutes, restPoints, escapeAreas              int
}

type task0Character struct {
	Attributes map[string]int `json:"attributes"`
	Skills     struct {
		High    map[string]int `json:"high"`
		Regular map[string]int `json:"regular"`
	} `json:"final_skills"`
}

// NewTask0Rules compiles numerical operands from the held machine rules, not
// from model prose. It checks all 40 source citations before any Run starts.
func NewTask0Rules(sources *InputSources) (*Task0Rules, error) {
	if sources == nil || inputSHA(sources.files[task0MachineRulesPath]) != "139d095fe54926e1599edf208b65f7a89061f1cda6d8b492f83b5e47c0693c78" {
		return nil, ErrRule
	}
	var document struct {
		Schema string        `json:"aipt_schema"`
		Rules  []machineRule `json:"rules"`
	}
	if json.Unmarshal(sources.files[task0MachineRulesPath], &document) != nil || document.Schema != "aipt.machine-rules.v1" || len(document.Rules) != 40 {
		return nil, ErrRule
	}
	r := &Task0Rules{catalog: map[string]machineRule{}, characters: map[string]task0Character{}, skillAttributes: map[string]string{}}
	for _, rule := range document.Rules {
		if rule.ID == "" || r.catalog[rule.ID].ID != "" || rule.Canonical || rule.Lifecycle != "PROPOSAL" || rule.Status != "ACTIVE_PROPOSAL" || len(rule.Resolution) == 0 {
			return nil, ErrRule
		}
		for _, citation := range append([]RuleCitation{rule.Primary}, rule.Supporting...) {
			body, ok := sources.files[citation.Path]
			if !ok || inputSHA(body) != citation.SourceSHA256 {
				return nil, ErrRule
			}
			switch citation.LocatorType {
			case "MARKDOWN_HEADING":
				if _, _, err := markdownSection(body, citation.Locator, false); err != nil {
					return nil, ErrRule
				}
			case "EXACT_TEXT":
				if strings.Count(string(body), citation.Locator) != 1 {
					return nil, ErrRule
				}
			default:
				return nil, ErrRule
			}
		}
		r.catalog[rule.ID] = rule
	}
	for i := 1; i <= 40; i++ {
		if r.catalog[fmt.Sprintf("UNR-RULE-%04d", i)].ID == "" {
			return nil, ErrRule
		}
	}
	var characters struct {
		FirstRoster []string                  `json:"first_roster"`
		Characters  map[string]task0Character `json:"characters"`
	}
	if json.Unmarshal(sources.files[Task0CharactersPath], &characters) != nil || len(characters.FirstRoster) != 4 {
		return nil, ErrRule
	}
	for i, name := range characters.FirstRoster {
		character, ok := characters.Characters[name]
		if !ok || len(character.Attributes) != 5 || len(character.Skills.High) == 0 {
			return nil, ErrRule
		}
		for _, value := range character.Attributes {
			if value < 0 || value > 100 {
				return nil, ErrRule
			}
		}
		for _, skills := range []map[string]int{character.Skills.High, character.Skills.Regular} {
			for _, value := range skills {
				if value < 0 || value > 100 {
					return nil, ErrRule
				}
			}
		}
		r.characters[fmt.Sprintf("UNR-CHAR-%04d", i+1)] = character
	}
	var mapping struct {
		Skills []struct {
			Skill     string `json:"skill"`
			Attribute string `json:"attribute"`
		} `json:"skills"`
	}
	if r.decode("UNR-RULE-0002", "untrained_mapping", &mapping) != nil || len(mapping.Skills) != 35 {
		return nil, ErrRule
	}
	for _, item := range mapping.Skills {
		if item.Skill == "" || item.Attribute == "" || r.skillAttributes[item.Skill] != "" {
			return nil, ErrRule
		}
		r.skillAttributes[item.Skill] = item.Attribute
	}
	var clamp struct {
		Min int `json:"min"`
		Max int `json:"max"`
	}
	if r.decode("UNR-RULE-0003", "clamp", &clamp) != nil {
		return nil, ErrRule
	}
	r.modifierMin, r.modifierMax = clamp.Min, clamp.Max
	var tiers struct {
		Order []struct {
			Priority  int    `json:"priority"`
			Tier      string `json:"tier"`
			Condition struct {
				R struct {
					Min any `json:"min"`
					Max any `json:"max"`
				} `json:"r"`
			} `json:"condition"`
		} `json:"order"`
	}
	if r.decode("UNR-RULE-0005", "ordered_result_tiers", &tiers) != nil || len(tiers.Order) != 5 {
		return nil, ErrRule
	}
	cat, ok := tiers.Order[0].Condition.R.Min.(float64)
	if !ok || cat != math.Trunc(cat) {
		return nil, ErrRule
	}
	r.catastropheMin = int(cat)
	thresholds := r.resolutions("UNR-RULE-0005", "derived_threshold")
	if len(thresholds) != 2 {
		return nil, ErrRule
	}
	for _, raw := range thresholds {
		var t struct {
			ID     string `json:"id"`
			Divide int    `json:"divide_by"`
			Offset int    `json:"offset"`
			Max    int    `json:"clamp_max"`
		}
		if json.Unmarshal(raw, &t) != nil {
			return nil, ErrRule
		}
		if t.ID == "critical_threshold" {
			r.criticalDivisor = t.Divide
		} else if t.ID == "costly_max" {
			r.costOffset, r.costMax = t.Offset, t.Max
		} else {
			return nil, ErrRule
		}
	}
	var warning struct {
		Any []struct {
			State string `json:"state"`
			Value any    `json:"value"`
		} `json:"any_of"`
	}
	if r.decode("UNR-RULE-0006", "warning_condition", &warning) != nil || len(warning.Any) != 4 {
		return nil, ErrRule
	}
	for _, w := range warning.Any {
		if w.State == "scene.noticed_by_it" {
			if w.Value != true {
				return nil, ErrRule
			}
			continue
		}
		value, ok := w.Value.(float64)
		if !ok || value != math.Trunc(value) {
			return nil, ErrRule
		}
		switch w.State {
		case "character.pressure":
			r.pressureWarning = int(value)
		case "character.pollution":
			r.pollutionWarning = int(value)
		case "scene.alarm_level":
			r.alarmWarning = int(value)
		default:
			return nil, ErrRule
		}
	}
	for _, track := range []struct {
		Rule, Kind string
		Out        *int
	}{{"UNR-RULE-0019", "track", &r.pressureCap}, {"UNR-RULE-0020", "track", &r.fatigueCap}, {"UNR-RULE-0022", "track", &r.pollutionCap}, {"UNR-RULE-0023", "resource", &r.planCap}} {
		var value struct {
			Cap int `json:"cap"`
		}
		if r.decode(track.Rule, track.Kind, &value) != nil || value.Cap <= 0 {
			return nil, ErrRule
		}
		*track.Out = value.Cap
	}
	var clock struct {
		Segments int `json:"segments"`
	}
	var times struct {
		Move   int `json:"cross_area_move_minutes"`
		Action int `json:"single_action_minutes"`
	}
	var recon struct {
		Minutes int `json:"time_per_check_minutes"`
	}
	var rest struct {
		Points int `json:"per_character"`
	}
	var escape struct {
		Condition struct {
			Value int `json:"value"`
		} `json:"condition"`
	}
	if r.decode("UNR-RULE-0036", "clock", &clock) != nil || r.decode("UNR-RULE-0040", "time_units", &times) != nil || r.decode("UNR-RULE-0034", "recon_action", &recon) != nil || r.decode("UNR-RULE-0039", "action_points", &rest) != nil || r.decode("UNR-RULE-0032", "escape", &escape) != nil {
		return nil, ErrRule
	}
	r.patrolSegments, r.moveMinutes, r.actionMinutes, r.reconMinutes, r.restPoints, r.escapeAreas = clock.Segments, times.Move, times.Action, recon.Minutes, rest.Points, escape.Condition.Value
	if r.criticalDivisor <= 0 || r.modifierMin > 0 || r.modifierMax < 0 || r.costOffset <= 0 || r.costMax >= 100 || r.catastropheMin <= r.costMax || r.pressureWarning <= 0 || r.pollutionWarning <= 0 || r.alarmWarning <= 0 || r.moveMinutes <= 0 || r.actionMinutes <= 0 || r.reconMinutes <= 0 || r.restPoints <= 0 || r.escapeAreas <= 0 {
		return nil, ErrRule
	}
	return r, nil
}

func (r *Task0Rules) resolutions(id, kind string) []json.RawMessage {
	var result []json.RawMessage
	for _, raw := range r.catalog[id].Resolution {
		var item struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal(raw, &item) == nil && item.Kind == kind {
			result = append(result, raw)
		}
	}
	return result
}
func (r *Task0Rules) decode(id, kind string, out any) error {
	values := r.resolutions(id, kind)
	if len(values) != 1 || json.Unmarshal(values[0], out) != nil {
		return ErrRule
	}
	return nil
}

type CheckSpec struct {
	CharacterID string   `json:"character_id"`
	Skill       string   `json:"skill"`
	Environment int      `json:"environment"`
	Tool        int      `json:"tool"`
	Time        int      `json:"time"`
	Assistants  []string `json:"assistants"`
	Advantage   int      `json:"advantage"`
	CostChoice  string   `json:"cost_choice"`
}
type CharacterTracks struct {
	Pressure     int    `json:"pressure"`
	Fatigue      int    `json:"fatigue"`
	Pollution    int    `json:"pollution"`
	Wound        string `json:"wound"`
	WoundTreated bool   `json:"wound_treated"`
	Load         int    `json:"load"`
	PlanPoints   int    `json:"plan_points"`
}
type CheckResult struct {
	CharacterID  string   `json:"character_id"`
	Skill        string   `json:"skill"`
	SkillValue   int      `json:"skill_value"`
	Modifier     int      `json:"modifier"`
	StatePenalty int      `json:"state_penalty"`
	Target       int      `json:"target"`
	Roll         int      `json:"roll"`
	Tier         string   `json:"tier"`
	Warning      bool     `json:"warning"`
	RuleIDs      []string `json:"rule_ids"`
}

func (r *Task0Rules) skillValue(id, skill string) (int, error) {
	c, ok := r.characters[id]
	if !ok || r.skillAttributes[skill] == "" {
		return 0, ErrRule
	}
	if value, ok := c.Skills.High[skill]; ok {
		return value, nil
	}
	if value, ok := c.Skills.Regular[skill]; ok {
		return value, nil
	}
	value, ok := c.Attributes[r.skillAttributes[skill]]
	if !ok {
		return 0, ErrRule
	}
	return value / 2, nil
}

func (r *Task0Rules) resolveCheck(spec CheckSpec, tracks map[string]CharacterTracks, alarm int, noticed bool, roll int) (CheckResult, error) {
	result := CheckResult{CharacterID: spec.CharacterID, Skill: spec.Skill, Roll: roll, RuleIDs: []string{"UNR-RULE-0002", "UNR-RULE-0003", "UNR-RULE-0004", "UNR-RULE-0005", "UNR-RULE-0006", "UNR-RULE-0008", "UNR-RULE-0020", "UNR-RULE-0021", "UNR-RULE-0025"}}
	t, ok := tracks[spec.CharacterID]
	if r == nil || !ok || roll < 1 || roll > 100 || alarm < 0 || alarm > 3 || t.Pressure < 0 || t.Pressure > r.pressureCap || t.Fatigue < 0 || t.Fatigue > r.fatigueCap || t.Pollution < 0 || t.Pollution > r.pollutionCap || t.Load < 0 || spec.Advantage < -1 || spec.Advantage > 1 || len(spec.Assistants) > 2 || !slices.Contains([]string{"exposure", "time", "resource", "pressure"}, spec.CostChoice) {
		return result, ErrRule
	}
	base, err := r.skillValue(spec.CharacterID, spec.Skill)
	if err != nil {
		return result, ErrRule
	}
	result.SkillValue = base
	assistance := 0
	seen := map[string]bool{spec.CharacterID: true}
	for _, id := range spec.Assistants {
		value, err := r.skillValue(id, spec.Skill)
		if err != nil || seen[id] || value < 40 {
			return result, ErrRule
		}
		seen[id] = true
		assistance += 10
	}
	for _, value := range []int{spec.Environment, spec.Tool, spec.Time} {
		if value < -20 || value > 20 || value%10 != 0 {
			return result, ErrRule
		}
	}
	result.Modifier = min(r.modifierMax, max(r.modifierMin, spec.Environment+spec.Tool+spec.Time+assistance))
	var fatigue struct {
		Every  int `json:"per_full_points"`
		Change struct {
			Amount int `json:"amount"`
		} `json:"change"`
	}
	if r.decode("UNR-RULE-0020", "state_penalty", &fatigue) != nil || fatigue.Every <= 0 || fatigue.Change.Amount >= 0 {
		return result, ErrRule
	}
	penalty := (t.Fatigue / fatigue.Every) * (-fatigue.Change.Amount)
	if t.Wound != "" {
		var wounds struct {
			Levels []struct {
				Level     string `json:"level"`
				Penalty   int    `json:"state_penalty"`
				Treatment struct {
					Penalty int `json:"state_penalty_after"`
				} `json:"treatment"`
			} `json:"levels"`
		}
		if r.decode("UNR-RULE-0021", "wound_levels", &wounds) != nil {
			return result, ErrRule
		}
		found := false
		for _, w := range wounds.Levels {
			if w.Level == t.Wound {
				if w.Level == "fatal" {
					return result, ErrRule
				}
				found = true
				if t.WoundTreated {
					penalty -= w.Treatment.Penalty
				} else {
					penalty -= w.Penalty
				}
			}
		}
		if !found {
			return result, ErrRule
		}
	}
	if slices.Contains([]string{"隐匿", "攀爬", "潜入行动"}, spec.Skill) {
		c := r.characters[spec.CharacterID]
		limit := 3 + c.Attributes["体能"]/10
		overload := max(0, t.Load-limit)
		if overload > (math.MaxInt-penalty)/10 {
			return result, ErrRule
		}
		penalty += overload * 10
	}
	result.StatePenalty = penalty
	baseWithModifier := base + result.Modifier
	if penalty < 0 || baseWithModifier < 0 && penalty > math.MaxInt+baseWithModifier {
		return result, ErrRule
	}
	result.Target = baseWithModifier - penalty
	result.Warning = t.Pressure >= r.pressureWarning || t.Pollution >= r.pollutionWarning || alarm >= r.alarmWarning || noticed
	result.Tier = r.resultTier(result.Target, roll, result.Warning)
	return result, nil
}

func (r *Task0Rules) resultTier(target, roll int, warning bool) string {
	if warning && roll >= r.catastropheMin {
		return "catastrophic_failure"
	}
	if roll <= int(math.Floor(float64(target)/float64(r.criticalDivisor))) {
		return "critical_success"
	}
	if roll <= target {
		return "success"
	}
	if roll <= min(target+r.costOffset, r.costMax) {
		return "costly_success"
	}
	return "failure_with_progress"
}

// UniformDraw rejects the tiny incomplete interval rather than introducing
// modulo bias. A rejected predetermined Core draw fails the action; callers
// must never manufacture or substitute an unaudited random value.
func UniformDraw(draw runcore.RNGDraw, sides int) (int, error) {
	if sides < 2 || sides > 100 || draw.Version != runcore.RNGVersionV1 || len(draw.ValueHex) != 16 {
		return 0, ErrRule
	}
	raw, err := hex.DecodeString(draw.ValueHex)
	if err != nil || hex.EncodeToString(raw) != draw.ValueHex || len(raw) != 8 {
		return 0, ErrRule
	}
	value := binary.BigEndian.Uint64(raw)
	bound := uint64(sides)
	threshold := -bound % bound
	if value < threshold {
		return 0, ErrRule
	}
	return int(value%bound) + 1, nil
}

func ResolveD100(draws []runcore.RNGDraw, advantage int) (int, error) {
	if advantage < -1 || advantage > 1 || len(draws) != 2+min(1, max(0, int(math.Abs(float64(advantage))))) {
		return 0, ErrRule
	}
	ones, err := UniformDraw(draws[0], 10)
	if err != nil {
		return 0, err
	}
	ones--
	tens, err := UniformDraw(draws[1], 10)
	if err != nil {
		return 0, err
	}
	tens--
	// Frozen UNR-RULE-0004 selects the ten-sided tens component first.
	// Only then are shared ones combined and 00 interpreted as 100.
	if advantage != 0 {
		extra, err := UniformDraw(draws[2], 10)
		if err != nil {
			return 0, err
		}
		if advantage > 0 {
			tens = min(tens, extra-1)
		} else {
			tens = max(tens, extra-1)
		}
	}
	result := 10*tens + ones
	if result == 0 {
		result = 100
	}
	return result, nil
}

func (r *Task0Rules) opposedWinner(left, right CheckResult) (string, error) {
	var order struct {
		Order []string `json:"order_best_to_worst"`
	}
	if r.decode("UNR-RULE-0007", "tier_rank", &order) != nil || len(order.Order) != 5 {
		return "", ErrRule
	}
	l, rr := slices.Index(order.Order, left.Tier), slices.Index(order.Order, right.Tier)
	if l < 0 || rr < 0 {
		return "", ErrRule
	}
	if left.Tier == "failure_with_progress" && right.Tier == "failure_with_progress" {
		return "none_status_quo", nil
	}
	if l < rr {
		return "attacker", nil
	}
	if l > rr {
		return "defender", nil
	}
	if left.SkillValue > right.SkillValue {
		return "attacker", nil
	}
	return "defender", nil
}
