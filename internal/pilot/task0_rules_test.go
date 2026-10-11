package pilot

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"testing"

	"github.com/zyc14588/AIPT/internal/runcore"
)

func TestD100ExactZeroDoubleZeroAndSharedOnes(t *testing.T) {
	draw := func(hex string) runcore.RNGDraw { return runcore.RNGDraw{Version: runcore.RNGVersionV1, ValueHex: hex} }
	// Digits are ValueHex modulo ten; value ten gives displayed zero.
	roll, err := ResolveD100([]runcore.RNGDraw{draw("0000000000000009"), draw("0000000000000009")}, 0)
	if err != nil || roll != 99 {
		t.Fatal("base digits", roll, err)
	}
	roll, err = ResolveD100([]runcore.RNGDraw{draw("000000000000000a"), draw("000000000000000a")}, 0)
	if err != nil || roll != 100 {
		t.Fatal("double zero must be 100", roll, err)
	}
	roll, err = ResolveD100([]runcore.RNGDraw{draw("000000000000000a"), draw("000000000000000a"), draw("000000000000000f")}, 1)
	if err != nil || roll != 100 {
		t.Fatal("advantage with shared ones", roll, err)
	}
	roll, err = ResolveD100([]runcore.RNGDraw{draw("000000000000000a"), draw("000000000000000a"), draw("000000000000000f")}, -1)
	if err != nil || roll != 50 {
		t.Fatal("disadvantage with shared ones", roll, err)
	}
	for _, bad := range []string{"0000000000000000", "xxxxxxxxxxxxxxxx", "000000000000000A"} {
		if _, err := UniformDraw(draw(bad), 10); !errors.Is(err, ErrRule) {
			t.Fatal("biased/invalid draw accepted", bad)
		}
	}
}

func TestFiveTierFixedBoundariesWarningPrecedenceAndOpposedTies(t *testing.T) {
	r := &Task0Rules{criticalDivisor: 5, costOffset: 15, costMax: 95, catastropheMin: 96, catalog: map[string]machineRule{"UNR-RULE-0007": {Resolution: []json.RawMessage{json.RawMessage(`{"kind":"tier_rank","order_best_to_worst":["critical_success","success","costly_success","failure_with_progress","catastrophic_failure"]}`)}}}}
	for _, tc := range []struct {
		target, roll int
		warning      bool
		tier         string
	}{{70, 14, false, "critical_success"}, {70, 15, false, "success"}, {70, 70, false, "success"}, {70, 71, false, "costly_success"}, {70, 85, false, "costly_success"}, {70, 86, false, "failure_with_progress"}, {90, 95, false, "costly_success"}, {90, 96, false, "failure_with_progress"}, {98, 96, false, "success"}, {98, 96, true, "catastrophic_failure"}, {500, 100, true, "catastrophic_failure"}, {0, 1, false, "costly_success"}, {-20, 1, false, "failure_with_progress"}} {
		if got := r.resultTier(tc.target, tc.roll, tc.warning); got != tc.tier {
			t.Fatalf("target=%d roll=%d warning=%v: %s != %s", tc.target, tc.roll, tc.warning, got, tc.tier)
		}
	}
	for _, tc := range []struct {
		left, right CheckResult
		want        string
	}{
		{CheckResult{Tier: "critical_success", SkillValue: 30}, CheckResult{Tier: "success", SkillValue: 90}, "attacker"},
		{CheckResult{Tier: "success", SkillValue: 40}, CheckResult{Tier: "success", SkillValue: 40}, "defender"},
		{CheckResult{Tier: "success", SkillValue: 60}, CheckResult{Tier: "success", SkillValue: 40}, "attacker"},
		{CheckResult{Tier: "failure_with_progress", SkillValue: 90}, CheckResult{Tier: "failure_with_progress", SkillValue: 10}, "none_status_quo"},
	} {
		got, err := r.opposedWinner(tc.left, tc.right)
		if err != nil || got != tc.want {
			t.Fatal("opposed source rule", got, err)
		}
	}
}

func TestActualPinnedTask0NumericalRulesOptionalPrivateAcceptance(t *testing.T) {
	root := os.Getenv("AIPT_B007_PRIVATE_INPUT_ROOT")
	if root == "" {
		t.Skip("real fixed game sources stay private")
	}
	annex, err := os.ReadFile("../../docs/pilot/inputs/task0-input-annex-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	sources, err := LoadTask0Inputs(root, annex)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewTask0Rules(sources)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.catalog) != 40 || len(r.characters) != 4 || len(r.skillAttributes) != 35 || r.reconMinutes != 30 || r.moveMinutes != 10 || r.planCap != 2 || r.restPoints != 2 {
		t.Fatal("incomplete exact-source rule compilation")
	}
	tracks := map[string]CharacterTracks{}
	for id := range r.characters {
		tracks[id] = CharacterTracks{PlanPoints: r.planCap}
	}
	baseSpec := CheckSpec{CharacterID: "UNR-CHAR-0001", Skill: "隐匿", Tool: 10, Environment: 20, CostChoice: "exposure"}
	result, err := r.resolveCheck(baseSpec, tracks, 0, false, 50)
	if err != nil || result.SkillValue != 68 || result.Modifier != 20 || result.Target != 88 || result.Tier != "success" {
		t.Fatal("source skill / modifier upper bound", result, err)
	}
	tracks["UNR-CHAR-0001"] = CharacterTracks{Fatigue: 4, Wound: "severe", Pressure: 7, PlanPoints: 2}
	result, err = r.resolveCheck(baseSpec, tracks, 0, false, 96)
	if err != nil || result.StatePenalty != 40 || result.Target != 48 || result.Tier != "catastrophic_failure" {
		t.Fatal("independent state penalties and catastrophe", result, err)
	}
	if value, err := r.skillValue("UNR-CHAR-0001", "话术"); err != nil || value != 10 {
		t.Fatal("untrained half attribute rule", value, err)
	}
	baseSpec.Assistants = []string{"UNR-CHAR-0001"}
	if _, err := r.resolveCheck(baseSpec, tracks, 0, false, 30); !errors.Is(err, ErrRule) {
		t.Fatal("self assistance accepted")
	}
}

// Regression oracle follows frozen UNR-RULE-0004's component selection, not
// best/worst full-percentile ranking. The double-zero edge distinguishes them.
func TestD100AllSharedOnesAndTensAgainstFrozenComponentRule(t *testing.T) {
	draw := func(digit int) runcore.RNGDraw {
		return runcore.RNGDraw{Version: runcore.RNGVersionV1, ValueHex: fmt.Sprintf("%016x", digit+10)}
	}
	for ones := 0; ones < 10; ones++ {
		for tens := 0; tens < 10; tens++ {
			for extra := 0; extra < 10; extra++ {
				for _, adv := range []int{-1, 1} {
					selected := tens
					if adv == 1 && extra < tens || adv == -1 && extra > tens {
						selected = extra
					}
					want := 10*selected + ones
					if want == 0 {
						want = 100
					}
					got, err := ResolveD100([]runcore.RNGDraw{draw(ones), draw(tens), draw(extra)}, adv)
					if err != nil || got != want {
						t.Fatalf("ones=%d tens=%d extra=%d adv=%d: got %d err %v want %d", ones, tens, extra, adv, got, err, want)
					}
				}
			}
		}
	}
}

func TestUnrepresentableLoadCannotTurnPenaltyIntoBenefit(t *testing.T) {
	r := &Task0Rules{pressureCap: 10, fatigueCap: 10, pollutionCap: 10, modifierMin: -20, modifierMax: 20, criticalDivisor: 5, costOffset: 15, costMax: 95, catastropheMin: 96,
		pressureWarning: 7, pollutionWarning: 1, alarmWarning: 2, characters: map[string]task0Character{}, skillAttributes: map[string]string{"隐匿": "体能"}, catalog: map[string]machineRule{"UNR-RULE-0020": {Resolution: []json.RawMessage{json.RawMessage(`{"kind":"state_penalty","per_full_points":2,"change":{"amount":-10}}`)}}}}
	c := task0Character{Attributes: map[string]int{"体能": 50}}
	c.Skills.High = map[string]int{"隐匿": 68}
	r.characters["UNR-CHAR-0001"] = c
	spec := CheckSpec{CharacterID: "UNR-CHAR-0001", Skill: "隐匿", CostChoice: "time"}
	for _, load := range []int{math.MaxInt, math.MaxInt - 1, math.MaxInt/10 + 100} {
		result, err := r.resolveCheck(spec, map[string]CharacterTracks{spec.CharacterID: {Load: load}}, 0, false, 20)
		if !errors.Is(err, ErrRule) {
			t.Fatalf("unrepresentable penalty admitted load=%d result=%+v err=%v", load, result, err)
		}
	}
	for _, load := range []int{0, 8, 9, 100000} {
		result, err := r.resolveCheck(spec, map[string]CharacterTracks{spec.CharacterID: {Load: load}}, 0, false, 20)
		if err != nil || result.StatePenalty < 0 || result.Target > 68 {
			t.Fatalf("load granted benefit load=%d result=%+v err=%v", load, result, err)
		}
	}
}
