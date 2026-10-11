package pilot

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zyc14588/AIPT/internal/orchestrator"
)

func TestTask0ContextUnpublishedHandoutBodyIsGMOnlyAndReleasedBodyPublic(t *testing.T) {
	for _, seat := range []orchestrator.SeatID{orchestrator.SeatGM, orchestrator.SeatPlayer1} {
		t.Run(string(seat), func(t *testing.T) {
			kernel, state, _ := task0AuthenticationFixture()
			projection := task0ContextFixtureProjection(t, seat, state.DomainState)
			var public task0PublicView
			json.Unmarshal(projection.Fields[0].Value, &public)
			public.Handouts = json.RawMessage(`{"NON_CANON_RELEASED":{"text":"NON_CANON_PUBLIC_BODY"}}`)
			projection.Fields[0].Value, _ = json.Marshal(public)
			if seat == orchestrator.SeatGM {
				var gm task0GMView
				json.Unmarshal(projection.Fields[1].Value, &gm)
				gm.Handouts = public.Handouts
				gm.AllHandouts = json.RawMessage(`{"NON_CANON_RELEASED":{"text":"NON_CANON_PUBLIC_BODY"},"NON_CANON_UNRELEASED":{"text":"NON_CANON_GM_BODY_ONLY"}}`)
				projection.Fields[1].Value, _ = json.Marshal(gm)
			}
			raw, _ := json.Marshal(projection)
			kernel.game = &task0ContextFixtureGame{raw: raw}
			ctx, err := task0TurnContext(context.Background(), seat, state.Binding.RunID, "NON-CANON-handout-reference", state.Sequence)
			if err != nil {
				t.Fatal(err)
			}
			syntax := &task0Syntax{bySeat: map[orchestrator.SeatID]json.RawMessage{seat: json.RawMessage(`{"NON_CANON_transport":true}`)}}
			input, refs, err := kernel.turnContextInput(ctx, state, syntax)
			if err != nil {
				t.Fatal(err)
			}
			private, publicCount := 0, 0
			for _, source := range input.RequestedSources {
				content := refs.contents[source.SourceID].Content
				if strings.Contains(content, "NON_CANON_GM_BODY_ONLY") {
					private++
					if seat != orchestrator.SeatGM || source.Scope != orchestrator.ScopeGMOnly || len(source.AllowedSeats) != 0 || source.Classification != orchestrator.ClassTableHiddenRemoteAllowed || !strings.Contains(content, "NON_CANON_UNRELEASED") {
						t.Fatal("unpublished body lost its handout identity or GM-only authorization")
					}
				}
				if strings.Contains(content, "NON_CANON_PUBLIC_BODY") {
					publicCount++
					if source.Scope != orchestrator.ScopePublic || source.Classification != orchestrator.ClassPublic {
						t.Fatal("released body not public or duplicated as private")
					}
				}
			}
			if publicCount != 1 || (seat == orchestrator.SeatGM && private != 1) || (seat != orchestrator.SeatGM && private != 0) {
				t.Fatal("handout visibility/body reference count differs")
			}
		})
	}
}
