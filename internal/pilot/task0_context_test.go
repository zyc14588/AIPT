package pilot

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/protocol"
)

func TestTask0ContextParameterRegistryRejectsExecutableOrAmbiguousSyntax(t *testing.T) {
	for _, sample := range []struct {
		body  string
		valid bool
	}{
		{"WAIT: ['minutes'], MOVE: ['to', 'group'], OBSERVE: [],", true},
		{"WAIT: ['minutes'], WAIT: [],", false},
		{"WAIT: ['minutes', 'minutes'],", false},
		{"WAIT: ['minutes']; exec(),", false},
		{"WAIT: ['minutes'] MOVE: [],", false},
		{"WAIT: ['minutes'], PRIVATE: [process.env.SECRET],", false},
		{"WAIT: ['minutes']", false},
		{"", false},
	} {
		_, err := task0ParameterRegistry(sample.body)
		if (err == nil) != sample.valid {
			t.Fatal("parameter registry admitted ambiguous data")
		}
	}
}

type task0ContextFixtureGame struct {
	raw   []byte
	calls int
}

func (g *task0ContextFixtureGame) invoke(_ context.Context, operation string, _ map[string]any) (json.RawMessage, error) {
	g.calls++
	if operation != "PROJECTION" {
		return nil, ErrTask0
	}
	return slices.Clone(g.raw), nil
}

func task0ContextFixtureProjection(t *testing.T, seat orchestrator.SeatID, domain json.RawMessage) *protocol.Projection {
	t.Helper()
	makeField := func(id string, value any, label string, seats []string) protocol.StateField {
		raw, _ := json.Marshal(value)
		canonical, err := protocol.CanonicalJSON(raw)
		if err != nil {
			t.Fatal(err)
		}
		return protocol.StateField{FieldID: id, Value: json.RawMessage(canonical), Visibility: protocol.Visibility{Label: label, AuthorizedSeatIDs: seats}}
	}
	public := task0PublicView{Characters: json.RawMessage(`[{"character_id":"UNR-CHAR-0001","NON_CANON":true},{"character_id":"UNR-CHAR-0002","NON_CANON":true},{"character_id":"UNR-CHAR-0003","NON_CANON":true},{"character_id":"UNR-CHAR-0004","NON_CANON":true}]`), Reference: "NON_CANON_PUBLIC_DATA", Situation: json.RawMessage(`{"non_canon":true}`), Handouts: json.RawMessage(`{}`), Ledger: json.RawMessage(`null`), Data: true}
	fields := []protocol.StateField{makeField("task0-public", public, "PUBLIC", []string{"seat-gm", "seat-01", "seat-02", "seat-03", "seat-04"})}
	if seat == orchestrator.SeatGM {
		gm := task0GMView{Schema: "unregistered.task0-role-projection/v2", Principal: "GM", Characters: public.Characters, Reference: public.Reference, Situation: public.Situation, Handouts: public.Handouts, Data: true, GM: json.RawMessage(`{"NON_CANON_GM_SECRET":"ONLY_GM"}`), GMReference: "NON_CANON_GM_REFERENCE", SafetyReference: "NON_CANON_GM_SAFETY", Private: json.RawMessage(`{"NON_CANON_ALL_PRIVATE":"ONLY_GM"}`), AllHandouts: public.Handouts, Domain: domain}
		fields = append(fields, makeField("task0-gm", gm, "TABLE_HIDDEN_REMOTE_ALLOWED", []string{"seat-gm"}))
	}
	for _, player := range orchestrator.BaselineSeats()[1:] {
		if seat != orchestrator.SeatGM && player != seat {
			continue
		}
		wire := task0WireSeat(player)
		own := task0OwnView{State: json.RawMessage(`{"actor_id":"` + string(player) + `"}`), Private: json.RawMessage(`{"non_canon_private":"PRIVATE_` + string(player) + `"}`)}
		fields = append(fields, makeField("task0-"+wire, own, "TABLE_HIDDEN_REMOTE_ALLOWED", []string{"seat-gm", wire}))
	}
	canonical, err := protocol.CanonicalJSON(domain)
	if err != nil {
		t.Fatal(err)
	}
	wire := task0WireSeat(seat)
	return &protocol.Projection{ProtocolVersion: "1.0.0", SchemaVersion: "1.0.0", FixtureID: task0FixtureID, ProjectionID: "task0-projection-" + wire + "-" + inputSHA([]byte(canonical))[8:24], SeatID: wire, Fields: fields}
}

func TestTask0ContextRejectsProjectionIdentityLabelsAndCrossSeatRetrieval(t *testing.T) {
	for _, scenario := range []string{"valid_player", "valid_gm", "missing_turn", "other_sequence", "other_seat", "projection_hash", "missing_own", "public_reclassified", "private_reclassified", "widened_recipients", "foreign_private", "duplicate_field", "stale_gm_domain"} {
		t.Run(scenario, func(t *testing.T) {
			k, state, _ := task0AuthenticationFixture()
			seat := orchestrator.SeatPlayer1
			if scenario == "valid_gm" || scenario == "stale_gm_domain" {
				seat = orchestrator.SeatGM
			}
			ctx, err := task0TurnContext(context.Background(), seat, state.Binding.RunID, "NON-CANON-context", state.Sequence)
			if err != nil {
				t.Fatal(err)
			}
			projection := task0ContextFixtureProjection(t, seat, state.DomainState)
			switch scenario {
			case "missing_turn":
				ctx = context.Background()
			case "other_sequence":
				state.Sequence++
			case "other_seat":
				projection.SeatID = "seat-02"
			case "projection_hash":
				projection.ProjectionID = strings.Replace(projection.ProjectionID, "task0-projection", "task0-unbound", 1)
			case "missing_own":
				projection.Fields = projection.Fields[:1]
			case "public_reclassified":
				projection.Fields[0].Visibility.Label = "TABLE_HIDDEN_REMOTE_ALLOWED"
			case "private_reclassified":
				projection.Fields[1].Visibility.Label = "PUBLIC"
			case "widened_recipients":
				projection.Fields[1].Visibility.AuthorizedSeatIDs = append(projection.Fields[1].Visibility.AuthorizedSeatIDs, "seat-02")
			case "foreign_private":
				projection.Fields[1].FieldID = "task0-seat-02"
			case "duplicate_field":
				projection.Fields = append(projection.Fields, projection.Fields[1])
			case "stale_gm_domain":
				var gm task0GMView
				json.Unmarshal(projection.Fields[1].Value, &gm)
				gm.Domain = json.RawMessage(`{"non_canon_other_state":true}`)
				projection.Fields[1].Value, _ = json.Marshal(gm)
			}
			raw, _ := json.Marshal(projection)
			game := &task0ContextFixtureGame{raw: raw}
			k.game = game
			syntax := &task0Syntax{bySeat: map[orchestrator.SeatID]json.RawMessage{seat: json.RawMessage(`{"NON_CANON_transport":true}`)}}
			input, refs, err := k.turnContextInput(ctx, state, syntax)
			valid := scenario == "valid_player" || scenario == "valid_gm"
			if (err == nil) != valid {
				t.Fatal("untrusted projection context admitted", scenario)
			}
			if !valid {
				if (scenario == "missing_turn" || scenario == "other_sequence") && game.calls != 0 {
					t.Fatal("unauthenticated context dispatched game")
				}
				return
			}
			if len(input.StateFacts) != 1 || input.StateFacts[0].ValueSHA256 != inputSHA(input.StateFacts[0].Value) || input.Summary.RunID != state.Binding.RunID || input.Summary.SeatID != seat || len(input.Summary.RequiredFactIDs) != 0 || len(input.Summary.Facts) != 0 {
				t.Fatal("persistent state lost its mandatory identity")
			}
			role := orchestrator.RolePlayer
			if seat == orchestrator.SeatGM {
				role = orchestrator.RoleGM
			}
			view, err := orchestrator.BuildAuthorizedView(state.Binding.RunID, orchestrator.Seat{RunID: state.Binding.RunID, SeatID: seat, Role: role}, input.StateFacts)
			if err != nil || len(view.Facts) != 1 {
				t.Fatal("B003 role visibility contract rejected", err)
			}
			slot := &task0ReferenceSlot{}
			if slot.activate(ctx, refs) != nil {
				t.Fatal("private reference admission failed")
			}
			requested := []orchestrator.AuthorizedSource{}
			for _, source := range input.RequestedSources {
				requested = append(requested, orchestrator.AuthorizedSource{SourceID: source.SourceID, Classification: source.Classification, ExpectedSHA256: source.ExpectedSHA256})
			}
			contents, err := slot.Retrieve(ctx, requested)
			if err != nil {
				t.Fatal("authorized role data rejected")
			}
			all, _ := json.Marshal(contents)
			if seat != orchestrator.SeatGM && (strings.Contains(string(all), "NON_CANON_GM_") || strings.Contains(string(all), "PRIVATE_PLAYER_2") || strings.Contains(string(all), "NON_CANON_ALL_PRIVATE")) {
				t.Fatal("foreign private data entered player view")
			}
			foreign, _ := task0TurnContext(context.Background(), orchestrator.SeatPlayer2, state.Binding.RunID, "NON-CANON-context", state.Sequence)
			if _, err := slot.Retrieve(foreign, requested); err == nil {
				t.Fatal("cross-seat reference reuse admitted")
			}
			if slot.activate(ctx, refs) == nil {
				t.Fatal("active invocation references overwritten")
			}
			if slot.retire(refs) != nil {
				t.Fatal("owned references did not retire")
			}
			if _, err := slot.Retrieve(ctx, requested); err == nil {
				t.Fatal("retired invocation references reused")
			}
		})
	}
}
