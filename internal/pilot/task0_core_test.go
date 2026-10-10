package pilot

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/runcore"
	"github.com/zyc14588/AIPT/internal/testplan"
)

// NON_CANON control fixture. No accepted game kernel, runtime capsule, model
// or production queue is executed by these authentication probes.
func task0AuthenticationFixture() (*task0KernelCore, runcore.RunState, runcore.ActionProposal) {
	b := runcore.RunBinding{Schema: runcore.RunBindingSchema, RunID: "NON-CANON-authentication",
		Manifest:            runcore.ArtifactBinding{ID: "NON-CANON-manifest", Schema: testplan.RunManifestSchema, CanonicalSHA256: strings.Repeat("a", 64)},
		RuntimeAdapterInput: runcore.ArtifactBinding{ID: "NON-CANON-adapter", Schema: "fixture/v1", CanonicalSHA256: strings.Repeat("b", 64)}, SourcePackage: task0PrototypeSourceBinding}
	k := &task0KernelCore{binding: b, types: map[string]bool{"PLAYER_INTENT": true}}
	s := runcore.RunState{Binding: b, Sequence: 7, DomainState: json.RawMessage(`{"non_canon_state":true}`)}
	p := runcore.ActionProposal{Schema: runcore.ActionProposalSchema, RunID: b.RunID, ActionID: "NON-CANON-action", ActorID: "UNR-CHAR-0001", ActionType: "PLAYER_INTENT", ExpectedSequence: 7,
		Source: runcore.RuleSource{Kind: runcore.RuleSourceExplicit, Reference: task0PrototypeSourceBinding.PackageID}, Payload: json.RawMessage(`{"kind":"NON_CANON"}`), RNGRequests: []runcore.RNGRequest{}}
	return k, s, p
}

func TestTask0CoreAuthRequiresTrustedSeatNonceRunAndSequence(t *testing.T) {
	for _, scenario := range []string{"valid", "missing_context", "foreign_actor", "foreign_run", "other_nonce", "stale_sequence", "other_source_binding", "other_manifest", "invalid_seat"} {
		t.Run(scenario, func(t *testing.T) {
			k, s, p := task0AuthenticationFixture()
			ctx, err := task0TurnContext(context.Background(), orchestrator.SeatPlayer1, p.RunID, p.ActionID, s.Sequence)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "missing_context":
				ctx = context.Background()
			case "foreign_actor":
				p.ActorID = "UNR-CHAR-0002"
			case "foreign_run":
				p.RunID = "NON-CANON-other-run"
			case "other_nonce":
				p.ActionID = "NON-CANON-other-action"
			case "stale_sequence":
				p.ExpectedSequence--
			case "other_source_binding":
				s.Binding.SourcePackage.Commit = strings.Repeat("1", 40)
			case "other_manifest":
				s.Binding.Manifest.CanonicalSHA256 = strings.Repeat("c", 64)
			case "invalid_seat":
				ctx = context.WithValue(context.Background(), task0TurnKey{}, task0AuthenticatedTurn{"ALL_PLAYERS", p.RunID, p.ActionID, s.Sequence})
			}
			err = k.authorize(ctx, s, p)
			if (err == nil) != (scenario == "valid") {
				t.Fatal("authenticated action outcome differs", scenario)
			}
		})
	}
}

type nonCanonTask0Game struct {
	operation string
	input     map[string]any
	proposal  runcore.ActionProposal
}

func (g *nonCanonTask0Game) invoke(_ context.Context, operation string, input map[string]any) (json.RawMessage, error) {
	g.operation, g.input = operation, input
	if operation == "PROPOSE" {
		raw, _ := json.Marshal(g.proposal)
		return raw, nil
	}
	if operation == "APPLY" {
		return json.RawMessage(`{"non_canon_next_state":true}`), nil
	}
	return json.RawMessage(`{"valid":true}`), nil
}

func TestTask0FrameRejectsProviderAuthorityAndPreservesEmptyRNG(t *testing.T) {
	for _, scenario := range []string{"valid", "provider_seat", "provider_source", "provider_draws", "foreign_actor", "case_alias", "duplicate_actor", "reply_null_rng", "reply_changed_actor", "reply_changed_nonce", "reply_foreign_stream"} {
		t.Run(scenario, func(t *testing.T) {
			k, s, p := task0AuthenticationFixture()
			g := &nonCanonTask0Game{proposal: p}
			k.game = g
			ctx, _ := task0TurnContext(context.Background(), orchestrator.SeatPlayer1, p.RunID, p.ActionID, s.Sequence)
			frame := []byte(`{"actor_id":"UNR-CHAR-0001","action_type":"PLAYER_INTENT","payload":{"kind":"NON_CANON"}}`)
			switch scenario {
			case "provider_seat", "provider_source", "provider_draws":
				field := map[string]string{"provider_seat": "seat", "provider_source": "source", "provider_draws": "draws"}[scenario]
				frame = []byte(strings.TrimSuffix(string(frame), "}") + `,"` + field + `":[]}`)
			case "foreign_actor":
				frame = []byte(strings.ReplaceAll(string(frame), "UNR-CHAR-0001", "UNR-CHAR-0002"))
			case "case_alias":
				frame = []byte(strings.ReplaceAll(string(frame), "actor_id", "Actor_ID"))
			case "duplicate_actor":
				frame = []byte(strings.TrimSuffix(string(frame), "}") + `,"actor_id":"UNR-CHAR-0001"}`)
			case "reply_null_rng":
				g.proposal.RNGRequests = nil
			case "reply_changed_actor":
				g.proposal.ActorID = "GM"
			case "reply_changed_nonce":
				g.proposal.ActionID = "NON-CANON-other-action"
			case "reply_foreign_stream":
				g.proposal.RNGRequests = []runcore.RNGRequest{{StreamID: "foreign", Count: 2}}
			}
			got, err := k.normalizeFrame(ctx, s, frame)
			if (err == nil) != (scenario == "valid") {
				t.Fatal("provider frame authority outcome differs", scenario)
			}
			if scenario == "valid" && (got.RNGRequests == nil || len(got.RNGRequests) != 0) {
				t.Fatal("empty RNG became null")
			}
		})
	}
}

func TestTask0CoreApplySendsOnlyExactCoreDraws(t *testing.T) {
	k, s, p := task0AuthenticationFixture()
	g := &nonCanonTask0Game{}
	k.game = g
	if _, err := k.Apply(context.Background(), s, p, nil); err != nil {
		t.Fatal(err)
	}
	draws, ok := g.input["draws"].([]runcore.RNGDraw)
	if !ok || draws == nil || len(draws) != 0 || g.operation != "APPLY" {
		t.Fatal("zero-draw wire is not an explicit Core array")
	}
	if _, err := k.Apply(context.Background(), s, p, make([]runcore.RNGDraw, 33)); err == nil {
		t.Fatal("game draw ceiling exceeded")
	}
}

func TestTask0TurnGrantRejectsUntrustedControlIdentity(t *testing.T) {
	for _, seat := range []orchestrator.SeatID{"", "ALL_PLAYERS", "PLAYER_5", "seat-01"} {
		if _, err := task0TurnContext(context.Background(), seat, "fixture-run", "fixture-action", 1); err == nil {
			t.Fatal("untrusted runtime seat accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := task0TurnContext(ctx, orchestrator.SeatGM, "fixture-run", "fixture-action", 1); err == nil {
		t.Fatal("canceled invocation granted")
	}
}

func task0ManifestFixture(t *testing.T) testplan.FrozenManifest {
	t.Helper()
	m := pilotManifest(t, "NON-CANON-task0-binding").Manifest
	m.Source.Game = testplan.RepositorySource{Repository: task0PrototypeSourceBinding.Repository, Commit: task0PrototypeSourceBinding.Commit, Tree: task0PrototypeSourceBinding.Tree}
	m.PromptAssets = []testplan.PromptAsset{{AssetID: "b007-task0-input-annex-q003", SHA256: Task0InputAnnexSHA},
		{AssetID: "b007-task0-input-annex-q009", SHA256: Task0PrototypeAnnexSHA}, {AssetID: "b007-task0-runtime-adapter-v2", SHA256: Task0RuntimeAdapterSHA}}
	m.SeatRoster = []testplan.Seat{}
	for _, seat := range orchestrator.BaselineSeats() {
		role := "PLAYER"
		if seat == orchestrator.SeatGM {
			role = "GM"
		}
		m.SeatRoster = append(m.SeatRoster, testplan.Seat{SeatID: string(seat), RoleID: role, ModelAssignmentID: "model-a"})
	}
	m.CanonicalSHA256 = ""
	f, err := testplan.BindRunManifest(m)
	if err != nil {
		t.Fatal("NON_CANON fixture binding failed", err)
	}
	return f
}

func TestTask0CoreManifestPinsContainingSourceAndRetainedAuthority(t *testing.T) {
	for _, scenario := range []string{"valid", "old_game_revision", "changed_game_tree", "another_aipt_revision", "missing_q003", "changed_q009", "wrong_adapter", "foreign_roster_seat", "changed_role", "higher_input_budget", "stale_typed_manifest", "changed_canonical", "changed_digest"} {
		t.Run(scenario, func(t *testing.T) {
			f := task0ManifestFixture(t)
			accepted := f.Manifest.Source.AIPT
			m := f.Manifest
			switch scenario {
			case "old_game_revision":
				m.Source.Game.Commit = strings.Repeat("1", 40)
			case "changed_game_tree":
				m.Source.Game.Tree = strings.Repeat("2", 40)
			case "another_aipt_revision":
				accepted.Commit = strings.Repeat("3", 40)
			case "missing_q003":
				m.PromptAssets = m.PromptAssets[1:]
			case "changed_q009":
				m.PromptAssets[1].SHA256 = strings.Repeat("4", 64)
			case "wrong_adapter":
				m.PromptAssets[2].SHA256 = strings.Repeat("5", 64)
			case "foreign_roster_seat":
				m.SeatRoster[1].SeatID = "ALL_PLAYERS"
			case "changed_role":
				m.SeatRoster[1].RoleID = "GM"
			case "higher_input_budget":
				m.Budget.MaxInputTokens++
			case "stale_typed_manifest":
				f.Manifest.RunID = "NON-CANON-stale-run"
			case "changed_canonical":
				f.Canonical = append(f.Canonical, []byte(`{}`)...)
			case "changed_digest":
				f.Digest[0] ^= 1
			}
			if scenario != "stale_typed_manifest" && scenario != "changed_canonical" && scenario != "changed_digest" {
				m.CanonicalSHA256 = ""
				var err error
				f, err = testplan.BindRunManifest(m)
				if err != nil {
					t.Fatal("NON_CANON malformed fixture", scenario, err)
				}
			}
			b, err := task0CoreBinding(f, accepted)
			if (err == nil) != (scenario == "valid") {
				t.Fatal("source-bound manifest outcome differs", scenario)
			}
			if err == nil && (b.SourcePackage != task0PrototypeSourceBinding || b.RuntimeAdapterInput.CanonicalSHA256 != Task0RuntimeAdapterCanonicalSHA) {
				t.Fatal("bound source/adapter identity differs")
			}
		})
	}
}
