package pilot

import (
	"github.com/zyc14588/AIPT/internal/modelgateway"
	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/testplan"
)

const task0SetupBindingSchema = "aipt.private.b007-fixed-setup-binding/v1"
const task0SetupControlSchema = "aipt.private.b007-fixed-setup-control/v1"

// Fixed code metadata includes the complete 789307-byte runtime manifest.
// JSON encodes byte slices as Base64; PREP embeds SETUP and Parent embeds PREP.
// Each envelope has its own finite bound. Control and model limits are separate.
const (
	task0SetupBindingMaxBytes       = 2 << 20
	task0PreparationBindingMaxBytes = 4 << 20
	task0ParentBindingMaxBytes      = 8 << 20
)

// SETUP receives execution identities, never PREP's source, evidence, key or
// database locators. Its compiled digest authenticates the complete object.
// Launch requests contain a role and fixed descriptor slots, not paths/argv.
type task0SetupBinding struct {
	Schema          string               `json:"schema"`
	Policy          string               `json:"policy"`
	AuthoritySHA    string               `json:"authority_sha256"`
	CA              task0SystemCABinding `json:"system_ca"`
	Manifest        []byte               `json:"run_manifest_bytes"`
	Dispatch        []byte               `json:"dispatch_binding_bytes"`
	Local           []byte               `json:"local_binding_bytes"`
	RuntimeManifest []byte               `json:"runtime_manifest_bytes"`
	RuntimePolicy   []byte               `json:"runtime_policy_bytes"`
	Roles           []task0SetupRole     `json:"roles"`
}

type task0SetupRole struct {
	Role           string `json:"role"`
	ProfileBinding string `json:"profile_binding"`
	ProgramSHA     string `json:"program_sha256"`
	ProgramBytes   int64  `json:"program_bytes"`
	ManifestSHA    string `json:"runtime_manifest_sha256"`
}

type acceptedTask0Setup struct {
	identity string
	binding  task0SetupBinding
	dispatch *acceptedTask0DispatchGrant
	local    *acceptedPilotLocalGrant
	policy   runtimeLaunchPolicy
	manifest RuntimeCodeManifest
	roles    map[string]task0SetupRole
}

func task0SetupRoleName(name string) bool {
	return name == "GAME" || name == "LOCAL" || name == string(orchestrator.SeatGM) || name == string(orchestrator.SeatPlayer1) ||
		name == string(orchestrator.SeatPlayer2) || name == string(orchestrator.SeatPlayer3) || name == string(orchestrator.SeatPlayer4)
}

func decodeTask0Setup(raw []byte, expectedSHA string) (*acceptedTask0Setup, error) {
	var b task0SetupBinding
	if !digest(expectedSHA) || inputSHA(raw) != expectedSHA || decodeFrozenJSON(raw, task0SetupBindingMaxBytes, &b) != nil ||
		b.Schema != task0SetupBindingSchema || b.Policy != task0SetupPolicy || b.AuthoritySHA != task0Q014AuthoritySHA || !task0SystemCABindingValid(b.CA) || len(b.Roles) != 7 {
		return nil, ErrRuntimeLaunch
	}
	f, err := testplan.DecodeRunManifest(b.Manifest)
	if err != nil || f.Manifest.RunID != task0DiagnosticRunID {
		return nil, ErrRuntimeLaunch
	}
	g, err := decodeTask0DispatchGrant(b.Dispatch, inputSHA(b.Dispatch), f)
	if err != nil {
		return nil, ErrRuntimeLaunch
	}
	l, err := decodeAcceptedPilotLocalGrant(b.Local, inputSHA(b.Local), g.binding.RuntimeManifestSHA, b.RuntimeManifest, b.RuntimePolicy)
	if err != nil || l.binding.FullIndependentReviewSHA256 != g.binding.FullReviewSHA || l.binding.ImmutableOnlineCIReceiptSHA256 != g.binding.OnlineCIReceiptSHA ||
		l.binding.AcceptedImplementationCommit != g.binding.Implementation.Commit || l.binding.Adapter.AdapterEntrypointSHA256 != task0ModelWorkerSHA {
		return nil, ErrRuntimeLaunch
	}
	m, err := decodeCodeManifest(b.RuntimeManifest, g.binding.RuntimeManifestSHA)
	if err != nil {
		return nil, ErrRuntimeLaunch
	}
	p, err := decodeRuntimeLaunchPolicy(b.RuntimePolicy, m)
	if err != nil || validatePilotLocalPolicy(l.binding, p, m) != nil {
		return nil, ErrRuntimeLaunch
	}
	a := &acceptedTask0Setup{expectedSHA, b, g, l, p, m, map[string]task0SetupRole{}}
	profiles := map[string]bool{}
	for _, role := range b.Roles {
		if !task0SetupRoleName(role.Role) || a.roles[role.Role].Role != "" || !digest(role.ProgramSHA) || !digest(role.ManifestSHA) || role.ProgramBytes < 64 || role.ProgramBytes > 4<<30 {
			return nil, ErrRuntimeLaunch
		}
		a.roles[role.Role] = role
		if role.Role == "GAME" {
			if role.ProfileBinding != "" {
				return nil, ErrRuntimeLaunch
			}
			continue
		}
		entry, ok := g.profiles[role.ProfileBinding]
		if !ok || profiles[role.ProfileBinding] {
			return nil, ErrRuntimeLaunch
		}
		profiles[role.ProfileBinding] = true
		if role.Role == "LOCAL" {
			if entry.Profile.BackendKind != modelgateway.BackendLocalLlamaCPP || !task0SameJSON(entry.Profile, l.binding.Profile) || !task0SameJSON(entry.Sampling, l.binding.Sampling) ||
				role.ProgramSHA != l.binding.Profile.LocalRuntimeIdentity.IsolationHelperSHA256 || role.ProgramSHA != l.binding.Local.IsolationExecutableSHA256 || role.ManifestSHA != g.binding.RuntimeManifestSHA {
				return nil, ErrRuntimeLaunch
			}
		} else if entry.Profile.BackendKind != modelgateway.BackendRemoteDeepSeek || role.Role != string(entry.Seat) {
			return nil, ErrRuntimeLaunch
		}
	}
	if len(profiles) != 6 {
		return nil, ErrRuntimeLaunch
	}
	return a, nil
}

// This binds SETUP's restricted role table to the already accepted PREP
// inputs; a second sealed binding cannot replace a helper or sampling profile.
func task0SetupMatchesPreparation(s *acceptedTask0Setup, a *acceptedTask0Preparation) bool {
	if s == nil || a == nil || !task0SameJSON(s.binding.Manifest, a.binding.Manifest) || !task0SameJSON(s.binding.Dispatch, a.binding.Dispatch) ||
		!task0SameJSON(s.binding.Local, a.binding.Local) || !task0SameJSON(s.binding.RuntimeManifest, a.binding.RuntimeManifest) || !task0SameJSON(s.binding.RuntimePolicy, a.binding.RuntimePolicy) {
		return false
	}
	game := s.roles["GAME"]
	if game.ProgramSHA != a.binding.Game.File.SHA256 || game.ProgramBytes != a.binding.Game.File.Bytes || game.ManifestSHA != a.binding.Game.ManifestSHA {
		return false
	}
	for _, helper := range a.binding.RemoteHelpers {
		entry, ok := a.dispatch.profiles[helper.ProfileBinding]
		role := s.roles[string(entry.Seat)]
		if !ok || role.ProfileBinding != helper.ProfileBinding || role.ProgramSHA != helper.File.SHA256 || role.ProgramBytes != helper.File.Bytes || role.ManifestSHA != helper.ManifestSHA {
			return false
		}
	}
	return true
}

type task0SetupFrame struct {
	Schema     string                 `json:"schema"`
	Operation  string                 `json:"operation"`
	BindingSHA string                 `json:"binding_sha256"`
	Generation string                 `json:"generation"`
	Nonce      string                 `json:"nonce"`
	Sequence   int                    `json:"sequence"`
	Role       string                 `json:"role"`
	Waited     bool                   `json:"direct_wait_completed"`
	ExitCode   int                    `json:"exit_code"`
	Joined     int                    `json:"joined_children"`
	Forbidden  []task0SetupFDIdentity `json:"forbidden_inputs"`
}

type task0SetupFDIdentity struct {
	Dev uint64 `json:"dev"`
	Ino uint64 `json:"ino"`
}

func task0SetupFrameValid(f task0SetupFrame, operation, binding, generation, nonce string, sequence int, role string) bool {
	return f.Schema == task0SetupControlSchema && f.Operation == operation && f.BindingSHA == binding && f.Generation == generation &&
		f.Nonce == nonce && digest(binding) && digest(generation) && digest(nonce) && f.Sequence == sequence && f.Role == role && sequence >= 0 && sequence <= 34 &&
		(role == "" || task0SetupRoleName(role))
}
