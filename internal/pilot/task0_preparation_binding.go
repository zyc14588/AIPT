package pilot

import (
	"bytes"
	"debug/elf"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zyc14588/AIPT/internal/modelgateway"
	"github.com/zyc14588/AIPT/internal/testplan"
)

const task0Q011AuthoritySHA = "57edcd5470a8be49f5089040df4165243a1de6e893299cf510241529c61e878d"
const task0DiagnosticRunID = "B007D"

// These are private, externally accepted build inputs. The compiled binding
// digest covers the complete bytes, including all paths and subordinate
// digests; they are neither web/CLI selectors nor self-authenticating receipts.
// Byte slices preserve exact subordinate source bytes through JSON encoding.
type task0PreparationBinding struct {
	Schema              string                   `json:"schema"`
	AuthoritySHA        string                   `json:"authority_sha256"`
	PrivateAuthoritySHA string                   `json:"private_evidence_authority_sha256"`
	SystemCA            task0SystemCABinding     `json:"system_ca"`
	Setup               task0PreparationFile     `json:"fixed_setup_executable"`
	SetupBinding        []byte                   `json:"fixed_setup_binding_bytes"`
	Manifest            []byte                   `json:"run_manifest_bytes"`
	Dispatch            []byte                   `json:"dispatch_binding_bytes"`
	Local               []byte                   `json:"local_binding_bytes"`
	RuntimeManifest     []byte                   `json:"runtime_manifest_bytes"`
	RuntimePolicy       []byte                   `json:"runtime_policy_bytes"`
	Remote              []byte                   `json:"remote_binding_bytes"`
	PrototypeAnnex      []byte                   `json:"prototype_annex_bytes"`
	RetainedAnnex       []byte                   `json:"retained_annex_bytes"`
	SourceRoot          string                   `json:"private_game_source_root"`
	BudgetRoot          string                   `json:"private_budget_root"`
	EvidenceRoot        string                   `json:"private_evidence_root"`
	KeyRoot             string                   `json:"private_owner_key_root"`
	Database            task0PreparationFile     `json:"private_database_connection"`
	Pricing             Pricing                  `json:"pricing"`
	Game                task0PreparationHelper   `json:"game_helper"`
	RemoteHelpers       []task0PreparationHelper `json:"remote_helpers"`
}

type task0PreparationFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type task0PreparationHelper struct {
	File           task0PreparationFile `json:"file"`
	ProfileBinding string               `json:"profile_binding"`
	ManifestSHA    string               `json:"runtime_manifest_sha256"`
}

type acceptedTask0Preparation struct {
	identity string
	binding  task0PreparationBinding
	manifest testplan.FrozenManifest
	dispatch *acceptedTask0DispatchGrant
	local    *acceptedPilotLocalGrant
	setup    *acceptedTask0Setup
}

func task0PreparationPath(p string) bool {
	return len(p) > 1 && len(p) <= 4096 && filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.ContainsAny(p, "\x00\r\n")
}

func task0PreparationFileValid(f task0PreparationFile, max int64) bool {
	return task0PreparationPath(f.Path) && digest(f.SHA256) && f.Bytes > 0 && f.Bytes <= max
}

func decodeTask0Preparation(raw []byte, expectedSHA string) (*acceptedTask0Preparation, error) {
	var b task0PreparationBinding
	if !digest(expectedSHA) || inputSHA(raw) != expectedSHA || decodeFrozenJSON(raw, task0PreparationBindingMaxBytes, &b) != nil ||
		b.Schema != "aipt.private.b007-task0-preparation-binding/v2" || b.AuthoritySHA != LocalClosureAuthoritySHA || b.PrivateAuthoritySHA != task0Q011AuthoritySHA ||
		!task0SystemCABindingValid(b.SystemCA) || !task0PreparationFileValid(b.Setup, 128<<20) ||
		inputSHA(b.PrototypeAnnex) != Task0PrototypeAnnexSHA || inputSHA(b.RetainedAnnex) != Task0InputAnnexSHA ||
		!task0PreparationFileValid(b.Database, 16384) || !task0PreparationFileValid(b.Game.File, 4<<30) || b.Game.ProfileBinding != "" || !digest(b.Game.ManifestSHA) || len(b.RemoteHelpers) != 5 {
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
	entry, ok := g.profiles[l.binding.Profile.BindingID()]
	if !ok || entry.Profile.BackendKind != modelgateway.BackendLocalLlamaCPP || !task0SameJSON(entry.Profile, l.binding.Profile) || !task0SameJSON(entry.Sampling, l.binding.Sampling) {
		return nil, ErrRuntimeLaunch
	}
	var remote task0RemoteBinding
	if decodeFrozenJSON(b.Remote, 1<<20, &remote) != nil || remote.Schema != "aipt.private.b007-task0-accepted-remote-launch/v1" || remote.AuthoritySHA != BudgetAuthority ||
		remote.DispatchSHA != g.identity || remote.ManifestSHA != g.binding.ManifestSHA || remote.ReviewSHA != g.binding.FullReviewSHA || remote.CIReceiptSHA != g.binding.OnlineCIReceiptSHA ||
		remote.Source != g.binding.Implementation || len(remote.Roles) != 5 {
		return nil, ErrRuntimeLaunch
	}
	seen := map[string]bool{}
	paths := map[string]bool{b.Game.File.Path: true}
	for _, h := range b.RemoteHelpers {
		e, exists := g.profiles[h.ProfileBinding]
		if !exists || e.Profile.BackendKind != modelgateway.BackendRemoteDeepSeek || seen[h.ProfileBinding] || paths[h.File.Path] || !task0PreparationFileValid(h.File, 4<<30) || !digest(h.ManifestSHA) {
			return nil, ErrRuntimeLaunch
		}
		matched := 0
		for _, r := range remote.Roles {
			if r.ProfileBinding == h.ProfileBinding && r.HelperSHA == h.File.SHA256 && r.ManifestSHA == h.ManifestSHA {
				matched++
			}
		}
		if matched != 1 {
			return nil, ErrRuntimeLaunch
		}
		seen[h.ProfileBinding], paths[h.File.Path] = true, true
	}
	roots := []string{b.SourceRoot, b.BudgetRoot, b.EvidenceRoot, b.KeyRoot}
	for i, p := range roots {
		if !task0PreparationPath(p) {
			return nil, ErrRuntimeLaunch
		}
		for _, q := range roots[:i] {
			if !task0SeparatePrivatePaths(p, q) {
				return nil, ErrRuntimeLaunch
			}
		}
	}
	// Connection material never shares the prompt/source, evidence or key roots.
	for _, p := range roots {
		if !task0SeparatePrivatePaths(filepath.Dir(b.Database.Path), p) {
			return nil, ErrRuntimeLaunch
		}
	}
	a := &acceptedTask0Preparation{identity: expectedSHA, binding: b, manifest: f, dispatch: g, local: l}
	a.setup, err = decodeTask0Setup(b.SetupBinding, inputSHA(b.SetupBinding))
	if err != nil || !task0SetupMatchesPreparation(a.setup, a) || paths[b.Setup.Path] {
		return nil, ErrRuntimeLaunch
	}
	return a, nil
}

// Open a held owner-only directory and its exact regular leaf. No inherited
// source/cache FD or symlink can replace a fresh PREP namespace source open.
func task0OpenPreparationFile(spec task0PreparationFile, executable bool) (*os.File, error) {
	max := int64(1 << 20)
	if executable {
		max = 4 << 30
	}
	if !task0PreparationFileValid(spec, max) {
		return nil, ErrRuntimeLaunch
	}
	dir, ds, err := task0OpenPrivateReportRoot(filepath.Dir(spec.Path))
	if err != nil {
		return nil, ErrRuntimeLaunch
	}
	defer dir.Close()
	fd, err := syscall.Openat(int(dir.Fd()), filepath.Base(spec.Path), syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrRuntimeLaunch
	}
	f := os.NewFile(uintptr(fd), "held accepted private preparation source")
	keep := false
	defer func() {
		if !keep {
			f.Close()
		}
	}()
	var before, after syscall.Stat_t
	mode := uint32(0400)
	if executable {
		mode = 0500
	}
	if syscall.Fstat(fd, &before) != nil || before.Mode&syscall.S_IFMT != syscall.S_IFREG || before.Mode&07777 != mode || before.Uid != uint32(os.Geteuid()) || before.Nlink != 1 || before.Size != spec.Bytes || inputSHAFileMetadata(f) != spec.SHA256 ||
		syscall.Fstat(fd, &after) != nil || !task0SamePrivateRecordState(before, after) {
		return nil, ErrRuntimeLaunch
	}
	check, cs, err := task0OpenPrivateReportRoot(filepath.Dir(spec.Path))
	if err != nil {
		return nil, ErrRuntimeLaunch
	}
	defer check.Close()
	if !task0SameReportDirectory(ds, cs) {
		return nil, ErrRuntimeLaunch
	}
	var named syscall.Stat_t
	nfd, err := syscall.Openat(int(check.Fd()), filepath.Base(spec.Path), syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrRuntimeLaunch
	}
	nerr := syscall.Fstat(nfd, &named)
	syscall.Close(nfd)
	if nerr != nil || !task0SamePrivateRecordState(before, named) {
		return nil, ErrRuntimeLaunch
	}
	keep = true
	return f, nil
}

func task0HoldPreparationHelper(spec task0PreparationFile) (*os.File, error) {
	source, err := task0OpenPreparationFile(spec, true)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	held, err := sealedCodeSnapshot(source, spec.Bytes, true)
	if err != nil || held == nil {
		return nil, ErrRuntimeLaunch
	}
	if inputSHAFileMetadata(held) != spec.SHA256 || !staticPreparationFilePrefix(held) {
		held.Close()
		return nil, ErrRuntimeLaunch
	}
	return held, nil
}

// Capsule suffixes can exceed the static PREP binary limit. The prefix must
// still be a fixed static ELF; OpenEmbeddedCodeCapsule verifies its full suffix.
func staticPreparationFilePrefix(f *os.File) bool {
	if f == nil {
		return false
	}
	info, err := f.Stat()
	if err != nil || info.Size() < 64 || info.Size() > 4<<30 || !info.Mode().IsRegular() {
		return false
	}
	e, err := elf.NewFile(io.NewSectionReader(f, 0, info.Size()))
	if err != nil {
		return false
	}
	defer e.Close()
	if e.Class != elf.ELFCLASS64 || e.Data != elf.ELFDATA2LSB || e.Machine != elf.EM_X86_64 || (e.Type != elf.ET_EXEC && e.Type != elf.ET_DYN) {
		return false
	}
	for _, p := range e.Progs {
		if p.Type == elf.PT_INTERP {
			return false
		}
	}
	d, err := readNativeDynamic(e, info.Size())
	return err == nil && len(d.needed) == 0
}

func task0PreparationDatabase(spec task0PreparationFile) (*pgxpool.Config, error) {
	// The accepted parent supplies no PostgreSQL environment. Reject it here
	// too, before pgx's parser could load an ambient service/password file.
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "PG") {
			return nil, ErrRuntimeLaunch
		}
	}
	f, err := task0OpenPreparationFile(spec, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.NewSectionReader(f, 0, spec.Bytes))
	defer clear(raw)
	if err != nil || inputSHA(raw) != spec.SHA256 || !bytes.HasPrefix(raw, []byte("postgresql://")) || bytes.ContainsAny(raw, "\x00\r\n") {
		return nil, ErrRuntimeLaunch
	}
	u, err := url.Parse(string(raw))
	if err != nil || u.Scheme != "postgresql" || u.Hostname() != "127.0.0.1" || u.Port() != "15432" || u.Path != "/aipt_b007_diag" || u.User == nil || u.User.Username() == "" || u.Fragment != "" || u.RawQuery != "sslmode=disable" {
		return nil, ErrRuntimeLaunch
	}
	password, _ := u.User.Password()
	if strings.ContainsAny(u.User.Username()+password, "\x00\r\n") {
		return nil, ErrRuntimeLaunch
	}
	u.User = url.UserPassword(u.User.Username(), password)
	query := u.Query()
	query.Set("passfile", "/dev/null")
	u.RawQuery = query.Encode()
	cfg, err := pgxpool.ParseConfig(u.String())
	if err != nil || cfg.ConnConfig.Host != "127.0.0.1" || cfg.ConnConfig.Port != 15432 || cfg.ConnConfig.Database != "aipt_b007_diag" || cfg.ConnConfig.User != u.User.Username() || cfg.ConnConfig.Password != password ||
		cfg.ConnConfig.TLSConfig != nil || len(cfg.ConnConfig.Fallbacks) != 0 || len(cfg.ConnConfig.RuntimeParams) != 0 || cfg.ConnConfig.ValidateConnect != nil {
		return nil, ErrRuntimeLaunch
	}
	cfg.MinConns, cfg.MaxConns = 0, 4
	return cfg, nil
}
