package pilot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/zyc14588/AIPT/internal/evidence"
	"github.com/zyc14588/AIPT/internal/protocol"
	"github.com/zyc14588/AIPT/internal/runcontrol"
	"github.com/zyc14588/AIPT/internal/runcore"
	"github.com/zyc14588/AIPT/internal/storage/postgres"
	"github.com/zyc14588/AIPT/internal/testplan"
)

const task0PrivateEvidenceAuthority = "57edcd5470a8be49f5089040df4165243a1de6e893299cf510241529c61e878d"
const task0EvidenceRepository = "https://github.com/zyc14588/AIPT"

// B006's Reports interface remains exact. Only the trusted B007 preparation
// path constructs this adapter, with the same accepted grant and budget as
// the table. No source verifier, key material or bundle selector is an API.
type task0PrivateReports struct {
	mu                  sync.RWMutex
	budget              *GlobalBudget
	grant               *acceptedTask0DispatchGrant
	root, keys          *os.File
	rootState, keyState syscall.Stat_t
	key                 *evidence.PrivateAuditKey
	closed              bool
}

var _ runcontrol.Reports = (*task0PrivateReports)(nil)

func newTask0PrivateReports(ctx context.Context, budget *GlobalBudget, grant *acceptedTask0DispatchGrant, rootPath, keyPath, keyReference string) (*task0PrivateReports, error) {
	if task0CheckBudgetTransport(ctx, budget, grant) != nil || !task0SeparatePrivatePaths(rootPath, keyPath) {
		return nil, runcontrol.ErrReportUnavailable
	}
	root, rs, err := task0OpenPrivateReportRoot(rootPath)
	if err != nil {
		return nil, runcontrol.ErrReportUnavailable
	}
	keys, ks, err := task0OpenPrivateReportRoot(keyPath)
	if err != nil {
		root.Close()
		return nil, runcontrol.ErrReportUnavailable
	}
	key, err := evidence.LoadPrivateAuditKeyAt(keys, keyReference)
	if err != nil {
		root.Close()
		keys.Close()
		return nil, runcontrol.ErrReportUnavailable
	}
	return &task0PrivateReports{budget: budget, grant: grant, root: root, keys: keys, rootState: rs, keyState: ks, key: key}, nil
}

func task0SeparatePrivatePaths(a, b string) bool {
	return filepath.IsAbs(a) && filepath.Clean(a) == a && filepath.IsAbs(b) && filepath.Clean(b) == b && a != "/" && b != "/" && a != b && !strings.HasPrefix(a, b+"/") && !strings.HasPrefix(b, a+"/")
}

func task0ReportDirectoryState(s syscall.Stat_t) bool {
	return s.Mode&syscall.S_IFMT == syscall.S_IFDIR && s.Mode&0777 == 0700 && s.Uid == uint32(os.Geteuid())
}

func task0SameReportDirectory(a, b syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && task0ReportDirectoryState(a) && task0ReportDirectoryState(b)
}

// Resolve the private root once, component by component with NOFOLLOW.
// Every later lookup is relative to the retained descriptor.
func task0OpenPrivateReportRoot(path string) (*os.File, syscall.Stat_t, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, syscall.Stat_t{}, runcontrol.ErrReportUnavailable
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, syscall.Stat_t{}, runcontrol.ErrReportUnavailable
	}
	for _, name := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, e := syscall.Openat(fd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if e != nil {
			return nil, syscall.Stat_t{}, runcontrol.ErrReportUnavailable
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), "held private Task0 report root")
	var state syscall.Stat_t
	if f == nil || syscall.Fstat(fd, &state) != nil || !task0ReportDirectoryState(state) {
		if f != nil {
			f.Close()
		} else {
			syscall.Close(fd)
		}
		return nil, syscall.Stat_t{}, runcontrol.ErrReportUnavailable
	}
	return f, state, nil
}

func task0OpenReportDirectoryAt(parent *os.File, name string) (*os.File, syscall.Stat_t, error) {
	if parent == nil || name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
		return nil, syscall.Stat_t{}, runcontrol.ErrReportUnavailable
	}
	fd, err := syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, syscall.Stat_t{}, runcontrol.ErrReportUnavailable
	}
	f := os.NewFile(uintptr(fd), "held private Task0 report directory")
	var s syscall.Stat_t
	if f == nil || syscall.Fstat(fd, &s) != nil || !task0ReportDirectoryState(s) {
		if f != nil {
			f.Close()
		} else {
			syscall.Close(fd)
		}
		return nil, syscall.Stat_t{}, runcontrol.ErrReportUnavailable
	}
	return f, s, nil
}

func task0ReportDirectoryMatches(parent *os.File, name string, held syscall.Stat_t) bool {
	f, s, err := task0OpenReportDirectoryAt(parent, name)
	if err != nil {
		return false
	}
	defer f.Close()
	return task0SameReportDirectory(s, held)
}

func task0PrivateReportRecord(grant *acceptedTask0DispatchGrant, record postgres.RunRecord) error {
	if grant == nil || !digest(grant.identity) || record.QualificationEligible || record.Classification != "DIAGNOSTIC" ||
		record.RunID != grant.manifest.Manifest.RunID || record.ManifestID != grant.manifest.Manifest.ManifestID ||
		record.ManifestSHA256 != grant.manifest.Digest || !bytes.Equal(record.ManifestCanonical, grant.manifest.Canonical) {
		return runcontrol.ErrReportUnavailable
	}
	if _, err := task0CoreBinding(grant.manifest, grant.binding.Implementation); err != nil {
		return runcontrol.ErrReportUnavailable
	}
	return nil
}

func (p *task0PrivateReports) verify(ctx context.Context, record postgres.RunRecord) (task0PublicReport, error) {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return task0PublicReport{}, runcontrol.ErrReportUnavailable
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed || p.root == nil || p.keys == nil || p.key == nil || p.budget == nil || p.budget.pool == nil || task0PrivateReportRecord(p.grant, record) != nil {
		return task0PublicReport{}, runcontrol.ErrReportUnavailable
	}
	var rs, ks syscall.Stat_t
	if syscall.Fstat(int(p.root.Fd()), &rs) != nil || syscall.Fstat(int(p.keys.Fd()), &ks) != nil ||
		!task0SameReportDirectory(p.rootState, rs) || !task0SameReportDirectory(p.keyState, ks) {
		return task0PublicReport{}, runcontrol.ErrReportUnavailable
	}
	name := inputSHA([]byte(record.RunID))
	runDir, runState, err := task0OpenReportDirectoryAt(p.root, name)
	if err != nil {
		return task0PublicReport{}, runcontrol.ErrReportUnavailable
	}
	defer runDir.Close()
	bundle, bundleState, err := task0OpenReportDirectoryAt(runDir, "audit-ready")
	if err != nil {
		return task0PublicReport{}, runcontrol.ErrReportUnavailable
	}
	defer bundle.Close()
	held, err := evidence.VerifyPrivateAuditReadyAt(ctx, bundle, p.key)
	if err != nil {
		return task0PublicReport{}, runcontrol.ErrReportUnavailable
	}
	// The trusted adapter never returns decrypted assets, even on failure.
	defer func() {
		for _, data := range held.LogicalAssets {
			clear(data)
		}
	}()
	totals, err := p.budget.Totals(ctx)
	if err != nil || !task0ReportDirectoryMatches(p.root, name, runState) || !task0ReportDirectoryMatches(runDir, "audit-ready", bundleState) {
		return task0PublicReport{}, runcontrol.ErrReportUnavailable
	}
	return task0BuildPublicReport(p.grant, record, held, totals)
}

func (p *task0PrivateReports) Inspect(ctx context.Context, record postgres.RunRecord) (runcontrol.ReportView, error) {
	public, err := p.verify(ctx, record)
	if err != nil {
		return runcontrol.ReportView{}, err
	}
	return runcontrol.ReportView{RunID: public.Report.RunID, ReportID: public.Report.ReportID, Root: public.PrivateAuditRoot,
		ExecutionStatus: public.Report.ExecutionStatus, QualificationEligible: false, Formats: []string{"csv", "html", "json", "junit", "md"}}, nil
}

func (p *task0PrivateReports) Export(ctx context.Context, record postgres.RunRecord, format string) (runcontrol.Download, error) {
	if format != "json" && format != "md" && format != "csv" && format != "junit" && format != "html" {
		return runcontrol.Download{}, runcontrol.ErrInvalid
	}
	public, err := p.verify(ctx, record)
	if err != nil {
		return runcontrol.Download{}, err
	}
	return task0ExportPublicReport(public, format)
}

func (p *task0PrivateReports) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	return errors.Join(p.key.Close(), p.root.Close(), p.keys.Close())
}

// JSON adds only this typed control envelope to the existing canonical report.
// Existing deterministic renderers consume the same sanitized Report field.
type task0PublicBudget struct {
	RemoteAttempts       int   `json:"remote_attempts"`
	LocalCalls           int   `json:"local_calls"`
	InputReservedTokens  int   `json:"input_reserved_tokens"`
	OutputReservedTokens int   `json:"output_reserved_tokens"`
	ReservedNanodollars  int64 `json:"reserved_nanodollars"`
}
type task0PublicReport struct {
	Schema                      string             `json:"schema"`
	AuthoritySHA                string             `json:"authority_sha256"`
	PrivateEvidenceAuthoritySHA string             `json:"private_evidence_authority_sha256"`
	PrivateAuditRoot            string             `json:"private_audit_ready_root"`
	GameCommit                  string             `json:"game_commit"`
	GameTree                    string             `json:"game_tree"`
	GamePackageSHA              string             `json:"game_package_sha256"`
	ProfileBindings             []string           `json:"profile_bindings"`
	Budget                      task0PublicBudget  `json:"budget"`
	Report                      evidence.RunReport `json:"report"`
}

func task0BuildPublicReport(grant *acceptedTask0DispatchGrant, record postgres.RunRecord, held evidence.PrivateAuditReadyVerification, totals BudgetTotals) (task0PublicReport, error) {
	fail := func() (task0PublicReport, error) { return task0PublicReport{}, runcontrol.ErrReportUnavailable }
	if task0PrivateReportRecord(grant, record) != nil || !digest(held.Root) || !digest(held.Manifest.RawCaptureRoot) || !digest(held.Manifest.PlaintextRoot) {
		return fail()
	}
	source := evidence.SourceIdentity{Repository: task0EvidenceRepository, Commit: grant.binding.Implementation.Commit, Tree: grant.binding.Implementation.Tree}
	binding := evidence.ArtifactIdentity{ID: record.ManifestID, Schema: testplan.RunManifestSchema, CanonicalSHA256: hex.EncodeToString(record.ManifestSHA256[:])}
	if held.Manifest.Schema != evidence.PrivateAuditSchema || held.Manifest.Stage != evidence.AuditReadyStage || held.Manifest.NormalizationVersion != evidence.PrivateAuditNormalization ||
		held.Manifest.Source != source || held.Manifest.RunID != record.RunID || held.Manifest.RunManifest != binding || held.Closure.RunID != record.RunID || held.Closure.RunManifest != binding ||
		held.Closure.Source != source || held.Report.Source != source || held.Report.RunID != record.RunID || held.Report.RunManifest != binding || held.Report.QualificationEligible ||
		held.Report.ExecutionStatus != "COMPLETED" || held.Report.AuditorVerdictClaimed || held.Manifest.Disclosure.Profile != evidence.DisclosurePrivateFull || !held.Manifest.Disclosure.ContainsUnpublishedContent ||
		held.Manifest.Disclosure.Encryption.Status != evidence.EncryptionEncrypted || held.Manifest.Disclosure.Encryption.Scheme != evidence.PrivateAuditEncryption {
		return fail()
	}
	privateReport, err := evidence.NormalizeRunReport(held.Report)
	closure, errClosure := evidence.NormalizeRunEvidenceClosure(held.Closure)
	if err != nil || errClosure != nil || !task0CanonicalValuesEqual(closure.Ledger, held.Manifest.Ledger) || !task0CanonicalValuesEqual(privateReport.Replay, closure.Replay) ||
		privateReport.Coverage.Total != 5 || privateReport.Coverage.Covered != 5 || len(closure.ActionReceipts) < 6 ||
		totals.RemoteAttempts != len(closure.ActionReceipts)+4 || totals.RemoteAttempts > MaxRemoteAttempts || totals.LocalCalls != 1 ||
		totals.InputTokens != (totals.RemoteAttempts+totals.LocalCalls)*8192 || totals.InputTokens > MaxInputTokens ||
		totals.OutputTokens != (totals.RemoteAttempts+totals.LocalCalls)*1024 || totals.OutputTokens > MaxOutputTokens ||
		totals.ReservedNanodollars < 0 || totals.ReservedNanodollars > MaxNanodollars ||
		privateReport.ModelExecution.RemoteDeepSeekRealCalls != int64(totals.RemoteAttempts) || privateReport.ModelExecution.LocalLlamaCPPRealCalls != 1 ||
		privateReport.ModelExecution.ProviderModelNetworkCalls != int64(totals.RemoteAttempts) {
		return fail()
	}
	closureBytes := held.LogicalAssets[evidence.RunClosureName]
	canonicalClosure, marshalErr := json.Marshal(closure)
	canonicalText, canonicalErr := protocol.CanonicalJSON(canonicalClosure)
	if len(closureBytes) == 0 || marshalErr != nil || canonicalErr != nil || !bytes.Equal(closureBytes, append([]byte(canonicalText), '\n')) {
		return fail()
	}
	// A fresh value is the public allowlist. No free-form ID, pathname,
	// reference, finding text, report revision or verdict is copied from private
	// content. Hash-only references and ordinal finding codes preserve counts.
	rng := evidence.RNGEvidence{Used: false, Version: "NONE", SeedDisclosureStatus: "NOT_APPLICABLE"}
	if closure.RNG.Used {
		if closure.RNG.Version != runcore.RNGVersionV1 || !digest(closure.RNG.SeedCommitment) {
			return fail()
		}
		rng = evidence.RNGEvidence{Used: true, Version: runcore.RNGVersionV1, SeedCommitment: closure.RNG.SeedCommitment, SeedDisclosureStatus: "COMMITTED_NOT_DISCLOSED"}
	}
	replay := evidence.ReplayEvidence{Schema: evidence.ReplayEvidenceSchema, Version: evidence.ContractVersion, RunID: record.RunID,
		RunManifestSHA256: binding.CanonicalSHA256, LedgerStreamID: "aipt.run-core:" + record.RunID, LedgerTailSequence: closure.Ledger.TailSequence,
		LedgerTailHash: closure.Ledger.TailEventHash, LiveFinalStateHash: closure.Replay.LiveFinalStateHash, ReplayedFinalStateHash: closure.Replay.ReplayedFinalStateHash,
		HashMatch: closure.Replay.HashMatch, Implementation: evidence.ReplayImplementation{ID: "AIPT-B007-TASK0-CORE-REPLAY", Version: "1", SHA256: closure.Replay.Implementation.SHA256}, RNG: rng}
	if closure.Ledger.StreamID != replay.LedgerStreamID || closure.Replay.LedgerStreamID != replay.LedgerStreamID {
		return fail()
	}
	report := evidence.RunReport{Schema: evidence.RunReportSchema, Version: evidence.ContractVersion, ReportID: "b007-public-" + inputSHA([]byte(record.RunID)), Revision: 1,
		Lifecycle: evidence.ReportProvisional, RunID: record.RunID, Source: source, RunManifest: binding, ExecutionStatus: "COMPLETED", Coverage: evidence.CoverageSummary{Total: 5, Covered: 5,
			References: []evidence.EvidenceReference{{ID: "B007-ENCRYPTED-CLOSURE", Path: "encrypted-private-closure.sha256", SHA256: inputSHA(closureBytes)}}}, Replay: replay,
		ModelExecution:        evidence.ModelExecutionFacts{RemoteDeepSeekRealCalls: int64(totals.RemoteAttempts), LocalLlamaCPPRealCalls: 1, ProviderModelNetworkCalls: int64(totals.RemoteAttempts), ReferenceIDs: []string{}},
		GateEligibilityFacts:  []evidence.GateEligibilityFact{{Gate: "B007_DIAGNOSTIC", Eligible: false, ReasonCode: "OWNER_DIAGNOSTIC_NONQUALIFICATION_ONLY"}},
		QualificationEligible: false, EvidenceRoots: []evidence.EvidenceRootIdentity{{Kind: "RAW_CAPTURE", SHA256: held.Manifest.RawCaptureRoot}, {Kind: "PRIVATE_AUDIT_READY", SHA256: held.Root}, {Kind: "PRIVATE_PLAINTEXT_NORMALIZATION", SHA256: held.Manifest.PlaintextRoot}}}
	for _, id := range privateReport.DefectFamilyReferences {
		report.DefectFamilyReferences = append(report.DefectFamilyReferences, "private-family-"+inputSHA([]byte(id)))
	}
	for _, id := range privateReport.DefectOccurrenceReferences {
		report.DefectOccurrenceReferences = append(report.DefectOccurrenceReferences, "private-occurrence-"+inputSHA([]byte(id)))
	}
	for _, id := range privateReport.AnomalyCodes {
		report.AnomalyCodes = append(report.AnomalyCodes, "B007_PRIVATE_ANOMALY_"+inputSHA([]byte(id)))
	}
	for _, pair := range []struct {
		input  []evidence.FindingReference
		output *[]evidence.FindingReference
	}{{privateReport.SecurityFindings, &report.SecurityFindings}, {privateReport.VisibilityFindings, &report.VisibilityFindings}} {
		for _, f := range pair.input {
			if f.Severity != "INFO" && f.Severity != "LOW" && f.Severity != "MEDIUM" && f.Severity != "HIGH" && f.Severity != "CRITICAL" {
				return fail()
			}
			*pair.output = append(*pair.output, evidence.FindingReference{FindingID: "private-finding-" + inputSHA([]byte(f.FindingID)), EvidenceID: "private-evidence-" + inputSHA([]byte(f.EvidenceID)), Severity: f.Severity})
		}
	}
	report, err = evidence.NormalizeRunReport(report)
	if err != nil {
		return fail()
	}
	profiles := []string{}
	for _, entry := range grant.binding.Profiles {
		profiles = append(profiles, entry.Profile.BindingID())
	}
	return task0PublicReport{Schema: "aipt.public.b007-task0-report/v1", AuthoritySHA: BudgetAuthority, PrivateEvidenceAuthoritySHA: task0PrivateEvidenceAuthority,
		PrivateAuditRoot: held.Root, GameCommit: task0PrototypeSourceBinding.Commit, GameTree: task0PrototypeSourceBinding.Tree, GamePackageSHA: task0PrototypeSourceBinding.CanonicalSHA256,
		ProfileBindings: profiles, Budget: task0PublicBudget{totals.RemoteAttempts, totals.LocalCalls, totals.InputTokens, totals.OutputTokens, totals.ReservedNanodollars}, Report: report}, nil
}

func task0CanonicalValuesEqual(a, b any) bool {
	ra, ea := json.Marshal(a)
	rb, eb := json.Marshal(b)
	if ea != nil || eb != nil {
		return false
	}
	ca, ea := protocol.CanonicalJSON(ra)
	cb, eb := protocol.CanonicalJSON(rb)
	return ea == nil && eb == nil && ca == cb
}

func task0ExportPublicReport(public task0PublicReport, format string) (runcontrol.Download, error) {
	var data []byte
	media := "application/octet-stream"
	name := "run-report." + format
	if format == "json" {
		raw, err := json.Marshal(public)
		if err != nil {
			return runcontrol.Download{}, runcontrol.ErrReportUnavailable
		}
		canonical, err := protocol.CanonicalJSON(raw)
		if err != nil {
			return runcontrol.Download{}, runcontrol.ErrReportUnavailable
		}
		data = append([]byte(canonical), '\n')
		media = "application/json"
	} else {
		views, err := evidence.RenderRunReport(public.Report)
		if err != nil {
			return runcontrol.Download{}, runcontrol.ErrReportUnavailable
		}
		switch format {
		case "md":
			data = views.Markdown
			media = "text/markdown; charset=utf-8"
		case "csv":
			data = views.CSV
			media = "text/csv; charset=utf-8"
		case "junit":
			data = views.JUnit
			media = "application/xml"
			name = "run-report.junit.xml"
		case "html":
			data = views.HTML
		default:
			return runcontrol.Download{}, runcontrol.ErrInvalid
		}
	}
	if len(data) == 0 || len(data) > runcontrol.MaxExportBytes {
		return runcontrol.Download{}, runcontrol.ErrReportUnavailable
	}
	h := sha256.Sum256(data)
	return runcontrol.Download{Filename: name, MediaType: media, SHA256: hex.EncodeToString(h[:]), Data: data}, nil
}
