package pilot

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zyc14588/AIPT/internal/evidence"
	"github.com/zyc14588/AIPT/internal/protocol"
	"github.com/zyc14588/AIPT/internal/runcontrol"
	"github.com/zyc14588/AIPT/internal/storage/postgres"
	"github.com/zyc14588/AIPT/internal/testplan"
)

// NON_CANON metadata-only fixture. A held value here is not decrypted proof,
// production acceptance, controlled-real certification or a model invocation.
func task0PrivateReportFixture(t *testing.T) (*acceptedTask0DispatchGrant, postgres.RunRecord, evidence.PrivateAuditReadyVerification, BudgetTotals) {
	t.Helper()
	b, f := task0DispatchBindingFixture(t)
	raw, _ := json.Marshal(b)
	g, err := decodeTask0DispatchGrant(raw, inputSHA(raw), f)
	if err != nil {
		t.Fatal(err)
	}
	record := postgres.RunRecord{RunID: f.Manifest.RunID, ManifestID: f.Manifest.ManifestID, Classification: "DIAGNOSTIC", QualificationEligible: false, ManifestCanonical: f.Canonical, ManifestSHA256: f.Digest}
	source := evidence.SourceIdentity{Repository: task0EvidenceRepository, Commit: b.Implementation.Commit, Tree: b.Implementation.Tree}
	manifest := evidence.ArtifactIdentity{ID: record.ManifestID, Schema: testplan.RunManifestSchema, CanonicalSHA256: hex.EncodeToString(f.Digest[:])}
	canary := "NON_CANON_PRIVATE_CANARY_NOT_PUBLIC"
	ref := evidence.EvidenceReference{ID: canary, Path: "private/" + canary + ".json", SHA256: strings.Repeat("3", 64)}
	state, projection, tail := strings.Repeat("4", 64), strings.Repeat("5", 64), strings.Repeat("6", 64)
	rng := evidence.RNGEvidence{Used: false, Version: "NONE", SeedDisclosureStatus: "NOT_APPLICABLE"}
	replay := evidence.ReplayEvidence{Schema: evidence.ReplayEvidenceSchema, Version: evidence.ContractVersion, RunID: record.RunID,
		RunManifestSHA256: manifest.CanonicalSHA256, LedgerStreamID: "aipt.run-core:" + record.RunID, LedgerTailSequence: 6, LedgerTailHash: &tail,
		LiveFinalStateHash: state, ReplayedFinalStateHash: state, HashMatch: true, Implementation: evidence.ReplayImplementation{ID: canary, Version: "1", SHA256: strings.Repeat("7", 64)}, RNG: rng}
	closure := evidence.RunEvidenceClosure{Schema: evidence.RunClosureSchema, Version: evidence.ContractVersion, RunID: record.RunID, RunManifest: manifest, Source: source, StateAuthority: "POSTGRESQL_APPEND_ONLY_HASH_CHAIN",
		Ledger: evidence.LedgerIdentity{StreamID: replay.LedgerStreamID, EventCount: 6, TailSequence: 6, TailEventHash: &tail}, Projection: evidence.ProjectionEvidence{Schema: "aipt.synthetic-projection/v1", CanonicalSHA256: projection, FinalStateHash: state},
		RuleCitations: []evidence.RuleCitation{{RuleID: canary, SourceSHA256: strings.Repeat("8", 64)}}, RNG: rng, Replay: replay, CoverageReferences: []evidence.EvidenceReference{ref},
		DefectOccurrenceIDs: []string{}, AnomalyCodes: []string{canary}, GateEligibilityFacts: []evidence.GateEligibilityFact{{Gate: canary, Eligible: false, ReasonCode: canary}}, ModelExecutionReferences: []evidence.ModelExecutionReference{}}
	for i := int64(1); i <= 6; i++ {
		closure.ActionReceipts = append(closure.ActionReceipts, evidence.ActionReceiptEvidence{ActionID: canary + string(rune('A'+i)), Sequence: i, EventHash: tail, StateHash: state, ProjectionHash: projection, Evidence: ref})
	}
	closure, err = evidence.NormalizeRunEvidenceClosure(closure)
	if err != nil {
		t.Fatal(err)
	}
	r, err := evidence.NormalizeRunReport(evidence.RunReport{Schema: evidence.RunReportSchema, Version: evidence.ContractVersion, ReportID: canary, Revision: 1, Lifecycle: evidence.ReportProvisional,
		RunID: record.RunID, Source: source, RunManifest: manifest, ExecutionStatus: "COMPLETED", Coverage: evidence.CoverageSummary{Total: 5, Covered: 5, References: []evidence.EvidenceReference{ref}}, Replay: closure.Replay,
		DefectFamilyReferences: []string{canary}, DefectOccurrenceReferences: []string{canary}, AnomalyCodes: []string{canary}, SecurityFindings: []evidence.FindingReference{{FindingID: canary, EvidenceID: canary, Severity: "HIGH"}}, VisibilityFindings: []evidence.FindingReference{{FindingID: canary, EvidenceID: canary, Severity: "LOW"}},
		ModelExecution: evidence.ModelExecutionFacts{RemoteDeepSeekRealCalls: 10, LocalLlamaCPPRealCalls: 1, ProviderModelNetworkCalls: 10, ReferenceIDs: []string{canary}}, GateEligibilityFacts: closure.GateEligibilityFacts,
		EvidenceRoots: []evidence.EvidenceRootIdentity{{Kind: canary, SHA256: strings.Repeat("9", 64)}}, QualificationEligible: false})
	if err != nil {
		t.Fatal(err)
	}
	closureBody, _ := json.Marshal(closure)
	c, _ := protocol.CanonicalJSON(closureBody)
	held := evidence.PrivateAuditReadyVerification{Root: strings.Repeat("a", 64), Manifest: evidence.PrivateAuditManifest{Schema: evidence.PrivateAuditSchema, Version: evidence.ContractVersion, Stage: evidence.AuditReadyStage, NormalizationVersion: evidence.PrivateAuditNormalization,
		Source: source, RunID: record.RunID, RunManifest: manifest, Ledger: closure.Ledger, RawCaptureRoot: strings.Repeat("b", 64), PlaintextRoot: strings.Repeat("c", 64),
		Disclosure: evidence.Disclosure{Profile: evidence.DisclosurePrivateFull, ContainsUnpublishedContent: true, Encryption: evidence.Encryption{Status: evidence.EncryptionEncrypted, Scheme: evidence.PrivateAuditEncryption, KeyReference: "key-" + strings.Repeat("d", 32)}}}, Closure: closure, Report: r,
		LogicalAssets: map[string][]byte{evidence.RunClosureName: append([]byte(c), '\n'), "private/hidden-model-body.txt": []byte(canary)}}
	return g, record, held, BudgetTotals{RemoteAttempts: 10, LocalCalls: 1, InputTokens: 11 * 8192, OutputTokens: 11 * 1024, ReservedNanodollars: 1_000_000}
}

func TestTask0PrivateReportsPublicAllowlistAndDeterministicDerivatives(t *testing.T) {
	g, r, h, b := task0PrivateReportFixture(t)
	public, err := task0BuildPublicReport(g, r, h, b)
	if err != nil {
		t.Fatal(err)
	}
	if public.PrivateAuditRoot != h.Root || public.Report.QualificationEligible || public.Report.AuditorVerdictClaimed || public.Report.ExecutionStatus != "COMPLETED" || public.Report.Source.Repository != task0EvidenceRepository {
		t.Fatal("public binding changed")
	}
	if len(public.Report.SecurityFindings) != 1 || len(public.Report.VisibilityFindings) != 1 || len(public.Report.DefectOccurrenceReferences) != 1 || len(public.Report.AnomalyCodes) != 1 {
		t.Fatal("finding counts silently lost")
	}
	for _, format := range []string{"json", "md", "csv", "junit", "html"} {
		t.Run(format, func(t *testing.T) {
			a, err := task0ExportPublicReport(public, format)
			if err != nil {
				t.Fatal(err)
			}
			second, err := task0ExportPublicReport(public, format)
			if err != nil || !bytes.Equal(a.Data, second.Data) || a.SHA256 != inputSHA(a.Data) {
				t.Fatal("derivative is not canonical and deterministic")
			}
			for _, private := range []string{"NON_CANON_PRIVATE_CANARY_NOT_PUBLIC", "private/hidden-model-body.txt", h.Manifest.Disclosure.Encryption.KeyReference, "/home/", "root_seed_hex", "DEEPSEEK_API_KEY"} {
				if bytes.Contains(a.Data, []byte(private)) {
					t.Fatal("private field reached public derivative", format)
				}
			}
			if format == "html" && a.MediaType != "application/octet-stream" {
				t.Fatal("HTML active content served inline")
			}
		})
	}
	if _, err := task0ExportPublicReport(public, "private"); err != runcontrol.ErrInvalid {
		t.Fatal("unknown/private format accepted")
	}
}

func TestTask0PrivateReportsRejectsForeignBindingOrFalseCompletion(t *testing.T) {
	for _, attack := range []string{"record_run", "record_manifest", "record_digest", "record_bytes", "record_qual", "record_class", "private_source", "short_source", "private_run", "private_manifest", "private_report_source", "private_report_run", "private_report_qual", "private_schema", "plaintext_profile", "unencrypted", "incomplete", "false_verdict", "failed_replay", "foreign_stream", "missing_closure", "changed_closure", "false_coverage", "missing_receipt", "remote_count", "local_count", "input_count", "output_count", "cost_ceiling", "provider_count", "severity_text"} {
		t.Run(attack, func(t *testing.T) {
			g, r, h, b := task0PrivateReportFixture(t)
			switch attack {
			case "record_run":
				r.RunID += "-other"
			case "record_manifest":
				r.ManifestID += "-other"
			case "record_digest":
				r.ManifestSHA256[0] ^= 1
			case "record_bytes":
				r.ManifestCanonical = append(append([]byte(nil), r.ManifestCanonical...), ' ')
			case "record_qual":
				r.QualificationEligible = true
			case "record_class":
				r.Classification = "QUALIFICATION"
			case "private_source":
				h.Manifest.Source.Commit = strings.Repeat("e", 40)
			case "short_source":
				h.Manifest.Source.Repository = "zyc14588/AIPT"
			case "private_run":
				h.Manifest.RunID += "-other"
			case "private_manifest":
				h.Manifest.RunManifest.CanonicalSHA256 = strings.Repeat("e", 64)
			case "private_report_source":
				h.Report.Source.Tree = strings.Repeat("e", 40)
			case "private_report_run":
				h.Report.RunID += "-other"
			case "private_report_qual":
				h.Report.QualificationEligible = true
			case "private_schema":
				h.Manifest.Schema = "aipt.audit-ready/v1"
			case "plaintext_profile":
				h.Manifest.Disclosure.Profile = evidence.DisclosurePublic
			case "unencrypted":
				h.Manifest.Disclosure.Encryption.Status = evidence.EncryptionUnencrypted
			case "incomplete":
				h.Report.ExecutionStatus = "IN_PROGRESS"
			case "false_verdict":
				h.Report.AuditorVerdictClaimed = true
			case "failed_replay":
				h.Report.Replay.HashMatch = false
			case "foreign_stream":
				h.Closure.Ledger.StreamID += "-other"
			case "missing_closure":
				delete(h.LogicalAssets, evidence.RunClosureName)
			case "changed_closure":
				h.LogicalAssets[evidence.RunClosureName] = []byte("{}\n")
			case "false_coverage":
				h.Report.Coverage.Covered = 4
			case "missing_receipt":
				h.Closure.ActionReceipts = h.Closure.ActionReceipts[:5]
			case "remote_count":
				b.RemoteAttempts++
			case "local_count":
				b.LocalCalls = 0
			case "input_count":
				b.InputTokens--
			case "output_count":
				b.OutputTokens--
			case "cost_ceiling":
				b.ReservedNanodollars = MaxNanodollars + 1
			case "provider_count":
				h.Report.ModelExecution.ProviderModelNetworkCalls++
			case "severity_text":
				h.Report.SecurityFindings[0].Severity = "NON_CANON_PRIVATE_CANARY_NOT_PUBLIC"
			}
			if _, err := task0BuildPublicReport(g, r, h, b); err != runcontrol.ErrReportUnavailable {
				t.Fatal("unverified completion or disclosure accepted", attack, err)
			}
		})
	}
}

func TestTask0PrivateReportRootsRejectAliasesAndFollowHeldInodes(t *testing.T) {
	root := privateRoot(t)
	f, s, err := task0OpenPrivateReportRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = os.Mkdir(filepath.Join(root, "run"), 0700); err != nil {
		t.Fatal(err)
	}
	run, rs, err := task0OpenReportDirectoryAt(f, "run")
	if err != nil {
		t.Fatal(err)
	}
	defer run.Close()
	if err = os.Rename(root, root+"-retained"); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if !task0ReportDirectoryMatches(f, "run", rs) || !task0ReportDirectoryState(s) {
		t.Fatal("held root reopened substituted path")
	}
	for _, name := range []string{".", "..", "../run", "run/child", "run\\child", "missing"} {
		if a, _, err := task0OpenReportDirectoryAt(f, name); err == nil {
			a.Close()
			t.Fatal("unsafe directory selector accepted", name)
		}
	}
	if os.Symlink("run", filepath.Join(root+"-retained", "alias")) != nil {
		t.Fatal("fixture symlink failed")
	}
	if a, _, err := task0OpenReportDirectoryAt(f, "alias"); err == nil {
		a.Close()
		t.Fatal("directory alias followed")
	}
	if a, _, err := task0OpenPrivateReportRoot(filepath.Join(root+"-retained", "alias")); err == nil {
		a.Close()
		t.Fatal("root alias followed")
	}
	if task0SeparatePrivatePaths(root, root+"/keys") || task0SeparatePrivatePaths(root+"/reports", root) || task0SeparatePrivatePaths(root, root) {
		t.Fatal("bundle and key roots overlap")
	}
	if p, err := newTask0PrivateReports(context.Background(), &GlobalBudget{}, &acceptedTask0DispatchGrant{}, root, root+"-keys", "key-"+strings.Repeat("a", 32)); err == nil || p != nil {
		t.Fatal("unaccepted budget/grant reached report construction")
	}
}
