package runcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/zyc14588/AIPT/internal/evidence"
	"github.com/zyc14588/AIPT/internal/storage/postgres"
	"github.com/zyc14588/AIPT/internal/testplan"
)

func heldFixture(t *testing.T) (evidence.AuditReadyVerification, postgres.RunRecord) {
	t.Helper()
	q := newTestQueue()
	record, err := q.EnqueueRun(context.Background(), definition(t, "run-a", false).Input)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := testplan.DecodeRunManifest(record.ManifestCanonical)
	source := evidence.SourceIdentity{Repository: f.Manifest.Source.AIPT.Repository, Commit: f.Manifest.Source.AIPT.Commit, Tree: f.Manifest.Source.AIPT.Tree}
	binding := evidence.ArtifactIdentity{ID: record.ManifestID, Schema: testplan.RunManifestSchema, CanonicalSHA256: hex.EncodeToString(record.ManifestSHA256[:])}
	held := evidence.AuditReadyVerification{Manifest: evidence.AuditReadyManifest{Source: source, Disclosure: evidence.Disclosure{Profile: evidence.DisclosurePrivateFull, ContainsUnpublishedContent: true, Encryption: evidence.Encryption{Status: evidence.EncryptionEncrypted}}}, Report: evidence.RunReport{RunID: record.RunID, RunManifest: binding, Source: source, QualificationEligible: false}, Closure: evidence.RunEvidenceClosure{RunID: record.RunID, RunManifest: binding, Source: source}, LogicalAssets: map[string][]byte{}}
	for format, path := range reportFormats {
		data := []byte("held public " + format)
		digest := sha256.Sum256(data)
		kind := evidence.ContentKindReportDerivative
		if format == "json" {
			kind = evidence.ContentKindContract
		}
		held.LogicalAssets[path] = data
		held.BundleIndex.LogicalAssets = append(held.BundleIndex.LogicalAssets, evidence.LogicalAsset{Path: path, Classification: evidence.ContentPublic, ContentKind: kind, Bytes: int64(len(data)), SHA256: hex.EncodeToString(digest[:])})
	}
	return held, record
}
func TestReportBindingAndPublicClassificationFailClosed(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-run", "wrong-manifest", "wrong-source", "private-json", "credential-json", "wrong-digest", "wrong-eligibility"} {
		t.Run(mode, func(t *testing.T) {
			held, record := heldFixture(t)
			switch mode {
			case "wrong-run":
				held.Report.RunID = "other-run"
			case "wrong-manifest":
				held.Closure.RunManifest.ID = "other-manifest"
			case "wrong-source":
				held.Report.Source.Commit = strings.Repeat("8", 40)
			case "wrong-digest":
				record.ManifestSHA256 = sha256.Sum256([]byte("other"))
			case "wrong-eligibility":
				held.Report.QualificationEligible = true
			case "private-json", "credential-json":
				for i := range held.BundleIndex.LogicalAssets {
					if held.BundleIndex.LogicalAssets[i].Path == evidence.RunReportName {
						held.BundleIndex.LogicalAssets[i].Classification = evidence.ContentLocalOnlySecret
						if mode == "credential-json" {
							held.BundleIndex.LogicalAssets[i].Classification = evidence.ContentCredentialSecret
						}
					}
				}
			}
			err := validateHeldReport(held, record)
			if (err == nil) != (mode == "valid") {
				t.Fatalf("binding validation %s: %v", mode, err)
			}
		})
	}
}
func TestExportUsesHeldBytesAndDeniesHiddenOrTamperedAssets(t *testing.T) {
	held, _ := heldFixture(t)
	for format := range reportFormats {
		download, err := exportHeldReport(held, format)
		if err != nil || string(download.Data) != "held public "+format {
			t.Fatalf("%s %+v %v", format, download, err)
		}
		if format == "html" && download.MediaType != "application/octet-stream" {
			t.Fatal("HTML allowed active rendering")
		}
	}
	for _, classification := range []evidence.ContentClassification{evidence.ContentUnreleasedRemote, evidence.ContentTableHiddenRemote, evidence.ContentLocalOnlySecret, evidence.ContentHumanPrivateData, evidence.ContentCredentialSecret} {
		private, _ := heldFixture(t)
		for i := range private.BundleIndex.LogicalAssets {
			if private.BundleIndex.LogicalAssets[i].Path == evidence.RunReportCSVName {
				private.BundleIndex.LogicalAssets[i].Classification = classification
			}
		}
		if _, err := exportHeldReport(private, "csv"); !errors.Is(err, ErrDisclosure) {
			t.Fatalf("private report exported: %s", classification)
		}
	}
	held.LogicalAssets[evidence.RunReportCSVName] = []byte("replaced while held")
	if _, err := exportHeldReport(held, "csv"); !errors.Is(err, ErrReportUnavailable) {
		t.Fatal("replaced bytes passed digest")
	}
	if _, err := exportHeldReport(held, "../../raw"); !errors.Is(err, ErrDisclosure) {
		t.Fatal("path format accepted")
	}
}
func TestReportDirectoryCannotEscapeRootAndNoOnlineFallback(t *testing.T) {
	provider, err := NewFileReports(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path, err := provider.BundleDirectory("run/../../secret")
	if err != nil || !strings.HasPrefix(path, provider.root+"/") || strings.Contains(strings.TrimPrefix(path, provider.root), "..") {
		t.Fatal("Run ID escaped report root")
	}
	held, record := heldFixture(t)
	_ = held
	if _, err := provider.Inspect(context.Background(), record); !errors.Is(err, ErrReportUnavailable) {
		t.Fatal("absent bundle obtained a report")
	}
}
