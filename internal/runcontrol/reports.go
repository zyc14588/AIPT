package runcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"

	"github.com/zyc14588/AIPT/internal/evidence"
	"github.com/zyc14588/AIPT/internal/storage/postgres"
	"github.com/zyc14588/AIPT/internal/testplan"
)

const reportRepository = "zyc14588/AIPT"

var reportFormats = map[string]string{"json": evidence.RunReportName, "md": evidence.RunReportMarkdownName, "csv": evidence.RunReportCSVName, "junit": evidence.RunReportJUnitName, "html": evidence.RunReportHTMLName}

// FileReports uses the built-in B005 online verifier with a fixed repository.
// No public constructor accepts a verifier, mirror, proof or mutable path map.
// The filesystem path is server-owned and never returned to Web/RPC clients.
type FileReports struct{ root string }

func NewFileReports(root string) (*FileReports, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
		return nil, ErrInvalid
	}
	return &FileReports{root: root}, nil
}

// BundleDirectory hashes identity rather than joining a Run ID (B001 permits
// slash and '..' within identity). A Run ID cannot escape this private root.
func (p *FileReports) BundleDirectory(runID string) (string, error) {
	if !identityPattern.MatchString(runID) {
		return "", ErrInvalid
	}
	digest := sha256.Sum256([]byte(runID))
	return filepath.Join(p.root, hex.EncodeToString(digest[:]), "audit-ready"), nil
}
func (p *FileReports) verify(ctx context.Context, record postgres.RunRecord) (evidence.AuditReadyVerification, error) {
	directory, err := p.BundleDirectory(record.RunID)
	if err != nil {
		return evidence.AuditReadyVerification{}, err
	}
	held, err := evidence.VerifyAuditReadyForRepository(ctx, directory, reportRepository)
	if err != nil {
		return evidence.AuditReadyVerification{}, ErrReportUnavailable
	}
	if err := validateHeldReport(held, record); err != nil {
		return evidence.AuditReadyVerification{}, err
	}
	return held, nil
}

func validateHeldReport(held evidence.AuditReadyVerification, record postgres.RunRecord) error {
	manifest, err := testplan.DecodeRunManifest(record.ManifestCanonical)
	if err != nil || manifest.Digest != record.ManifestSHA256 || manifest.Manifest.RunID != record.RunID || manifest.Manifest.ManifestID != record.ManifestID {
		return ErrReportUnavailable
	}
	m := manifest.Manifest
	source := evidence.SourceIdentity{Repository: m.Source.AIPT.Repository, Commit: m.Source.AIPT.Commit, Tree: m.Source.AIPT.Tree}
	binding := evidence.ArtifactIdentity{ID: record.ManifestID, Schema: testplan.RunManifestSchema, CanonicalSHA256: hex.EncodeToString(record.ManifestSHA256[:])}
	if held.Report.RunID != record.RunID || held.Closure.RunID != record.RunID || held.Report.RunManifest != binding || held.Closure.RunManifest != binding || held.Report.Source != source || held.Closure.Source != source || held.Manifest.Source != source || held.Report.QualificationEligible != record.QualificationEligible {
		return ErrReportUnavailable
	}
	if _, exists := publicReportAssets(held)["json"]; !exists {
		return ErrDisclosure
	}
	return nil
}

func publicReportAssets(held evidence.AuditReadyVerification) map[string]evidence.LogicalAsset {
	result := map[string]evidence.LogicalAsset{}
	for format, path := range reportFormats {
		for _, asset := range held.BundleIndex.LogicalAssets {
			if asset.Path == path && asset.Classification == evidence.ContentPublic && ((format == "json" && asset.ContentKind == evidence.ContentKindContract) || (format != "json" && asset.ContentKind == evidence.ContentKindReportDerivative)) && asset.Bytes <= MaxExportBytes {
				result[format] = asset
			}
		}
	}
	return result
}
func heldReportView(held evidence.AuditReadyVerification) ReportView {
	formats := []string{}
	for format := range publicReportAssets(held) {
		formats = append(formats, format)
	}
	sort.Strings(formats)
	return ReportView{RunID: held.Report.RunID, ReportID: held.Report.ReportID, Root: held.Root, ExecutionStatus: held.Report.ExecutionStatus, QualificationEligible: held.Report.QualificationEligible, Formats: formats}
}
func (p *FileReports) Inspect(ctx context.Context, record postgres.RunRecord) (ReportView, error) {
	held, err := p.verify(ctx, record)
	if err != nil {
		return ReportView{}, err
	}
	return heldReportView(held), nil
}
func (p *FileReports) Export(ctx context.Context, record postgres.RunRecord, format string) (Download, error) {
	if _, ok := reportFormats[format]; !ok {
		return Download{}, ErrInvalid
	}
	held, err := p.verify(ctx, record)
	if err != nil {
		return Download{}, err
	}
	return exportHeldReport(held, format)
}

// Export only the bytes already held by this exact verification. Never reopen
// an asset pathname after proof verification (including a chunked asset).
func exportHeldReport(held evidence.AuditReadyVerification, format string) (Download, error) {
	asset, exists := publicReportAssets(held)[format]
	if !exists {
		return Download{}, ErrDisclosure
	}
	data, exists := held.LogicalAssets[asset.Path]
	if !exists || int64(len(data)) != asset.Bytes || len(data) > MaxExportBytes {
		return Download{}, ErrReportUnavailable
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != asset.SHA256 {
		return Download{}, ErrReportUnavailable
	}
	media := "application/octet-stream"
	switch format {
	case "json":
		media = "application/json"
	case "md":
		media = "text/markdown; charset=utf-8"
	case "csv":
		media = "text/csv; charset=utf-8"
	case "junit":
		media = "application/xml"
	}
	return Download{Filename: asset.Path, MediaType: media, SHA256: asset.SHA256, Data: append([]byte(nil), data...)}, nil
}
