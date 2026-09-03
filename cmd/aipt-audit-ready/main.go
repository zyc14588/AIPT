// Command aipt-audit-ready is the deliberately offline B005 audit-bundle
// surface. It reads an explicit local request, verifies a local bare Git
// mirror, and never fetches source, calls a model, or changes authoritative
// run state.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/zyc14588/AIPT/internal/evidence"
)

const maxRequestBytes = int64(64 << 20)

type supplementalSpec struct {
	Path           string                         `json:"path"`
	MediaType      string                         `json:"media_type"`
	Classification evidence.ContentClassification `json:"classification"`
	ContentKind    evidence.ContentKind           `json:"content_kind"`
	DataBase64     string                         `json:"data_base64"`
}

type generateSpec struct {
	Destination         string                               `json:"destination"`
	RawCapture          string                               `json:"raw_capture"`
	MirrorPath          string                               `json:"mirror_path"`
	ExpectedRepository  string                               `json:"expected_repository"`
	RemoteName          string                               `json:"remote_name,omitempty"`
	Disclosure          evidence.Disclosure                  `json:"disclosure"`
	CoreClassifications evidence.CoreEvidenceClassifications `json:"core_evidence_classifications"`
	Closure             evidence.RunEvidenceClosure          `json:"closure"`
	DefectFamilies      []evidence.DefectFamily              `json:"defect_families"`
	DefectOccurrences   []evidence.DefectOccurrence          `json:"defect_occurrences"`
	Report              evidence.RunReport                   `json:"report"`
	Supplemental        []supplementalSpec                   `json:"supplemental"`
	ExportProfile       evidence.ExportProfile               `json:"export_profile"`
}

type commandResult struct {
	Result string                  `json:"result"`
	Stage  string                  `json:"stage"`
	Root   string                  `json:"root_sha256"`
	Source evidence.SourceIdentity `json:"source"`
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, stableErrorCode(err))
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, output io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("usage")
	}
	switch arguments[0] {
	case "generate":
		flags := flag.NewFlagSet("generate", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		specPath := flags.String("spec", "", "local generation request")
		if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *specPath == "" {
			return errors.New("usage")
		}
		spec, err := readGenerateSpec(*specPath)
		if err != nil {
			return err
		}
		if err := evidence.ValidateAuditReadyRepositoryIdentity(spec.ExpectedRepository); err != nil {
			return err
		}
		supplemental := make([]evidence.LogicalAssetInput, len(spec.Supplemental))
		for index, item := range spec.Supplemental {
			data, decodeErr := base64.StdEncoding.Strict().DecodeString(item.DataBase64)
			if decodeErr != nil || int64(len(data)) > spec.ExportProfile.MaxAssetBytes {
				return evidence.ErrAuditReadyInvalid
			}
			supplemental[index] = evidence.LogicalAssetInput{
				Path: item.Path, MediaType: item.MediaType, Classification: item.Classification,
				ContentKind: item.ContentKind, Data: data,
			}
		}
		verifier := evidence.GitMirrorVerifier{
			MirrorPath: spec.MirrorPath, ExpectedRepository: spec.ExpectedRepository, RemoteName: spec.RemoteName,
		}
		result, err := evidence.GenerateAuditReady(ctx, evidence.GenerateAuditReadyInput{
			Destination: spec.Destination, RawCapture: spec.RawCapture, SourceVerifier: verifier,
			Disclosure: spec.Disclosure, CoreClassifications: spec.CoreClassifications,
			Closure: spec.Closure, DefectFamilies: spec.DefectFamilies,
			DefectOccurrences: spec.DefectOccurrences, Report: spec.Report, Supplemental: supplemental,
			ExportProfile: spec.ExportProfile,
		})
		if err != nil {
			return err
		}
		return writeResult(output, result)
	case "verify":
		flags := flag.NewFlagSet("verify", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		bundle := flags.String("bundle", "", "AUDIT_READY directory")
		mirror := flags.String("mirror", "", "local bare Git mirror")
		repository := flags.String("repository", "", "expected repository identity")
		remote := flags.String("remote", "origin", "mirror remote name")
		if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *bundle == "" || *mirror == "" || *repository == "" {
			return errors.New("usage")
		}
		if err := evidence.ValidateAuditReadyRepositoryIdentity(*repository); err != nil {
			return err
		}
		result, err := evidence.VerifyAuditReady(ctx, *bundle, evidence.GitMirrorVerifier{
			MirrorPath: *mirror, ExpectedRepository: *repository, RemoteName: *remote,
		})
		if err != nil {
			return err
		}
		return writeResult(output, result)
	default:
		return errors.New("usage")
	}
}

func readGenerateSpec(path string) (generateSpec, error) {
	file, err := os.Open(path)
	if err != nil {
		return generateSpec{}, evidence.ErrAuditReadyInvalid
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxRequestBytes+1))
	if err != nil || int64(len(data)) > maxRequestBytes {
		return generateSpec{}, evidence.ErrAuditReadyInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var spec generateSpec
	if err := decoder.Decode(&spec); err != nil {
		return generateSpec{}, evidence.ErrAuditReadyInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return generateSpec{}, evidence.ErrAuditReadyInvalid
	}
	return spec, nil
}

func writeResult(output io.Writer, result evidence.AuditReadyVerification) error {
	if err := evidence.ValidateAuditReadyRepositoryIdentity(result.Manifest.Source.Repository); err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(true)
	return encoder.Encode(commandResult{Result: "PASS", Stage: evidence.AuditReadyStage, Root: result.Root, Source: result.Manifest.Source})
}

func stableErrorCode(err error) string {
	switch {
	case errors.Is(err, evidence.ErrEncryptionRequired):
		return evidence.ErrEncryptionRequired.Error()
	case errors.Is(err, evidence.ErrDisclosureViolation):
		return evidence.ErrDisclosureViolation.Error()
	case errors.Is(err, evidence.ErrSourceUnverified):
		return evidence.ErrSourceUnverified.Error()
	case errors.Is(err, evidence.ErrUnsafePath):
		return evidence.ErrUnsafePath.Error()
	case errors.Is(err, evidence.ErrTargetExists):
		return evidence.ErrTargetExists.Error()
	case errors.Is(err, evidence.ErrStreamChanged):
		return evidence.ErrStreamChanged.Error()
	case errors.Is(err, evidence.ErrChunkInvalid):
		return evidence.ErrChunkInvalid.Error()
	case errors.Is(err, evidence.ErrReplayMismatch):
		return evidence.ErrReplayMismatch.Error()
	case errors.Is(err, evidence.ErrDefectInvalid):
		return evidence.ErrDefectInvalid.Error()
	case errors.Is(err, evidence.ErrReportInvalid), errors.Is(err, evidence.ErrReportTransition):
		return evidence.ErrReportInvalid.Error()
	case errors.Is(err, evidence.ErrAuditReadyInvalid):
		return evidence.ErrAuditReadyInvalid.Error()
	default:
		return "AIPT_AUDIT_READY_COMMAND_FAILED"
	}
}
