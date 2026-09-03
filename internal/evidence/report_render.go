package evidence

import (
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"html"
	"strconv"
	"strings"
)

type ReportDerivatives struct {
	Markdown []byte
	CSV      []byte
	JUnit    []byte
	HTML     []byte
}

// RenderRunReport regenerates every human-readable view solely from the
// canonical report value. Views carry no independent authority.
func RenderRunReport(report RunReport) (ReportDerivatives, error) {
	normalized, err := NormalizeRunReport(report)
	if err != nil {
		return ReportDerivatives{}, err
	}
	markdown := renderReportMarkdown(normalized)
	csvBytes, err := renderReportCSV(normalized)
	if err != nil {
		return ReportDerivatives{}, err
	}
	junit, err := renderReportJUnit(normalized)
	if err != nil {
		return ReportDerivatives{}, err
	}
	htmlBytes := renderReportHTML(normalized)
	return ReportDerivatives{Markdown: markdown, CSV: csvBytes, JUnit: junit, HTML: htmlBytes}, nil
}

func renderReportMarkdown(report RunReport) []byte {
	var output strings.Builder
	fmt.Fprintf(&output, "# Run report `%s`\n\n", report.ReportID)
	fmt.Fprintf(&output, "- Lifecycle: `%s`\n", report.Lifecycle)
	fmt.Fprintf(&output, "- Revision: `%d`\n", report.Revision)
	fmt.Fprintf(&output, "- Run: `%s`\n", report.RunID)
	fmt.Fprintf(&output, "- Execution: `%s`\n", report.ExecutionStatus)
	fmt.Fprintf(&output, "- Source commit/tree: `%s` / `%s`\n", report.Source.Commit, report.Source.Tree)
	fmt.Fprintf(&output, "- Replay hash match: `%t`\n", report.Replay.HashMatch)
	fmt.Fprintf(&output, "- Auditor verdict claimed: `%t`\n", report.AuditorVerdictClaimed)
	fmt.Fprintf(&output, "- Qualification eligible: `%t`\n\n", report.QualificationEligible)
	output.WriteString("## Coverage\n\n")
	fmt.Fprintf(&output, "%d of %d declared items are covered.\n\n", report.Coverage.Covered, report.Coverage.Total)
	output.WriteString("## Gate eligibility facts\n\n")
	output.WriteString("| Gate | Eligible | Reason |\n|---|---:|---|\n")
	for _, fact := range report.GateEligibilityFacts {
		fmt.Fprintf(&output, "| `%s` | `%t` | `%s` |\n", fact.Gate, fact.Eligible, fact.ReasonCode)
	}
	output.WriteString("\n## Findings and anomalies\n\n")
	fmt.Fprintf(&output, "- Defect families: %d\n", len(report.DefectFamilyReferences))
	fmt.Fprintf(&output, "- Defect occurrences: %d\n", len(report.DefectOccurrenceReferences))
	fmt.Fprintf(&output, "- Anomalies: %d\n", len(report.AnomalyCodes))
	fmt.Fprintf(&output, "- Security findings: %d\n", len(report.SecurityFindings))
	fmt.Fprintf(&output, "- Visibility findings: %d\n", len(report.VisibilityFindings))
	return []byte(output.String())
}

func renderReportCSV(report RunReport) ([]byte, error) {
	var output bytes.Buffer
	writer := csv.NewWriter(&output)
	rows := [][]string{
		{"field", "value"},
		{"report_id", report.ReportID},
		{"revision", strconv.FormatInt(report.Revision, 10)},
		{"lifecycle", string(report.Lifecycle)},
		{"run_id", report.RunID},
		{"execution_status", report.ExecutionStatus},
		{"source_repository", report.Source.Repository},
		{"source_commit", report.Source.Commit},
		{"source_tree", report.Source.Tree},
		{"run_manifest_sha256", report.RunManifest.CanonicalSHA256},
		{"replay_hash_match", strconv.FormatBool(report.Replay.HashMatch)},
		{"coverage_total", strconv.FormatInt(report.Coverage.Total, 10)},
		{"coverage_covered", strconv.FormatInt(report.Coverage.Covered, 10)},
		{"defect_family_count", strconv.Itoa(len(report.DefectFamilyReferences))},
		{"defect_occurrence_count", strconv.Itoa(len(report.DefectOccurrenceReferences))},
		{"anomaly_count", strconv.Itoa(len(report.AnomalyCodes))},
		{"security_finding_count", strconv.Itoa(len(report.SecurityFindings))},
		{"visibility_finding_count", strconv.Itoa(len(report.VisibilityFindings))},
		{"auditor_verdict_claimed", strconv.FormatBool(report.AuditorVerdictClaimed)},
		{"qualification_eligible", strconv.FormatBool(report.QualificationEligible)},
	}
	for _, row := range rows {
		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}
	for _, fact := range report.GateEligibilityFacts {
		if err := writer.Write([]string{"gate." + fact.Gate, strconv.FormatBool(fact.Eligible) + ":" + fact.ReasonCode}); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func renderReportJUnit(report RunReport) ([]byte, error) {
	type failure struct {
		Message string `xml:"message,attr"`
	}
	type testCase struct {
		Name    string   `xml:"name,attr"`
		Failure *failure `xml:"failure,omitempty"`
	}
	type testSuite struct {
		XMLName  xml.Name   `xml:"testsuite"`
		Name     string     `xml:"name,attr"`
		Tests    int        `xml:"tests,attr"`
		Failures int        `xml:"failures,attr"`
		Cases    []testCase `xml:"testcase"`
	}
	cases := []testCase{{Name: "replay.hash_match"}}
	if !report.Replay.HashMatch {
		cases[0].Failure = &failure{Message: "replay hash mismatch"}
	}
	for _, fact := range report.GateEligibilityFacts {
		item := testCase{Name: "gate." + fact.Gate}
		if !fact.Eligible {
			item.Failure = &failure{Message: fact.ReasonCode}
		}
		cases = append(cases, item)
	}
	failures := 0
	for _, item := range cases {
		if item.Failure != nil {
			failures++
		}
	}
	encoded, err := xml.Marshal(testSuite{Name: report.ReportID, Tests: len(cases), Failures: failures, Cases: cases})
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), append(encoded, '\n')...), nil
}

func renderReportHTML(report RunReport) []byte {
	escape := html.EscapeString
	var output strings.Builder
	output.WriteString("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>AIPT run report</title></head><body>\n")
	fmt.Fprintf(&output, "<h1>Run report <code>%s</code></h1>\n", escape(report.ReportID))
	output.WriteString("<dl>")
	fmt.Fprintf(&output, "<dt>Lifecycle</dt><dd>%s</dd>", escape(string(report.Lifecycle)))
	fmt.Fprintf(&output, "<dt>Run</dt><dd>%s</dd>", escape(report.RunID))
	fmt.Fprintf(&output, "<dt>Execution</dt><dd>%s</dd>", escape(report.ExecutionStatus))
	fmt.Fprintf(&output, "<dt>Replay hash match</dt><dd>%t</dd>", report.Replay.HashMatch)
	fmt.Fprintf(&output, "<dt>Auditor verdict claimed</dt><dd>%t</dd>", report.AuditorVerdictClaimed)
	output.WriteString("</dl>\n<h2>Gate eligibility facts</h2>\n<table><thead><tr><th>Gate</th><th>Eligible</th><th>Reason</th></tr></thead><tbody>\n")
	for _, fact := range report.GateEligibilityFacts {
		fmt.Fprintf(&output, "<tr><td>%s</td><td>%t</td><td>%s</td></tr>\n", escape(fact.Gate), fact.Eligible, escape(fact.ReasonCode))
	}
	output.WriteString("</tbody></table>\n</body></html>\n")
	return []byte(output.String())
}
