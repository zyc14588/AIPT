package web

import (
	"encoding/json"
	"testing"
)

func TestCapabilitiesAreTruthfulNotImplementedViews(t *testing.T) {
	queue, run, statusTable, report := Capabilities()
	if queue.BackendAuthority != "POSTGRESQL" || queue.ImplementationStatus != "NOT_IMPLEMENTED" || queue.Items == nil || len(queue.Items) != 0 {
		t.Fatalf("queue capability drifted: %#v", queue)
	}
	if run.ImplementationStatus != "NOT_IMPLEMENTED" || run.ActiveRun != nil {
		t.Fatalf("run capability drifted: %#v", run)
	}
	if statusTable.ImplementationStatus != "NOT_IMPLEMENTED" || statusTable.Seats == nil || len(statusTable.Seats) != 0 {
		t.Fatalf("status/table capability drifted: %#v", statusTable)
	}
	if report.RawCapture != "IMPLEMENTED_LIBRARY_ONLY" {
		t.Fatalf("RAW_CAPTURE capability = %q", report.RawCapture)
	}
	for name, value := range map[string]string{
		"UI_EXPORT_ACTION":       report.UIExportAction,
		"AUDIT_READY_GENERATOR":  report.AuditReadyGenerator,
		"AUDIT_RESULT_GENERATOR": report.AuditResultGenerator,
		"SIGNING":                report.Signing,
		"ENCRYPTION":             report.Encryption,
		"CHUNKING":               report.Chunking,
	} {
		if value != "NOT_IMPLEMENTED" {
			t.Errorf("%s = %q, want NOT_IMPLEMENTED", name, value)
		}
	}
}

func TestCapabilitiesEncodeEmptyCollectionsAndNullRun(t *testing.T) {
	queue, run, statusTable, report := Capabilities()
	encoded, err := json.Marshal(struct {
		Queue       QueuePanel       `json:"queue"`
		Run         RunPanel         `json:"run"`
		StatusTable StatusTablePanel `json:"status_table"`
		Report      ReportPanel      `json:"report"`
	}{queue, run, statusTable, report})
	if err != nil {
		t.Fatal(err)
	}
	const expected = `{"queue":{"backend_authority":"POSTGRESQL","implementation_status":"NOT_IMPLEMENTED","items":[]},"run":{"implementation_status":"NOT_IMPLEMENTED","active_run":null},"status_table":{"implementation_status":"NOT_IMPLEMENTED","seats":[]},"report":{"raw_capture":"IMPLEMENTED_LIBRARY_ONLY","ui_export_action":"NOT_IMPLEMENTED","audit_ready_generator":"NOT_IMPLEMENTED","audit_result_generator":"NOT_IMPLEMENTED","signing":"NOT_IMPLEMENTED","encryption":"NOT_IMPLEMENTED","chunking":"NOT_IMPLEMENTED"}}`
	if string(encoded) != expected {
		t.Fatalf("capability JSON drifted:\n got %s\nwant %s", encoded, expected)
	}
}
