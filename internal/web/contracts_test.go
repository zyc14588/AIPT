package web

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDashboardContractHasExactSixCredentialFreePanels(t *testing.T) {
	dashboard := Dashboard{
		Schema: DashboardSchema,
		Config: ConfigPanel{
			Schema:            "aipt.config/v1",
			Profile:           "development",
			DatabaseIdentity:  "aipt_development",
			DatabaseNamespace: "aipt_dev",
			EvidenceNamespace: "aipt.evidence.development",
		},
		Health:      HealthPanel{ServingStatus: StatusServing, RuntimeReadiness: ReadinessNotAsserted},
		Queue:       QueuePanel{BackendAuthority: AuthorityPostgreSQL, ImplementationStatus: StatusNotImplemented, Items: []QueueItem{}},
		Run:         RunPanel{ImplementationStatus: StatusNotImplemented, ActiveRun: nil},
		StatusTable: StatusTablePanel{ImplementationStatus: StatusNotImplemented, Seats: []Seat{}},
		Report: ReportPanel{
			RawCapture: StatusLibraryOnly, UIExportAction: StatusNotImplemented,
			AuditReadyGenerator: StatusNotImplemented, AuditResultGenerator: StatusNotImplemented,
			Signing: StatusNotImplemented, Encryption: StatusNotImplemented, Chunking: StatusNotImplemented,
		},
	}
	encoded, err := json.Marshal(dashboard)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &root); err != nil {
		t.Fatal(err)
	}
	if len(root) != 7 {
		t.Fatalf("dashboard root members = %d, want schema plus six panels", len(root))
	}
	for _, key := range []string{"config", "health", "queue", "run", "status_table", "report"} {
		if _, ok := root[key]; !ok {
			t.Fatalf("missing panel %q", key)
		}
	}
	lower := strings.ToLower(string(encoded))
	for _, forbidden := range []string{"dsn", "password", "credential", "secret", "token"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("credential-bearing token %q appeared in dashboard JSON", forbidden)
		}
	}
}
