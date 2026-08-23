// Package web provides the local-only AIPT dashboard host and its strict,
// read-only public contracts.
package web

const (
	// DashboardSchema is the exact schema marker for a dashboard snapshot.
	DashboardSchema = "aipt.web-dashboard/v1"

	StatusServing        = "SERVING"
	ReadinessNotAsserted = "NOT_ASSERTED"
	AuthorityPostgreSQL  = "POSTGRESQL"
	StatusNotImplemented = "NOT_IMPLEMENTED"
	StatusLibraryOnly    = "IMPLEMENTED_LIBRARY_ONLY"
)

// Dashboard is one immutable read model. It has exactly the six M0 panels;
// no panel is an authority or a command surface.
type Dashboard struct {
	Schema      string           `json:"schema"`
	Config      ConfigPanel      `json:"config"`
	Health      HealthPanel      `json:"health"`
	Queue       QueuePanel       `json:"queue"`
	Run         RunPanel         `json:"run"`
	StatusTable StatusTablePanel `json:"status_table"`
	Report      ReportPanel      `json:"report"`
}

// ConfigPanel is a credential-free projection of the already validated
// shared config service. It deliberately has no DSN or credential member.
type ConfigPanel struct {
	Schema            string `json:"schema"`
	Profile           string `json:"profile"`
	DatabaseIdentity  string `json:"database_identity"`
	DatabaseNamespace string `json:"database_namespace"`
	EvidenceNamespace string `json:"evidence_namespace"`
}

// HealthPanel reports only the facts known by the serving Web component. It
// never promotes process startup or HTTP serving to multi-stage readiness.
type HealthPanel struct {
	ServingStatus    string `json:"serving_status"`
	RuntimeReadiness string `json:"runtime_readiness"`
}

// QueuePanel is a truthful capability view. Queue authority is PostgreSQL,
// but B007 does not implement the queue backend.
type QueuePanel struct {
	BackendAuthority     string      `json:"backend_authority"`
	ImplementationStatus string      `json:"implementation_status"`
	Items                []QueueItem `json:"items"`
}

// QueueItem is intentionally uninhabited by the B007 provider. The Web
// schema requires Items to be empty.
type QueueItem struct{}

// RunPanel states that no run engine exists and therefore has no active run.
type RunPanel struct {
	ImplementationStatus string    `json:"implementation_status"`
	ActiveRun            *RunState `json:"active_run"`
}

// RunState is intentionally uninhabited by the B007 provider. The Web schema
// requires ActiveRun to be null.
type RunState struct{}

// StatusTablePanel states that no status/table backend exists.
type StatusTablePanel struct {
	ImplementationStatus string `json:"implementation_status"`
	Seats                []Seat `json:"seats"`
}

// Seat is intentionally uninhabited by the B007 provider. The Web schema
// requires Seats to be empty.
type Seat struct{}

// ReportPanel exposes capability truth only. It does not offer an export or
// generator endpoint.
type ReportPanel struct {
	RawCapture           string `json:"raw_capture"`
	UIExportAction       string `json:"ui_export_action"`
	AuditReadyGenerator  string `json:"audit_ready_generator"`
	AuditResultGenerator string `json:"audit_result_generator"`
	Signing              string `json:"signing"`
	Encryption           string `json:"encryption"`
	Chunking             string `json:"chunking"`
}
