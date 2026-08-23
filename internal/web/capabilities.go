package web

// Capabilities returns the four truthful backend capability panels for B007.
// The empty slices are deliberate JSON arrays, not missing data or synthetic
// rows. No database query, queue table, run engine, or report export occurs.
func Capabilities() (QueuePanel, RunPanel, StatusTablePanel, ReportPanel) {
	queue := QueuePanel{
		BackendAuthority:     AuthorityPostgreSQL,
		ImplementationStatus: StatusNotImplemented,
		Items:                make([]QueueItem, 0),
	}
	run := RunPanel{
		ImplementationStatus: StatusNotImplemented,
		ActiveRun:            nil,
	}
	statusTable := StatusTablePanel{
		ImplementationStatus: StatusNotImplemented,
		Seats:                make([]Seat, 0),
	}
	report := ReportPanel{
		RawCapture:           StatusLibraryOnly,
		UIExportAction:       StatusNotImplemented,
		AuditReadyGenerator:  StatusNotImplemented,
		AuditResultGenerator: StatusNotImplemented,
		Signing:              StatusNotImplemented,
		Encryption:           StatusNotImplemented,
		Chunking:             StatusNotImplemented,
	}
	return queue, run, statusTable, report
}
