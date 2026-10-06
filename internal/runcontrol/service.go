package runcontrol

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/zyc14588/AIPT/internal/storage/postgres"
	"github.com/zyc14588/AIPT/internal/testplan"
)

type Options struct {
	Queue         Queue
	Reader        Reader
	Definitions   []Definition
	Executor      Executor
	Reports       Reports
	Lifetime      context.Context
	Capabilities  postgres.CapabilitySet
	HolderID      string
	LeaseDuration time.Duration
}

type registration struct {
	definition Definition
	frozen     testplan.FrozenManifest
}
type Service struct {
	queue          Queue
	reader         Reader
	registrations  map[string]registration
	byRun          map[string]string
	executor       Executor
	reports        Reports
	lifetime       context.Context
	cancelLifetime context.CancelFunc
	capabilities   postgres.CapabilitySet
	holderID       string
	leaseDuration  time.Duration
	mu             sync.Mutex
	active         *activeRun
	lastError      *string
	stopped        bool
}

type activeRun struct {
	runID  string
	cancel context.CancelFunc
	done   chan struct{}
}

func New(options Options) (*Service, error) {
	if options.Queue == nil || options.Reader == nil || options.Lifetime == nil || !identityPattern.MatchString(options.HolderID) || options.LeaseDuration < 3*time.Second || options.LeaseDuration > 5*time.Minute || len(options.Definitions) > 64 {
		return nil, ErrInvalid
	}
	lifetime, cancel := context.WithCancel(options.Lifetime)
	service := &Service{queue: options.Queue, reader: options.Reader, executor: options.Executor, reports: options.Reports, lifetime: lifetime, cancelLifetime: cancel, holderID: options.HolderID, leaseDuration: options.LeaseDuration, registrations: map[string]registration{}, byRun: map[string]string{}, capabilities: copyCapabilities(options.Capabilities)}
	registrations, byRun, err := checkedRegistrations(options.Definitions)
	if err != nil {
		cancel()
		return nil, err
	}
	service.registrations, service.byRun = registrations, byRun
	return service, nil
}

func copyCapabilities(c postgres.CapabilitySet) postgres.CapabilitySet {
	return postgres.CapabilitySet{ResourceIDs: append([]string(nil), c.ResourceIDs...), ModelIDs: append([]string(nil), c.ModelIDs...), CertificationIDs: append([]string(nil), c.CertificationIDs...), Labels: append([]string(nil), c.Labels...)}
}

func (s *Service) available() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.stopped && s.lifetime.Err() == nil
}

func (s *Service) Snapshot(ctx context.Context, limit int) (Snapshot, error) {
	if !s.available() {
		return Snapshot{}, ErrUnavailable
	}
	projection, err := s.reader.Snapshot(ctx, limit)
	if err != nil {
		return Snapshot{}, err
	}
	result := Snapshot{Schema: Schema, QueueAuthority: "POSTGRESQL_B001_QUEUESTORE", GameplayAuthority: "B002_APPEND_ONLY_POSTGRESQL_LEDGER", Paused: projection.Paused, Truncated: projection.Truncated, Items: []RunView{}, Registrations: []Registration{}, ExecutorConfigured: s.executor != nil, QualificationExecutionAuthorized: false}
	for _, item := range projection.Records {
		result.Items = append(result.Items, publicRun(item))
	}
	for _, item := range s.registrations {
		m := item.frozen.Manifest
		result.Registrations = append(result.Registrations, Registration{ID: item.definition.ID, RunID: m.RunID, ManifestID: m.ManifestID, ManifestSHA256: hex.EncodeToString(item.frozen.Digest[:]), Classification: m.Classification})
	}
	sort.Slice(result.Registrations, func(i, j int) bool { return result.Registrations[i].ID < result.Registrations[j].ID })
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active != nil {
		id := s.active.runID
		result.WorkerRunID = &id
	}
	if s.lastError != nil {
		code := *s.lastError
		result.WorkerLastError = &code
	}
	return result, nil
}

func (s *Service) Enqueue(ctx context.Context, id string) (RunView, error) {
	if !s.available() {
		return RunView{}, ErrUnavailable
	}
	item, exists := s.registrations[id]
	if !exists {
		return RunView{}, ErrNotFound
	}
	if item.frozen.Manifest.Classification != "DIAGNOSTIC" || item.frozen.Manifest.QualificationEligible {
		return RunView{}, ErrNotAuthorized
	}
	input := item.definition.Input
	input.ManifestBytes = append([]byte(nil), input.ManifestBytes...)
	record, err := s.queue.EnqueueRun(ctx, input)
	if err != nil {
		return RunView{}, err
	}
	return publicRun(record), nil
}

func (s *Service) Run(ctx context.Context, id string) (RunDetail, error) {
	if !s.available() {
		return RunDetail{}, ErrUnavailable
	}
	if !identityPattern.MatchString(id) {
		return RunDetail{}, ErrInvalid
	}
	record, err := s.queue.GetRun(ctx, id)
	if err != nil {
		return RunDetail{}, err
	}
	frozen, err := testplan.DecodeRunManifest(record.ManifestCanonical)
	if err != nil || frozen.Digest != record.ManifestSHA256 || frozen.Manifest.RunID != record.RunID || frozen.Manifest.ManifestID != record.ManifestID {
		return RunDetail{}, ErrUnavailable
	}
	attempts, err := s.queue.ReadAttempts(ctx, id)
	if err != nil {
		return RunDetail{}, err
	}
	result := RunDetail{Run: publicRun(record), Seats: []SeatView{}, Attempts: []AttemptView{}}
	for _, seat := range frozen.Manifest.SeatRoster {
		result.Seats = append(result.Seats, SeatView{SeatID: seat.SeatID, RoleID: seat.RoleID, ModelAssignmentID: seat.ModelAssignmentID, AssignmentStatus: "ASSIGNED"})
	}
	for _, attempt := range attempts {
		var digest *string
		if attempt.EvidenceSHA256 != nil {
			value := hex.EncodeToString(attempt.EvidenceSHA256[:])
			digest = &value
		}
		result.Attempts = append(result.Attempts, AttemptView{Number: attempt.AttemptNumber, Kind: attempt.Kind, Outcome: attempt.Outcome, EvidenceSHA256: digest, RecordedAt: attempt.RecordedAt})
	}
	return result, nil
}

func (s *Service) Inspect(ctx context.Context, id string) (ReportView, error) {
	if !s.available() {
		return ReportView{}, ErrUnavailable
	}
	if !identityPattern.MatchString(id) {
		return ReportView{}, ErrInvalid
	}
	if s.reports == nil {
		return ReportView{}, ErrReportUnavailable
	}
	record, err := s.queue.GetRun(ctx, id)
	if err != nil {
		return ReportView{}, err
	}
	return s.reports.Inspect(ctx, record)
}

func (s *Service) Export(ctx context.Context, id, format string) (Download, error) {
	if !s.available() {
		return Download{}, ErrUnavailable
	}
	if !identityPattern.MatchString(id) {
		return Download{}, ErrInvalid
	}
	if _, ok := reportFormats[format]; !ok {
		return Download{}, ErrInvalid
	}
	if s.reports == nil {
		return Download{}, ErrReportUnavailable
	}
	record, err := s.queue.GetRun(ctx, id)
	if err != nil {
		return Download{}, err
	}
	download, err := s.reports.Export(ctx, record, format)
	if err != nil {
		return Download{}, err
	}
	if len(download.Data) > MaxExportBytes {
		return Download{}, ErrReportUnavailable
	}
	return download, nil
}

// Invoke is the single method implementation used by HTTP and stdio RPC.
func (s *Service) Invoke(ctx context.Context, method string, params json.RawMessage) (any, error) {
	if !s.available() {
		return nil, ErrUnavailable
	}
	switch method {
	case "aipt.v1.queue.list":
		var p struct {
			Limit int `json:"limit"`
		}
		if err := DecodeObject(params, &p, "limit"); err != nil {
			return nil, err
		}
		return s.Snapshot(ctx, p.Limit)
	case "aipt.v1.queue.enqueue":
		var p struct {
			ID string `json:"registration_id"`
		}
		if err := DecodeObject(params, &p, "registration_id"); err != nil {
			return nil, err
		}
		return s.Enqueue(ctx, p.ID)
	case "aipt.v1.queue.pause":
		var p struct {
			Paused *bool `json:"paused"`
		}
		if err := DecodeObject(params, &p, "paused"); err != nil || p.Paused == nil {
			return nil, ErrInvalid
		}
		if err := s.queue.SetQueuePaused(ctx, *p.Paused, "B006_OPERATOR_QUEUE_ONLY"); err != nil {
			return nil, err
		}
		return struct {
			Paused bool `json:"paused"`
		}{*p.Paused}, nil
	case "aipt.v1.queue.cancel":
		var p struct {
			ID string `json:"run_id"`
		}
		if err := DecodeObject(params, &p, "run_id"); err != nil || !identityPattern.MatchString(p.ID) {
			return nil, ErrInvalid
		}
		if err := s.queue.CancelQueuedRun(ctx, p.ID, "B006_OPERATOR_QUEUED_CANCEL"); err != nil {
			return nil, err
		}
		return struct {
			RunID string `json:"run_id"`
		}{p.ID}, nil
	case "aipt.v1.queue.recover":
		if err := DecodeObject(params, &struct{}{}); err != nil {
			return nil, err
		}
		ids, err := s.queue.RecoverExpiredLeases(ctx)
		if err != nil {
			return nil, err
		}
		if ids == nil {
			ids = []string{}
		}
		return struct {
			RunIDs []string `json:"run_ids"`
		}{ids}, nil
	case "aipt.v1.run.next":
		if err := DecodeObject(params, &struct{}{}); err != nil {
			return nil, err
		}
		return s.RunNext(ctx)
	case "aipt.v1.run.get":
		var p struct {
			ID string `json:"run_id"`
		}
		if err := DecodeObject(params, &p, "run_id"); err != nil {
			return nil, err
		}
		return s.Run(ctx, p.ID)
	case "aipt.v1.report.inspect":
		var p struct {
			ID string `json:"run_id"`
		}
		if err := DecodeObject(params, &p, "run_id"); err != nil {
			return nil, err
		}
		return s.Inspect(ctx, p.ID)
	case "aipt.v1.report.export":
		var p struct {
			ID     string `json:"run_id"`
			Format string `json:"format"`
		}
		if err := DecodeObject(params, &p, "run_id", "format"); err != nil {
			return nil, err
		}
		return s.Export(ctx, p.ID, p.Format)
	default:
		return nil, ErrUnknownMethod
	}
}

func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	s.stopped = true
	s.cancelLifetime()
	active := s.active
	if active != nil {
		active.cancel()
	}
	s.mu.Unlock()
	if active == nil {
		return nil
	}
	select {
	case <-active.done:
		return nil
	case <-ctx.Done():
		return ErrUnavailable
	}
}

func checkedRegistrations(definitions []Definition) (map[string]registration, map[string]string, error) {
	if len(definitions) > 64 {
		return nil, nil, ErrInvalid
	}
	registrations := map[string]registration{}
	byRun := map[string]string{}
	for _, definition := range definitions {
		if !validDefinitionInput(definition) {
			return nil, nil, ErrInvalid
		}
		if _, exists := registrations[definition.ID]; exists {
			return nil, nil, ErrInvalid
		}
		frozen, err := testplan.DecodeRunManifest(definition.Input.ManifestBytes)
		if err != nil {
			return nil, nil, ErrInvalid
		}
		// Rebinding catches casing aliases that the frozen decoder would otherwise
		// normalize. The stored canonical bytes must describe this exact struct.
		rebound, err := testplan.BindRunManifest(frozen.Manifest)
		if err != nil || !bytes.Equal(rebound.Canonical, frozen.Canonical) {
			return nil, nil, ErrInvalid
		}
		for _, dependency := range definition.Input.DependencyRunIDs {
			if dependency == frozen.Manifest.RunID {
				return nil, nil, ErrInvalid
			}
		}
		if _, exists := byRun[frozen.Manifest.RunID]; exists {
			return nil, nil, ErrInvalid
		}
		definition.Input.ManifestBytes = append([]byte(nil), frozen.Canonical...)
		definition.Input.RequiredLabels = append([]string(nil), definition.Input.RequiredLabels...)
		definition.Input.DependencyRunIDs = append([]string(nil), definition.Input.DependencyRunIDs...)
		if definition.Input.EligibleAfter != nil {
			v := *definition.Input.EligibleAfter
			definition.Input.EligibleAfter = &v
		}
		registrations[definition.ID] = registration{definition: definition, frozen: frozen}
		byRun[frozen.Manifest.RunID] = definition.ID
	}
	return registrations, byRun, nil
}

func validDefinitionInput(d Definition) bool {
	if !identityPattern.MatchString(d.ID) {
		return false
	}
	for _, name := range []string{d.Input.CampaignName, d.Input.SuiteName, d.Input.CaseName} {
		if !utf8.ValidString(name) || strings.TrimSpace(name) == "" || len([]rune(name)) > 200 {
			return false
		}
	}
	switch d.Input.Priority {
	case postgres.PriorityRelease, postgres.PriorityHotfix, postgres.PriorityMilestone, postgres.PrioritySystem, postgres.PriorityCalibration, postgres.PriorityExploratory, postgres.PriorityBackground:
	default:
		return false
	}
	for _, id := range []string{d.Input.RequiredResourceID, d.Input.RequiredModelID, d.Input.RequiredCertificationID} {
		if !identityPattern.MatchString(id) {
			return false
		}
	}
	for _, values := range [][]string{d.Input.RequiredLabels, d.Input.DependencyRunIDs} {
		if len(values) > 64 {
			return false
		}
		seen := map[string]bool{}
		for _, id := range values {
			if !identityPattern.MatchString(id) || seen[id] {
				return false
			}
			seen[id] = true
		}
	}
	return true
}
