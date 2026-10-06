package runcontrol

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/zyc14588/AIPT/internal/storage/postgres"
	"github.com/zyc14588/AIPT/internal/testplan"
)

// RunNext claims only the B001-selected next Run, never a caller-selected
// lease or completion. No executor or PUBLIC verified report means no claim.
func (s *Service) RunNext(ctx context.Context) (RunView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped || s.lifetime.Err() != nil {
		return RunView{}, ErrUnavailable
	}
	if s.executor == nil || s.reports == nil {
		return RunView{}, ErrNotConfigured
	}
	if s.active != nil {
		return RunView{}, ErrConflict
	}
	lease, err := s.queue.AcquireLease(ctx, postgres.AcquireLeaseInput{HolderID: s.holderID, LeaseDuration: s.leaseDuration, Capabilities: copyCapabilities(s.capabilities)})
	if err != nil {
		return RunView{}, err
	}
	release := func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.queue.ReleaseLease(cleanup, lease.LeaseID, lease.Token, postgres.ReleaseRequeue)
	}
	record, err := s.queue.GetRun(ctx, lease.RunID)
	if err != nil {
		release()
		return RunView{}, err
	}
	id, exists := s.byRun[record.RunID]
	if !exists {
		release()
		return RunView{}, ErrNotAuthorized
	}
	registered := s.registrations[id]
	input := registered.definition.Input
	if record.ManifestID != registered.frozen.Manifest.ManifestID || record.ManifestSHA256 != registered.frozen.Digest || !bytes.Equal(record.ManifestCanonical, registered.frozen.Canonical) || record.Classification != "DIAGNOSTIC" || record.QualificationEligible || lease.Formal || record.RequiredResourceID != input.RequiredResourceID || record.RequiredModelID != input.RequiredModelID || record.RequiredCertificationID != input.RequiredCertificationID {
		release()
		return RunView{}, ErrNotAuthorized
	}
	// Decode fresh storage bytes so an executor cannot mutate the registry.
	frozen, err := testplan.DecodeRunManifest(record.ManifestCanonical)
	if err != nil {
		release()
		return RunView{}, ErrUnavailable
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		release()
		return RunView{}, ErrUnavailable
	}
	attemptID := "b006-" + hex.EncodeToString(nonce)
	prior, err := s.queue.ReadAttempts(ctx, record.RunID)
	if err != nil {
		release()
		return RunView{}, err
	}
	kind := postgres.AttemptNewRun
	if len(prior) > 0 {
		kind = postgres.AttemptSameRunRecovery
	}
	if _, err := s.queue.AppendAttempt(ctx, record.RunID, attemptID+"-start", kind, postgres.AttemptStarted, nil); err != nil {
		release()
		return RunView{}, err
	}
	// The HTTP/RPC request lifetime cannot cancel an accepted background Run.
	runCtx, cancel := context.WithTimeout(s.lifetime, time.Duration(frozen.Manifest.Budget.MaxDurationSeconds)*time.Second)
	active := &activeRun{runID: record.RunID, cancel: cancel, done: make(chan struct{})}
	s.active = active
	s.lastError = nil
	go s.execute(runCtx, active, lease, record, frozen, attemptID)
	return publicRun(record), nil
}

func (s *Service) execute(ctx context.Context, active *activeRun, lease postgres.Lease, record postgres.RunRecord, manifest testplan.FrozenManifest, attemptID string) {
	defer func() {
		active.cancel()
		s.mu.Lock()
		if s.active == active {
			s.active = nil
		}
		close(active.done)
		s.mu.Unlock()
	}()
	heartbeatCtx, stopHeartbeat := context.WithCancel(ctx)
	heartbeatDone := make(chan struct{})
	heartbeatFailure := make(chan error, 1)
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(s.leaseDuration / 3)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				renewal, cancel := context.WithTimeout(heartbeatCtx, s.leaseDuration/3)
				_, err := s.queue.RenewLease(renewal, lease.LeaseID, lease.Token, s.leaseDuration)
				cancel()
				if err != nil {
					heartbeatFailure <- err
					active.cancel()
					return
				}
			}
		}
	}()
	completion, executionErr := s.executor.Execute(ctx, Execution{Manifest: manifest, AttemptID: attemptID})
	if ctx.Err() != nil && executionErr == nil {
		executionErr = ErrUnavailable
	}
	if executionErr == nil {
		var zero [32]byte
		if completion.AuditReadyRoot == zero {
			executionErr = ErrReportUnavailable
		} else {
			verified, err := s.reports.Inspect(ctx, record)
			if err != nil || verified.RunID != record.RunID || verified.Root != hex.EncodeToString(completion.AuditReadyRoot[:]) || verified.QualificationEligible || verified.ExecutionStatus != "COMPLETED" {
				executionErr = ErrReportUnavailable
			}
		}
	}
	// Verification may finish after shutdown/budget cancellation. Its returned
	// matching report must never turn canceled work into success.
	if ctx.Err() != nil && executionErr == nil {
		executionErr = ErrUnavailable
	}
	stopHeartbeat()
	<-heartbeatDone
	select {
	case failure := <-heartbeatFailure:
		executionErr = failure
	default:
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Check current database ownership again before any successful finalization.
	if executionErr == nil {
		if ctx.Err() != nil || !s.available() {
			executionErr = ErrUnavailable
		} else {
			_, executionErr = s.queue.RenewLease(ctx, lease.LeaseID, lease.Token, s.leaseDuration)
		}
	}
	if executionErr == nil && (ctx.Err() != nil || !s.available()) {
		executionErr = ErrUnavailable
	}
	outcome := postgres.AttemptFailed
	disposition := postgres.ReleaseRequeue
	var digest *[32]byte
	if executionErr == nil {
		outcome = postgres.AttemptSucceeded
		disposition = postgres.ReleaseComplete
		digest = &completion.AuditReadyRoot
	}
	finalizeCtx := cleanup
	if executionErr == nil {
		finalizeCtx = ctx
	}
	if _, err := s.queue.AppendAttempt(finalizeCtx, record.RunID, attemptID+"-finish", postgres.AttemptRecord, outcome, digest); err != nil {
		executionErr = err
		disposition = postgres.ReleaseRequeue
	}
	if executionErr != nil {
		finalizeCtx = cleanup
	}
	if err := s.queue.ReleaseLease(finalizeCtx, lease.LeaseID, lease.Token, disposition); err != nil {
		executionErr = err
	}
	if executionErr != nil {
		code := PublicCode(executionErr)
		s.mu.Lock()
		s.lastError = &code
		s.mu.Unlock()
	}
}
