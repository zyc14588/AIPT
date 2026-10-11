package pilot

import (
	"bytes"
	"context"
	"encoding/hex"
	"sync"
	"time"

	"github.com/zyc14588/AIPT/internal/modelgateway"
	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/runcontrol"
	"github.com/zyc14588/AIPT/internal/storage/postgres"
	"github.com/zyc14588/AIPT/internal/testplan"
)

// The preparation process installs this concrete driver into the unchanged
// B006 service. Construction makes no model calls. In particular it carries
// only the accepted local grant, and opens/starts the registered local model
// inside Execute after the queue has acquired its original diagnostic lease.
type task0Executor struct {
	mu         sync.Mutex
	budget     *GlobalBudget
	grant      *acceptedTask0DispatchGrant
	localGrant *acceptedPilotLocalGrant
	game       *task0OwnedGameHelper
	remote     *task0FrozenRemoteTransport
	sources    *Task0PrototypeSources
	publisher  *task0EvidencePublisher
	reports    *task0PrivateReports
	queue      *postgres.QueueStore
	consumed   bool
	setup      *task0SetupClient
}

func newTask0DelegatedExecutor(ctx context.Context, owner *task0SetupClient, budget *GlobalBudget, grant *acceptedTask0DispatchGrant, local *acceptedPilotLocalGrant, game *task0OwnedGameHelper, remote *task0FrozenRemoteTransport, sources *Task0PrototypeSources, publisher *task0EvidencePublisher, reports *task0PrivateReports) (*task0Executor, error) {
	if owner == nil || !owner.live() || game == nil || game.delegated == nil || game.delegated.owner != owner || remote == nil || remote.setup != owner {
		return nil, ErrTask0
	}
	e, err := newTask0Executor(ctx, budget, grant, local, game, remote, sources, publisher, reports)
	if err != nil {
		return nil, err
	}
	e.setup = owner
	return e, nil
}

var _ runcontrol.Executor = (*task0Executor)(nil)

func newTask0Executor(ctx context.Context, budget *GlobalBudget, grant *acceptedTask0DispatchGrant, local *acceptedPilotLocalGrant, game *task0OwnedGameHelper, remote *task0FrozenRemoteTransport, sources *Task0PrototypeSources, publisher *task0EvidencePublisher, reports *task0PrivateReports) (*task0Executor, error) {
	if task0CheckBudgetTransport(ctx, budget, grant) != nil || local == nil || game == nil || (game.process == nil && game.delegated == nil) || game.wire == nil || remote == nil ||
		remote.grant != grant || remote.closed || sources == nil || sources.identity != Task0PrototypeAnnexSHA || sources.binding != task0PrototypeSourceBinding ||
		publisher == nil || publisher.budget != budget || publisher.grant != grant || !publisher.stable() || reports == nil || reports.closed || reports.budget != budget || reports.grant != grant ||
		reports.rootState.Dev != publisher.rootState.Dev || reports.rootState.Ino != publisher.rootState.Ino {
		return nil, ErrTask0
	}
	b := local.binding
	entry, ok := grant.profiles[b.Profile.BindingID()]
	if !ok || entry.Profile.BackendKind != modelgateway.BackendLocalLlamaCPP || !task0SameJSON(entry.Profile, b.Profile) || !task0SameJSON(entry.Sampling, b.Sampling) ||
		b.FullIndependentReviewSHA256 != grant.binding.FullReviewSHA || b.ImmutableOnlineCIReceiptSHA256 != grant.binding.OnlineCIReceiptSHA ||
		b.RuntimeManifestSHA256 != grant.binding.RuntimeManifestSHA || b.AcceptedImplementationCommit != grant.binding.Implementation.Commit || b.Adapter.AdapterEntrypointSHA256 != task0ModelWorkerSHA {
		return nil, ErrTask0
	}
	queue, err := postgres.NewQueueStore(budget.pool, nil)
	if err != nil {
		return nil, ErrTask0
	}
	return &task0Executor{budget: budget, grant: grant, localGrant: local, game: game, remote: remote, sources: sources, publisher: publisher, reports: reports, queue: queue}, nil
}

// Check the durable original attempt, exact queue manifest and live lease.
// Any prior B006 attempt, reservation or private execution intent prevents
// restarting this diagnostic after an uncertain or failed execution.
func (e *task0Executor) claimExecution(ctx context.Context, execution runcontrol.Execution) error {
	if e == nil || ctx == nil || ctx.Err() != nil || e.consumed || e.queue == nil || e.budget == nil || e.grant == nil || e.budget.checkRoot() != nil {
		return ErrTask0
	}
	a := execution.AttemptID
	if len(a) != 37 || a[:5] != "b006-" {
		return ErrTask0
	}
	nonce, err := hex.DecodeString(a[5:])
	if err != nil || len(nonce) != 16 || hex.EncodeToString(nonce) != a[5:] {
		return ErrTask0
	}
	f, err := testplan.DecodeRunManifest(execution.Manifest.Canonical)
	if err != nil || f.Digest != execution.Manifest.Digest || f.Digest != e.grant.manifest.Digest || !bytes.Equal(f.Canonical, e.grant.manifest.Canonical) ||
		f.Manifest.RunID != execution.Manifest.Manifest.RunID || f.Manifest.Classification != "DIAGNOSTIC" || f.Manifest.QualificationEligible {
		return ErrTask0
	}
	record, err := e.queue.GetRun(ctx, f.Manifest.RunID)
	if err != nil || record.Status != postgres.RunLeased || record.Classification != "DIAGNOSTIC" || record.QualificationEligible || record.ManifestSHA256 != f.Digest || !bytes.Equal(record.ManifestCanonical, f.Canonical) {
		return ErrTask0
	}
	attempts, err := e.queue.ReadAttempts(ctx, f.Manifest.RunID)
	if err != nil || len(attempts) != 1 || attempts[0].AttemptNumber != 1 || attempts[0].AttemptID != a+"-start" || attempts[0].Kind != postgres.AttemptNewRun || attempts[0].Outcome != postgres.AttemptStarted || attempts[0].EvidenceSHA256 != nil {
		return ErrTask0
	}
	var leases int
	if e.budget.pool.QueryRow(ctx, `SELECT count(*) FROM aipt.run_leases WHERE run_id=$1 AND generation=1 AND status='ACTIVE' AND formal_slot IS NULL AND expires_at>statement_timestamp()`, f.Manifest.RunID).Scan(&leases) != nil || leases != 1 {
		return ErrTask0
	}
	totals, err := e.budget.Totals(ctx)
	if err != nil || totals != (BudgetTotals{}) {
		return ErrTask0
	}
	e.consumed = true
	body, err := task0PrivateCanonicalLine(struct {
		Schema      string `json:"schema"`
		ManifestSHA string `json:"manifest_sha256"`
		GrantSHA    string `json:"dispatch_grant_sha256"`
		AttemptID   string `json:"attempt_id"`
	}{"aipt.private.b007-task0-original-execution-intent/v1", e.grant.binding.ManifestSHA, e.grant.identity, a})
	if err != nil || persistTask0PrivateRecord(e.budget, "task0-original-execution.private.json", body) != nil {
		return ErrTask0
	}
	return nil
}

func (e *task0Executor) Execute(ctx context.Context, execution runcontrol.Execution) (completion runcontrol.Completion, err error) {
	if e == nil || e.setup == nil || !e.setup.live() {
		return completion, ErrTask0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.claimExecution(ctx, execution) != nil {
		return completion, ErrTask0
	}
	// All owned children retire on every exit. Reports remain available for
	// the unchanged B006 independent reinspection before lease completion.
	defer func() {
		if e.game.retireOwned() != nil {
			completion = runcontrol.Completion{}
			err = ErrTask0
		}
	}()
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if e.remote.Close(cleanup) != nil {
			completion = runcontrol.Completion{}
			err = ErrTask0
		}
	}()
	memory, err := newTask0MemoryReceiptWriter(e.budget, e.localGrant)
	if err != nil {
		return completion, ErrTask0
	}
	defer memory.Close()
	local, err := openTask0DelegatedLocal(ctx, e.setup, e.localGrant, memory)
	if err != nil {
		return completion, ErrTask0
	}
	defer local.retire()
	localTransport, err := newTask0LocalBudgetTransport(ctx, e.budget, local, e.grant)
	if err != nil {
		return completion, ErrTask0
	}
	localEntry := e.grant.profiles[e.localGrant.binding.Profile.BindingID()]
	localCert, certErr := runTask0RoleCertification(ctx, localTransport, localEntry)
	retireErr := local.retire()
	memoryErr := memory.Close()
	if certErr != nil || retireErr != nil || memoryErr != nil || memory.failed || memory.count != 3 {
		return completion, ErrTask0
	}
	remoteTransport, err := newTask0BudgetTransport(ctx, e.budget, e.remote, e.grant)
	if err != nil {
		return completion, ErrTask0
	}
	certs := []modelgateway.Certification{localCert}
	profiles := []modelgateway.ModelProfile{localEntry.Profile}
	samplings := []modelgateway.SamplingProfile{localEntry.Sampling}
	seenSamplings := map[string]bool{localEntry.Sampling.BindingID(): true}
	for _, seat := range orchestrator.BaselineSeats() {
		var entry task0DispatchProfile
		for _, candidate := range e.grant.profiles {
			if candidate.Seat == seat && candidate.Profile.BackendKind == modelgateway.BackendRemoteDeepSeek {
				entry = candidate
			}
		}
		if entry.Profile.ProfileID == "" {
			return completion, ErrTask0
		}
		cert, certErr := runTask0RoleCertification(ctx, remoteTransport, entry)
		if certErr != nil {
			return completion, ErrTask0
		}
		certs = append(certs, cert)
		profiles = append(profiles, entry.Profile)
		if !seenSamplings[entry.Sampling.BindingID()] {
			samplings = append(samplings, entry.Sampling)
			seenSamplings[entry.Sampling.BindingID()] = true
		}
	}
	registry, err := modelgateway.NewRegistry(samplings, profiles, certs)
	if err != nil {
		return completion, ErrTask0
	}
	table, err := newTask0Table(ctx, e.budget, e.game, remoteTransport, registry, e.sources)
	if err != nil {
		return completion, ErrTask0
	}
	defer func() {
		if table.retire() != nil {
			completion = runcontrol.Completion{}
			err = ErrTask0
		}
	}()
	result, err := table.execute(ctx)
	if err != nil {
		return completion, ErrTask0
	}
	// Close model routes before evidence publication; keep the held seed and
	// game available only for the independent authoritative Core replay.
	closeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = table.gateway.Close(closeCtx)
	cancel()
	if err != nil || ctx.Err() != nil {
		return completion, ErrTask0
	}
	return e.publisher.publish(ctx, table, result, e.reports)
}
