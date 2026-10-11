package pilot

import (
	"context"
	"os"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zyc14588/AIPT/internal/evidence"
	"github.com/zyc14588/AIPT/internal/runcontrol"
	"github.com/zyc14588/AIPT/internal/storage/postgres"
	"github.com/zyc14588/AIPT/internal/testplan"
)

const task0DiagnosticRegistration = "B007-TASK0-ONE-DIAGNOSTIC"

// Only an externally bound static PREP admitted by its owning host parent can
// enter this path. Namespace creation and private proc admission precede every
// source, connection, helper, model/cache or key lookup.
func RunAcceptedTask0Preparation(expectedBindingSHA string) (runErr error) {
	if !digest(expectedBindingSHA) || len(os.Args) != 1 || !task0PreparationCredentialValid(os.Getenv("DEEPSEEK_API_KEY")) {
		return ErrRuntimeLaunch
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	runtime, raw, err := receiveTask0CAPreparation(ctx, expectedBindingSHA)
	if err != nil {
		return ErrRuntimeLaunch
	}
	defer clear(raw)
	defer func() { task0PreparationCleanup(&runErr, runtime.retire()) }()
	a, err := decodeTask0Preparation(raw, expectedBindingSHA)
	if err != nil {
		return ErrRuntimeLaunch
	}
	defer task0ClearPreparation(a)
	if runtime.admitCA(a) != nil {
		return ErrRuntimeLaunch
	}
	result, err := executeTask0Preparation(ctx, a, runtime)
	if err != nil || ctx.Err() != nil || runtime.joinSetup(&result) != nil || !task0ParentResultValid(result, expectedBindingSHA) {
		return ErrRuntimeLaunch
	}
	if runtime.guard() != nil || runtime.control.SetDeadline(time.Now().Add(10*time.Second)) != nil {
		return ErrRuntimeLaunch
	}
	threads, err := task0PrivilegeThreads("/proc/self", 0, 0, 0)
	if err != nil {
		return ErrRuntimeLaunch
	}
	runtime.proof.Threads = len(threads)
	complete := task0CAFrame{Schema: task0CAAdmissionSchema, Operation: "COMPLETE", BindingSHA: a.identity, Generation: runtime.proof.Generation, Nonce: runtime.admissionNonce, Proof: &runtime.proof, Result: &result}
	if task0CAPacket(runtime.control, &complete, true) != nil {
		return ErrRuntimeLaunch
	}
	var response task0CAFrame
	complete.Operation = "RESULT_ACCEPTED"
	if task0CAPacket(runtime.control, &response, false) != nil || !task0SameJSON(complete, response) || runtime.guard() != nil {
		return ErrRuntimeLaunch
	}
	return nil
}

func task0ClearPreparation(a *acceptedTask0Preparation) {
	if a == nil {
		return
	}
	b := &a.binding
	for _, raw := range [][]byte{b.Manifest, b.Dispatch, b.Local, b.RuntimeManifest, b.RuntimePolicy, b.Remote, b.PrototypeAnnex, b.RetainedAnnex, b.SetupBinding} {
		clear(raw)
	}
}

type task0PreparationRoots struct {
	paths  []string
	files  []*os.File
	states []syscall.Stat_t
}

func openTask0PreparationRoots(b task0PreparationBinding) (*task0PreparationRoots, error) {
	r := &task0PreparationRoots{paths: []string{b.SourceRoot, b.BudgetRoot, b.EvidenceRoot, b.KeyRoot}}
	for i, p := range r.paths {
		if !task0PreparationPath(p) {
			r.Close()
			return nil, ErrRuntimeLaunch
		}
		for _, q := range r.paths[:i] {
			if !task0SeparatePrivatePaths(p, q) {
				r.Close()
				return nil, ErrRuntimeLaunch
			}
		}
		f, s, err := task0OpenPrivateReportRoot(p)
		if err != nil {
			r.Close()
			return nil, ErrRuntimeLaunch
		}
		for _, prior := range r.states {
			if prior.Dev == s.Dev && prior.Ino == s.Ino {
				f.Close()
				r.Close()
				return nil, ErrRuntimeLaunch
			}
		}
		r.files = append(r.files, f)
		r.states = append(r.states, s)
	}
	return r, nil
}

func (r *task0PreparationRoots) stable() bool {
	if r == nil || len(r.paths) != 4 || len(r.files) != 4 || len(r.states) != 4 {
		return false
	}
	for i, p := range r.paths {
		var held syscall.Stat_t
		if r.files[i] == nil || syscall.Fstat(int(r.files[i].Fd()), &held) != nil || !task0SameReportDirectory(held, r.states[i]) {
			return false
		}
		f, s, err := task0OpenPrivateReportRoot(p)
		if err != nil {
			return false
		}
		closeErr := f.Close()
		if closeErr != nil || !task0SameReportDirectory(s, r.states[i]) {
			return false
		}
	}
	return true
}

func (r *task0PreparationRoots) Close() error {
	if r == nil {
		return nil
	}
	var result error
	for i, f := range r.files {
		if f != nil {
			if f.Close() != nil {
				result = ErrRuntimeLaunch
			}
			r.files[i] = nil
		}
	}
	return result
}

func task0PreparationCleanup(result *error, closeErr error) {
	if closeErr != nil {
		*result = ErrRuntimeLaunch
	}
}

func task0DiagnosticDefinition(f testplan.FrozenManifest) runcontrol.Definition {
	return runcontrol.Definition{ID: task0DiagnosticRegistration, Input: postgres.EnqueueRunInput{
		ManifestBytes: append([]byte(nil), f.Canonical...), CampaignName: "B007 non-qualifying diagnostic", SuiteName: "Task0 prototype integration", CaseName: "One Owner-authorized diagnostic",
		Priority: postgres.PriorityCalibration, RequiredResourceID: "B007-TASK0-RESOURCE", RequiredModelID: "B007-TASK0-MODELS", RequiredCertificationID: "B007-TASK0-MINIMUM-CERTIFICATIONS", RequiredLabels: []string{"B007-TASK0-NON-QUAL"},
	}}
}

func task0DiagnosticServiceOptions(ctx context.Context, queue *postgres.QueueStore, reader *runcontrol.PostgresReader, f testplan.FrozenManifest) runcontrol.Options {
	d := task0DiagnosticDefinition(f)
	return runcontrol.Options{Queue: queue, Reader: reader, Definitions: []runcontrol.Definition{d}, Lifetime: ctx, HolderID: "B007-TASK0-OWNED-PREP", LeaseDuration: 30 * time.Second,
		Capabilities: postgres.CapabilitySet{ResourceIDs: []string{d.Input.RequiredResourceID}, ModelIDs: []string{d.Input.RequiredModelID}, CertificationIDs: []string{d.Input.RequiredCertificationID}, Labels: append([]string(nil), d.Input.RequiredLabels...)}}
}

// A new diagnostic is never inferred from missing local files. The original
// B006 enrollment must succeed once; duplicate queue/claim/intent state stops
// this path. No recovery, requeue loop or second RunNext is installed here.
func task0EnrollDiagnostic(ctx context.Context, options runcontrol.Options) error {
	service, err := runcontrol.New(options)
	if err != nil {
		return ErrRuntimeLaunch
	}
	defer service.Stop(context.Background())
	view, err := service.Enqueue(ctx, task0DiagnosticRegistration)
	if err != nil || view.RunID != task0DiagnosticRunID || view.Status != postgres.RunQueued || view.QualificationEligible || view.Classification != "DIAGNOSTIC" {
		return ErrRuntimeLaunch
	}
	return nil
}

func task0WaitDiagnostic(ctx context.Context, service *runcontrol.Service) (runcontrol.RunDetail, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		snapshot, err := service.Snapshot(ctx, 1)
		if err != nil || snapshot.Paused || snapshot.Truncated || snapshot.QualificationExecutionAuthorized || snapshot.WorkerLastError != nil || len(snapshot.Items) != 1 || snapshot.Items[0].RunID != task0DiagnosticRunID {
			return runcontrol.RunDetail{}, ErrRuntimeLaunch
		}
		if snapshot.WorkerRunID == nil {
			detail, err := service.Run(ctx, task0DiagnosticRunID)
			if err != nil || detail.Run.Status != postgres.RunCompleted || detail.Run.QualificationEligible || detail.Run.Classification != "DIAGNOSTIC" || len(detail.Attempts) != 2 ||
				detail.Attempts[0].Number != 1 || detail.Attempts[0].Kind != postgres.AttemptNewRun || detail.Attempts[0].Outcome != postgres.AttemptStarted || detail.Attempts[0].EvidenceSHA256 != nil ||
				detail.Attempts[1].Number != 2 || detail.Attempts[1].Kind != postgres.AttemptRecord || detail.Attempts[1].Outcome != postgres.AttemptSucceeded || detail.Attempts[1].EvidenceSHA256 == nil || !digest(*detail.Attempts[1].EvidenceSHA256) {
				return runcontrol.RunDetail{}, ErrRuntimeLaunch
			}
			return detail, nil
		}
		if *snapshot.WorkerRunID != task0DiagnosticRunID {
			return runcontrol.RunDetail{}, ErrRuntimeLaunch
		}
		select {
		case <-ctx.Done():
			return runcontrol.RunDetail{}, ErrRuntimeLaunch
		case <-ticker.C:
		}
	}
}

type task0ExportAcceptance struct {
	Schema     string              `json:"schema"`
	BindingSHA string              `json:"preparation_binding_sha256"`
	RunID      string              `json:"run_id"`
	RootSHA    string              `json:"ciphertext_evidence_root_sha256"`
	Exports    []task0ExportDigest `json:"public_exports"`
}

type task0ExportDigest struct {
	Format string `json:"format"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

func task0VerifyDiagnosticReports(ctx context.Context, service *runcontrol.Service, budget *GlobalBudget, bindingSHA string, detail runcontrol.RunDetail) (string, error) {
	view, err := service.Inspect(ctx, task0DiagnosticRunID)
	if err != nil || len(detail.Attempts) != 2 || detail.Attempts[1].EvidenceSHA256 == nil || view.RunID != task0DiagnosticRunID || view.Root != *detail.Attempts[1].EvidenceSHA256 || !digest(view.Root) || view.ExecutionStatus != "COMPLETED" || view.QualificationEligible || !task0SameJSON(view.Formats, []string{"csv", "html", "json", "junit", "md"}) {
		return "", ErrRuntimeLaunch
	}
	receipt := task0ExportAcceptance{Schema: "aipt.private.b007-task0-original-b006-export-acceptance/v1", BindingSHA: bindingSHA, RunID: task0DiagnosticRunID, RootSHA: view.Root, Exports: []task0ExportDigest{}}
	for _, format := range view.Formats {
		d, err := service.Export(ctx, task0DiagnosticRunID, format)
		valid := err == nil && len(d.Data) > 0 && len(d.Data) <= runcontrol.MaxExportBytes && digest(d.SHA256) && inputSHA(d.Data) == d.SHA256
		if valid {
			receipt.Exports = append(receipt.Exports, task0ExportDigest{format, d.SHA256, len(d.Data)})
		}
		clear(d.Data)
		if !valid || ctx.Err() != nil {
			return "", ErrRuntimeLaunch
		}
	}
	body, err := task0PrivateCanonicalLine(receipt)
	if err != nil {
		return "", ErrRuntimeLaunch
	}
	defer clear(body)
	if persistTask0PrivateRecord(budget, "task0-original-b006-export-acceptance.private.json", body) != nil {
		return "", ErrRuntimeLaunch
	}
	return view.Root, nil
}

func executeTask0Preparation(ctx context.Context, a *acceptedTask0Preparation, runtime *task0AcceptedPreparationRuntime) (result task0PreparationResult, err error) {
	if ctx == nil || ctx.Err() != nil || a == nil || runtime == nil || runtime.guard() != nil || !digest(a.identity) || os.Getpid() != 1 || os.Geteuid() != 0 || !namespaceIsNotHost("user") || !namespaceIsNotHost("pid") || !namespaceIsNotHost("mnt") {
		return result, ErrRuntimeLaunch
	}
	b := a.binding
	roots, err := openTask0PreparationRoots(b)
	if err != nil {
		return result, ErrRuntimeLaunch
	}
	defer func() { task0PreparationCleanup(&err, roots.Close()) }()
	sources, err := LoadTask0PrototypeInputs(b.SourceRoot, b.PrototypeAnnex, b.RetainedAnnex)
	if err != nil || !roots.stable() {
		return result, ErrRuntimeLaunch
	}
	defer func() {
		clear(sources.manifest)
		for _, raw := range sources.files {
			clear(raw)
		}
		if sources.legacy != nil {
			for _, raw := range sources.legacy.files {
				clear(raw)
			}
		}
	}()
	gameFile, err := task0HoldPreparationHelper(b.Game.File)
	if err != nil {
		return result, ErrRuntimeLaunch
	}
	defer func() { task0PreparationCleanup(&err, gameFile.Close()) }()
	game, err := launchTask0DelegatedGame(ctx, runtime.setup, gameFile, b.Game.File.SHA256, b.Game.ManifestSHA)
	if err != nil {
		return result, ErrRuntimeLaunch
	}
	defer func() { task0PreparationCleanup(&err, game.retireOwned()) }()
	helperFiles := map[string]*os.File{}
	defer func() {
		for _, f := range helperFiles {
			task0PreparationCleanup(&err, f.Close())
		}
	}()
	for _, h := range b.RemoteHelpers {
		f, openErr := task0HoldPreparationHelper(h.File)
		if openErr != nil {
			return result, ErrRuntimeLaunch
		}
		helperFiles[h.ProfileBinding] = f
	}
	remote, err := newTask0DelegatedRemoteTransport(ctx, runtime.setup, b.Remote, inputSHA(b.Remote), a.dispatch, helperFiles)
	if err != nil {
		return result, ErrRuntimeLaunch
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		task0PreparationCleanup(&err, remote.Close(cleanup))
	}()
	config, err := task0PreparationDatabase(b.Database)
	if err != nil || !roots.stable() {
		return result, ErrRuntimeLaunch
	}
	config.ConnConfig.ConnectTimeout = 5 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return result, ErrRuntimeLaunch
	}
	defer pool.Close()
	setup, setupCancel := context.WithTimeout(ctx, 30*time.Second)
	defer setupCancel()
	var version int
	if pool.Ping(setup) != nil || pool.QueryRow(setup, "SHOW server_version_num").Scan(&version) != nil || version != 180004 || postgres.MigrateUp(setup, pool) != nil {
		return result, ErrRuntimeLaunch
	}
	var existing int
	if pool.QueryRow(setup, "SELECT count(*) FROM aipt.playtest_runs").Scan(&existing) != nil || existing != 0 {
		return result, ErrRuntimeLaunch
	}
	queue, err := postgres.NewQueueStore(pool, nil)
	if err != nil {
		return result, ErrRuntimeLaunch
	}
	reader, err := runcontrol.NewPostgresReader(pool)
	if err != nil {
		return result, ErrRuntimeLaunch
	}
	options := task0DiagnosticServiceOptions(ctx, queue, reader, a.manifest)
	if !roots.stable() || task0EnrollDiagnostic(setup, options) != nil {
		return result, ErrRuntimeLaunch
	}
	budget, err := OpenGlobalBudget(setup, pool, b.BudgetRoot, a.manifest, b.Pricing)
	if err != nil {
		return result, ErrRuntimeLaunch
	}
	defer func() { task0PreparationCleanup(&err, budget.Close()) }()
	if budget.device != roots.states[1].Dev || budget.inode != roots.states[1].Ino || !roots.stable() {
		return result, ErrRuntimeLaunch
	}
	key, err := evidence.CreatePrivateAuditKey(b.KeyRoot)
	if err != nil {
		return result, ErrRuntimeLaunch
	}
	defer func() { task0PreparationCleanup(&err, key.Close()) }()
	reports, err := newTask0PrivateReports(ctx, budget, a.dispatch, b.EvidenceRoot, b.KeyRoot, key.Reference())
	if err != nil {
		return result, ErrRuntimeLaunch
	}
	defer func() { task0PreparationCleanup(&err, reports.Close()) }()
	publisher, err := newTask0EvidencePublisher(ctx, budget, a.dispatch, b.EvidenceRoot, key)
	if err != nil {
		return result, ErrRuntimeLaunch
	}
	defer func() { task0PreparationCleanup(&err, publisher.Close()) }()
	driver, err := newTask0DelegatedExecutor(ctx, runtime.setup, budget, a.dispatch, a.local, game, remote, sources, publisher, reports)
	if err != nil || !roots.stable() {
		return result, ErrRuntimeLaunch
	}
	options.Executor, options.Reports = driver, reports
	service, err := runcontrol.New(options)
	if err != nil {
		return result, ErrRuntimeLaunch
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		task0PreparationCleanup(&err, service.Stop(cleanup))
	}()
	view, err := service.RunNext(ctx)
	if err != nil || view.RunID != task0DiagnosticRunID || view.QualificationEligible {
		return result, ErrRuntimeLaunch
	}
	detail, err := task0WaitDiagnostic(ctx, service)
	if err != nil {
		return result, ErrRuntimeLaunch
	}
	root, err := task0VerifyDiagnosticReports(ctx, service, budget, a.identity, detail)
	if err != nil || !roots.stable() || ctx.Err() != nil || runtime.guard() != nil {
		return result, ErrRuntimeLaunch
	}
	return task0PreparationResult{BindingSHA: a.identity, RunID: task0DiagnosticRunID, Status: "COMPLETED_NON_QUAL", EvidenceRootSHA: root}, nil
}
