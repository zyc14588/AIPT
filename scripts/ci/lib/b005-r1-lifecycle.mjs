// B005 R1 retains the accepted governance root. Explicit R6 authorization
// admits the exact rejected R5 merge as repair base, never final acceptance.
// This module does no external IO or qualification run.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual as equal } from 'node:util';
import { git } from './cli.mjs';
import { validateInstance } from './json-schema.mjs';
import { AUTHORITY_LIFECYCLE_MODEL, AUTHORITY_LIFECYCLE_EVENTS, AUTHORITY_LIFECYCLE_ORDERING, lifecycleRecordSha256, resolveEffectiveAuthority } from './authority-lifecycle.mjs';

export const B005_TASK = 'AIPT-MVP-B005';
export const R1_BRANCH = 'codex/aipt-mvp-b005-r1';
export const R1_BASE = 'fdbf9637b38a773fbc7ea57a21e6f75dd89b235f';
export const R1_BASE_TREE = 'a307008b48f78ab1b89d5ae5009669244318693f';
export const R6_BASE = '08f8b2ecf721759940f4e4fef862b1a4da9c1834';
export const R6_BASE_TREE = '2551e27b50b1971bbdec82707d83f03d28a95b15';
export const R6_REJECTED_CANDIDATE = '51bcebedb27e7e4aa31f76c50919f343fcd92bbc';
export const R6_AUTHORITY_PATH = 'docs/authority/registry/b005-r1-post-merge-repair.json';
export const R6_RECEIPT_FINDING = 'LOCAL-B005-R1-001';
export const R6_REQUIRED_CHANGED = [
  'internal/evidence/audit_ready.go', 'internal/evidence/remote_provenance_test.go',
  'scripts/ci/lib/b005-r1-lifecycle.mjs', 'scripts/ci/test/b005-r1-lifecycle.test.mjs',
  'scripts/ci/validate/mvp-b005.mjs', 'docs/authority/registry/project-status.json',
  'docs/authority/PROJECT_STATUS.md', 'docs/milestones/MVP.md', R6_AUTHORITY_PATH,
];
export function expectedR6RepairAuthority() {
  return {
    "schema": "aipt.b005.r1-post-merge-repair-authority/v1",
    "version": "1.0.0",
    "task_id": "AIPT-MVP-B005",
    "decision_id": "B005-R6-POST-MERGE-REPAIR-Q001=A",
    "authorization_source": "OWNER_EXPLICIT_CHAT_AUTHORIZATION",
    "authorized_on": "2026-10-06",
    "disposition": "AUTHORIZED",
    "revision": "R6",
    "governance_closeout_commit": "fdbf9637b38a773fbc7ea57a21e6f75dd89b235f",
    "repair_base": {
      "commit": "08f8b2ecf721759940f4e4fef862b1a4da9c1834",
      "tree": "2551e27b50b1971bbdec82707d83f03d28a95b15",
      "parents": [
        "fdbf9637b38a773fbc7ea57a21e6f75dd89b235f",
        "51bcebedb27e7e4aa31f76c50919f343fcd92bbc"
      ]
    },
    "rejected_candidate": {
      "commit": "51bcebedb27e7e4aa31f76c50919f343fcd92bbc",
      "tree": "2551e27b50b1971bbdec82707d83f03d28a95b15"
    },
    "failed_post_merge": {
      "commit": "08f8b2ecf721759940f4e4fef862b1a4da9c1834",
      "independent_review_result": "FAIL",
      "reviewer_source": "LOCAL_INDEPENDENT_CODEX_AGENT",
      "review_report_sha256": "4edaa5956f8f2a0a77e60ab5ed1e1538a66b77f8e3a5c1ba95cdafe6b04f787f",
      "reviewed_paths": 23,
      "finding_id": "LOCAL-B005-R1-001",
      "original_three_findings_locally_verified_fixed": true,
      "public_ci_run_id": 37409519294,
      "public_ci_jobs_success": 5,
      "accepted_as_final_merge": false,
      "lifecycle_records_created": false
    },
    "publication": "NEW_PUBLIC_R6_PULL_REQUEST",
    "candidate_rule": "SINGLE_COMMIT_CHILD_OF_EXACT_REPAIR_BASE",
    "merge_rule": "EXACT_REPAIR_BASE_AND_CANDIDATE_PARENTS_WITH_CANDIDATE_TREE",
    "independent_review": "SAME_OWNER_AUTHORIZED_READ_ONLY_LOCAL_CODEX_AGENT_ON_FINAL_BYTES",
    "closeout_requirements": [
      "INDEPENDENT_LOCAL_REVIEW_PASS",
      "EXACT_FINAL_MAIN_MERGE_COMMIT_AND_TREE",
      "NEW_MAIN_PUSH_CI_ALL_FIVE_JOBS_SUCCESS",
      "LOCAL_ONLINE_FINAL_SOURCE_PROOF_AND_FRESH_VERIFICATION",
      "NEW_INDEPENDENT_IMMUTABLE_FINAL_CI_CATALOGUE",
      "CANONICAL_APPEND_ONLY_LIFECYCLE_RECORDS"
    ],
    "history_rewrite_permitted": false,
    "failed_merge_can_receive_closeout": false,
    "governance_anchors_may_change": false,
    "real_model_calls": 0,
    "qualification_runs_executed": 0
  };
}
const GOV_TASK = 'AIPT-MVP-B005-REMOTE-PROVENANCE-AUTHORITY-001';
const GOV_CANDIDATE = '09bdd1c4787a283846356db6738b54db582342e8';
const GOV_MERGE = '7cedc640f64052103162b4160ffae2f0f8a901df';
const GOV_TREE = '66f05aa436a8e6d7bb87040f093c999dd987e48a';
export const STATUS_PATH = 'docs/authority/registry/project-status.json';
export const REMOTE_SCHEMA_PATH = 'schemas/remote-provenance/v1/aipt-remote-provenance.schema.json';
export const REMOTE_MATRIX_PATH = 'testdata/evidence/v1/b005-r1-remote-provenance-matrix.json';
export const B005_RECORD_ROOT = 'docs/authority/registry/authority-lifecycle/records/aipt-mvp-b005';
export const B005_RECORD_PATHS = ['001-merged', '002-post-merge-verified', '003-closed'].map((name) => `${B005_RECORD_ROOT}/${name}.json`);
export const B005_CI_PATH = 'docs/authority/registry/verified-ci-evidence/aipt-mvp-b005/post-merge-ci.json';
const FINDINGS = ['csf_a1972a15d20bffccad42fbdb', 'csf_4c0f54541fae325dd26494b0', 'csf_b28e7fb44b3e754d93704fa2'];
const GOV_FROZEN = [
  'docs/authority/registry/remote-provenance-policy.json',
  'schemas/remote-provenance/v1/aipt-remote-provenance-policy.schema.json',
  'docs/authority/amendments/AIPT_MVP_B005_REMOTE_PROVENANCE_AUTHORITY_001.md',
  'scripts/ci/validate/b005-remote-provenance-authority.mjs',
  ...['001-merged', '002-post-merge-verified', '003-closed'].map((name) => `docs/authority/registry/authority-lifecycle/records/${GOV_TASK.toLowerCase()}/${name}.json`),
  `docs/authority/registry/verified-ci-evidence/${GOV_TASK.toLowerCase()}/post-merge-ci.json`,
];
export const R1_REQUIRED_CHANGED = [
  'cmd/aipt-audit-ready/main.go', 'cmd/aipt-audit-ready/main_test.go',
  'internal/evidence/audit_ready.go', 'internal/evidence/audit_ready_test.go',
  'internal/evidence/closure_types.go', 'internal/evidence/source_verify.go',
  'internal/evidence/remote_provenance.go', 'internal/evidence/remote_provenance_test.go',
  'internal/evidence/postgres_integration_test.go', REMOTE_SCHEMA_PATH, REMOTE_MATRIX_PATH,
  STATUS_PATH, 'docs/evidence/README.md', 'docs/evidence/B005_AUTHORITY_MATRIX.md',
  'docs/authority/PROJECT_STATUS.md', 'docs/milestones/MVP.md',
  'scripts/ci/lib/b005-r1-lifecycle.mjs', 'scripts/ci/test/b005-r1-lifecycle.test.mjs',
  'scripts/ci/validate/mvp-b005.mjs', 'scripts/ci/validate/int001-closeout-authority.mjs', 'scripts/ci/validate/evidence.mjs',
  'scripts/ci/run-checks.mjs', 'package.json',
];
const R1_ALLOWED = new Set([...R1_REQUIRED_CHANGED, R6_AUTHORITY_PATH, 'docs/authority/BATCH_DEPENDENCY_GRAPH.md', 'docs/authority/README.md']);
const CLOSEOUT_ALLOWED = new Set([...B005_RECORD_PATHS, B005_CI_PATH, STATUS_PATH, 'docs/authority/PROJECT_STATUS.md']);
const hex40 = /^[0-9a-f]{40}$/u;
export function digest(value) { return createHash('sha256').update(value).digest('hex'); }
function result(repo, args) { return git(repo, args, { check: false }); }
function rows(repo, args) { const r = result(repo, args); return r.status === 0 ? r.stdout.trim().split('\n').filter(Boolean) : []; }
function out(repo, args) { const r = result(repo, args); return r.status === 0 ? r.stdout.trim() : null; }
export function blob(repo, commit, relative) { const r = result(repo, ['show', `${commit}:${relative}`]); return r.status === 0 ? r.stdout : null; }
function read(repo, relative) { return fs.readFileSync(path.join(repo, relative), 'utf8'); }
export function facts(repo, commit) {
  if (!hex40.test(commit ?? '')) return null;
  const row = out(repo, ['rev-list', '--parents', '-n', '1', commit]);
  if (!row) return null;
  const [oid, ...parents] = row.split(/\s+/u);
  return { commit: oid, tree: out(repo, ['rev-parse', `${oid}^{tree}`]), parents };
}
function firstParentContains(repo, head, commit) { return Boolean(head && commit && rows(repo, ['rev-list', '--first-parent', head]).includes(commit)); }
function changed(repo, from, to) { return rows(repo, ['diff', '--name-only', '--no-renames', from, to]).sort(); }
function inventory(repo) {
  return [...new Set([...changed(repo, R1_BASE, 'HEAD'),
    ...rows(repo, ['diff', '--name-only', '--no-renames']),
    ...rows(repo, ['diff', '--cached', '--name-only', '--no-renames']),
    ...rows(repo, ['ls-files', '--others', '--exclude-standard'])])].filter((p) => !p.split('/').includes('node_modules')).sort();
}
function dirty(repo) { return rows(repo, ['status', '--porcelain=v1', '--untracked-files=all']).some((line) => !line.includes('node_modules/')); }
function linear(repo, commit) {
  const chain = rows(repo, ['rev-list', '--reverse', '--parents', `${R1_BASE}..${commit}`]);
  let previous = R1_BASE;
  for (const row of chain) { const [oid, ...parents] = row.split(/\s+/u); if (!equal(parents, [previous])) return false; previous = oid; }
  return chain.length > 0 && previous === commit;
}
function repairCandidate(repo, commit) { return equal(facts(repo, commit)?.parents, [R6_BASE]); }
export function candidateBase(repo, commit) {
  if (repairCandidate(repo, commit)) return R6_BASE;
  return linear(repo, commit) ? R1_BASE : null;
}
function repairAuthorityProblems(repo, head, candidate = null) {
  const problems = [];
  const main = out(repo, ['rev-parse', 'refs/remotes/origin/main^{commit}']);
  if (facts(repo, R6_BASE)?.tree !== R6_BASE_TREE ||
      !equal(facts(repo, R6_BASE)?.parents, [R1_BASE, R6_REJECTED_CANDIDATE]) ||
      facts(repo, R6_REJECTED_CANDIDATE)?.tree !== R6_BASE_TREE ||
      !equal(facts(repo, R6_REJECTED_CANDIDATE)?.parents, [R1_BASE]) ||
      !firstParentContains(repo, main, R6_BASE) || !firstParentContains(repo, head, R6_BASE)) {
    problems.push('R6 repair does not preserve the exact failed R5 merge on accepted main');
  }
  const expected = `${JSON.stringify(expectedR6RepairAuthority(), null, 2)}\n`;
  let current = null; try { current = read(repo, R6_AUTHORITY_PATH); } catch { /* fail closed */ }
  if (current !== expected || (candidate && blob(repo, candidate, R6_AUTHORITY_PATH) !== expected)) {
    problems.push('R6 lacks the exact Owner authorization and failed-review identity');
  }
  return problems;
}
function candidateScopeProblems(repo, commit) {
  const paths = changed(repo, R1_BASE, commit);
  const problems = [];
  if (paths.some((p) => !R1_ALLOWED.has(p)) || R1_REQUIRED_CHANGED.some((p) => !paths.includes(p))) {
    problems.push('R1 cumulative Candidate scope is incomplete or unauthorized');
  }
  if (candidateBase(repo, commit) === R6_BASE) {
    const repairPaths = changed(repo, R6_BASE, commit);
    if (repairPaths.some((p) => !R6_REQUIRED_CHANGED.includes(p)) ||
        R6_REQUIRED_CHANGED.some((p) => !repairPaths.includes(p))) problems.push('R6 Candidate scope is not exact');
    problems.push(...repairAuthorityProblems(repo, commit, commit));
  } else if (paths.includes(R6_AUTHORITY_PATH)) {
    problems.push('R6 authorization cannot be reused on another Candidate base');
  }
  return problems;
}
export function acceptedGovernanceProblems(repo, head = out(repo, ['rev-parse', 'HEAD^{commit}'])) {
  const problems = [];
  const main = out(repo, ['rev-parse', 'refs/remotes/origin/main^{commit}']);
  if (facts(repo, R1_BASE)?.tree !== R1_BASE_TREE || !equal(facts(repo, R1_BASE)?.parents, [GOV_MERGE]) ||
      facts(repo, GOV_CANDIDATE)?.tree !== GOV_TREE || facts(repo, GOV_MERGE)?.tree !== GOV_TREE ||
      !equal(facts(repo, GOV_MERGE)?.parents, ['c07e1aae94f681733ad73c1800423248bcc72376', GOV_CANDIDATE]) ||
      !firstParentContains(repo, main, R1_BASE) || !firstParentContains(repo, head, R1_BASE)) {
    problems.push('R1 does not descend from the exact Owner-accepted governance closeout on main');
  }
  for (const relative of GOV_FROZEN) {
    const accepted = blob(repo, R1_BASE, relative);
    let current = null; try { current = read(repo, relative); } catch { /* fail closed */ }
    if (accepted === null || current !== accepted || blob(repo, main, relative) !== accepted ||
        rows(repo, ['log', '--first-parent', '--full-history', '--format=%H', `${R1_BASE}..${head}`, '--', relative]).length > 0 ||
        rows(repo, ['log', '--first-parent', '--full-history', '--format=%H', `${R1_BASE}..${main}`, '--', relative]).length > 0) {
      problems.push(`accepted governance anchor changed: ${relative}`);
    }
  }
  return problems;
}
export function expectedR1ConstructionStatus(repo, candidateCommit = null) {
  const text = blob(repo, R1_BASE, STATUS_PATH);
  if (text === null) throw new Error('accepted R1 base status unavailable');
  const expected = JSON.parse(text);
  expected.as_of = '2026-10-06';
  expected.authority_snapshot_id = 'AIPT-MVP-B005-R1-CONSTRUCTION-001';
  const b005 = expected.repositories.AIPT.mvp_b005;
  b005.publicly_pushed = true;
  b005.public_ci_status = 'HISTORICAL_MERGE_CI_SUCCESS_POST_MERGE_SECURITY_BLOCKED_R1_PENDING';
  b005.open_findings = [...FINDINGS];
  b005.blocked_implementation = {
    commit: 'c07e1aae94f681733ad73c1800423248bcc72376', tree: '828defa8ea85a757b43d1a04ce05016ebeea9020',
    public_ci_run: 33767358596, public_ci_conclusion: 'success', post_merge_security_result: 'FAIL',
    accepted_as_final_merge: false, lifecycle_records_created: false,
  };
  b005.r1_recovery = {
    task_id: B005_TASK, revision: 'R1', state: 'IN_PROGRESS_PENDING_INDEPENDENT_ACCEPTANCE',
    start_authority: 'OWNER_CONTINUE_M0_MVP_AND_AUTHORIZED_B005_R1',
    base: { commit: R1_BASE, tree: R1_BASE_TREE },
    governance: { task_id: GOV_TASK, state: 'CLOSED', candidate_commit: GOV_CANDIDATE, merge_commit: GOV_MERGE,
      closeout_commit: R1_BASE, policy_sha256: 'fb0cfe0f253c468bc00816d7f1d499e6945898e807db36207a8dd04752a82649',
      independent_ci_catalogue_sha256: '3c9957885db84923efb60eecd38b114eb61eb4aefec70379e6332662c5166059' },
    policy_id: 'ONLINE_GITHUB_REMOTE_PROVENANCE_V1', provider: 'GITHUB_PUBLIC_HTTPS_API_V1',
    production_entry: 'BUILTIN_FIXED_ANONYMOUS_HTTPS_ONLY', test_seam: 'PACKAGE_PRIVATE_SYNTHETIC_ONLY',
    mirror_status: 'LOCAL_OBJECT_MATCH', receipt_fields: 8, receipt_bound_into_root: true,
    fresh_github_requests_per_generation: 1, fresh_github_requests_per_independent_verification: 1,
    expected_repository_bound_before_online_verification: true,
    optional_mirror_bound_to_held_raw_source: true,
    remote_probe_count: 12, git_safety_probe_count: 2, synthetic_ci_github_requests: 0,
    real_model_calls: 0, qualification_runs_executed: 0, public_candidate_status: 'PENDING',
    independent_security_acceptance: 'PENDING', open_findings: [...FINDINGS],
  };
  expected.runtime.status = 'AIPT-MVP-B005 R1 is the sole active construction batch at GLOBAL_WIP 1 after accepted remote-provenance governance closeout; fixed online GitHub Commit/Tree verification and bounded local consistency checks are implemented pending independent acceptance; runtime_ready remains false at IPC and real playtest/qualification Runs remain unexecuted';
  const repair = candidateCommit ? candidateBase(repo, candidateCommit) === R6_BASE : fs.existsSync(path.join(repo, R6_AUTHORITY_PATH));
  if (repair) {
    expected.authority_snapshot_id = 'AIPT-MVP-B005-R1-R6-CONSTRUCTION-001';
    b005.public_ci_status = 'R5_POST_MERGE_SECURITY_FAIL_R6_REPAIR_PENDING';
    b005.open_findings = [...FINDINGS, R6_RECEIPT_FINDING];
    b005.r1_recovery.revision = 'R6';
    b005.r1_recovery.base = { commit: R6_BASE, tree: R6_BASE_TREE };
    b005.r1_recovery.original_governance_base = { commit: R1_BASE, tree: R1_BASE_TREE };
    b005.r1_recovery.failed_r5_post_merge = expectedR6RepairAuthority().failed_post_merge;
    b005.r1_recovery.owner_authorization = { decision_id: 'B005-R6-POST-MERGE-REPAIR-Q001=A', path: R6_AUTHORITY_PATH,
      sha256: digest(`${JSON.stringify(expectedR6RepairAuthority(), null, 2)}\n`) };
    b005.r1_recovery.receipt_field_names_case_sensitive = true;
    b005.r1_recovery.receipt_canonical_bytes_enforced = true;
    b005.r1_recovery.receipt_field_alias_regression_cases = 16;
    b005.r1_recovery.valid_chunked_receipt_control = true;
    b005.r1_recovery.independent_review_source = 'LOCAL_INDEPENDENT_CODEX_AGENT';
    b005.r1_recovery.open_findings = [...FINDINGS, R6_RECEIPT_FINDING];
    expected.runtime.status = 'AIPT-MVP-B005 R6 is the sole active repair batch after R5 local independent review FAIL; exact canonical receipt bytes are enforced, final independent acceptance is pending; runtime_ready remains false at IPC and no real playtest or qualification Run has started';
  }
  return expected;
}
export function expectedB005CloseoutStatus(repo, candidate, merge, catalogue) {
  const expected = expectedR1ConstructionStatus(repo, candidate.commit);
  expected.authority_snapshot_id = candidateBase(repo, candidate.commit) === R6_BASE ? 'AIPT-MVP-B005-R1-R6-CLOSEOUT-001' : 'AIPT-MVP-B005-R1-CLOSEOUT-001';
  const track = expected.tracks['AIPT-STANDALONE'];
  track.construction = 'IDLE_WAITING_NEXT_BATCH'; track.current_batch = 'NO_ACTIVE_BATCH'; track.global_wip = 0;
  track.batch_history[B005_TASK] = 'MERGED_CLOSED';
  const b005 = expected.repositories.AIPT.mvp_b005;
  b005.state = 'MERGED_CLOSED'; b005.open_findings = [];
  b005.public_ci_status = 'R1_POST_MERGE_CI_AND_INDEPENDENT_SECURITY_ACCEPTED';
  b005.r1_recovery.state = 'MERGED_CLOSED'; b005.r1_recovery.public_candidate_status = 'ACCEPTED';
  b005.r1_recovery.independent_security_acceptance = 'PASS'; b005.r1_recovery.open_findings = [];
  b005.r1_recovery.candidate = { commit: candidate.commit, tree: candidate.tree };
  b005.r1_recovery.merge = { commit: merge.commit, tree: merge.tree, parents: merge.parents };
  b005.r1_recovery.post_merge_ci = { run_id: catalogue.run.id, head_sha: merge.commit, conclusion: 'success', jobs_passed: 5, jobs_failed: 0, jobs_skipped: 0,
    independent_catalogue_path: B005_CI_PATH, independent_catalogue_sha256: digest(`${JSON.stringify(catalogue, null, 2)}\n`) };
  b005.r1_recovery.closed_findings = [...FINDINGS, ...(candidateBase(repo, candidate.commit) === R6_BASE ? [R6_RECEIPT_FINDING] : [])];
  expected.runtime.status = 'AIPT-MVP-B005 R1 evidence closure is MERGED_CLOSED after exact post-merge CI and independent security acceptance; runtime_ready remains false at IPC; no real playtest or qualification Run has started';
  return expected;
}
export function renderB005CloseoutHumanStatus(repo, candidate, merge, catalogue) {
  const frozen = blob(repo, candidate.commit, 'docs/authority/PROJECT_STATUS.md');
  if (frozen === null) throw new Error('B005 Candidate human status unavailable');
  const repairNote = candidateBase(repo, candidate.commit) === R6_BASE ? ` R6 独立验收来源为 LOCAL_INDEPENDENT_CODEX_AGENT；收据 finding ${R6_RECEIPT_FINDING} 已关闭。旧 R5 merge ${R6_BASE} 的独立审查 FAIL 与成功 CI 保留为失败历史，NOT_ACCEPTED。` : '';
  return frozen + `\nB005 R1 正式关闭（2026-10-06）：Candidate ${candidate.commit}（tree ${candidate.tree}）由合法 merge ${merge.commit} 集成；精确 post-merge CI ${catalogue.run.id} 的 5/5 jobs 为 success，独立安全验收 PASS，三项 R1 findings 已关闭。B005 = MERGED_CLOSED；M0 = 100%，MVP = 8/13（61.5%），按 22 项等权批次总体 = 17/22（77.3%）。关闭时 GLOBAL_WIP=0，B006 未启动；runtime_ready=false，首个阻塞 gate=IPC，真实桌测与资格 Run=0。依据为 canonical B005 append-only lifecycle records 与独立不可变 CI catalogue。原 failed merge c07e1aae94f681733ad73c1800423248bcc72376 保持 NOT_ACCEPTED。${repairNote}\n`;
}
function exactKeys(value, keys) { return value !== null && typeof value === 'object' && !Array.isArray(value) && equal(Object.keys(value).sort(), [...keys].sort()); }
function positiveID(value) { return Number.isSafeInteger(value) && value > 0; }
const CI_JOB_NAMES = ['b000-retro (fixed B000 commit, read-only expansion)', 'toolchain (ubuntu-24.04)', 'toolchain (ubuntu-26.04)', 'supply-chain (R4-Q023 gates)', 'storage-postgres (ephemeral PostgreSQL 18.4 integration)'].sort();
export function ciCatalogueProblems(catalogue, merge, workflowSha256) {
  const problems = [];
  if (!exactKeys(catalogue, ['schema', 'version', 'task_id', 'repository', 'workflow_path', 'workflow_sha256', 'acceptance', 'run', 'jobs']) ||
      catalogue.schema !== 'aipt.public.verified-ci-evidence/v1' || catalogue.version !== '1.0.0' || catalogue.task_id !== B005_TASK ||
      catalogue.repository !== 'zyc14588/AIPT' || catalogue.workflow_path !== '.github/workflows/ci.yml' || catalogue.workflow_sha256 !== workflowSha256) problems.push('B005 independent CI catalogue identity/workflow is invalid');
  const acceptance = catalogue?.acceptance;
  if (!exactKeys(acceptance, ['decision_id', 'mode', 'offline_trust_basis', 'verified_at']) ||
      acceptance?.decision_id !== 'B005-GOV-CI-Q001=A' || acceptance?.mode !== 'LOCAL_ONLINE_GITHUB_ACTIONS_VERIFICATION' ||
      acceptance?.offline_trust_basis !== 'OWNER_ACCEPTED_IMMUTABLE_MAIN_CI_CATALOGUE' ||
      typeof acceptance?.verified_at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(acceptance.verified_at) || !Number.isFinite(Date.parse(acceptance.verified_at))) problems.push('B005 independent CI catalogue lacks authorized online acceptance basis');
  const run = catalogue?.run;
  if (!exactKeys(run, ['id', 'head_sha', 'head_branch', 'event', 'status', 'conclusion', 'run_attempt']) || !positiveID(run?.id) || !positiveID(run?.run_attempt) ||
      run?.head_sha !== merge?.commit || run?.head_branch !== 'main' || run?.event !== 'push' || run?.status !== 'completed' || run?.conclusion !== 'success') problems.push('B005 independent CI catalogue is not an exact successful main merge run');
  const jobs = catalogue?.jobs;
  if (!Array.isArray(jobs) || jobs.length !== 5 || !equal(jobs.map((job) => job?.name).sort(), CI_JOB_NAMES) || new Set(jobs.map((job) => job?.id)).size !== 5 ||
      jobs.some((job) => !exactKeys(job, ['id', 'name', 'head_sha', 'status', 'conclusion']) || !positiveID(job.id) || job.head_sha !== merge?.commit || job.status !== 'completed' || job.conclusion !== 'success')) problems.push('B005 independent CI catalogue lacks all five exact successful jobs');
  return problems;
}
function postFacts(catalogue) { return { run_id: catalogue.run.id, head_sha: catalogue.run.head_sha, conclusion: 'success', jobs_passed: 5, jobs_failed: 0, jobs_skipped: 0 }; }
function legalMerge(repo, candidate, head) {
  const merge = facts(repo, head); const base = candidateBase(repo, candidate?.commit);
  return base && candidate?.commit !== R6_REJECTED_CANDIDATE && merge?.tree === candidate?.tree &&
    equal(merge?.parents, [base, candidate?.commit]) ? merge : null;
}
function lifecycle(repo, head, proposal = false) {
  const problems = [];
  const acceptedMain = proposal ? head : out(repo, ['rev-parse', 'refs/remotes/origin/main^{commit}']);
  const introductions = B005_RECORD_PATHS.map((relative) => rows(repo, ['log', '--first-parent', '--reverse', '--format=%H', '--diff-filter=A', acceptedMain, '--', relative]));
  if (introductions.every((r) => r.length === 0)) return { accepted: false, problems: ['B005 lifecycle is not accepted on main'] };
  if (introductions.some((r) => r.length !== 1) || new Set(introductions.map((r) => r[0])).size !== 1) return { accepted: false, problems: ['B005 lifecycle is partial, duplicated or forked'] };
  const closeoutCommit = introductions[0][0];
  if (!firstParentContains(repo, head, closeoutCommit)) problems.push('B005 closeout is outside first-parent ancestry');
  let records, catalogue;
  try { records = B005_RECORD_PATHS.map((relative) => JSON.parse(blob(repo, closeoutCommit, relative))); catalogue = JSON.parse(blob(repo, closeoutCommit, B005_CI_PATH)); }
  catch { return { accepted: false, problems: [...problems, 'B005 accepted lifecycle/independent CI evidence is unreadable'] }; }
  const identity = records[0]?.semantic_artifact_identity;
  const candidate = facts(repo, identity?.candidate_commit);
  const merge = facts(repo, records[0]?.event_evidence?.merge_identity?.commit);
  const paths = candidate ? changed(repo, R1_BASE, candidate.commit) : [];
  if (!candidate || !candidateBase(repo, candidate.commit) || candidate.commit === R6_REJECTED_CANDIDATE ||
      !legalMerge(repo, candidate, merge?.commit) || !equal(facts(repo, closeoutCommit)?.parents, [merge?.commit])) {
    problems.push('B005 closeout does not bind an exact authorized Candidate/Base merge and direct successor');
  }
  if (candidate) problems.push(...candidateScopeProblems(repo, candidate.commit));
  const closeoutPaths = merge ? changed(repo, merge.commit, closeoutCommit) : [];
  if (closeoutPaths.some((p) => !CLOSEOUT_ALLOWED.has(p)) || [...B005_RECORD_PATHS, B005_CI_PATH, STATUS_PATH, 'docs/authority/PROJECT_STATUS.md'].some((p) => !closeoutPaths.includes(p))) problems.push('B005 closeout includes business changes or misses required projections/evidence');
  problems.push(...ciCatalogueProblems(catalogue, merge, digest(blob(repo, merge?.commit, '.github/workflows/ci.yml') ?? '')));
  const immutablePaths = [...B005_RECORD_PATHS, B005_CI_PATH];
  for (const revision of new Set([head, acceptedMain])) {
    if (rows(repo, ['log', '--first-parent', '--full-history', '--format=%H', `${closeoutCommit}..${revision}`, '--', B005_RECORD_ROOT, path.posix.dirname(B005_CI_PATH)]).length > 0) problems.push('B005 lifecycle or CI catalogue was rewritten after closeout');
    const recordInventory = rows(repo, ['ls-tree', '-r', '--name-only', revision, '--', B005_RECORD_ROOT]);
    const catalogueInventory = rows(repo, ['ls-tree', '-r', '--name-only', revision, '--', path.posix.dirname(B005_CI_PATH)]);
    if (!equal(recordInventory.sort(), [...B005_RECORD_PATHS].sort()) || !equal(catalogueInventory, [B005_CI_PATH])) problems.push('B005 accepted evidence inventory is not exact');
  }
  for (const relative of immutablePaths) {
    const introduced = blob(repo, closeoutCommit, relative);
    let current = null; try { current = read(repo, relative); } catch { /* fail closed */ }
    if (introduced === null || current !== introduced || blob(repo, acceptedMain, relative) !== introduced) problems.push(`B005 immutable accepted evidence changed: ${relative}`);
    if (!equal(rows(repo, ['log', '--first-parent', '--format=%H', '--diff-filter=A', acceptedMain, '--', relative]), [closeoutCommit])) problems.push('B005 accepted evidence has an invalid introduction');
  }
  for (const relative of paths.filter((p) => (p.startsWith('internal/evidence/') || p.startsWith('cmd/aipt-audit-ready/')) && p.endsWith('.go') && !p.endsWith('_test.go') || p === REMOTE_SCHEMA_PATH || p === REMOTE_MATRIX_PATH || p === R6_AUTHORITY_PATH)) {
    let current = null; try { current = read(repo, relative); } catch { /* fail closed */ }
    if (current !== blob(repo, candidate?.commit, relative) || rows(repo, ['log', '--first-parent', '--full-history', '--format=%H', `${merge?.commit}..${head}`, '--', relative]).length > 0) problems.push(`accepted R1 runtime/schema/matrix changed: ${relative}`);
  }
  try {
    if (!equal(fs.readdirSync(path.join(repo, B005_RECORD_ROOT)).sort(), B005_RECORD_PATHS.map((p) => path.posix.basename(p)).sort()) ||
        !equal(fs.readdirSync(path.join(repo, path.posix.dirname(B005_CI_PATH))), ['post-merge-ci.json'])) problems.push('B005 working evidence inventory contains unexpected files');
  } catch { problems.push('B005 working evidence inventory is unreadable'); }
  const expectedIdentity = {
    task_id: B005_TASK, artifact_id: B005_TASK, artifact_path: 'internal/evidence/remote_provenance.go',
    artifact_sha256: digest(blob(repo, candidate?.commit, 'internal/evidence/remote_provenance.go') ?? ''),
    candidate_commit: candidate?.commit, candidate_tree: candidate?.tree, semantic_snapshot_state: 'CANDIDATE_FROZEN', semantic_snapshot_accepted: false,
  };
  if (!equal(identity, expectedIdentity)) problems.push('B005 lifecycle semantic identity is not exact');
  const schema = JSON.parse(read(repo, 'schemas/authority-lifecycle/v1/aipt-authority-lifecycle-record.schema.json'));
  const ids = ['MERGED', 'POST-MERGE-VERIFIED', 'CLOSED'].map((event, index) => `${B005_TASK}-LIFECYCLE-00${index + 1}-${event}`);
  for (const [index, record] of records.entries()) {
    problems.push(...validateInstance(schema, record).errors.map((error) => error.message));
    const provenance = { source_task: B005_TASK, source_commit: index === 0 ? candidate?.commit : merge?.commit, source_tree: candidate?.tree,
      record_creation_authority: 'MERGE_AND_CLOSEOUT_AIPT_MVP_B005_R1', record_creator_task: B005_TASK, historical_evidence_claimed_only_if_proven: true };
    if (record.record_id !== ids[index] || record.created_by_task !== B005_TASK || record.authority_basis?.authorized_by_task !== B005_TASK ||
        record.authority_basis?.authorization_kind !== 'ACCEPTED_LIFECYCLE_MODEL' || !equal(record.provenance, provenance) ||
        record.record_identity?.path !== B005_RECORD_PATHS[index] || read(repo, B005_RECORD_PATHS[index]) !== `${JSON.stringify(record, null, 2)}\n`) problems.push('B005 lifecycle identity/provenance/serialization drifted');
  }
  const resolution = resolveEffectiveAuthority({ semantic_artifact_identity: expectedIdentity, records,
    policy: { model_id: AUTHORITY_LIFECYCLE_MODEL, events: AUTHORITY_LIFECYCLE_EVENTS, ordering: AUTHORITY_LIFECYCLE_ORDERING,
      canonical_truth_source: 'ACCEPTED_APPEND_ONLY_LIFECYCLE_RECORD_CHAIN', semantic_fields_are_snapshot_metadata: true, semantic_artifact_mutation_permitted: false, unlisted_transition: 'REJECT', closed_terminal: true },
    record_acceptance: Object.fromEntries(records.map((record, index) => [record.record_id, { accepted: true, commit: closeoutCommit, commit_ordinal: 1, first_parent_ancestry: true,
      path: B005_RECORD_PATHS[index], introduced_sha256: digest(blob(repo, closeoutCommit, B005_RECORD_PATHS[index]) ?? ''), current_sha256: digest(read(repo, B005_RECORD_PATHS[index])), canonical_record_sha256: lifecycleRecordSha256(record) }])),
    authority_basis_acceptance: Object.fromEntries(ids.map((id) => [id, true])), evidence_catalogue: {
      merge_commits: merge ? { [merge.commit]: { tree: merge.tree, parents: merge.parents, accepted_ancestry: true } } : {},
      post_merge_runs: catalogue && problems.length === 0 ? { [String(catalogue.run.id)]: postFacts(catalogue) } : {},
      closeout_records: { [ids[2]]: { commit: closeoutCommit, governance_only: true, owner_authorized: true } },
    }, expected_accepted_record_ids: ids, expected_lifecycle_state: 'CLOSED' });
  problems.push(...resolution.problems);
  try {
    if (blob(repo, closeoutCommit, 'docs/authority/PROJECT_STATUS.md') !== renderB005CloseoutHumanStatus(repo, candidate, merge, catalogue)) problems.push('B005 closeout human status is not canonical');
    if (!equal(JSON.parse(blob(repo, candidate.commit, STATUS_PATH)), expectedR1ConstructionStatus(repo, candidate.commit)) ||
        !equal(JSON.parse(blob(repo, closeoutCommit, STATUS_PATH)), expectedB005CloseoutStatus(repo, candidate, merge, catalogue))) problems.push('B005 Candidate/closeout status projection is not exact');
  } catch { problems.push('B005 historical status projection is unreadable'); }
  return { accepted: !proposal && problems.length === 0 && resolution.effective, proposal_valid: proposal && problems.length === 0 && resolution.effective,
    problems, candidate, merge, closeoutCommit, catalogue, paths, resolution };
}
export function resolveB005R1Topology(repo) {
  const head = out(repo, ['rev-parse', 'HEAD^{commit}']); const headFacts = facts(repo, head);
  const branch = out(repo, ['branch', '--show-current']) || process.env.GITHUB_HEAD_REF || (process.env.GITHUB_REF?.startsWith('refs/heads/') ? process.env.GITHUB_REF.slice(11) : 'DETACHED');
  const paths = inventory(repo);
  const problems = acceptedGovernanceProblems(repo, head);
  const present = fs.existsSync(path.join(repo, B005_RECORD_ROOT));
  if (present) {
    const accepted = lifecycle(repo, head);
    if (accepted.accepted) return { phase: problems.length ? 'REJECTED' : 'CLOSED_HISTORICAL_REPLAY', head, headFacts, branch, candidate: accepted.candidate?.commit, paths: accepted.paths, problems, lifecycle: accepted };
    const proposal = dirty(repo) ? null : lifecycle(repo, head, true);
    if (proposal?.proposal_valid) return { phase: problems.length ? 'REJECTED' : 'CLOSEOUT_PROPOSAL', head, headFacts, branch, candidate: proposal.candidate?.commit, paths: proposal.paths, problems, lifecycle: proposal };
    return { phase: 'REJECTED', head, headFacts, branch, candidate: null, paths, problems: [...problems, ...accepted.problems, ...(proposal?.problems ?? [])] };
  }
  const scopeValid = paths.every((p) => R1_ALLOWED.has(p));
  const repairPresent = fs.existsSync(path.join(repo, R6_AUTHORITY_PATH));
  if (repairPresent && branch === 'codex/aipt-mvp-b005-r1-r6' &&
      (head === R6_BASE || repairCandidate(repo, head)) && scopeValid) {
    const candidate = head === R6_BASE ? null : head;
    const repairPaths = [...new Set([...changed(repo, R6_BASE, 'HEAD'),
      ...rows(repo, ['diff', '--name-only', '--no-renames']),
      ...rows(repo, ['diff', '--cached', '--name-only', '--no-renames']),
      ...rows(repo, ['ls-files', '--others', '--exclude-standard'])])].filter((p) => !p.split('/').includes('node_modules'));
    const repairProblems = [...problems, ...repairAuthorityProblems(repo, head, candidate)];
    if (repairPaths.some((p) => !R6_REQUIRED_CHANGED.includes(p)) ||
        R6_REQUIRED_CHANGED.some((p) => !repairPaths.includes(p))) repairProblems.push('R6 construction scope is not exact');
    if (candidate) repairProblems.push(...candidateScopeProblems(repo, candidate));
    return { phase: repairProblems.length ? 'REJECTED' : dirty(repo) ? 'CONSTRUCTION' : candidate ? 'CANDIDATE' : 'REJECTED',
      revision: 'R6', base: R6_BASE, head, headFacts, branch, candidate, paths, problems: repairProblems };
  }
  if (head === R6_REJECTED_CANDIDATE || head === R6_BASE) return { phase: 'REJECTED', head, headFacts, branch, candidate: null, paths,
    problems: [...problems, 'known failed R5 Candidate/merge cannot receive final acceptance'] };
  if (dirty(repo) && /^codex\/aipt-mvp-b005-r1(?:-r[1-9][0-9]*)?$/u.test(branch) && (head === R1_BASE || linear(repo, head)) && scopeValid && !repairPresent) return { phase: problems.length ? 'REJECTED' : 'CONSTRUCTION', head, headFacts, branch, candidate: null, paths, problems };
  if (!dirty(repo) && /^codex\/aipt-mvp-b005-r1(?:-r[1-9][0-9]*)?$/u.test(branch) && linear(repo, head) && scopeValid && !repairPresent) return { phase: problems.length ? 'REJECTED' : 'CANDIDATE', head, headFacts, branch, candidate: head, paths, problems };
  const merges = rows(repo, ['rev-list', '--first-parent', `${R1_BASE}..${head}`]).map((revision) => {
    const m = facts(repo, revision); const c = facts(repo, m?.parents[1]);
    return c && candidateBase(repo, c.commit) && legalMerge(repo, c, revision) ? { merge: m, candidate: c } : null;
  }).filter(Boolean);
  if (!dirty(repo) && merges.length === 1) {
    const { merge, candidate } = merges[0]; const candidatePaths = changed(repo, R1_BASE, candidate.commit);
    const scopeProblems = candidateScopeProblems(repo, candidate.commit); problems.push(...scopeProblems);
    const legal = scopeProblems.length === 0 && merge.commit === head;
    return { phase: legal && !problems.length ? 'LEGAL_MERGE' : 'REJECTED', head, headFacts, branch, candidate: candidate.commit, paths: candidatePaths, problems, merge };
  }
  return { phase: 'REJECTED', head, headFacts, branch, candidate: null, paths, problems: [...problems, 'B005 R1 branch/base/scope/merge topology is not authorized'] };
}
export function b005R1StatusProblems(repo, status, topology = resolveB005R1Topology(repo)) {
  if (['CONSTRUCTION', 'CANDIDATE', 'LEGAL_MERGE'].includes(topology.phase)) return equal(status, expectedR1ConstructionStatus(repo)) ? [] : ['project-status differs from exact B005 R1 construction projection'];
  if (['CLOSEOUT_PROPOSAL', 'CLOSED_HISTORICAL_REPLAY'].includes(topology.phase)) {
    const l = topology.lifecycle; const frozen = expectedB005CloseoutStatus(repo, l.candidate, l.merge, l.catalogue);
    if (topology.phase === 'CLOSEOUT_PROPOSAL' || topology.head === l.closeoutCommit) return equal(status, frozen) ? [] : ['project-status differs from exact B005 R1 closeout projection'];
    const track = status?.tracks?.['AIPT-STANDALONE'];
    return equal(status?.repositories?.AIPT?.mvp_b005, frozen.repositories.AIPT.mvp_b005) && track?.batch_history?.[B005_TASK] === 'MERGED_CLOSED' &&
      Number.isInteger(track?.global_wip) && track.global_wip >= 0 && track.global_wip <= 1 ? [] : ['project-status reopened or changed the accepted B005 closeout'];
  }
  return ['project-status has no accepted B005 R1 topology'];
}
