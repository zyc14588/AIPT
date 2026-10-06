import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  R1_BASE, R1_BASE_TREE, R1_BRANCH, R1_REQUIRED_CHANGED, STATUS_PATH,
  B005_TASK, B005_RECORD_PATHS, B005_RECORD_ROOT, B005_CI_PATH,
  facts, blob, digest, resolveB005R1Topology, b005R1StatusProblems,
  expectedR1ConstructionStatus, expectedB005CloseoutStatus, renderB005CloseoutHumanStatus,
} from '../lib/b005-r1-lifecycle.mjs';
import { lifecycleRecordSha256 } from '../lib/authority-lifecycle.mjs';

// Local Git fixtures only. Fake job IDs are never accepted in the actual
// project; each acceptance ref belongs exclusively to its disposable clone.
const source = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
function git(repo, ...args) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GITHUB_')));
  Object.assign(env, { GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_AUTHOR_NAME: 'AIPT Synthetic', GIT_COMMITTER_NAME: 'AIPT Synthetic', GIT_AUTHOR_EMAIL: 'synthetic@example.invalid', GIT_COMMITTER_EMAIL: 'synthetic@example.invalid', GIT_AUTHOR_DATE: '2026-10-06T02:00:00Z', GIT_COMMITTER_DATE: '2026-10-06T02:00:00Z' });
  const result = spawnSync('git', args, { cwd: repo, env, encoding: 'utf8', timeout: 15000, maxBuffer: 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  return result.stdout.trim();
}
function write(repo, relative, value) {
  const target = path.join(repo, relative); fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, typeof value === 'string' ? value : `${JSON.stringify(value, null, 2)}\n`);
}
function fixture(t, closed = false, accepted = false) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'aipt-b005-r1-lifecycle-test-'));
  t.after(() => fs.rmSync(temp, { recursive: true, force: true }));
  const repo = path.join(temp, 'repo');
  git(temp, 'clone', '--quiet', '--no-local', '--no-checkout', source, repo);
  git(repo, 'checkout', '--quiet', '-B', R1_BRANCH, R1_BASE);
  assert.equal(git(repo, 'rev-parse', 'HEAD^{tree}'), R1_BASE_TREE);
  git(repo, 'update-ref', 'refs/remotes/origin/main', R1_BASE);
  for (const relative of R1_REQUIRED_CHANGED) write(repo, relative, fs.readFileSync(path.join(source, relative), 'utf8'));
  write(repo, STATUS_PATH, expectedR1ConstructionStatus(repo));
  git(repo, 'add', '--', ...R1_REQUIRED_CHANGED);
  git(repo, 'commit', '--quiet', '-m', 'synthetic R1 candidate');
  const candidate = facts(repo, git(repo, 'rev-parse', 'HEAD'));
  if (!closed) return { repo, candidate };
  git(repo, 'checkout', '--quiet', '-B', 'main', R1_BASE);
  git(repo, 'merge', '--quiet', '--no-ff', '--no-edit', candidate.commit);
  const merge = facts(repo, git(repo, 'rev-parse', 'HEAD'));
  git(repo, 'update-ref', 'refs/remotes/origin/main', merge.commit);
  const catalogue = {
    schema: 'aipt.public.verified-ci-evidence/v1', version: '1.0.0', task_id: B005_TASK,
    repository: 'zyc14588/AIPT', workflow_path: '.github/workflows/ci.yml', workflow_sha256: digest(blob(repo, merge.commit, '.github/workflows/ci.yml')),
    acceptance: { decision_id: 'B005-GOV-CI-Q001=A', mode: 'LOCAL_ONLINE_GITHUB_ACTIONS_VERIFICATION', offline_trust_basis: 'OWNER_ACCEPTED_IMMUTABLE_MAIN_CI_CATALOGUE', verified_at: '2026-10-06T02:00:00.000Z' },
    run: { id: 1, head_sha: merge.commit, head_branch: 'main', event: 'push', status: 'completed', conclusion: 'success', run_attempt: 1 },
    jobs: ['b000-retro (fixed B000 commit, read-only expansion)', 'toolchain (ubuntu-24.04)', 'toolchain (ubuntu-26.04)', 'supply-chain (R4-Q023 gates)', 'storage-postgres (ephemeral PostgreSQL 18.4 integration)'].map((name, index) => ({ id: index + 1, name, head_sha: merge.commit, status: 'completed', conclusion: 'success' })),
  };
  const identity = { task_id: B005_TASK, artifact_id: B005_TASK, artifact_path: 'internal/evidence/remote_provenance.go', artifact_sha256: digest(blob(repo, candidate.commit, 'internal/evidence/remote_provenance.go')), candidate_commit: candidate.commit, candidate_tree: candidate.tree, semantic_snapshot_state: 'CANDIDATE_FROZEN', semantic_snapshot_accepted: false };
  const records = [];
  for (let index = 0; index < 3; index += 1) {
    const record = JSON.parse(blob(repo, R1_BASE, `docs/authority/registry/authority-lifecycle/records/aipt-mvp-b004/${['001-merged','002-post-merge-verified','003-closed'][index]}.json`));
    record.record_id = `${B005_TASK}-LIFECYCLE-00${index + 1}-${['MERGED','POST-MERGE-VERIFIED','CLOSED'][index]}`;
    record.task_id = B005_TASK; record.semantic_artifact_identity = identity;
    record.predecessor_lifecycle_record = index ? { record_id: records[index-1].record_id, record_sha256: lifecycleRecordSha256(records[index-1]) } : null;
    record.authority_basis.authorized_by_task = B005_TASK; record.created_by_task = B005_TASK;
    record.record_identity.path = B005_RECORD_PATHS[index];
    record.provenance = { source_task: B005_TASK, source_commit: index ? merge.commit : candidate.commit, source_tree: candidate.tree, record_creation_authority: 'MERGE_AND_CLOSEOUT_AIPT_MVP_B005_R1', record_creator_task: B005_TASK, historical_evidence_claimed_only_if_proven: true };
    if (index === 0) record.event_evidence.merge_identity = merge;
    if (index === 1) record.event_evidence.post_merge_evidence = { run_id: 1, head_sha: merge.commit, conclusion: 'success', jobs_passed: 5, jobs_failed: 0, jobs_skipped: 0 };
    records.push(record); write(repo, B005_RECORD_PATHS[index], record);
  }
  write(repo, B005_CI_PATH, catalogue);
  write(repo, STATUS_PATH, expectedB005CloseoutStatus(repo, candidate, merge, catalogue));
  write(repo, 'docs/authority/PROJECT_STATUS.md', renderB005CloseoutHumanStatus(repo, candidate, merge, catalogue));
  git(repo, 'add', '--', ...B005_RECORD_PATHS, B005_CI_PATH, STATUS_PATH, 'docs/authority/PROJECT_STATUS.md');
  git(repo, 'commit', '--quiet', '-m', 'synthetic B005 closeout');
  const closeout = git(repo, 'rev-parse', 'HEAD');
  if (accepted) git(repo, 'update-ref', 'refs/remotes/origin/main', closeout);
  return { repo, candidate, merge, closeout, catalogue, records };
}
test('L01 exact accepted-governance R1 candidate is eligible', (t) => {
  const { repo } = fixture(t); const topology = resolveB005R1Topology(repo);
  assert.equal(topology.phase, 'CANDIDATE', JSON.stringify(topology.problems));
  assert.deepEqual(b005R1StatusProblems(repo, JSON.parse(fs.readFileSync(path.join(repo, STATUS_PATH))), topology), []);
});
test('L02 old blocked merge cannot act as R1 base', (t) => {
  const { repo } = fixture(t); git(repo, 'checkout', '--quiet', '--detach', 'c07e1aae94f681733ad73c1800423248bcc72376');
  assert.equal(resolveB005R1Topology(repo).phase, 'REJECTED');
});
test('L03 protected predecessor edit fails scope', (t) => {
  const { repo } = fixture(t); fs.appendFileSync(path.join(repo, 'internal/modelgateway/gateway.go'), '\n// out of scope fixture\n');
  assert.equal(resolveB005R1Topology(repo).phase, 'REJECTED');
});
test('L04 governance rewrite and restore in history fails', (t) => {
  const { repo } = fixture(t); const relative = 'docs/authority/registry/remote-provenance-policy.json';
  const frozen = fs.readFileSync(path.join(repo, relative), 'utf8');
  write(repo, relative, `${frozen}\n`); git(repo, 'add', relative); git(repo, 'commit', '--quiet', '-m', 'synthetic forbidden rewrite');
  write(repo, relative, frozen); git(repo, 'add', relative); git(repo, 'commit', '--quiet', '-m', 'synthetic restore');
  assert.equal(resolveB005R1Topology(repo).phase, 'REJECTED');
});
test('L05 records not accepted on main remain a proposal', (t) => {
  const { repo } = fixture(t, true, false); const topology = resolveB005R1Topology(repo);
  assert.equal(topology.phase, 'CLOSEOUT_PROPOSAL', JSON.stringify(topology.problems));
  assert.equal(topology.lifecycle.accepted, false); assert.equal(topology.lifecycle.proposal_valid, true);
});
test('L06 accepted exact closeout supports frozen historical replay', (t) => {
  const { repo } = fixture(t, true, true); const topology = resolveB005R1Topology(repo);
  assert.equal(topology.phase, 'CLOSED_HISTORICAL_REPLAY', JSON.stringify(topology.problems));
  assert.equal(topology.lifecycle.accepted, true);
  assert.deepEqual(b005R1StatusProblems(repo, JSON.parse(fs.readFileSync(path.join(repo, STATUS_PATH))), topology), []);
});
test('L07 one failed CI job rejects a closeout', (t) => {
  const { repo, catalogue } = fixture(t, true, true); catalogue.jobs[0].conclusion = 'failure'; write(repo, B005_CI_PATH, catalogue);
  assert.equal(resolveB005R1Topology(repo).phase, 'REJECTED');
});
test('L08 lifecycle rewrite and restore in accepted history rejects', (t) => {
  const { repo } = fixture(t, true, true); const relative = B005_RECORD_PATHS[0]; const frozen = fs.readFileSync(path.join(repo, relative), 'utf8');
  write(repo, relative, `${frozen}\n`); git(repo, 'add', relative); git(repo, 'commit', '--quiet', '-m', 'synthetic lifecycle rewrite');
  write(repo, relative, frozen); git(repo, 'add', relative); git(repo, 'commit', '--quiet', '-m', 'synthetic lifecycle restore');
  git(repo, 'update-ref', 'refs/remotes/origin/main', git(repo, 'rev-parse', 'HEAD'));
  assert.equal(resolveB005R1Topology(repo).phase, 'REJECTED');
});
test('L09 fake extra lifecycle file in working state rejects', (t) => {
  const { repo, records } = fixture(t, true, true); write(repo, `${B005_RECORD_ROOT}/004-fork.json`, records[2]);
  assert.equal(resolveB005R1Topology(repo).phase, 'REJECTED');
});
test('L10 closed B005 status cannot fabricate runtime readiness or reopen B005', (t) => {
  const { repo } = fixture(t, true, true); const topology = resolveB005R1Topology(repo);
  const status = JSON.parse(fs.readFileSync(path.join(repo, STATUS_PATH))); status.runtime.runtime_ready = true;
  assert.ok(b005R1StatusProblems(repo, status, topology).length);
  const reopened = JSON.parse(fs.readFileSync(path.join(repo, STATUS_PATH))); reopened.repositories.AIPT.mvp_b005.state = 'IN_PROGRESS';
  assert.ok(b005R1StatusProblems(repo, reopened, topology).length);
});
test('L11 post-closeout runtime rewrite cannot inherit old acceptance', (t) => {
  const { repo } = fixture(t, true, true); fs.appendFileSync(path.join(repo, 'internal/evidence/remote_provenance.go'), '\n// rewritten runtime fixture\n');
  assert.equal(resolveB005R1Topology(repo).phase, 'REJECTED');
});
