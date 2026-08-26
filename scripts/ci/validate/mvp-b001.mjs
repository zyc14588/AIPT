#!/usr/bin/env node
// AIPT-MVP-B001 fail-closed Test Plan / immutable Manifest / PostgreSQL queue
// authority gate. Node.js standard library only.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  MVP_B000_IMPLEMENTATION_MERGE,
  MVP_B001,
  MVP_B001_ACCEPTANCE,
  MVP_B001_CLOSEOUT_ALLOWED_PATHS,
} from '../lib/constants.mjs';
import { git, runAsMain } from '../lib/cli.mjs';
import { checkSchemaDocument, validateInstance } from '../lib/json-schema.mjs';
import { run as runHistoricalWebValidator } from './web-ui.mjs';

const STATUS_PATH = 'docs/authority/registry/project-status.json';
const GRAPH_PATH = 'docs/authority/registry/batch-graph.json';
const TEST_PLAN_SCHEMA_PATH = 'schemas/testplan/v1/aipt-test-plan.schema.json';
const MANIFEST_SCHEMA_PATH = 'schemas/run-manifest/v1/aipt-run-manifest.schema.json';
const LEDGER_MIGRATION = 'internal/storage/postgres/migrations/000001_ledger.sql';
const LEDGER_SHA256 = 'cbab234c8d6a265397dcc553bd9bdb17006712f77ec482b0ef8332f050c9f591';
const PLATFORM = 'FROZEN_WAITING_M1_ENGINE';
const MAIN_BRANCH = 'main';
const PR_REF = /^refs\/pull\/[1-9][0-9]*\/(?:head|merge)$/;
const SUCCESSOR_AUTHORITY_BRANCH = 'task/UNREGISTERED-AIPT-P1-B000-AUTHORITY-001';
const B001_CLOSEOUT_COMMIT = 'eede815e818d87362605f55d5bfd2a0460e6e130';
const B001_CLOSEOUT_TREE = 'd2668f0ea9d3b72969199c7cd8afc5edb94c2a6b';

const TASK_TYPES = [
  'SYSTEM_QUALIFICATION', 'RULE', 'PROSE', 'ORACLE',
  'HUMAN_SIMULATION', 'ADVERSARIAL', 'PACKAGE_BUILD',
  'CALIBRATION', 'REGRESSION',
];
const PRIORITIES = [
  'RELEASE', 'HOTFIX', 'MILESTONE', 'SYSTEM',
  'CALIBRATION', 'EXPLORATORY', 'BACKGROUND',
];

const ALLOWED_PATHS = new Set([
  '.github/workflows/ci.yml',
  'README.md',
  'docs/architecture/README.md',
  'docs/authority/BATCH_DEPENDENCY_GRAPH.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'docs/milestones/MVP.md',
  'docs/test-model/README.md',
  'package.json',
  'schemas/testplan/v1/aipt-test-plan.schema.json',
  'schemas/run-manifest/v1/aipt-run-manifest.schema.json',
  'internal/testplan/contracts.go',
  'internal/testplan/contracts_test.go',
  'internal/storage/postgres/migrations/000002_playtest_queue.sql',
  'internal/storage/postgres/queue.go',
  'internal/storage/postgres/queue_errors.go',
  'internal/storage/postgres/queue_types.go',
  'internal/storage/postgres/queue_test.go',
  'internal/storage/postgres/queue_integration_test.go',
  'internal/storage/postgres/schema_test.go',
  'internal/storage/postgres/migration_integration_test.go',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/mvp-b001.mjs',
  'scripts/ci/validate/storage.mjs',
  'scripts/ci/validate/m0-development-pass.mjs',
  'scripts/ci/validate/mvp-bootstrap.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
  'scripts/ci/validate/workflow.mjs',
  'scripts/ci/validate/standalone-entrypoints.mjs',
]);

const REQUIRED_CHANGED_PATHS = [
  '.github/workflows/ci.yml', 'README.md',
  'docs/architecture/README.md', 'docs/authority/BATCH_DEPENDENCY_GRAPH.md',
  'docs/authority/PROJECT_STATUS.md', 'docs/milestones/MVP.md',
  'docs/test-model/README.md', 'package.json',
  TEST_PLAN_SCHEMA_PATH, MANIFEST_SCHEMA_PATH,
  'internal/testplan/contracts.go', 'internal/testplan/contracts_test.go',
  MVP_B001.migration, 'internal/storage/postgres/queue.go',
  'internal/storage/postgres/queue_errors.go', 'internal/storage/postgres/queue_types.go',
  'internal/storage/postgres/queue_test.go', 'internal/storage/postgres/queue_integration_test.go',
  STATUS_PATH, 'scripts/ci/lib/constants.mjs', 'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/m0-development-pass.mjs', 'scripts/ci/validate/mvp-b001.mjs',
  'scripts/ci/validate/mvp-bootstrap.mjs', 'scripts/ci/validate/standalone-entrypoints.mjs',
  'scripts/ci/validate/status-transition.mjs', 'scripts/ci/validate/storage.mjs',
  'scripts/ci/validate/tree-integrity.mjs', 'scripts/ci/validate/workflow.mjs',
];

const CANDIDATE_DOCUMENT_REQUIREMENTS = new Map([
  ['README.md', [MVP_B001.task_id, MVP_B001.authority, 'IMPLEMENT_AND_FREEZE_CANDIDATE_ONLY', MVP_B001.base_commit, MVP_B001.base_tree, 'GLOBAL_WIP = 1', MVP_B001.next_batch, 'Run Core', 'Agent']],
  ['docs/authority/PROJECT_STATUS.md', [MVP_B001.snapshot, MVP_B001.task_id, MVP_B001.authority, 'TEST_PLAN_MANIFEST_POSTGRES_QUEUE_LEASE_ONLY', 'merge_authorized = false', 'closeout_authorized = false', 'CODEX_ONLY', 'b150a551b8d465e31e418e1b2eaf5e79bbb7d28e']],
  ['docs/authority/BATCH_DEPENDENCY_GRAPH.md', [MVP_B001.task_id, 'IN_PROGRESS', MVP_B001.next_batch, 'NOT_STARTED', 'NOT_AUTHORIZED', 'GLOBAL_WIP = 1', 'Run Core']],
  ['docs/test-model/README.md', ['Campaign → Suite → Case → Run', 'SYSTEM_QUALIFICATION', 'REGRESSION', 'canonical SHA-256', 'RELEASE → HOTFIX → MILESTONE → SYSTEM → CALIBRATION → EXPLORATORY → BACKGROUND', '16', 'WIP = 1', 'pause/resume']],
  ['docs/architecture/README.md', ['000001_ledger.sql', '000002_playtest_queue.sql', 'run_id COLLATE "C"', 'WIP=1', 'TokenSource', 'Run Core']],
  ['docs/milestones/MVP.md', [MVP_B001.task_id, MVP_B001.authority, 'IN_PROGRESS', 'GLOBAL_WIP = 1', MVP_B001.next_batch, 'NOT_AUTHORIZED', 'Run Core', '真实桌测']],
]);

const CLOSEOUT_DOCUMENT_REQUIREMENTS = new Map([
  ['README.md', [MVP_B001.task_id, 'AIPT-MVP-B001-CLOSEOUT-001', 'MERGED_CLOSED',
    MVP_B001_ACCEPTANCE.candidate_commit, MVP_B001_ACCEPTANCE.candidate_tree,
    MVP_B001_ACCEPTANCE.merge_commit, String(MVP_B001_ACCEPTANCE.post_merge_ci_run),
    'GLOBAL_WIP = 0', MVP_B001.next_batch, 'NOT_AUTHORIZED', 'Run Core', 'Agent']],
  ['docs/authority/PROJECT_STATUS.md', [MVP_B001.task_id, 'AIPT-MVP-B001-CLOSEOUT-001',
    'MERGED_CLOSED', MVP_B001_ACCEPTANCE.candidate_commit, MVP_B001_ACCEPTANCE.candidate_tree,
    MVP_B001_ACCEPTANCE.merge_commit, String(MVP_B001_ACCEPTANCE.post_merge_ci_run),
    'TEST_PLAN_MANIFEST_POSTGRES_QUEUE_LEASE_ONLY', 'GLOBAL_WIP = 0', MVP_B001.next_batch,
    'NOT_STARTED', 'NOT_AUTHORIZED', 'CODEX_ONLY']],
  ['docs/authority/BATCH_DEPENDENCY_GRAPH.md', [MVP_B001.task_id, 'MERGED_CLOSED',
    MVP_B001_ACCEPTANCE.candidate_commit, MVP_B001_ACCEPTANCE.merge_commit,
    String(MVP_B001_ACCEPTANCE.post_merge_ci_run), MVP_B001.next_batch, 'NOT_STARTED',
    'NOT_AUTHORIZED', 'GLOBAL_WIP = 0', 'Run Core']],
  ['docs/test-model/README.md', ['Campaign → Suite → Case → Run', 'SYSTEM_QUALIFICATION',
    'REGRESSION', 'canonical SHA-256',
    'RELEASE → HOTFIX → MILESTONE → SYSTEM → CALIBRATION → EXPLORATORY → BACKGROUND',
    '16', 'WIP = 1', 'pause/resume']],
  ['docs/architecture/README.md', ['000001_ledger.sql', '000002_playtest_queue.sql',
    'run_id COLLATE "C"', 'WIP=1', 'TokenSource', 'Run Core']],
  ['docs/milestones/MVP.md', [MVP_B001.task_id, 'AIPT-MVP-B001-CLOSEOUT-001',
    'MERGED_CLOSED', MVP_B001_ACCEPTANCE.candidate_commit, MVP_B001_ACCEPTANCE.merge_commit,
    String(MVP_B001_ACCEPTANCE.post_merge_ci_run), 'GLOBAL_WIP = 0', MVP_B001.next_batch,
    'NOT_STARTED', 'NOT_AUTHORIZED', 'Run Core', '真实桌测']],
]);

const FROZEN_PATHS = [
  'docs/authority/registry/batch-graph.json',
  'docs/authority/registry/decisions.json',
  'docs/authority/registry/supersessions.json',
  'docs/authority/registry/deferred-parameters.json',
  'docs/milestones/M0.md',
  'docs/milestones/M0_DEVELOPMENT_PASS.md',
  'docs/milestones/m0-development-pass.json',
  '.go-version', 'go.mod', 'go.sum', 'pnpm-lock.yaml', 'pnpm-workspace.yaml',
  'tools/toolchain.lock.json', 'tools/ci-actions.lock.json', 'LICENSE',
];

const REQUIRED_MIGRATION_SQL = [
  'CREATE TABLE aipt.playtest_campaigns',
  'CREATE TABLE aipt.playtest_suites',
  'CREATE TABLE aipt.playtest_cases',
  'CREATE TABLE aipt.run_manifests',
  'CREATE TABLE aipt.playtest_runs',
  'CREATE TABLE aipt.run_dependencies',
  'CREATE TABLE aipt.playtest_queue_control',
  'CREATE TABLE aipt.run_leases',
  'CREATE TABLE aipt.run_attempts',
  'AIPT_RUN_MANIFEST_IMMUTABLE',
  'BEFORE UPDATE OR DELETE OR TRUNCATE ON aipt.run_manifests',
  'AIPT_RUN_ATTEMPT_APPEND_ONLY',
  'BEFORE UPDATE OR DELETE OR TRUNCATE ON aipt.run_attempts',
  'CREATE UNIQUE INDEX run_leases_one_active_per_run',
  'CREATE UNIQUE INDEX run_leases_one_active_formal_slot',
  "WHERE status = 'ACTIVE' AND formal_slot = 1",
  'token_sha256', 'generation', 'heartbeat_at', 'expires_at',
  'aipt.playtest_priority_rank(priority_class)',
  'queued_at ASC', 'run_id COLLATE "C" ASC',
  "'NEW_RUN', 'SAME_RUN_RECOVERY', 'ATTEMPT'",
  "pause_scope = 'QUEUE_ONLY'",
];

function read(repo, relative) {
  return fs.readFileSync(path.join(repo, relative), 'utf8');
}

function readJSON(repo, relative) {
  return JSON.parse(read(repo, relative));
}

function baseText(repo, relative) {
  const cp = git(repo, ['show', `${MVP_B001.base_commit}:${relative}`], { check: false });
  if (cp.status !== 0) throw new Error(`fixed Base path unavailable: ${relative}`);
  return cp.stdout;
}

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function compareExact(actual, expected, at = '$') {
  const problems = [];
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual)) return [`${at} must be an array`];
    if (actual.length !== expected.length) problems.push(`${at} length drifted`);
    for (let i = 0; i < Math.min(actual.length, expected.length); i += 1) {
      problems.push(...compareExact(actual[i], expected[i], `${at}[${i}]`));
    }
    return problems;
  }
  if (isObject(expected)) {
    if (!isObject(actual)) return [`${at} must be an object`];
    const actualKeys = Object.keys(actual).sort();
    const expectedKeys = Object.keys(expected).sort();
    if (JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) problems.push(`${at} key set drifted`);
    for (const key of expectedKeys) {
      if (Object.hasOwn(actual, key)) problems.push(...compareExact(actual[key], expected[key], `${at}.${key}`));
    }
    return problems;
  }
  if (!Object.is(actual, expected)) problems.push(`${at} drifted`);
  return problems;
}

function canonicalJSON(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(',')}]`;
  if (isObject(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function bindManifest(instance) {
  const projection = clone(instance);
  delete projection.canonical_sha256;
  const digest = sha256(canonicalJSON(projection));
  return { ...projection, canonical_sha256: digest };
}

function validPlanFixture() {
  return {
    schema: 'aipt.test-plan/v1',
    plan_id: 'plan-v1',
    campaigns: [{
      campaign_id: 'campaign-1', name: 'Campaign', suites: [{
        suite_id: 'suite-1', name: 'Suite', cases: TASK_TYPES.map((taskType, index) => ({
          case_id: `case-${index + 1}`, name: `Case ${index + 1}`, task_type: taskType,
          runs: [{
            run_id: `run-${index + 1}`, run_type: taskType, manifest_id: `manifest-${index + 1}`,
            attempt_policy: { scope: 'RUN_INTERNAL_ONLY', max_attempts: 3 },
          }],
        })),
      }],
    }],
  };
}

function validManifestFixture() {
  return bindManifest({
    schema: 'aipt.run-manifest/v1', manifest_id: 'manifest-1', run_id: 'run-1',
    ancestry: { campaign_id: 'campaign-1', suite_id: 'suite-1', case_id: 'case-1' },
    run_type: 'RULE',
    source: {
      aipt: { repository: 'zyc14588/AIPT', commit: '1'.repeat(40), tree: '2'.repeat(40) },
      game: { repository: 'fixture/game', commit: '3'.repeat(40), tree: '4'.repeat(40) },
    },
    model_assignments: [{ assignment_id: 'assignment-1', model_profile_id: 'model-profile-v1' }],
    prompt_assets: [{ asset_id: 'prompt-asset-v1', sha256: '5'.repeat(64) }],
    seat_roster: [{ seat_id: 'gm', role_id: 'GM', model_assignment_id: 'assignment-1' }],
    budget: { policy_id: 'budget-policy-v1', limits_id: 'budget-limits-v1', max_input_tokens: 1000, max_output_tokens: 500, max_duration_seconds: 60 },
    evidence: { profile_id: 'evidence-profile-v1', config_id: 'evidence-config-v1' },
    visibility_profile_id: 'AIPT_VISIBILITY_STANDARD_V1',
    safety_applicable: true, safety_profile_id: 'AIPT_SAFETY_STANDARD_V1',
    classification: 'QUALIFICATION', qualification_eligible: true,
  });
}

function checkManifestDigest(instance) {
  if (!isObject(instance) || typeof instance.canonical_sha256 !== 'string') return false;
  const projection = clone(instance);
  const claimed = projection.canonical_sha256;
  delete projection.canonical_sha256;
  return sha256(canonicalJSON(projection)) === claimed;
}

function validateManifestFixture(schema, instance) {
  const errors = [...validateInstance(schema, instance).errors];
  if (!checkManifestDigest(instance)) errors.push({ message: 'canonical_sha256 mismatch' });
  const assignmentIDs = new Set((instance?.model_assignments ?? []).map((assignment) => assignment.assignment_id));
  for (const seat of instance?.seat_roster ?? []) {
    if (!assignmentIDs.has(seat.model_assignment_id)) errors.push({ message: 'seat references an unknown model assignment' });
  }
  const text = canonicalJSON(instance);
  if (/(?:api[_-]?key|authorization|bearer|credential|password|\bdsn\b|prompt[_-]?(?:body|text)|human[_-]?private|(?:sk|dsk)-[A-Za-z0-9_-]{8,})/i.test(text)) {
    errors.push({ message: 'prohibited secret/Prompt/private material' });
  }
  return errors;
}

function schemaAndMutationChecks(planSchema, manifestSchema) {
  const problems = [];
  for (const [name, schema] of [['Test Plan', planSchema], ['Run Manifest', manifestSchema]]) {
    for (const issue of checkSchemaDocument(schema).errors) problems.push(`${name} schema: ${issue}`);
  }
  const planTypes = planSchema?.$defs?.taskType?.enum;
  if (JSON.stringify(planTypes) !== JSON.stringify(TASK_TYPES)) problems.push('Test Plan task type set/order drifted');
  const plan = validPlanFixture();
  if (validateInstance(planSchema, plan).errors.length !== 0) problems.push('valid four-level Test Plan fixture rejected');
  const manifest = validManifestFixture();
  if (validateManifestFixture(manifestSchema, manifest).length !== 0) problems.push('valid bound Run Manifest fixture rejected');

  const probes = [];
  const addPlan = (label, mutate) => {
    const value = clone(plan); mutate(value);
    probes.push([label, validateInstance(planSchema, value).errors.length > 0]);
  };
  const addManifest = (label, mutate, rebind = false) => {
    let value = clone(manifest); mutate(value); if (rebind) value = bindManifest(value);
    probes.push([label, validateManifestFixture(manifestSchema, value).length > 0]);
  };
  addPlan('unknown task type', (v) => { v.campaigns[0].suites[0].cases[0].task_type = 'UNKNOWN'; });
  addPlan('Attempt fifth hierarchy level', (v) => { v.campaigns[0].suites[0].cases[0].runs[0].attempts = []; });
  addPlan('Attempt scope escaped Run', (v) => { v.campaigns[0].suites[0].cases[0].runs[0].attempt_policy.scope = 'USER_TASK'; });
  addManifest('source commit drift without digest rebind', (v) => { v.source.aipt.commit = 'f'.repeat(40); });
  addManifest('Prompt body injected', (v) => { v.prompt_body = 'private Prompt text'; }, true);
  addManifest('credential injected', (v) => { v.prompt_assets[0].asset_id = 'api_key-secret-value'; }, true);
  addManifest('private absolute path', (v) => { v.prompt_assets[0].asset_id = '/private/prompt'; }, true);
  addManifest('unknown visibility', (v) => { v.visibility_profile_id = 'UNKNOWN'; }, true);
  addManifest('unknown SafetyProfile', (v) => { v.safety_profile_id = 'UNKNOWN'; }, true);
  addManifest('diagnostic qualification forgery', (v) => { v.classification = 'DIAGNOSTIC'; }, true);
  addManifest('unknown Run type', (v) => { v.run_type = 'UNKNOWN'; }, true);
  addManifest('seat rebind', (v) => { v.seat_roster[0].model_assignment_id = 'missing'; }, true);
  for (const [label, rejected] of probes) if (!rejected) problems.push(`schema mutation accepted: ${label}`);
  return { problems, probeCount: probes.length };
}

export function checkMigrationContract(files) {
  const problems = [];
  const names = [...files.keys()].sort();
  const expected = ['000001_ledger.sql', '000002_playtest_queue.sql'];
  if (JSON.stringify(names) !== JSON.stringify(expected)) problems.push(`migration inventory = ${JSON.stringify(names)}`);
  const ledger = files.get('000001_ledger.sql');
  const queue = files.get('000002_playtest_queue.sql');
  if (!ledger || sha256(ledger) !== LEDGER_SHA256) problems.push('000001 ledger bytes/checksum drifted');
  if (!queue || sha256(queue) !== MVP_B001.migration_sha256) problems.push('000002 queue bytes/checksum drifted');
  if (queue) {
    for (const needle of REQUIRED_MIGRATION_SQL) if (!queue.includes(needle)) problems.push(`000002 misses ${needle}`);
    const executable = queue.replace(/--[^\n]*/g, '');
    if (/\bDROP\s+(?:TABLE|TYPE|FUNCTION|SCHEMA)\b|\bALTER\s+TYPE\b|\bTRUNCATE\s+(?:TABLE\s+)?aipt\./i.test(executable)) {
      problems.push('000002 contains forbidden destructive SQL');
    }
  }
  return problems;
}

function migrationMutationChecks(ledger, queue) {
  const baseline = new Map([['000001_ledger.sql', ledger], ['000002_playtest_queue.sql', queue]]);
  const probes = [
    ['000001 modified', new Map([['000001_ledger.sql', `${ledger}\n`], ['000002_playtest_queue.sql', queue]])],
    ['000002 modified', new Map([['000001_ledger.sql', ledger], ['000002_playtest_queue.sql', `${queue}\n`]])],
    ['unknown 000003 injected', new Map([...baseline, ['000003_unknown.sql', 'SELECT 1;']])],
    ['migration order/name drift', new Map([['000001_ledger.sql', ledger], ['000002_queue_drift.sql', queue]])],
    ['Manifest immutable trigger removed', new Map([['000001_ledger.sql', ledger], ['000002_playtest_queue.sql', queue.replace('AIPT_RUN_MANIFEST_IMMUTABLE', 'REMOVED')]])],
    ['WIP1 constraint removed', new Map([['000001_ledger.sql', ledger], ['000002_playtest_queue.sql', queue.replace('CREATE UNIQUE INDEX run_leases_one_active_formal_slot', 'CREATE INDEX removed_formal_slot')]])],
    ['lease ownership token removed', new Map([['000001_ledger.sql', ledger], ['000002_playtest_queue.sql', queue.replaceAll('token_sha256', 'removed_token')]])],
    ['Attempt append-only removed', new Map([['000001_ledger.sql', ledger], ['000002_playtest_queue.sql', queue.replace('AIPT_RUN_ATTEMPT_APPEND_ONLY', 'REMOVED')]])],
  ];
  return probes.map(([label, mutated]) => [label, checkMigrationContract(mutated).length > 0]);
}

function expectedCandidateStatus(base) {
  const expected = clone(base);
  expected.as_of = '2026-08-26';
  expected.authority_snapshot_id = MVP_B001.snapshot;
  const standalone = expected.tracks['AIPT-STANDALONE'];
  standalone.construction = 'IN_PROGRESS';
  standalone.current_batch = MVP_B001.task_id;
  standalone.next_serial_batch = MVP_B001.next_batch;
  standalone.next_batch_state = 'NOT_AUTHORIZED';
  standalone.next_batch_authorized = false;
  standalone.next_batch_started = false;
  standalone.batch_history[MVP_B001.task_id] = 'IN_PROGRESS';
  standalone.global_wip = 1;
  expected.repositories.AIPT.pending_candidate = {
    milestone: 'MVP', task_id: MVP_B001.task_id, authority: MVP_B001.authority,
    branch: MVP_B001.branch, base_commit: MVP_B001.base_commit, base_tree: MVP_B001.base_tree,
    state: 'IN_PROGRESS', scope: 'TEST_PLAN_MANIFEST_POSTGRES_QUEUE_LEASE_ONLY',
    merge_authorized: false, closeout_authorized: false,
  };
  return expected;
}

function expectedCloseoutStatus(base, facts) {
  const expected = expectedCandidateStatus(base);
  expected.authority_snapshot_id = 'AIPT-MVP-B001-CLOSEOUT-001';
  const standalone = expected.tracks['AIPT-STANDALONE'];
  standalone.construction = 'IDLE_WAITING_NEXT_BATCH';
  standalone.current_batch = 'NO_ACTIVE_BATCH';
  standalone.batch_history[MVP_B001.task_id] = 'MERGED_CLOSED';
  standalone.global_wip = 0;
  delete expected.repositories.AIPT.pending_candidate;
  expected.repositories.AIPT.mvp_b001 = {
    task_id: MVP_B001.task_id, state: 'MERGED_CLOSED', start_authority: MVP_B001.authority,
    closeout_authority: 'AIPT-MVP-B001-CLOSEOUT-001',
    base: { commit: MVP_B001.base_commit, tree: MVP_B001.base_tree },
    candidate: {
      commit: MVP_B001_ACCEPTANCE.candidate_commit,
      tree: MVP_B001_ACCEPTANCE.candidate_tree,
      ci_run: MVP_B001_ACCEPTANCE.candidate_ci_run,
      ci_conclusion: MVP_B001_ACCEPTANCE.candidate_ci_conclusion,
    },
    implementation_merge: {
      commit: MVP_B001_ACCEPTANCE.merge_commit,
      tree: MVP_B001_ACCEPTANCE.merge_tree,
      parents: [...MVP_B001_ACCEPTANCE.merge_parents],
      subject: MVP_B001_ACCEPTANCE.merge_subject,
    },
    post_merge_ci: {
      run: MVP_B001_ACCEPTANCE.post_merge_ci_run,
      head_sha: MVP_B001_ACCEPTANCE.post_merge_ci_head_sha,
      conclusion: MVP_B001_ACCEPTANCE.post_merge_ci_conclusion,
      jobs_passed: MVP_B001_ACCEPTANCE.post_merge_ci_jobs_passed,
      jobs_failed: MVP_B001_ACCEPTANCE.post_merge_ci_jobs_failed,
      jobs_skipped: MVP_B001_ACCEPTANCE.post_merge_ci_jobs_skipped,
    },
    scope: 'TEST_PLAN_MANIFEST_POSTGRES_QUEUE_LEASE_ONLY',
    real_model_calls: 0, real_playtest_executed: false,
    merged: true, post_merge_verified: true, closed: true, open_findings: [],
  };
  return expected;
}

function readCommit(repo, commit) {
  if (!commit) return null;
  const cp = git(repo, ['rev-list', '--parents', '-n', '1', commit], { check: false });
  if (cp.status !== 0) return null;
  const parts = cp.stdout.trim().split(/\s+/);
  const tree = git(repo, ['rev-parse', `${commit}^{tree}`], { check: false });
  const subject = git(repo, ['show', '-s', '--format=%s', commit], { check: false });
  return { commit, parents: parts.slice(1), tree: tree.stdout.trim(), subject: subject.stdout.trim() };
}

function lines(cp) {
  return cp.status === 0 ? cp.stdout.split('\n').filter(Boolean) : null;
}

export function collectLifecycleFacts(repo, env = process.env) {
  const head = git(repo, ['rev-parse', 'HEAD^{commit}']).stdout.trim();
  const headCommit = readCommit(repo, head);
  const branchCP = git(repo, ['symbolic-ref', '--short', 'HEAD'], { check: false });
  const branch = branchCP.status === 0 ? branchCP.stdout.trim() : null;
  const merges = lines(git(repo, ['rev-list', '--merges', '--reverse', `${MVP_B001.base_commit}..HEAD`], { check: false })) ?? [];
  const merge = merges.length === 1 ? readCommit(repo, merges[0]) : null;
  const candidate = merge?.parents?.length === 2 ? merge.parents[1] : head;
  const candidateCommit = readCommit(repo, candidate);
  const candidateMerges = lines(git(repo, ['rev-list', '--merges', `${MVP_B001.base_commit}..${candidate}`], { check: false })) ?? [];
  const countCP = git(repo, ['rev-list', '--count', `${MVP_B001.base_commit}..${candidate}`], { check: false });
  const historyCP = git(repo, ['rev-list', '--reverse', '--parents', `${MVP_B001.base_commit}..${candidate}`], { check: false });
  const history = lines(historyCP) ?? [];
  let previous = MVP_B001.base_commit;
  let candidateLinear = history.length > 0;
  for (const line of history) {
    const parts = line.split(/\s+/);
    if (parts.length !== 2 || parts[1] !== previous) candidateLinear = false;
    previous = parts[0];
  }
  const descendants = merge ? (lines(git(repo, ['rev-list', '--reverse', '--ancestry-path', `${merge.commit}..HEAD`], { check: false })) ?? []) : [];
  const closeoutChangedPaths = merge && descendants.length === 1
    ? (lines(git(repo, ['diff', '--name-only', '--no-renames', merge.commit, 'HEAD'], { check: false })) ?? []).sort()
    : [];
  const github = {
    present: env.GITHUB_ACTIONS === 'true', event: env.GITHUB_EVENT_NAME || null,
    ref: env.GITHUB_REF || null, headRef: env.GITHUB_HEAD_REF || null,
    baseRef: env.GITHUB_BASE_REF || null, sha: env.GITHUB_SHA || null,
  };
  let phase = 'UNKNOWN';
  if (github.present && github.event === 'pull_request' && /\/head$/.test(github.ref || '')) phase = 'PULL_REQUEST_CHECK';
  else if (github.present && github.event === 'pull_request' && /\/merge$/.test(github.ref || '')) phase = 'PULL_REQUEST_CHECK';
  else if ((github.present && github.event === 'push' && github.ref === `refs/heads/${MVP_B001.branch}`) || (!github.present && branch === MVP_B001.branch)) phase = 'CANDIDATE_PUSH';
  else if ((github.present && github.event === 'push' && github.ref === `refs/heads/${MAIN_BRANCH}`) || (!github.present && branch === MAIN_BRANCH)) phase = descendants.length === 0 ? 'POST_MERGE_MAIN' : 'CLOSEOUT_MAIN';
  return {
    baseCommit: MVP_B001.base_commit, baseTree: git(repo, ['rev-parse', `${MVP_B001.base_commit}^{tree}`]).stdout.trim(),
    head, headTree: headCommit?.tree, headCommit, branch, github, phase,
    merges, merge, candidate, candidateTree: candidateCommit?.tree, candidateCommit,
    candidateMerges, candidateCount: Number(countCP.stdout.trim()), candidateLinear,
    candidateDescends: git(repo, ['merge-base', '--is-ancestor', MVP_B001.base_commit, candidate], { check: false }).status === 0,
    descendants, closeout: descendants.length === 1 ? readCommit(repo, descendants[0]) : null,
    closeoutChangedPaths,
  };
}

export function validateLifecycleFacts(facts) {
  const problems = [];
  if (facts.baseCommit !== MVP_B001.base_commit || facts.baseTree !== MVP_B001.base_tree) problems.push('fixed Base identity drifted');
  if (!facts.candidateDescends || !facts.candidateLinear || facts.candidateMerges.length !== 0) problems.push('Candidate lineage is not linear zero-merge from exact Base');
  if (!Number.isInteger(facts.candidateCount) || facts.candidateCount < 1 || facts.candidateCount > 4) problems.push('Candidate must contain 1..4 ordinary commits');
  if (!/^[0-9a-f]{40}$/.test(facts.candidate || '') || !/^[0-9a-f]{40}$/.test(facts.candidateTree || '')) problems.push('Candidate identity unreadable');
  if (facts.github?.present && facts.github.sha !== facts.head) problems.push('GITHUB_SHA is not checked-out HEAD');
  switch (facts.phase) {
    case 'CANDIDATE_PUSH':
      if (facts.merges.length !== 0 || facts.head !== facts.candidate) problems.push('Candidate checkout contains a merge');
      if (facts.github.present) {
        if (facts.github.event !== 'push' || facts.github.ref !== `refs/heads/${MVP_B001.branch}`) problems.push('Candidate push ref/event mismatch');
      } else if (facts.branch !== MVP_B001.branch) problems.push('local Candidate branch mismatch');
      break;
    case 'PULL_REQUEST_CHECK': {
      if (facts.github.event !== 'pull_request' || !PR_REF.test(facts.github.ref || '') || facts.github.headRef !== MVP_B001.branch || facts.github.baseRef !== MAIN_BRANCH) problems.push('PR ref/head/base binding mismatch');
      const synthetic = /\/merge$/.test(facts.github.ref || '');
      if (synthetic) validateMerge(facts, problems, false);
      else if (facts.merges.length !== 0 || facts.head !== facts.candidate) problems.push('PR head contains a merge');
      break;
    }
    case 'POST_MERGE_MAIN':
      validateMainBinding(facts, problems);
      validateMerge(facts, problems, true);
      if (facts.head !== facts.merge?.commit || facts.descendants.length !== 0) problems.push('post-merge HEAD is not exact implementation merge');
      break;
    case 'CLOSEOUT_MAIN':
      validateMainBinding(facts, problems);
      validateMerge(facts, problems, true);
      if (facts.descendants.length !== 1 || facts.closeout?.commit !== facts.head || facts.closeout?.parents?.length !== 1 || facts.closeout?.parents?.[0] !== facts.merge?.commit || facts.closeout?.subject !== MVP_B001.closeout_subject) problems.push('closeout is not one exact ordinary child of implementation merge');
      if (facts.candidate !== MVP_B001_ACCEPTANCE.candidate_commit ||
          facts.candidateTree !== MVP_B001_ACCEPTANCE.candidate_tree ||
          facts.merge?.commit !== MVP_B001_ACCEPTANCE.merge_commit ||
          facts.merge?.tree !== MVP_B001_ACCEPTANCE.merge_tree) {
        problems.push('closeout does not preserve the exact Owner-approved Candidate and merge identity');
      }
      if (JSON.stringify(facts.closeoutChangedPaths) !==
          JSON.stringify([...MVP_B001_CLOSEOUT_ALLOWED_PATHS].sort())) {
        problems.push('closeout changed paths are not the exact governance-only allowlist');
      }
      break;
    default:
      problems.push('checkout cannot be classified into an authorized B001 lifecycle phase');
  }
  return { result: problems.length === 0 ? 'PASS' : 'FAIL', problems, phase: facts.phase };
}

function validateMainBinding(facts, problems) {
  if (facts.github.present) {
    if (facts.github.event !== 'push' || facts.github.ref !== `refs/heads/${MAIN_BRANCH}`) problems.push('main push ref/event mismatch');
  } else if (facts.branch !== MAIN_BRANCH) problems.push('local main branch mismatch');
}

function validateMerge(facts, problems, requireSubject) {
  if (facts.merges.length !== 1 || !facts.merge || facts.merge.parents?.length !== 2 || facts.merge.parents[0] !== MVP_B001.base_commit || facts.merge.parents[1] !== facts.candidate) problems.push('implementation merge parent topology drifted');
  if (facts.merge?.tree !== facts.candidateTree) problems.push('merge tree differs from Candidate tree');
  if (requireSubject && facts.merge?.subject !== MVP_B001.merge_subject) problems.push('implementation merge subject drifted');
}

function lifecycleRegressionChecks() {
  const id = (char) => char.repeat(40);
  const candidate = {
    baseCommit: MVP_B001.base_commit, baseTree: MVP_B001.base_tree,
    head: MVP_B001_ACCEPTANCE.candidate_commit,
    headTree: MVP_B001_ACCEPTANCE.candidate_tree,
    branch: MVP_B001.branch,
    github: { present: false, event: null, ref: null, headRef: null, baseRef: null, sha: null },
    phase: 'CANDIDATE_PUSH', merges: [], merge: null,
    candidate: MVP_B001_ACCEPTANCE.candidate_commit,
    candidateTree: MVP_B001_ACCEPTANCE.candidate_tree,
    candidateMerges: [], candidateCount: 2, candidateLinear: true, candidateDescends: true,
    descendants: [], closeout: null, closeoutChangedPaths: [],
  };
  const prHead = { ...clone(candidate), branch: null, phase: 'PULL_REQUEST_CHECK', github: { present: true, event: 'pull_request', ref: 'refs/pull/1/head', headRef: MVP_B001.branch, baseRef: MAIN_BRANCH, sha: MVP_B001_ACCEPTANCE.candidate_commit } };
  const synthetic = {
    ...clone(candidate), head: id('c'), branch: null, phase: 'PULL_REQUEST_CHECK',
    github: { present: true, event: 'pull_request', ref: 'refs/pull/1/merge', headRef: MVP_B001.branch, baseRef: MAIN_BRANCH, sha: id('c') },
    merges: [id('c')], merge: { commit: id('c'), parents: [MVP_B001.base_commit, MVP_B001_ACCEPTANCE.candidate_commit], tree: MVP_B001_ACCEPTANCE.candidate_tree, subject: 'synthetic PR merge' },
  };
  const postMerge = {
    ...clone(synthetic), head: MVP_B001_ACCEPTANCE.merge_commit, phase: 'POST_MERGE_MAIN',
    github: { present: true, event: 'push', ref: 'refs/heads/main', headRef: null, baseRef: null, sha: MVP_B001_ACCEPTANCE.merge_commit },
    merges: [MVP_B001_ACCEPTANCE.merge_commit],
    merge: { commit: MVP_B001_ACCEPTANCE.merge_commit, parents: [...MVP_B001_ACCEPTANCE.merge_parents], tree: MVP_B001_ACCEPTANCE.merge_tree, subject: MVP_B001.merge_subject },
  };
  const closeoutCommit = { commit: id('e'), parents: [MVP_B001_ACCEPTANCE.merge_commit], tree: id('f'), subject: MVP_B001.closeout_subject };
  const closeout = { ...clone(postMerge), head: id('e'), headTree: id('f'), phase: 'CLOSEOUT_MAIN', github: { ...postMerge.github, sha: id('e') }, descendants: [id('e')], closeout: closeoutCommit, closeoutChangedPaths: [...MVP_B001_CLOSEOUT_ALLOWED_PATHS].sort() };
  const cases = [
    ['Candidate', candidate, 'PASS'], ['PR head', prHead, 'PASS'], ['PR synthetic merge', synthetic, 'PASS'],
    ['future implementation merge', postMerge, 'PASS'], ['future closeout', closeout, 'PASS'],
    ['wrong branch', { ...clone(candidate), branch: 'task/AIPT-MVP-B002' }, 'FAIL'],
    ['Candidate merge', { ...clone(candidate), candidateMerges: [id('9')] }, 'FAIL'],
    ['too many commits', { ...clone(candidate), candidateCount: 5 }, 'FAIL'],
    ['wrong merge parent', { ...clone(postMerge), merge: { ...postMerge.merge, parents: [id('9'), MVP_B001_ACCEPTANCE.candidate_commit] } }, 'FAIL'],
    ['merge tree drift', { ...clone(postMerge), merge: { ...postMerge.merge, tree: id('9') } }, 'FAIL'],
    ['merge subject drift', { ...clone(postMerge), merge: { ...postMerge.merge, subject: 'merge: wrong' } }, 'FAIL'],
    ['second merge', { ...clone(postMerge), merges: [id('d'), id('9')] }, 'FAIL'],
    ['closeout wrong parent', { ...clone(closeout), closeout: { ...closeoutCommit, parents: [id('9')] } }, 'FAIL'],
    ['closeout wrong subject', { ...clone(closeout), closeout: { ...closeoutCommit, subject: 'closeout: wrong' } }, 'FAIL'],
    ['closeout path missing', { ...clone(closeout), closeoutChangedPaths: MVP_B001_CLOSEOUT_ALLOWED_PATHS.slice(1) }, 'FAIL'],
    ['closeout path added', { ...clone(closeout), closeoutChangedPaths: [...MVP_B001_CLOSEOUT_ALLOWED_PATHS, 'internal/run/engine.go'].sort() }, 'FAIL'],
  ];
  return cases.map(([label, facts, expected]) => {
    const actual = validateLifecycleFacts(facts).result;
    return { label, expected, actual, matched: expected === actual };
  });
}

function changedPaths(repo) {
  const tracked = lines(git(repo, ['diff', '--name-only', '--no-renames', MVP_B001.base_commit], { check: false })) ?? [];
  const untracked = lines(git(repo, ['ls-files', '--others', '--exclude-standard'], { check: false })) ?? [];
  return [...new Set([...tracked, ...untracked].filter((p) => p && !p.split('/').includes('node_modules')))].sort();
}

function scopeProblems(repo, changed) {
  const problems = [];
  for (const relative of changed) {
    if (!ALLOWED_PATHS.has(relative)) problems.push(`path outside exact B001 scope: ${relative}`);
    try {
      const stat = fs.lstatSync(path.join(repo, relative));
      if (!stat.isFile() || stat.isSymbolicLink()) problems.push(`changed path is not a regular file: ${relative}`);
    } catch (error) { problems.push(`changed path unreadable: ${relative}: ${error.message}`); }
  }
  for (const relative of REQUIRED_CHANGED_PATHS) if (!changed.includes(relative)) problems.push(`required B001 path missing from Base diff: ${relative}`);
  return problems;
}

function frozenProblems(repo) {
  const problems = [];
  for (const relative of FROZEN_PATHS) {
    let current;
    try { current = read(repo, relative); } catch (error) { problems.push(`frozen path unreadable: ${relative}: ${error.message}`); continue; }
    let base;
    try { base = baseText(repo, relative); } catch (error) { problems.push(error.message); continue; }
    if (current !== base) problems.push(`frozen path changed from exact B000 closeout: ${relative}`);
  }
  return problems;
}

function runtimeBoundaryProblems(repo) {
  const problems = [];
  const productionPaths = [
    'internal/testplan/contracts.go', 'internal/storage/postgres/queue.go',
    'internal/storage/postgres/queue_types.go', 'internal/storage/postgres/queue_errors.go',
  ];
  for (const relative of productionPaths) {
    const text = read(repo, relative);
    if (/(?:api\.(?:deepseek|openai|anthropic)|net\/http|ChatCompletion|ResponsesAPI)/i.test(text)) problems.push(`product model/network call surface present: ${relative}`);
  }
  const changed = changedPaths(repo);
  for (const relative of changed) {
    if (/^(?:internal\/(?:run|agent|model|gateway|orchestration)|packages\/(?:run-core|agent-runtime)|cmd\/)/.test(relative)) problems.push(`B002/B003/B004 implementation path present: ${relative}`);
  }
  return problems;
}

function documentationAndGateProblems(repo, phase) {
  const problems = [];
  const requirements = phase === 'CLOSEOUT_MAIN'
    ? CLOSEOUT_DOCUMENT_REQUIREMENTS
    : CANDIDATE_DOCUMENT_REQUIREMENTS;
  for (const [relative, needles] of requirements) {
    const text = read(repo, relative);
    for (const needle of needles) if (!text.includes(needle)) problems.push(`${relative} misses required B001 truth: ${needle}`);
  }
  const packageJSON = readJSON(repo, 'package.json');
  if (packageJSON?.scripts?.['check:mvp-b001'] !== 'node scripts/ci/validate/mvp-b001.mjs') problems.push('package.json check:mvp-b001 command drifted');
  const runChecks = read(repo, 'scripts/ci/run-checks.mjs');
  for (const needle of ["import { run as runMvpB001 }", 'runMvpB001(ctx)', 'aipt.public.mvp-b001-validator-run/v1']) {
    if (!runChecks.includes(needle)) problems.push(`aggregate validator misses ${needle}`);
  }
  const workflow = read(repo, '.github/workflows/ci.yml');
  for (const needle of [
    'run: pnpm run check:mvp-b001',
    'QueueConcurrentFormalClaimsWIP1',
    'QueueLeaseHeartbeatExpiryRecoveryAndStaleHolder',
    'node scripts/ci/validate/mvp-b001.mjs --historical-launcher-integration',
    'node scripts/ci/validate/mvp-b001.mjs --historical-launcher-integration --race',
    'AIPT_REQUIRE_POSTGRES_INTEGRATION=1',
    'postgres@sha256:',
  ]) if (!workflow.includes(needle)) problems.push(`workflow misses B001 gate evidence: ${needle}`);
  return problems;
}

function statusMutationChecks(status, base, facts) {
  const closeoutPhase = facts.phase === 'CLOSEOUT_MAIN';
  const expected = closeoutPhase
    ? expectedCloseoutStatus(base, facts)
    : expectedCandidateStatus(base);
  const validate = (candidate) => compareExact(candidate, expected).length > 0;
  const mutations = [
    ['next batch authorized', (v) => { v.tracks['AIPT-STANDALONE'].next_batch_authorized = true; }],
    ['next batch started', (v) => { v.tracks['AIPT-STANDALONE'].next_batch_started = true; }],
    ['UNREGISTERED next started', (v) => { v.tracks['AIPT-STANDALONE'].batch_history[MVP_B001.next_batch] = 'IN_PROGRESS'; }],
    ['M0 pass revoked', (v) => { v.repositories.AIPT.verified_state.m0_development_pass.result = 'REVOKED'; }],
    ['MVP pass forged', (v) => { v.repositories.AIPT.verified_state.boundaries.mvp_development_pass = 'GRANTED'; }],
    ['platform unfrozen', (v) => { v.tracks['AIPT-PLATFORM-INTEGRATION'].status = 'UNFROZEN'; }],
  ];
  if (closeoutPhase) {
    mutations.push(
      ['B001 reopened', (v) => { v.tracks['AIPT-STANDALONE'].batch_history[MVP_B001.task_id] = 'IN_PROGRESS'; }],
      ['GLOBAL_WIP reopened', (v) => { v.tracks['AIPT-STANDALONE'].global_wip = 1; }],
      ['active batch reintroduced', (v) => { v.tracks['AIPT-STANDALONE'].current_batch = MVP_B001.task_id; }],
      ['pending Candidate reintroduced', (v) => { v.repositories.AIPT.pending_candidate = {}; }],
      ['accepted merge identity drift', (v) => { v.repositories.AIPT.mvp_b001.implementation_merge.commit = '0'.repeat(40); }],
      ['post-merge CI drift', (v) => { v.repositories.AIPT.mvp_b001.post_merge_ci.run = 0; }],
    );
  } else {
    mutations.push(
      ['GLOBAL_WIP bypass', (v) => { v.tracks['AIPT-STANDALONE'].global_wip = 0; }],
      ['B001 prematurely closed', (v) => { v.tracks['AIPT-STANDALONE'].batch_history[MVP_B001.task_id] = 'MERGED_CLOSED'; }],
      ['merge authorization forged', (v) => { v.repositories.AIPT.pending_candidate.merge_authorized = true; }],
    );
  }
  const results = mutations.map(([label, mutate]) => { const value = clone(status); mutate(value); return [label, validate(value)]; });
  return results;
}

export function runHistoricalWeb(ctx) {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aipt-b001-web-base-'));
  const baseRepo = path.join(temporaryRoot, 'repo');
  try {
    const clone = spawnSync('git', ['clone', '--quiet', '--shared', '--no-checkout', ctx.repo, baseRepo], { encoding: 'utf8' });
    if (clone.status !== 0) {
      return { name: 'web-ui', result: 'FAIL', details: [`FAIL: cannot materialize exact B001 Base for historical Web gate: ${(clone.stderr || '').trim()}`] };
    }
    const checkout = spawnSync('git', ['-C', baseRepo, 'checkout', '--quiet', '--detach', MVP_B001.base_commit], { encoding: 'utf8' });
    if (checkout.status !== 0) {
      return { name: 'web-ui', result: 'FAIL', details: [`FAIL: cannot checkout exact B001 Base for historical Web gate: ${(checkout.stderr || '').trim()}`] };
    }
    const report = runHistoricalWebValidator({ repo: baseRepo });
    return {
      ...report,
      details: [
        `ok: historical Web gate executed against exact immutable B001 Base ${MVP_B001.base_commit}; B001 scope separately forbids Web changes`,
        ...report.details,
      ],
    };
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

export function runHistoricalLauncherIntegration(ctx, args = {}) {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aipt-b001-launcher-base-'));
  const baseRepo = path.join(temporaryRoot, 'repo');
  const race = args.race === true;
  try {
    const clone = spawnSync('git', ['clone', '--quiet', '--shared', '--no-checkout', ctx.repo, baseRepo], { encoding: 'utf8' });
    if (clone.status !== 0) {
      return { name: 'launcher-historical-integration', result: 'FAIL', details: [`FAIL: cannot materialize exact B001 Base for historical Launcher integration: ${(clone.stderr || '').trim()}`] };
    }
    const checkout = spawnSync('git', ['-C', baseRepo, 'checkout', '--quiet', '--detach', MVP_B001.base_commit], { encoding: 'utf8' });
    if (checkout.status !== 0) {
      return { name: 'launcher-historical-integration', result: 'FAIL', details: [`FAIL: cannot checkout exact B001 Base for historical Launcher integration: ${(checkout.stderr || '').trim()}`] };
    }
    const goArgs = ['test'];
    if (race) goArgs.push('-race');
    goArgs.push('./internal/launcher', '-run', '^TestPostgresIntegrationLauncher', '-count=1', '-v');
    const test = spawnSync('go', goArgs, {
      cwd: baseRepo,
      encoding: 'utf8',
      env: process.env,
      maxBuffer: 16 * 1024 * 1024,
    });
    const output = `${test.stdout || ''}${test.stderr || ''}`.trim();
    return {
      name: 'launcher-historical-integration',
      result: test.status === 0 ? 'PASS' : 'FAIL',
      details: [
        `${test.status === 0 ? 'ok' : 'FAIL'}: ${race ? 'race ' : ''}Launcher integration executed against exact immutable B001 Base ${MVP_B001.base_commit}; B001 scope separately forbids Launcher changes`,
        ...(output ? [output] : []),
      ],
    };
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

function isSuccessorAuthorityCheckout(repo, env = process.env) {
  if (env.GITHUB_ACTIONS === 'true') {
    if (env.GITHUB_EVENT_NAME === 'push' &&
        env.GITHUB_REF === `refs/heads/${SUCCESSOR_AUTHORITY_BRANCH}`) return true;
    if (env.GITHUB_EVENT_NAME === 'pull_request' &&
        env.GITHUB_HEAD_REF === SUCCESSOR_AUTHORITY_BRANCH && env.GITHUB_BASE_REF === MAIN_BRANCH) return true;
    return false;
  }
  const branch = git(repo, ['symbolic-ref', '--short', 'HEAD'], { check: false });
  return branch.status === 0 && branch.stdout.trim() === SUCCESSOR_AUTHORITY_BRANCH;
}

function closeoutText(repo, relative) {
  const cp = git(repo, ['show', `${B001_CLOSEOUT_COMMIT}:${relative}`], { check: false });
  if (cp.status !== 0) throw new Error(`fixed B001 closeout path unavailable: ${relative}`);
  return cp.stdout;
}

function successorChangedPaths(repo) {
  const tracked = lines(git(repo, ['diff', '--name-only', '--no-renames', B001_CLOSEOUT_COMMIT], { check: false })) ?? [];
  const untracked = lines(git(repo, ['ls-files', '--others', '--exclude-standard'], { check: false })) ?? [];
  return [...new Set([...tracked, ...untracked]
    .filter((relative) => relative && !relative.split('/').includes('node_modules')))].sort();
}

function runSuccessorAuthorityPreservation(ctx) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push(`ok: ${message}`);
  const fail = (message) => { pass = false; details.push(`FAIL: ${message}`); };
  let status, planSchema, manifestSchema;
  try {
    status = readJSON(ctx.repo, STATUS_PATH);
    planSchema = readJSON(ctx.repo, TEST_PLAN_SCHEMA_PATH);
    manifestSchema = readJSON(ctx.repo, MANIFEST_SCHEMA_PATH);
  } catch (error) {
    fail(`B001 successor preservation input unreadable: ${error.message}`);
    return { result: 'FAIL', details, negative_probes: 'NOT_RUN' };
  }

  const closeoutTree = git(ctx.repo, ['rev-parse', `${B001_CLOSEOUT_COMMIT}^{tree}`], { check: false });
  const closeoutCommit = readCommit(ctx.repo, B001_CLOSEOUT_COMMIT);
  if (closeoutTree.status !== 0 || closeoutTree.stdout.trim() !== B001_CLOSEOUT_TREE ||
      closeoutCommit?.subject !== 'closeout: complete AIPT-MVP-B001' ||
      closeoutCommit?.parents?.length !== 1 || closeoutCommit.parents[0] !== MVP_B001_ACCEPTANCE.merge_commit) {
    fail('exact B001 closeout commit/tree/topology drifted');
  } else ok('exact B001 closeout commit/tree/topology verified');
  if (git(ctx.repo, ['merge-base', '--is-ancestor', B001_CLOSEOUT_COMMIT, 'HEAD'], { check: false }).status !== 0) {
    fail('successor authority Candidate does not descend from exact B001 closeout');
  } else ok('successor authority Candidate descends from exact B001 closeout');
  const laterMerges = lines(git(ctx.repo, ['rev-list', '--merges', `${B001_CLOSEOUT_COMMIT}..HEAD`], { check: false })) ?? [];
  if (laterMerges.length !== 0) fail('successor authority Candidate contains a merge');
  else ok('successor authority Candidate has zero post-closeout merges');
  const head = git(ctx.repo, ['rev-parse', 'HEAD^{commit}'], { check: false }).stdout.trim();
  if (process.env.GITHUB_ACTIONS === 'true' && process.env.GITHUB_SHA !== head) fail('GITHUB_SHA is not successor Candidate HEAD');
  else ok('successor authority checkout identity is bound to HEAD');

  try {
    if (read(ctx.repo, STATUS_PATH) !== closeoutText(ctx.repo, STATUS_PATH) ||
        read(ctx.repo, GRAPH_PATH) !== closeoutText(ctx.repo, GRAPH_PATH)) {
      fail('B001 closeout status or canonical batch graph changed');
    } else ok('B001 closeout status and canonical batch graph remain byte-identical');
  } catch (error) { fail(error.message); }

  const protectedPaths = [
    'schemas/testplan', 'schemas/run-manifest', 'internal/testplan',
    'internal/storage/postgres/migrations', 'internal/storage/postgres/queue.go',
    'internal/storage/postgres/queue_errors.go', 'internal/storage/postgres/queue_types.go',
    'internal/storage/postgres/queue_test.go', 'internal/storage/postgres/queue_integration_test.go',
  ];
  const protectedDiff = git(ctx.repo, ['diff', '--name-only', '--no-renames',
    B001_CLOSEOUT_COMMIT, '--', ...protectedPaths], { check: false });
  if (protectedDiff.status !== 0 || protectedDiff.stdout.trim() !== '') {
    fail('B001 protected Test Plan/Manifest/queue/lease/migration surface changed');
  } else ok('B001 protected Test Plan/Manifest/queue/lease/migration surface is byte-identical');

  const schemaChecks = schemaAndMutationChecks(planSchema, manifestSchema);
  for (const problem of schemaChecks.problems) fail(problem);
  if (schemaChecks.problems.length === 0) ok(`B001 schemas retain all ${schemaChecks.probeCount} security mutations`);
  const migrationFiles = new Map();
  for (const name of fs.readdirSync(path.join(ctx.repo, 'internal/storage/postgres/migrations'))) {
    migrationFiles.set(name, read(ctx.repo, `internal/storage/postgres/migrations/${name}`));
  }
  const migrationProblems = checkMigrationContract(migrationFiles);
  migrationProblems.forEach((problem) => fail(`migration: ${problem}`));
  if (migrationProblems.length === 0) ok('B001 migration inventory/checksums/WIP1/lease/Attempt invariants remain exact');
  const migrationProbes = migrationMutationChecks(
    migrationFiles.get('000001_ledger.sql'), migrationFiles.get('000002_playtest_queue.sql'));
  migrationProbes.forEach(([label, rejected]) => { if (!rejected) fail(`migration mutation accepted: ${label}`); });
  if (migrationProbes.every(([, rejected]) => rejected)) ok(`all ${migrationProbes.length} B001 migration mutations reject`);

  const docsAndGates = documentationAndGateProblems(ctx.repo, 'CLOSEOUT_MAIN');
  docsAndGates.forEach((problem) => fail(problem));
  if (docsAndGates.length === 0) ok('B001 closeout documentation and CI evidence remain present');
  const lifecycleProbes = lifecycleRegressionChecks();
  lifecycleProbes.forEach((probe) => { if (!probe.matched) fail(`B001 lifecycle probe mismatched: ${probe.label}`); });
  if (lifecycleProbes.every((probe) => probe.matched)) ok(`all ${lifecycleProbes.length} frozen B001 lifecycle probes matched`);

  const expectedStatus = JSON.parse(closeoutText(ctx.repo, STATUS_PATH));
  const statusProblems = compareExact(status, expectedStatus, '$status');
  statusProblems.forEach((problem) => fail(`B001 status: ${problem}`));
  const statusMutation = clone(status);
  statusMutation.tracks['AIPT-STANDALONE'].next_batch_authorized = true;
  if (compareExact(statusMutation, expectedStatus).length === 0) fail('B001 unauthorized-next mutation was accepted');
  else ok('B001 implementation successor remains NOT_STARTED/NOT_AUTHORIZED and mutation rejects');

  const changed = successorChangedPaths(ctx.repo);
  for (const relative of changed) {
    if (/^(?:internal\/(?:run|agent|model|gateway|orchestration)|packages\/(?:run-core|agent-runtime)|cmd\/)/.test(relative)) {
      fail(`runtime/business implementation path appears in authority Candidate: ${relative}`);
    }
  }
  if (!details.some((entry) => entry.includes('runtime/business implementation path'))) {
    ok('no Run Core, Agent orchestration, model gateway or real-playtest implementation path appears');
  }

  return {
    result: pass ? 'PASS' : 'FAIL',
    details,
    task_id: MVP_B001.task_id,
    lifecycle_phase: 'SUCCESSOR_AUTHORITY_CANDIDATE',
    candidate_commit: head,
    candidate_tree: git(ctx.repo, ['rev-parse', 'HEAD^{tree}'], { check: false }).stdout.trim(),
    migration: MVP_B001.migration,
    migration_sha256: MVP_B001.migration_sha256,
    changed_paths: changed,
    negative_probes: pass ? 'PASS' : 'FAIL',
    negative_probe_count: schemaChecks.probeCount + migrationProbes.length + lifecycleProbes.length + 1,
    external_model_calls: 0,
    next_batch_authorized: false,
    next_batch_started: false,
  };
}

export function run(ctx, args = {}) {
  if (args['historical-web']) return runHistoricalWeb(ctx);
  if (args['historical-launcher-integration']) return runHistoricalLauncherIntegration(ctx, args);
  if (isSuccessorAuthorityCheckout(ctx.repo)) return runSuccessorAuthorityPreservation(ctx);
  const details = [];
  let pass = true;
  const ok = (message) => details.push(`ok: ${message}`);
  const fail = (message) => { pass = false; details.push(`FAIL: ${message}`); };

  let status, baseStatus, graph, baseGraph, planSchema, manifestSchema;
  try {
    status = readJSON(ctx.repo, STATUS_PATH);
    baseStatus = JSON.parse(baseText(ctx.repo, STATUS_PATH));
    graph = readJSON(ctx.repo, GRAPH_PATH);
    baseGraph = JSON.parse(baseText(ctx.repo, GRAPH_PATH));
    planSchema = readJSON(ctx.repo, TEST_PLAN_SCHEMA_PATH);
    manifestSchema = readJSON(ctx.repo, MANIFEST_SCHEMA_PATH);
  } catch (error) {
    fail(`B001 authority input unreadable: ${error.message}`);
    return { result: 'FAIL', details, negative_probes: 'NOT_RUN' };
  }

  const baseTree = git(ctx.repo, ['rev-parse', `${MVP_B001.base_commit}^{tree}`], { check: false }).stdout.trim();
  const baseCommit = readCommit(ctx.repo, MVP_B001.base_commit);
  if (baseTree !== MVP_B001.base_tree || baseCommit?.subject !== 'closeout: complete AIPT-MVP-B000' || baseCommit?.parents?.length !== 1 || baseCommit.parents[0] !== MVP_B000_IMPLEMENTATION_MERGE.commit) {
    fail('exact B000 closeout Base commit/tree/topology drifted');
  } else ok('exact B000 closeout Base commit/tree/topology verified');

  const graphProblems = compareExact(graph, baseGraph, '$graph');
  if (graphProblems.length || graph?.serial_batches?.length !== 13) {
    for (const problem of graphProblems) fail(`frozen graph: ${problem}`);
    if (graph?.serial_batches?.length !== 13) fail('frozen graph is not exactly 13 items');
  } else ok('frozen canonical 13-item graph is byte/semantic identical to B000 closeout');
  if (read(ctx.repo, GRAPH_PATH) !== baseText(ctx.repo, GRAPH_PATH)) fail('frozen graph bytes changed');

  const facts = collectLifecycleFacts(ctx.repo);
  const lifecycle = validateLifecycleFacts(facts);
  const expectedStatus = lifecycle.phase === 'CLOSEOUT_MAIN'
    ? expectedCloseoutStatus(baseStatus, facts)
    : expectedCandidateStatus(baseStatus);
  const statusProblems = compareExact(status, expectedStatus, '$status');
  for (const problem of statusProblems) fail(`authority status: ${problem}`);
  if (statusProblems.length === 0) {
    ok(lifecycle.phase === 'CLOSEOUT_MAIN'
      ? 'B001 MERGED_CLOSED / GLOBAL_WIP=0 / accepted identities / next UNREGISTERED unauthorized status is exact'
      : 'B001 IN_PROGRESS / GLOBAL_WIP=1 / next UNREGISTERED unauthorized status is exact');
  }
  if (status.tracks?.['AIPT-PLATFORM-INTEGRATION']?.status !== PLATFORM || status.repositories?.AIPT?.verified_state?.m0_development_pass?.result !== 'GRANTED' || status.repositories?.AIPT?.verified_state?.boundaries?.mvp_development_pass !== 'NOT_GRANTED') fail('milestone/platform preservation boundary drifted');
  else ok('M0 Development Pass remains GRANTED; MVP remains NOT_GRANTED; Platform Integration remains frozen');
  if (compareExact(status.repositories?.AIPT?.mvp_bootstrap, baseStatus.repositories?.AIPT?.mvp_bootstrap, '$mvp_bootstrap').length) fail('B000 immutable closeout record drifted');
  else ok('B000 immutable Candidate/repair/merge/closeout record preserved');

  for (const problem of lifecycle.problems) fail(`lifecycle: ${problem}`);
  if (lifecycle.result === 'PASS') ok(`${lifecycle.phase} lifecycle topology PASS with zero-merge Candidate lineage`);

  const schemaChecks = schemaAndMutationChecks(planSchema, manifestSchema);
  for (const problem of schemaChecks.problems) fail(problem);
  if (schemaChecks.problems.length === 0) ok(`versioned four-level Test Plan and immutable Run Manifest contracts pass ${schemaChecks.probeCount} schema/security mutations`);

  const migrationFiles = new Map();
  for (const name of fs.readdirSync(path.join(ctx.repo, 'internal/storage/postgres/migrations'))) {
    migrationFiles.set(name, read(ctx.repo, `internal/storage/postgres/migrations/${name}`));
  }
  const migrationProblems = checkMigrationContract(migrationFiles);
  for (const problem of migrationProblems) fail(`migration: ${problem}`);
  if (migrationProblems.length === 0) ok('exact 000001 ledger + exact 000002 queue migration inventory/checksums/invariants verified');
  const migrationProbes = migrationMutationChecks(migrationFiles.get('000001_ledger.sql'), migrationFiles.get('000002_playtest_queue.sql'));
  for (const [label, rejected] of migrationProbes) if (!rejected) fail(`migration mutation accepted: ${label}`);
  if (migrationProbes.every(([, rejected]) => rejected)) ok(`all ${migrationProbes.length} migration/immutability/WIP1/lease mutations reject`);

  const changed = changedPaths(ctx.repo);
  const scope = scopeProblems(ctx.repo, changed);
  for (const problem of scope) fail(problem);
  if (scope.length === 0) ok(`exact B001 path scope verified across ${changed.length} changed regular files`);
  const frozen = frozenProblems(ctx.repo);
  for (const problem of frozen) fail(problem);
  if (frozen.length === 0) ok('M0 records, B000 graph, registries, dependencies, lockfiles, toolchains and LICENSE are frozen');
  const runtime = runtimeBoundaryProblems(ctx.repo);
  for (const problem of runtime) fail(problem);
  if (runtime.length === 0) ok('no Run Core, Agent orchestration, model gateway, product-model call or real-playtest implementation');
  const docsAndGates = documentationAndGateProblems(ctx.repo, lifecycle.phase);
  for (const problem of docsAndGates) fail(problem);
  if (docsAndGates.length === 0) ok('human authority docs, package aggregate and dual-runner/PostgreSQL CI evidence state the exact B001 boundary');

  const lifecycleProbes = lifecycleRegressionChecks();
  for (const probe of lifecycleProbes) if (!probe.matched) fail(`lifecycle regression mismatch: ${probe.label} expected ${probe.expected} got ${probe.actual}`);
  if (lifecycleProbes.every((probe) => probe.matched)) ok(`all ${lifecycleProbes.length} Candidate/PR/synthetic-merge/future-merge/future-closeout topology probes matched`);
  const statusProbes = statusMutationChecks(status, baseStatus, facts);
  for (const [label, rejected] of statusProbes) if (!rejected) fail(`status mutation accepted: ${label}`);
  if (statusProbes.every(([, rejected]) => rejected)) ok(`all ${statusProbes.length} status/next-batch/milestone mutations reject`);

  const allProbes = schemaChecks.probeCount + migrationProbes.length + lifecycleProbes.length + statusProbes.length;
  return {
    result: pass ? 'PASS' : 'FAIL', details,
    task_id: MVP_B001.task_id, base_commit: MVP_B001.base_commit, base_tree: MVP_B001.base_tree,
    lifecycle_phase: lifecycle.phase, candidate_commit: facts.candidate, candidate_tree: facts.candidateTree,
    post_base_merge_count: facts.candidateMerges.length,
    migration: MVP_B001.migration, migration_sha256: MVP_B001.migration_sha256,
    graph_items: graph?.serial_batches?.length ?? null,
    changed_paths: changed,
    negative_probes: pass ? 'PASS' : 'FAIL', negative_probe_count: allProbes,
    external_model_calls: 0, next_batch_authorized: false, next_batch_started: false,
  };
}

runAsMain(import.meta.url, 'mvp-b001', run);
