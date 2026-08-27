#!/usr/bin/env node
// Governance-only acceptance gate for
// UNREGISTERED-AIPT-P1-B000-AUTHORITY-POSTMERGE-REPAIR-001.
// It performs no network, model, agent, runtime or playtest operation.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { git, runAsMain } from '../lib/cli.mjs';
import { checkSchemaDocument, validateInstance } from '../lib/json-schema.mjs';
import { run as runAuthority } from './p1-b000-authority.mjs';
import { run as runB001 } from './mvp-b001.mjs';
import { run as runAmendment } from './p1-b000-authority-amendment.mjs';

const TASK_ID = 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-POSTMERGE-REPAIR-001';
const AMENDMENT_ID = 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-AMENDMENT-001';
const AMENDMENT_CANDIDATE = 'a1d614c7468f67d13bcbf32f65ade7613a85e202';
const AMENDMENT_TREE = 'c03ce80729cce470e35325fd4d4a35e221221c55';
const AMENDMENT_MERGE = '33a53d53c6db474f46a886dcbbba6d083eee4f27';
const AMENDMENT_CLOSEOUT = '2619339e53113633e02f3aef14156a1ff08c13f8';
const AUTHORITY_MERGE = '169f9bd006dabb88eb653ab09a33b0eef5eadaed';
const AUTHORITY_TREE = '9cf551e7bc70d4354ca21d62a2bd456ed6f401bb';
const SUPERSESSION_SCHEMA = 'schemas/authority-amendment/v1/aipt-authority-validator-supersession.schema.json';
const SUPERSESSION_DIRECTORY = 'docs/authority/registry/authority-validator-supersessions';
const REPAIR_VALIDATOR = 'scripts/ci/validate/p1-b000-authority-repair.mjs';
const MIGRATION = 'internal/storage/postgres/migrations/000002_playtest_queue.sql';
const MIGRATION_SHA256 = '47f02a5a2129473caa0db5e359a0b294a01b2a96329d9f6fa08ac87cc429c997';

const ROLE_POLICY = Object.freeze({
  AUTHORITY_VALIDATOR_IDENTITY: {
    path: 'scripts/ci/validate/p1-b000-authority.mjs',
    old: 'f5ed47898ad13b193cd685ae9649c18cada3a6fb5893c1810867c91869ad8c7c',
    historicalCommit: AUTHORITY_MERGE,
    constraints: [
      'SUPPORT_CANDIDATE_MERGED_POST_MERGE_CLOSED_TOPOLOGY',
      'PRESERVE_ARTIFACT_HASH_VALIDATION',
      'PRESERVE_ANCESTRY_VALIDATION',
      'PRESERVE_CANDIDATE_IDENTITY_VALIDATION',
      'PRESERVE_SCOPE_VALIDATION',
      'PRESERVE_NEGATIVE_LIFECYCLE_CHECKS',
      'REJECT_UNAUTHORIZED_COMMITS',
      'REJECT_ARTIFACT_DRIFT',
      'REJECT_ILLEGAL_LIFECYCLE_TRANSITIONS',
    ],
  },
  B001_HISTORICAL_VALIDATOR_IDENTITY: {
    path: 'scripts/ci/validate/mvp-b001.mjs',
    old: 'ba29c75b68c282484cbdceeb7ae035c010b51181ce8e2b5f5b54b9c11a241aaf',
    historicalCommit: AUTHORITY_MERGE,
    constraints: [
      'PRESERVE_B001_BUSINESS_SEMANTICS',
      'CLOSED_USES_IMMUTABLE_ACCEPTED_CLOSEOUT_IDENTITY',
      'ACTIVE_CANDIDATE_REQUIRES_PENDING_CANDIDATE',
      'INVALID_COMBINATION_RETURNS_STRUCTURED_FAIL',
      'PRESERVE_CAMPAIGN_SUITE_CASE_RUN',
      'PRESERVE_ATTEMPT_INTERNAL_ONLY',
      'PRESERVE_RUN_MANIFEST_IMMUTABILITY',
      'PRESERVE_POSTGRESQL_QUEUE_AUTHORITY',
      'PRESERVE_WIP_ONE_LEASE_HEARTBEAT_EXPIRY_RECOVERY',
      'PRESERVE_APPEND_ONLY_ATTEMPT_HISTORY',
    ],
  },
});

const PROTECTED_HASHES = Object.freeze({
  'docs/authority/UNREGISTERED_AIPT_P1_B000_AUTHORITY.md': '787e1a1a278905d69cd9e000badec8c4143060dcb136e4b0da3d2fb7a12c3ede',
  'docs/authority/registry/unregistered-aipt-p1-b000-authority.json': 'a9845bb74dac409ee243b7024e23aae271ab13c75e18116ae2513853cc02eed6',
  'schemas/playtest-package/v1/aipt-playtest-package.schema.json': '88e55b63c8a6366c872edf0d886202a5c375e224c801433364332ddc4e4e7549',
  'schemas/runtime-adapter-input/v1/aipt-runtime-adapter-input.schema.json': '935b88f2409e604d01a13657a7790dae16e19ebe0c4e96f054c580102ec17413',
  'docs/authority/registry/unregistered-aipt-p1-b000-authority-artifacts.json': '3e7d5ee752ac01ae4034fdaf2ec71231bb4f58eca9174e99619d0a13b200cd4f',
  [MIGRATION]: MIGRATION_SHA256,
});

const ALLOWED_REPAIR_PATHS = Object.freeze([
  '.github/workflows/ci.yml',
  '.github/workflows/p1-b000-post-merge-reverification.yml',
  'package.json',
  'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/historical-governance.mjs',
  'scripts/ci/validate/mvp-b001.mjs',
  'scripts/ci/validate/p1-b000-authority.mjs',
  'scripts/ci/validate/p1-b000-authority-repair.mjs',
  'scripts/ci/validate/p1-b000-post-merge-reverification.mjs',
  'scripts/ci/validate/standalone-entrypoints.mjs',
  'scripts/ci/validate/workflow.mjs',
]);

function read(repo, relative) {
  return fs.readFileSync(path.join(repo, relative));
}

function readJSON(repo, relative) {
  return JSON.parse(read(repo, relative).toString('utf8'));
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function gitBlob(repo, commit, relative) {
  const cp = git(repo, ['show', `${commit}:${relative}`], { check: false });
  return cp.status === 0 ? Buffer.from(cp.stdout, 'utf8') : null;
}

function recordsFrom(repo) {
  const directory = path.join(repo, SUPERSESSION_DIRECTORY);
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory).filter((name) => name.endsWith('.json'))
    .sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))
    .map((name) => readJSON(repo, `${SUPERSESSION_DIRECTORY}/${name}`));
}

export function validatePendingSupersessions(records, schema, options = {}) {
  const problems = [];
  const expectedRoles = Object.keys(ROLE_POLICY).sort();
  const roles = records.map((record) => record.role).sort();
  if (JSON.stringify(roles) !== JSON.stringify(expectedRoles)) {
    problems.push('supersession inventory is not exactly one link for each authorized role');
  }
  if (new Set(records.map((record) => record.record_id)).size !== records.length) {
    problems.push('duplicate/conflicting supersession record identity');
  }
  if (new Set(records.map((record) => record.role)).size !== records.length) {
    problems.push('duplicate/conflicting supersession role');
  }
  if (options.amendmentClosed === false) problems.push('accepted Amendment is not CLOSED');
  if (options.protectedArtifactsValid === false) problems.push('protected schema or Authority artifact changed');
  const currentHashes = options.currentHashes ?? {};
  let repairCommit = null;
  for (const record of records) {
    for (const error of validateInstance(schema, record).errors) {
      problems.push(`supersession ${record?.record_id ?? 'unknown'} schema: ${error.message}`);
    }
    const policy = ROLE_POLICY[record.role];
    if (!policy) {
      problems.push(`unknown supersession role ${record.role}`);
      continue;
    }
    if (record.chain_sequence !== 1 || record.predecessor_record_id !== null ||
        record.path !== policy.path || record.old_sha256 !== policy.old ||
        record.new_sha256 !== currentHashes[record.role] ||
        record.amendment_id !== AMENDMENT_ID || record.repair_task_id !== TASK_ID ||
        !policy.constraints.every((constraint) => record.semantic_constraints?.includes(constraint)) ||
        record.regression_evidence?.result !== 'PASS' ||
        record.regression_evidence?.negative_probe_count < 1 ||
        record.regression_evidence?.b001_regression !== 'PASS' ||
        record.amendment_acceptance?.accepted !== true ||
        record.amendment_acceptance?.candidate_commit !== AMENDMENT_CANDIDATE ||
        record.amendment_acceptance?.candidate_tree !== AMENDMENT_TREE ||
        record.amendment_acceptance?.merge_commit !== AMENDMENT_MERGE ||
        record.amendment_acceptance?.merge_tree !== AMENDMENT_TREE ||
        record.repair_acceptance?.state !== 'CANDIDATE_FROZEN' ||
        record.repair_acceptance?.independent_acceptance !== 'PENDING' ||
        record.repair_acceptance?.candidate_ci_run_id !== null ||
        record.repair_acceptance?.candidate_ci_conclusion !== 'pending' ||
        record.provenance?.created_by_task !== TASK_ID ||
        record.provenance?.append_only !== true || record.provenance?.original_identity_preserved !== true) {
      problems.push(`supersession ${record.record_id} identity, constraints, acceptance or provenance drifted`);
    }
    if (repairCommit === null) repairCommit = record.repair_candidate_commit;
    else if (repairCommit !== record.repair_candidate_commit) problems.push('supersession roles name different repair artifact commits');
    if (!options.skipGit && options.repo) {
      if (git(options.repo, ['merge-base', '--is-ancestor', AMENDMENT_CLOSEOUT, record.repair_candidate_commit], { check: false }).status !== 0 ||
          git(options.repo, ['merge-base', '--is-ancestor', record.repair_candidate_commit, 'HEAD'], { check: false }).status !== 0) {
        problems.push(`supersession ${record.record_id} repair artifact ancestry is invalid`);
      }
      const blob = gitBlob(options.repo, record.repair_candidate_commit, policy.path);
      if (!blob || sha256(blob) !== record.new_sha256) {
        problems.push(`supersession ${record.record_id} new validator identity is not reproducible`);
      }
    }
  }
  return problems;
}

function supersessionNegativeProbes(records, schema, currentHashes) {
  const validate = (value, options = {}) => validatePendingSupersessions(value, schema, {
    skipGit: true, currentHashes, amendmentClosed: true, protectedArtifactsValid: true, ...options,
  }).length > 0;
  const mutate = (fn) => { const value = clone(records); fn(value); return value; };
  return [
    ['S01 old hash mismatch', validate(mutate((v) => { v[0].old_sha256 = '0'.repeat(64); }))],
    ['S02 unknown Amendment identity', validate(mutate((v) => { v[0].amendment_id = 'UNKNOWN-AMENDMENT'; }))],
    ['S03 Amendment not CLOSED', validate(clone(records), { amendmentClosed: false })],
    ['S04 wrong repair task', validate(mutate((v) => { v[0].repair_task_id = 'WRONG-REPAIR'; }))],
    ['S05 schema semantic change', validate(clone(records), { protectedArtifactsValid: false })],
    ['S06 ancestry validation weakened', validate(mutate((v) => {
      const record = v.find((entry) => entry.role === 'AUTHORITY_VALIDATOR_IDENTITY');
      record.semantic_constraints = record.semantic_constraints.filter((x) => x !== 'PRESERVE_ANCESTRY_VALIDATION');
    }))],
    ['S07 artifact validation weakened', validate(mutate((v) => {
      const record = v.find((entry) => entry.role === 'AUTHORITY_VALIDATOR_IDENTITY');
      record.semantic_constraints = record.semantic_constraints.filter((x) => x !== 'PRESERVE_ARTIFACT_HASH_VALIDATION');
    }))],
    ['S08 missing regression evidence', validate(mutate((v) => { delete v[0].regression_evidence; }))],
    ['S09 new validator hash missing', validate(mutate((v) => { delete v[0].new_sha256; }))],
    ['S10 duplicate/conflicting supersession', validate([...clone(records), clone(records[0])])],
  ];
}

function changedPaths(repo) {
  const tracked = git(repo, ['diff', '--name-only', '--no-renames', AMENDMENT_CLOSEOUT, 'HEAD'], { check: false });
  const untracked = git(repo, ['ls-files', '--others', '--exclude-standard'], { check: false });
  return [...new Set([
    ...(tracked.status === 0 ? tracked.stdout.split('\n').filter(Boolean) : []),
    ...(untracked.status === 0 ? untracked.stdout.split('\n').filter(Boolean) : []),
  ].filter((relative) => !relative.split('/').includes('node_modules')))].sort();
}

function runImpl(ctx) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push(`ok: ${message}`);
  const fail = (message) => { pass = false; details.push(`FAIL: ${message}`); };
  let schema;
  try { schema = readJSON(ctx.repo, SUPERSESSION_SCHEMA); } catch (error) {
    return { result: 'FAIL', details: [`FAIL: repair input unreadable: ${error.message}`] };
  }
  const schemaErrors = checkSchemaDocument(schema).errors;
  schemaErrors.forEach((error) => fail(`supersession schema: ${error}`));
  if (schemaErrors.length === 0) ok('accepted supersession schema remains valid and unchanged');

  const protectedProblems = [];
  for (const [relative, expected] of Object.entries(PROTECTED_HASHES)) {
    try { if (sha256(read(ctx.repo, relative)) !== expected) protectedProblems.push(`${relative} SHA-256 drifted`); }
    catch (error) { protectedProblems.push(`${relative} unreadable: ${error.message}`); }
  }
  protectedProblems.forEach(fail);
  if (protectedProblems.length === 0) ok('Base Authority contracts, schemas and B001 migration retain all frozen SHA-256 identities');

  const reverificationWorkflow = read(ctx.repo, '.github/workflows/p1-b000-post-merge-reverification.yml').toString('utf8');
  const workflowNeedles = [
    'workflow_dispatch:',
    'accepted_repair_candidate:',
    'independent_acceptance:',
    'git merge-base --is-ancestor "${ACCEPTED_REPAIR_CANDIDATE}" origin/main',
    '--target-sha "${TARGET_SHA}"',
    '--expected-tree "${EXPECTED_TREE}"',
    '--emit-formal-evidence',
    '--workflow-run-id "${GITHUB_RUN_ID}"',
    'Original merge CI: `ABSENT`',
  ];
  const actionPins = [
    'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
    'actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e',
    'actions/setup-node@820762786026740c76f36085b0efc47a31fe5020',
  ];
  const missingWorkflowEvidence = workflowNeedles.filter((needle) => !reverificationWorkflow.includes(needle));
  if (missingWorkflowEvidence.length > 0 || actionPins.some((pin) => !reverificationWorkflow.includes(pin)) ||
      reverificationWorkflow.includes('continue-on-error:') || reverificationWorkflow.includes('secrets.')) {
    fail(`reverification workflow definition is incomplete or fail-open: ${missingWorkflowEvidence.join(', ')}`);
  } else ok('workflow_dispatch reverification definition pins actions, exact target inputs and accepted-repair ancestry without failure masking');

  for (const [role, policy] of Object.entries(ROLE_POLICY)) {
    const historical = gitBlob(ctx.repo, policy.historicalCommit, policy.path);
    if (!historical || sha256(historical) !== policy.old) fail(`${role} original frozen historical identity is not reproducible`);
    else ok(`${role} original frozen historical identity remains immutable`);
  }
  const amendmentAncestor = git(ctx.repo, ['merge-base', '--is-ancestor', AMENDMENT_CLOSEOUT, 'HEAD'], { check: false });
  const amendmentTree = git(ctx.repo, ['rev-parse', `${AMENDMENT_CANDIDATE}^{tree}`], { check: false }).stdout.trim();
  const amendmentMergeTree = git(ctx.repo, ['rev-parse', `${AMENDMENT_MERGE}^{tree}`], { check: false }).stdout.trim();
  if (amendmentAncestor.status !== 0 || amendmentTree !== AMENDMENT_TREE || amendmentMergeTree !== AMENDMENT_TREE) {
    fail('accepted Amendment R1 closeout ancestry or Candidate/merge tree drifted');
  } else ok('accepted Amendment R1 closeout ancestry and exact Candidate/merge tree verified');

  const records = recordsFrom(ctx.repo);
  const currentHashes = Object.fromEntries(Object.entries(ROLE_POLICY)
    .map(([role, policy]) => [role, sha256(read(ctx.repo, policy.path))]));
  const supersessionProblems = validatePendingSupersessions(records, schema, {
    repo: ctx.repo, currentHashes, amendmentClosed: true,
    protectedArtifactsValid: protectedProblems.length === 0,
  });
  supersessionProblems.forEach(fail);
  if (supersessionProblems.length === 0) ok('two pending supersession links preserve old identities and bind actual new validator bytes');

  const probes = supersessionNegativeProbes(records, schema, currentHashes);
  probes.forEach(([name, rejected]) => { if (!rejected) fail(`${name} was accepted`); });
  if (probes.every(([, rejected]) => rejected)) ok('all S01-S10 supersession provenance and anti-weakening mutations reject');

  const authority = runAuthority(ctx);
  const b001 = runB001(ctx);
  const amendment = runAmendment(ctx);
  for (const [name, report] of [['F1 Authority', authority], ['F2 B001', b001], ['accepted Amendment', amendment]]) {
    if (report.result !== 'PASS') fail(`${name} validator returned structured FAIL`);
    else ok(`${name} validator PASS`);
  }
  if (b001.uncaught_validator_errors !== 0) fail('B001 validator reports uncaught errors');
  else ok('B001 validator uncaught exception count is zero');

  const changed = changedPaths(ctx.repo);
  const escaped = changed.filter((relative) => !ALLOWED_REPAIR_PATHS.includes(relative) &&
    !relative.startsWith(`${SUPERSESSION_DIRECTORY}/`));
  escaped.forEach((relative) => fail(`path outside accepted repair scope: ${relative}`));
  if (escaped.length === 0) ok(`repair diff is confined to ${changed.length} governance validator/evidence/CI paths`);
  if (changed.some((relative) => /^(?:internal|cmd|packages|aipt)\//.test(relative))) {
    fail('business/runtime implementation path changed');
  } else ok('no business, Run Core, Agent, model gateway or playtest implementation path changed');

  const suiteIdentity = sha256(read(ctx.repo, REPAIR_VALIDATOR));
  for (const record of records) {
    if (record.regression_evidence?.suite_identity !== suiteIdentity) {
      fail(`supersession ${record.record_id} regression suite identity drifted`);
    }
  }
  if (records.length === 2 && records.every((record) => record.regression_evidence?.suite_identity === suiteIdentity)) {
    ok('supersession regression evidence binds this exact repair gate identity');
  }

  return {
    result: pass ? 'PASS' : 'FAIL', details,
    task_id: TASK_ID,
    authority_merge_commit: AUTHORITY_MERGE,
    authority_merge_tree: AUTHORITY_TREE,
    amendment_closeout: AMENDMENT_CLOSEOUT,
    original_validator_identities: Object.fromEntries(Object.entries(ROLE_POLICY).map(([role, value]) => [role, value.old])),
    staged_validator_identities: currentHashes,
    supersession_state: 'CANDIDATE_FROZEN',
    supersession_accepted: false,
    supersession_record_count: records.length,
    supersession_negative_probes: probes.every(([, rejected]) => rejected) ? 'PASS' : 'FAIL',
    supersession_negative_probe_count: probes.length,
    f1: authority.result,
    f2: b001.result,
    uncaught_validator_errors: 0,
    b001_regression: b001.result === 'PASS' ? 'PASS' : 'FAIL',
    migration_sha256: sha256(read(ctx.repo, MIGRATION)),
    changed_paths: changed,
    business_code_changed: false,
    b000_implementation_started: false,
    real_model_calls: 0,
    real_playtest_executed: false,
    merge_authorized: false,
  };
}

export function run(ctx) {
  try { return runImpl(ctx); } catch (error) {
    return {
      result: 'FAIL', details: [`FAIL: structured repair validator error: ${error.message}`],
      task_id: TASK_ID, uncaught_validator_errors: 0,
      business_code_changed: false, b000_implementation_started: false,
      real_model_calls: 0, real_playtest_executed: false, merge_authorized: false,
    };
  }
}

runAsMain(import.meta.url, 'p1-b000-authority-repair', run);
