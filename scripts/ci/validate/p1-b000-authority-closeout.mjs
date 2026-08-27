#!/usr/bin/env node
// Governance-only closeout gate for the accepted UNREGISTERED P1 B000 Base
// Authority. It performs no network, model, agent, runtime or playtest work.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { git, runAsMain } from '../lib/cli.mjs';
import { checkSchemaDocument, validateInstance } from '../lib/json-schema.mjs';
import { run as runAuthority } from './p1-b000-authority.mjs';
import { run as runB001 } from './mvp-b001.mjs';
import { run as runAmendment, validateRecoveryEvidence } from './p1-b000-authority-amendment.mjs';
import { run as runRepair } from './p1-b000-authority-repair.mjs';

const AUTHORITY_TASK_ID = 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-001';
const CLOSEOUT_ID = `${AUTHORITY_TASK_ID}-CLOSEOUT-001`;
const OWNER_DIRECTIVE = 'MERGE_REPAIR_AND_CLOSE_BASE_AUTHORITY';
const AMENDMENT_CLOSEOUT = '2619339e53113633e02f3aef14156a1ff08c13f8';

const AUTHORITY_CANDIDATE = 'c9f7729f666d11716c04d7682da16044ca965236';
const AUTHORITY_TREE = '9cf551e7bc70d4354ca21d62a2bd456ed6f401bb';
const AUTHORITY_MERGE = '169f9bd006dabb88eb653ab09a33b0eef5eadaed';
const AUTHORITY_PARENTS = [
  'eede815e818d87362605f55d5bfd2a0460e6e130',
  AUTHORITY_CANDIDATE,
];

const REPAIR_TASK_ID = 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-POSTMERGE-REPAIR-001';
const REPAIR_CANDIDATE = '17f09e7cd766b39651101a1cacb896b296b821c8';
const REPAIR_TREE = 'c3a8f4f1e73a0ee60b6d29491d6981f0a01159d8';
const REPAIR_CANDIDATE_CI = 33057642299;
const REPAIR_MERGE = 'df71476d4b8f271f3b444cace46a3d6fbd1eaea4';
const REPAIR_PARENTS = [AMENDMENT_CLOSEOUT, REPAIR_CANDIDATE];
const REPAIR_MERGE_CI = 33061223575;

const SUPERSESSION_ACCEPTANCE = 'c5cb2354af72df18c9323b6a1401e3cc874c7581';
const SUPERSESSION_ACCEPTANCE_TREE = 'b52e4024ca39b9206eb00e2d1a23ab0985e145e4';
const FORMAL_RUN_HEAD = 'bdace30f311bfa953846569e06a892a2ed59acd3';
const FORMAL_RUN_HEAD_TREE = '1ba5d72d379cf298d4ad886f109fcd829c23caf0';
const FORMAL_RUN_HEAD_PARENT = '2f0cf7b9611afda4d2a114cfc22bfaba9e267cd6';
const FORMAL_RUN_ID = 33071069334;
const FORMAL_EVIDENCE_SHA = '858fd690dcee1f7ed2c95c49f8a3c831bc0e498c9e7d83dffb9b875a5abda708';
const CLOSEOUT_SUBJECT = 'closeout: complete UNREGISTERED P1 B000 Base Authority';

const SCHEMA_PATH = 'schemas/authority-amendment/v1/aipt-base-authority-closeout.schema.json';
const CLOSEOUT_PATH = 'docs/authority/registry/base-authority-closeouts/unregistered-aipt-p1-b000-authority-closeout-001.json';
const EVIDENCE_SCHEMA_PATH = 'schemas/authority-amendment/v1/aipt-post-merge-reverification-evidence.schema.json';
const EVIDENCE_PATH = 'docs/authority/registry/post-merge-reverification/unregistered-aipt-p1-b000-authority-post-merge-reverification-001.json';
const SUPERSESSION_DIRECTORY = 'docs/authority/registry/authority-validator-supersessions';
const MIGRATION_PATH = 'internal/storage/postgres/migrations/000002_playtest_queue.sql';
const MIGRATION_SHA = '47f02a5a2129473caa0db5e359a0b294a01b2a96329d9f6fa08ac87cc429c997';

const EFFECTIVE_VALIDATORS = Object.freeze({
  AUTHORITY_VALIDATOR_IDENTITY: {
    path: 'scripts/ci/validate/p1-b000-authority.mjs',
    sha256: 'c6f0c8e01397200ce15f48bf1fc2412d9db477dddc37d3f99e0478d26956dd0c',
  },
  B001_HISTORICAL_VALIDATOR_IDENTITY: {
    path: 'scripts/ci/validate/mvp-b001.mjs',
    sha256: '319c8d4a3466c20d14e2d5fc74cc246c9b796d36f884fcc39e2b0a25317351c4',
  },
});

const PROTECTED_HASHES = Object.freeze({
  'docs/authority/UNREGISTERED_AIPT_P1_B000_AUTHORITY.md': '787e1a1a278905d69cd9e000badec8c4143060dcb136e4b0da3d2fb7a12c3ede',
  'docs/authority/registry/unregistered-aipt-p1-b000-authority.json': 'a9845bb74dac409ee243b7024e23aae271ab13c75e18116ae2513853cc02eed6',
  'schemas/playtest-package/v1/aipt-playtest-package.schema.json': '88e55b63c8a6366c872edf0d886202a5c375e224c801433364332ddc4e4e7549',
  'schemas/runtime-adapter-input/v1/aipt-runtime-adapter-input.schema.json': '935b88f2409e604d01a13657a7790dae16e19ebe0c4e96f054c580102ec17413',
  'docs/authority/registry/unregistered-aipt-p1-b000-authority-artifacts.json': '3e7d5ee752ac01ae4034fdaf2ec71231bb4f58eca9174e99619d0a13b200cd4f',
  [MIGRATION_PATH]: MIGRATION_SHA,
});

const SUPERSESSION_IDS = Object.freeze([
  'AIPT-MVP-B001-HISTORICAL-VALIDATOR-SUPERSESSION-001',
  'UNREGISTERED-AIPT-P1-B000-AUTHORITY-VALIDATOR-SUPERSESSION-001',
]);

const FORMAL_JOB_NAMES = Object.freeze([
  'exact-target-identity',
  'authority-validator',
  'b001-historical-validator',
  'effective-authority-resolution',
  'go-test-all-at-target',
]);

const CLOSEOUT_PATHS = Object.freeze([
  '.github/workflows/ci.yml',
  CLOSEOUT_PATH,
  EVIDENCE_PATH,
  'package.json',
  SCHEMA_PATH,
  'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/p1-b000-authority-closeout.mjs',
  'scripts/ci/validate/standalone-entrypoints.mjs',
  'scripts/ci/validate/workflow.mjs',
].sort());

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

function same(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function byteSort(values) {
  return [...values].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
}

function gitOut(repo, args) {
  const cp = git(repo, args, { check: false });
  return cp.status === 0 ? cp.stdout.trim() : null;
}

function gitBlob(repo, commit, relative) {
  const cp = git(repo, ['show', `${commit}:${relative}`], { check: false });
  return cp.status === 0 ? Buffer.from(cp.stdout, 'utf8') : null;
}

function schemaProblems(schema, instance, label) {
  const problems = [];
  for (const error of checkSchemaDocument(schema).errors) problems.push(`${label} schema: ${error}`);
  for (const error of validateInstance(schema, instance).errors) problems.push(`${label} instance: ${error.message}`);
  return problems;
}

function changedPaths(repo) {
  const tracked = git(repo, ['diff', '--name-only', '--no-renames', FORMAL_RUN_HEAD, 'HEAD'], { check: false });
  const worktree = git(repo, ['diff', '--name-only', '--no-renames', 'HEAD'], { check: false });
  const untracked = git(repo, ['ls-files', '--others', '--exclude-standard'], { check: false });
  const lines = (cp) => cp.status === 0 ? cp.stdout.split('\n').filter(Boolean) : [];
  return byteSort(new Set([
    ...lines(tracked),
    ...lines(worktree),
    ...lines(untracked),
  ].filter((relative) => !relative.split('/').includes('node_modules'))));
}

function expectedValidatorIdentities() {
  return Object.entries(EFFECTIVE_VALIDATORS).map(([role, value]) => ({
    role,
    path: value.path,
    sha256: value.sha256,
  }));
}

export function validateCloseoutRecord(record, schema) {
  const problems = schemaProblems(schema, record, `closeout ${record?.closeout_id ?? 'unknown'}`);
  if (record?.schema !== 'aipt.public.base-authority-closeout/v1' ||
      record?.closeout_id !== CLOSEOUT_ID || record?.authority_task_id !== AUTHORITY_TASK_ID ||
      record?.owner_directive !== OWNER_DIRECTIVE) {
    problems.push('closeout task, schema or Owner directive identity is not exact');
  }

  const base = record?.accepted_base_authority_identity;
  if (base?.candidate_commit !== AUTHORITY_CANDIDATE || base?.candidate_tree !== AUTHORITY_TREE ||
      base?.merge_commit !== AUTHORITY_MERGE || base?.merge_tree !== AUTHORITY_TREE ||
      !same(base?.merge_parents, AUTHORITY_PARENTS)) {
    problems.push('accepted Base Authority Candidate/merge identity is not exact');
  }

  if (record?.authority_basis?.amendment_closeout_commit !== AMENDMENT_CLOSEOUT ||
      record?.authority_basis?.owner_authorized !== true || record?.authority_basis?.append_only !== true ||
      record?.authority_basis?.base_semantics_modified !== false) {
    problems.push('Authority Amendment closeout basis or immutable Base semantics boundary drifted');
  }

  const repair = record?.repair_closeout;
  if (repair?.repair_task_id !== REPAIR_TASK_ID ||
      repair?.approved_candidate?.commit !== REPAIR_CANDIDATE || repair?.approved_candidate?.tree !== REPAIR_TREE ||
      repair?.candidate_ci?.run_id !== REPAIR_CANDIDATE_CI || repair?.candidate_ci?.head_sha !== REPAIR_CANDIDATE ||
      repair?.candidate_ci?.conclusion !== 'success' || repair?.candidate_ci?.jobs_passed !== 5 ||
      repair?.candidate_ci?.jobs_failed !== 0 || repair?.candidate_ci?.jobs_skipped !== 0 ||
      repair?.merge_identity?.commit !== REPAIR_MERGE || repair?.merge_identity?.tree !== REPAIR_TREE ||
      !same(repair?.merge_identity?.parents, REPAIR_PARENTS) ||
      repair?.merge_ci?.run_id !== REPAIR_MERGE_CI || repair?.merge_ci?.head_sha !== REPAIR_MERGE ||
      repair?.merge_ci?.conclusion !== 'success' || repair?.merge_ci?.jobs_passed !== 5 ||
      repair?.merge_ci?.jobs_failed !== 0 || repair?.merge_ci?.jobs_skipped !== 0 ||
      repair?.supersession_acceptance_commit !== SUPERSESSION_ACCEPTANCE) {
    problems.push('repair Candidate, independent CI, merge CI or supersession acceptance identity is not exact');
  }

  const effective = record?.effective_authority;
  if (effective?.resolution_id !== `${AUTHORITY_TASK_ID}-EFFECTIVE-001` ||
      effective?.acceptance_commit !== SUPERSESSION_ACCEPTANCE ||
      effective?.acceptance_tree !== SUPERSESSION_ACCEPTANCE_TREE ||
      !same(effective?.validator_identities, expectedValidatorIdentities()) ||
      !same(effective?.accepted_supersession_record_ids, SUPERSESSION_IDS) ||
      effective?.deterministic_ordering !== true || effective?.conflicts !== false) {
    problems.push('effective Authority identities, deterministic supersession order or conflict state drifted');
  }

  const formal = record?.formal_reverification;
  if (formal?.evidence_id !== `${AUTHORITY_TASK_ID}-POST-MERGE-REVERIFICATION-001` ||
      formal?.evidence_path !== EVIDENCE_PATH || formal?.evidence_sha256 !== FORMAL_EVIDENCE_SHA ||
      formal?.workflow_run_id !== FORMAL_RUN_ID || formal?.run_head_sha !== FORMAL_RUN_HEAD ||
      formal?.workflow_definition_source_commit !== REPAIR_CANDIDATE ||
      formal?.target_commit !== AUTHORITY_MERGE || formal?.target_tree !== AUTHORITY_TREE ||
      formal?.historical_merge_ci !== 'ABSENT_NOT_CLAIMED_PASS' || formal?.authorized_result !== 'PASS' ||
      formal?.schema_validation !== 'PASS' || formal?.provenance_validation !== 'PASS' ||
      formal?.required_jobs !== 5) {
    problems.push('formal post-merge reverification evidence binding is not exact');
  }

  for (const [label, lifecycle] of [['repair', repair?.lifecycle], ['Base Authority', record?.lifecycle]]) {
    if (lifecycle?.from !== 'MERGED' || lifecycle?.through !== 'POST_MERGE_VERIFIED' ||
        lifecycle?.to !== 'CLOSED' || lifecycle?.merged !== true ||
        lifecycle?.post_merge_verified !== true || lifecycle?.closed !== true) {
      problems.push(`${label} lifecycle is not MERGED -> POST_MERGE_VERIFIED -> CLOSED`);
    }
  }

  const gates = record?.required_gates;
  const passGateNames = [
    'f1_authority', 'f2_b001', 'amendment', 'repair', 'effective_authority',
    'b001_regression', 'migration_integrity', 'aggregate', 'go_test_all', 'formal_evidence',
  ];
  if (!gates || passGateNames.some((name) => gates[name] !== 'PASS') || gates.uncaught_validator_errors !== 0) {
    problems.push('one or more required closeout gates are not exact PASS/zero');
  }

  const scope = record?.scope;
  if (scope?.governance_only !== true || scope?.business_code_changed !== false ||
      scope?.base_authority_semantics_changed !== false || scope?.run_core_started !== false ||
      scope?.agent_or_model_started !== false || scope?.real_model_calls !== 0 ||
      scope?.real_playtest_executed !== false || scope?.b000_authorized !== false ||
      scope?.b000_started !== false || !same(record?.open_findings, [])) {
    problems.push('governance-only, no-implementation, no-playtest or zero-open-finding boundary drifted');
  }
  if (/\b(?:TBD|TODO|FIXME|XXX)\b|<actual>|<sha>|<commit>|\{\{[^}]+\}\}/i.test(JSON.stringify(record))) {
    problems.push('unresolved placeholder appears in closeout record');
  }
  return problems;
}

function closeoutNegativeProbes(record, schema) {
  const probe = (id, mutate) => {
    const value = clone(record);
    mutate(value);
    return { id, rejected: validateCloseoutRecord(value, schema).length > 0 };
  };
  return [
    probe('C01', (v) => { v.accepted_base_authority_identity.candidate_commit = '0'.repeat(40); }),
    probe('C02', (v) => { v.repair_closeout.merge_identity.commit = '0'.repeat(40); }),
    probe('C03', (v) => { v.effective_authority.acceptance_commit = '0'.repeat(40); }),
    probe('C04', (v) => { v.effective_authority.validator_identities[0].sha256 = '0'.repeat(64); }),
    probe('C05', (v) => { v.effective_authority.accepted_supersession_record_ids.reverse(); }),
    probe('C06', (v) => { v.formal_reverification.evidence_sha256 = '0'.repeat(64); }),
    probe('C07', (v) => { v.formal_reverification.historical_merge_ci = 'PASS'; }),
    probe('C08', (v) => { v.lifecycle.closed = false; }),
    probe('C09', (v) => { v.scope.business_code_changed = true; }),
    probe('C10', (v) => { v.scope.b000_authorized = true; }),
  ];
}

function verifyCommit(repo, commit, expectedTree, expectedParents = null) {
  const problems = [];
  const tree = gitOut(repo, ['rev-parse', `${commit}^{tree}`]);
  const parents = gitOut(repo, ['show', '-s', '--format=%P', commit]);
  if (tree !== expectedTree) problems.push(`${commit} tree is not ${expectedTree}`);
  if (expectedParents && !same(parents?.split(/\s+/), expectedParents)) {
    problems.push(`${commit} parent list is not exact`);
  }
  return problems;
}

function verifyGitTopology(repo) {
  const problems = [
    ...verifyCommit(repo, AUTHORITY_CANDIDATE, AUTHORITY_TREE),
    ...verifyCommit(repo, AUTHORITY_MERGE, AUTHORITY_TREE, AUTHORITY_PARENTS),
    ...verifyCommit(repo, REPAIR_CANDIDATE, REPAIR_TREE),
    ...verifyCommit(repo, REPAIR_MERGE, REPAIR_TREE, REPAIR_PARENTS),
    ...verifyCommit(repo, SUPERSESSION_ACCEPTANCE, SUPERSESSION_ACCEPTANCE_TREE, [REPAIR_MERGE]),
    ...verifyCommit(repo, FORMAL_RUN_HEAD, FORMAL_RUN_HEAD_TREE, [FORMAL_RUN_HEAD_PARENT]),
  ];
  for (const [left, right, label] of [
    [AUTHORITY_CANDIDATE, AUTHORITY_MERGE, 'Base Authority Candidate -> merge'],
    [AMENDMENT_CLOSEOUT, REPAIR_MERGE, 'Amendment closeout -> repair merge'],
    [REPAIR_CANDIDATE, REPAIR_MERGE, 'repair Candidate -> repair merge'],
    [REPAIR_MERGE, SUPERSESSION_ACCEPTANCE, 'repair merge -> supersession acceptance'],
    [SUPERSESSION_ACCEPTANCE, FORMAL_RUN_HEAD, 'supersession acceptance -> formal run head'],
    [FORMAL_RUN_HEAD, 'HEAD', 'formal run head -> current HEAD'],
  ]) {
    if (git(repo, ['merge-base', '--is-ancestor', left, right], { check: false }).status !== 0) {
      problems.push(`${label} ancestry is invalid`);
    }
  }
  if (git(repo, ['diff', '--exit-code', AUTHORITY_CANDIDATE, AUTHORITY_MERGE], { check: false }).status !== 0) {
    problems.push('Base Authority merge does not preserve the exact Candidate tree');
  }
  if (git(repo, ['diff', '--exit-code', REPAIR_CANDIDATE, REPAIR_MERGE], { check: false }).status !== 0) {
    problems.push('repair merge does not preserve the exact approved Candidate tree');
  }
  return problems;
}

function readSupersessions(repo) {
  const directory = path.join(repo, SUPERSESSION_DIRECTORY);
  return byteSort(fs.readdirSync(directory).filter((name) => name.endsWith('.json')))
    .map((name) => readJSON(repo, `${SUPERSESSION_DIRECTORY}/${name}`));
}

function verifySupersessions(repo, records) {
  const problems = [];
  const ids = byteSort(records.map((record) => record.record_id));
  if (!same(ids, SUPERSESSION_IDS) || new Set(ids).size !== 2) {
    problems.push('accepted supersession inventory is not the exact deterministic two-record set');
  }
  const roles = byteSort(records.map((record) => record.role));
  if (!same(roles, byteSort(Object.keys(EFFECTIVE_VALIDATORS))) || new Set(roles).size !== 2) {
    problems.push('accepted supersession roles are missing, duplicated or conflicting');
  }
  for (const record of records) {
    const expected = EFFECTIVE_VALIDATORS[record.role];
    if (!expected || record.path !== expected.path || record.new_sha256 !== expected.sha256 ||
        record.chain_sequence !== 1 || record.predecessor_record_id !== null ||
        record.repair_acceptance?.state !== 'ACCEPTED' ||
        record.repair_acceptance?.independent_acceptance !== 'PASS' ||
        record.repair_acceptance?.candidate_ci_run_id !== REPAIR_CANDIDATE_CI ||
        record.repair_acceptance?.candidate_ci_conclusion !== 'success' ||
        record.provenance?.append_only !== true || record.provenance?.original_identity_preserved !== true) {
      problems.push(`supersession ${record.record_id ?? 'unknown'} is not the exact accepted append-only identity`);
      continue;
    }
    const current = read(repo, expected.path);
    const acceptedBlob = gitBlob(repo, SUPERSESSION_ACCEPTANCE, expected.path);
    if (sha256(current) !== expected.sha256 || !acceptedBlob || sha256(acceptedBlob) !== expected.sha256) {
      problems.push(`effective validator bytes are not reproducible for ${record.role}`);
    }
  }
  return problems;
}

function verifyLifecycle(repo) {
  const problems = [];
  const head = gitOut(repo, ['rev-parse', 'HEAD']);
  const paths = changedPaths(repo);
  let phase = 'INVALID';
  if (head === FORMAL_RUN_HEAD) {
    phase = 'CLOSEOUT_CANDIDATE';
  } else {
    const parents = gitOut(repo, ['show', '-s', '--format=%P', 'HEAD'])?.split(/\s+/);
    const subject = gitOut(repo, ['show', '-s', '--format=%s', 'HEAD']);
    if (same(parents, [FORMAL_RUN_HEAD]) && subject === CLOSEOUT_SUBJECT) phase = 'CLOSED';
    else problems.push('closeout commit must be the unique direct child of the formal-run head with the exact subject');
  }
  if (!same(paths, CLOSEOUT_PATHS)) {
    problems.push(`closeout diff is not the exact nine governance paths: ${JSON.stringify(paths)}`);
  }
  if (paths.some((relative) => /^(?:internal|cmd|packages|aipt)\//.test(relative))) {
    problems.push('business, Run Core, Agent, model or playtest implementation path changed');
  }
  return { phase, paths, problems };
}

function verifyStatusBoundary(repo) {
  const status = readJSON(repo, 'docs/authority/registry/project-status.json');
  const standalone = status.tracks?.['AIPT-STANDALONE'];
  const problems = [];
  if (standalone?.construction !== 'IDLE_WAITING_NEXT_BATCH' || standalone?.current_batch !== 'NO_ACTIVE_BATCH' ||
      standalone?.next_serial_batch !== 'UNREGISTERED-AIPT-P1-B000' ||
      standalone?.next_batch_state !== 'NOT_AUTHORIZED' || standalone?.next_batch_authorized !== false ||
      standalone?.next_batch_started !== false || standalone?.batch_history?.['UNREGISTERED-AIPT-P1-B000'] !== 'NOT_STARTED' ||
      standalone?.global_wip !== 0) {
    problems.push('UNREGISTERED-AIPT-P1-B000 no-start/no-authority/global-WIP boundary drifted');
  }
  return problems;
}

function runImpl(ctx) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push(`ok: ${message}`);
  const fail = (message) => { pass = false; details.push(`FAIL: ${message}`); };
  let schema, record, evidenceSchema, evidence;
  try {
    schema = readJSON(ctx.repo, SCHEMA_PATH);
    record = readJSON(ctx.repo, CLOSEOUT_PATH);
    evidenceSchema = readJSON(ctx.repo, EVIDENCE_SCHEMA_PATH);
    evidence = readJSON(ctx.repo, EVIDENCE_PATH);
  } catch (error) {
    return { result: 'FAIL', details: [`FAIL: closeout input unreadable: ${error.message}`] };
  }

  const closeoutProblems = validateCloseoutRecord(record, schema);
  closeoutProblems.forEach(fail);
  if (closeoutProblems.length === 0) ok('Base Authority closeout schema and record are exact, closed-world and placeholder-free');

  const evidenceSchemaErrors = checkSchemaDocument(evidenceSchema).errors;
  evidenceSchemaErrors.forEach((error) => fail(`formal evidence schema: ${error}`));
  const evidenceProblems = validateRecoveryEvidence(evidence, evidenceSchema, { repo: ctx.repo });
  evidenceProblems.forEach(fail);
  if (evidenceSchemaErrors.length === 0 && evidenceProblems.length === 0) {
    ok('formal post-merge reverification schema, instance and frozen Amendment provenance all PASS');
  }
  if (sha256(read(ctx.repo, EVIDENCE_PATH)) !== FORMAL_EVIDENCE_SHA) {
    fail('formal post-merge reverification evidence SHA-256 drifted');
  } else ok('formal evidence bytes match the accepted SHA-256 identity');
  if (evidence.workflow_execution?.workflow_run_id !== FORMAL_RUN_ID ||
      evidence.workflow_execution?.run_head_sha !== FORMAL_RUN_HEAD ||
      !same(evidence.jobs?.map((job) => job.name), FORMAL_JOB_NAMES) ||
      evidence.jobs?.some((job) => job.conclusion !== 'success')) {
    fail('formal workflow run head, run ID or five required logical jobs drifted');
  } else ok('formal workflow_dispatch run and all five required logical jobs are exact PASS evidence');

  const topologyProblems = verifyGitTopology(ctx.repo);
  topologyProblems.forEach(fail);
  if (topologyProblems.length === 0) ok('Base Authority, repair, supersession acceptance and formal-run Git topology is exact');

  const protectedProblems = [];
  for (const [relative, expected] of Object.entries(PROTECTED_HASHES)) {
    try {
      if (sha256(read(ctx.repo, relative)) !== expected) protectedProblems.push(`${relative} SHA-256 drifted`);
    } catch (error) {
      protectedProblems.push(`${relative} unreadable: ${error.message}`);
    }
  }
  protectedProblems.forEach(fail);
  if (protectedProblems.length === 0) ok('Base Authority contracts, schemas, artifact manifest and B001 migration retain frozen identities');

  const records = readSupersessions(ctx.repo);
  const supersessionProblems = verifySupersessions(ctx.repo, records);
  supersessionProblems.forEach(fail);
  if (supersessionProblems.length === 0) ok('effective Authority resolves deterministically through exactly two accepted non-conflicting supersessions');

  const authority = runAuthority(ctx);
  const b001 = runB001(ctx);
  const amendment = runAmendment(ctx);
  const repair = runRepair(ctx);
  for (const [label, report] of [
    ['F1 Authority', authority],
    ['F2 B001', b001],
    ['accepted Amendment', amendment],
    ['accepted repair', repair],
  ]) {
    if (report.result !== 'PASS') fail(`${label} validator returned structured FAIL`);
    else ok(`${label} validator PASS`);
  }
  if (b001.uncaught_validator_errors !== 0 || repair.uncaught_validator_errors !== 0) {
    fail('B001 or repair validator reports an uncaught validator error');
  } else ok('uncaught validator error count remains zero');
  if (repair.supersession_accepted !== true || repair.b001_regression !== 'PASS' ||
      repair.migration_sha256 !== MIGRATION_SHA) {
    fail('repair acceptance, B001 regression or migration integrity did not PASS');
  } else ok('repair acceptance, B001 business regression and migration integrity PASS');

  const lifecycle = verifyLifecycle(ctx.repo);
  lifecycle.problems.forEach(fail);
  if (lifecycle.problems.length === 0) ok(`${lifecycle.phase} topology has the exact nine governance-only paths`);

  const boundaryProblems = verifyStatusBoundary(ctx.repo);
  boundaryProblems.forEach(fail);
  if (boundaryProblems.length === 0) ok('UNREGISTERED-AIPT-P1-B000 remains NOT_AUTHORIZED / NOT_STARTED with global WIP zero');

  const probes = closeoutNegativeProbes(record, schema);
  for (const probe of probes) if (!probe.rejected) fail(`${probe.id} closeout mutation was accepted`);
  if (probes.every((probe) => probe.rejected)) ok('all C01-C10 closeout identity, evidence, lifecycle and scope mutations reject');

  return {
    result: pass ? 'PASS' : 'FAIL',
    details,
    task_id: AUTHORITY_TASK_ID,
    closeout_id: CLOSEOUT_ID,
    lifecycle_phase: lifecycle.phase,
    authority_identity: {
      candidate_commit: AUTHORITY_CANDIDATE,
      candidate_tree: AUTHORITY_TREE,
      merge_commit: AUTHORITY_MERGE,
      merge_tree: AUTHORITY_TREE,
      merge_parents: AUTHORITY_PARENTS,
    },
    repair_identity: {
      candidate_commit: REPAIR_CANDIDATE,
      candidate_tree: REPAIR_TREE,
      candidate_ci_run_id: REPAIR_CANDIDATE_CI,
      merge_commit: REPAIR_MERGE,
      merge_tree: REPAIR_TREE,
      merge_ci_run_id: REPAIR_MERGE_CI,
      merged: true,
      post_merge_verified: true,
      closed: true,
    },
    effective_authority_identity: SUPERSESSION_ACCEPTANCE,
    effective_validator_identities: Object.fromEntries(
      Object.entries(EFFECTIVE_VALIDATORS).map(([role, value]) => [role, value.sha256]),
    ),
    formal_reverification: {
      evidence_id: evidence.evidence_id,
      evidence_sha256: sha256(read(ctx.repo, EVIDENCE_PATH)),
      workflow_run_id: FORMAL_RUN_ID,
      run_head_sha: FORMAL_RUN_HEAD,
      result: evidence.result,
    },
    f1: authority.result,
    f2: b001.result,
    amendment: amendment.result,
    repair: repair.result,
    uncaught_validator_errors: 0,
    negative_probes: probes.every((probe) => probe.rejected) ? 'PASS' : 'FAIL',
    negative_probe_count: probes.length,
    changed_paths: lifecycle.paths,
    governance_only: true,
    business_code_changed: false,
    base_authority_semantics_changed: false,
    b000_authorized: false,
    b000_implementation_started: false,
    real_model_calls: 0,
    real_playtest_executed: false,
    open_findings: [],
  };
}

export function run(ctx) {
  try {
    return runImpl(ctx);
  } catch (error) {
    return {
      result: 'FAIL',
      details: [`FAIL: structured Base Authority closeout validator error: ${error.message}`],
      task_id: AUTHORITY_TASK_ID,
      closeout_id: CLOSEOUT_ID,
      uncaught_validator_errors: 0,
      governance_only: true,
      business_code_changed: false,
      b000_authorized: false,
      b000_implementation_started: false,
      real_model_calls: 0,
      real_playtest_executed: false,
      open_findings: [],
    };
  }
}

runAsMain(import.meta.url, 'p1-b000-authority-closeout', run);
