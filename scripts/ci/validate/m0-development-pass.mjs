#!/usr/bin/env node
// AIPT-M0-B008 fail-closed M0 Development Pass Candidate validator.
// Node.js standard library only.
import fs from 'node:fs';
import path from 'node:path';
import {
  ALLOWED_PATHS, BASE_COMMIT, BASE_TREE, B007_CLOSEOUT,
  B007_EXTERNAL_SERIAL_PREDECESSOR, B007_IMPLEMENTATION_MERGE,
  CURRENT_BATCH, FROZEN_REGISTRY_PATHS, pathMatchesAllowed,
} from '../lib/constants.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

const RECORD_PATH = 'docs/milestones/m0-development-pass.json';
const DOCUMENT_PATH = 'docs/milestones/M0_DEVELOPMENT_PASS.md';
const STATUS_PATH = 'docs/authority/registry/project-status.json';
const AUDIT_ARCHIVE_SHA256 = '0eb777d62c8045acc29b0a80216951b4aeb36f856bf690d2cd394019a1f7119d';
const AUDIT_ROOT_SHA256 = '33becf9c765902442ec7d7445c50d3ac00737c50bccfc33b5bb4f56e2bdaa90b';
const GPT_AUDIT_SHA256 = 'd35fca102f28387c0e4c7045d65da8418ffc947189500bf639d4edb11bbba207';
const INTEGRATION_ROOT_SHA256 = '329c98d00600ede1e9bdd7830b30f7968cc3de4d458b57bb3f6730a0bfedac91';
const LEDGER_SHA256 = 'e294002e426e157c4eb765b4944568d853bdd4cd4a34afc763073ae21c85a88e';
const CLOSED_FINDINGS = [
  'AIPT-B008-AUDIT-EVIDENCE-SELF-CONTAINMENT-001',
  'AIPT-B008-SOURCE-TREE-DIGEST-001',
  'AIPT-B008-SOURCE-TREE-SUMMARY-FACT-001',
];
const CLOSED_BATCH_IDS = [
  'AIPT-M0-B000', 'AIPT-M0-B001', 'AIPT-M0-B002', 'AIPT-M0-B003',
  'AIPT-M0-B004', 'AIPT-M0-B005', 'AIPT-M0-B006', 'AIPT-M0-B007',
];
const REQUIRED_CHANGED_PATHS = [
  '.github/workflows/ci.yml',
  'README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'docs/milestones/M0.md',
  DOCUMENT_PATH,
  RECORD_PATH,
  'package.json',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/m0-development-pass.mjs',
  'scripts/ci/validate/standalone-entrypoints.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
  'scripts/ci/validate/workflow.mjs',
];
const FROZEN_FILES = [
  '.go-version', 'go.mod', 'go.sum', 'pnpm-lock.yaml', 'pnpm-workspace.yaml',
  'tools/toolchain.lock.json', 'tools/ci-actions.lock.json',
  'tools/supply-chain/policy.json', 'tools/supply-chain/licenses.json',
  ...FROZEN_REGISTRY_PATHS,
];

const EXPECTED_RECORD = {
  schema: 'aipt.m0.development-pass/v1',
  task_id: 'AIPT-M0-B008',
  record_state: 'CANDIDATE_PROPOSAL',
  authority: {
    directive_id: 'AIPT-M0-B008-GPT-PASS-AND-FINALIZE-001',
    authorization_scope: 'IMPLEMENT_AND_FREEZE_CANDIDATE_ONLY',
    branch: 'task/AIPT-M0-B008',
    merge_authorized: false,
  },
  lifecycle: {
    construction: 'IN_PROGRESS',
    current_batch: 'AIPT-M0-B008',
    global_wip: 1,
    batch_history: Object.fromEntries([
      ...CLOSED_BATCH_IDS.map((id) => [id, 'MERGED_CLOSED']),
      ['AIPT-M0-B008', 'IN_PROGRESS'],
    ]),
    next_serial_batch: 'NONE',
    next_batch_state: 'NOT_AUTHORIZED',
    next_batch_authorized: false,
    next_batch_started: false,
  },
  milestone_state: {
    gpt_audit: 'PASS',
    m0_development_pass: 'PROPOSED_PENDING_B008_MERGED_CLOSED',
  },
  proposal: {
    proposed_result: 'M0_DEVELOPMENT_PASS',
    current_effective_status: 'NOT_YET_GRANTED',
    effective_after: 'AIPT-M0-B008_MERGED_CLOSED',
  },
  source_bindings: {
    aipt: {
      source_b007_closeout: { commit: B007_CLOSEOUT.commit, tree: B007_CLOSEOUT.tree },
      accepted_m0_implementation: {
        commit: B007_IMPLEMENTATION_MERGE.commit,
        tree: B007_IMPLEMENTATION_MERGE.tree,
      },
    },
    unregistered: {
      closeout: {
        commit: B007_EXTERNAL_SERIAL_PREDECESSOR.closeout_commit,
        tree: B007_EXTERNAL_SERIAL_PREDECESSOR.closeout_tree,
      },
      accepted_implementation: {
        commit: B007_EXTERNAL_SERIAL_PREDECESSOR.merge_commit,
        tree: B007_EXTERNAL_SERIAL_PREDECESSOR.candidate_tree,
      },
    },
    integration: {
      id: 'INT-AIPT-UNREGISTERED-001',
      result: 'PASS',
      state: 'CLOSED',
      root_sha256: INTEGRATION_ROOT_SHA256,
    },
  },
  audit_binding: {
    audit_ready_archive_sha256: AUDIT_ARCHIVE_SHA256,
    audit_ready_root_sha256: AUDIT_ROOT_SHA256,
    gpt_audit_result_sha256: GPT_AUDIT_SHA256,
    gpt_result: 'PASS',
    gpt_open_findings: [],
    closed_stage_a_r1_findings: CLOSED_FINDINGS,
  },
  batch_identity_ledger: {
    archive_member: 'AUDIT_READY/BATCH_IDENTITY_LEDGER.json',
    schema: 'aipt.m0.batch-identity-ledger/v1',
    sha256: LEDGER_SHA256,
    bound_by_audit_ready_root_sha256: AUDIT_ROOT_SHA256,
  },
  boundaries: {
    production_qualification: 'NOT_GRANTED',
    release_qualification: 'NOT_GRANTED',
    mvp_development_pass: 'NOT_GRANTED',
    human_equivalence: 'NOT_CLAIMED',
    real_playtest_completion: 'NOT_CLAIMED',
    platform_integration: 'FROZEN_WAITING_M1_ENGINE',
    automatic_next_batch: 'NONE',
  },
};

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function compareExact(actual, expected, at = '$') {
  const problems = [];
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual)) return [`${at} must be an array`];
    if (actual.length !== expected.length) problems.push(`${at} array length drifted`);
    for (let i = 0; i < Math.min(actual.length, expected.length); i += 1) {
      problems.push(...compareExact(actual[i], expected[i], `${at}[${i}]`));
    }
    return problems;
  }
  if (isPlainObject(expected)) {
    if (!isPlainObject(actual)) return [`${at} must be an object`];
    const actualKeys = Object.keys(actual).sort();
    const expectedKeys = Object.keys(expected).sort();
    if (JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) {
      problems.push(`${at} key set drifted`);
    }
    for (const key of expectedKeys) {
      if (Object.hasOwn(actual, key)) {
        problems.push(...compareExact(actual[key], expected[key], `${at}.${key}`));
      }
    }
    return problems;
  }
  if (!Object.is(actual, expected)) problems.push(`${at} drifted`);
  return problems;
}

export function validateRecord(record) {
  return compareExact(record, EXPECTED_RECORD);
}

function validateChangedPaths(changed) {
  const problems = [];
  for (const relative of changed) {
    if (!pathMatchesAllowed(relative)) problems.push('path outside B008 scope: ' + relative);
    if (/^(?:internal|schemas|packages|cmd|testdata|tools)\//.test(relative)) {
      problems.push('runtime/product/dependency path changed: ' + relative);
    }
    if (relative === 'go.mod' || relative === 'go.sum' || relative === 'pnpm-lock.yaml' ||
        relative === 'pnpm-workspace.yaml' || relative === '.go-version') {
      problems.push('dependency/lock/toolchain path changed: ' + relative);
    }
  }
  return problems;
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function runNegativeProbes(record) {
  const probes = [
    ['AUDIT_READY root drift', (r) => { r.audit_binding.audit_ready_root_sha256 = '0'.repeat(64); }],
    ['audit archive digest drift', (r) => { r.audit_binding.audit_ready_archive_sha256 = '0'.repeat(64); }],
    ['GPT audit digest drift', (r) => { r.audit_binding.gpt_audit_result_sha256 = '0'.repeat(64); }],
    ['Integration root drift', (r) => { r.source_bindings.integration.root_sha256 = '0'.repeat(64); }],
    ['missing closed finding', (r) => { r.audit_binding.closed_stage_a_r1_findings.pop(); }],
    ['GPT result changed from PASS', (r) => { r.audit_binding.gpt_result = 'FAIL'; }],
    ['production qualification granted', (r) => { r.boundaries.production_qualification = 'GRANTED'; }],
    ['release qualification granted', (r) => { r.boundaries.release_qualification = 'GRANTED'; }],
    ['MVP Development Pass granted', (r) => { r.boundaries.mvp_development_pass = 'GRANTED'; }],
    ['human equivalence claimed', (r) => { r.boundaries.human_equivalence = 'CLAIMED'; }],
    ['real playtest claimed', (r) => { r.boundaries.real_playtest_completion = 'CLAIMED'; }],
    ['platform integration unfrozen', (r) => { r.boundaries.platform_integration = 'UNFROZEN'; }],
    ['B008 Candidate claims MERGED_CLOSED', (r) => { r.lifecycle.batch_history['AIPT-M0-B008'] = 'MERGED_CLOSED'; }],
    ['effective M0 pass set before merge/closeout', (r) => { r.proposal.current_effective_status = 'GRANTED'; }],
    ['automatic next batch added', (r) => { r.boundaries.automatic_next_batch = 'AIPT-M1-B000'; }],
  ];
  const results = [];
  for (const [label, mutate] of probes) {
    const copy = clone(record);
    mutate(copy);
    results.push([label, validateRecord(copy).length > 0]);
  }
  results.push([
    'forbidden runtime path modified',
    validateChangedPaths(['internal/model/runtime.go']).length > 0,
  ]);
  return results;
}

function readJson(repo, relative) {
  return JSON.parse(fs.readFileSync(path.join(repo, relative), 'utf8'));
}

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push('ok: ' + message);
  const fail = (message) => { pass = false; details.push('FAIL: ' + message); };
  let record;
  let status;
  try {
    record = readJson(ctx.repo, RECORD_PATH);
    status = readJson(ctx.repo, STATUS_PATH);
  } catch (error) {
    fail('Candidate record or project status is unreadable: ' + error.message);
    return { result: 'FAIL', details, negative_probes: 'NOT_RUN' };
  }

  const recordProblems = validateRecord(record);
  for (const problem of recordProblems) fail('record: ' + problem);
  if (recordProblems.length === 0) ok('record schema, key sets, identities and Candidate boundaries are exact');

  const standalone = status?.tracks?.['AIPT-STANDALONE'];
  const platform = status?.tracks?.['AIPT-PLATFORM-INTEGRATION'];
  const repoStatus = status?.repositories?.AIPT;
  const pending = repoStatus?.pending_candidate;
  if (standalone?.construction !== record.lifecycle.construction ||
      standalone?.current_batch !== record.lifecycle.current_batch ||
      standalone?.global_wip !== record.lifecycle.global_wip ||
      JSON.stringify(standalone?.batch_history) !== JSON.stringify(record.lifecycle.batch_history) ||
      standalone?.next_serial_batch !== record.lifecycle.next_serial_batch ||
      standalone?.next_batch_state !== record.lifecycle.next_batch_state ||
      standalone?.next_batch_authorized !== record.lifecycle.next_batch_authorized ||
      standalone?.next_batch_started !== record.lifecycle.next_batch_started) {
    fail('public project status disagrees with the Candidate lifecycle');
  } else ok('public project status matches the IN_PROGRESS/WIP1/no-next-batch lifecycle');
  if (repoStatus?.verified_head !== B007_IMPLEMENTATION_MERGE.commit ||
      repoStatus?.verified_tree !== B007_IMPLEMENTATION_MERGE.tree ||
      pending?.task_id !== CURRENT_BATCH || pending?.base_commit !== BASE_COMMIT ||
      pending?.base_tree !== BASE_TREE || pending?.state !== 'IN_PROGRESS' ||
      pending?.current_effective_status !== 'NOT_YET_GRANTED') {
    fail('accepted implementation or pending Candidate status drifted');
  } else ok('accepted implementation remains B007 while B008 is explicit and pending');
  if (platform?.status !== record.boundaries.platform_integration ||
      platform?.unfreeze_authorized !== false) {
    fail('platform integration is not frozen');
  } else ok('platform integration remains frozen without unfreeze authority');

  const document = fs.readFileSync(path.join(ctx.repo, DOCUMENT_PATH), 'utf8');
  const docNeedles = [
    'GPT M0 development audit is `PASS`',
    'only the B008 Candidate',
    '`NOT_YET_GRANTED`',
    'did not execute a real TRPG playtest',
    'not MVP Development Pass',
    'Production and release qualification are not granted',
    'No human-equivalence claim is made',
    'second-auditor production gate remains pending',
    'MODEL, HARNESS and IPC production gates remain unimplemented',
    '`FROZEN_WAITING_M1_ENGINE`',
    'No automatic M1, MVP, platform-integration or other next-batch authorization follows',
  ];
  const missingDocNeedles = docNeedles.filter((needle) => !document.includes(needle));
  if (missingDocNeedles.length > 0) {
    fail('human milestone document misses: ' + missingDocNeedles.join(', '));
  } else ok('human milestone document states every required non-inflation boundary');

  const baseCommit = git(ctx.repo, ['rev-parse', BASE_COMMIT + '^{commit}'], { check: false });
  const baseTree = git(ctx.repo, ['rev-parse', BASE_COMMIT + '^{tree}'], { check: false });
  if (baseCommit.status !== 0 || baseCommit.stdout.trim() !== BASE_COMMIT ||
      baseTree.status !== 0 || baseTree.stdout.trim() !== BASE_TREE) {
    fail('fixed B008 base commit/tree does not resolve exactly');
  } else ok('fixed B008 base commit/tree resolves exactly');
  const ancestry = git(ctx.repo, ['merge-base', '--is-ancestor', BASE_COMMIT, 'HEAD'], { check: false });
  if (ancestry.status !== 0) fail('HEAD does not descend from the fixed B008 base');
  else ok('HEAD descends from the fixed B008 base');
  const branch = git(ctx.repo, ['symbolic-ref', '--short', 'HEAD'], { check: false });
  if (branch.status !== 0 || branch.stdout.trim() !== 'task/AIPT-M0-B008') {
    fail('Candidate is not on task/AIPT-M0-B008');
  } else ok('Candidate branch is exact');
  const mergeList = git(ctx.repo, ['rev-list', '--merges', BASE_COMMIT + '..HEAD'], { check: false });
  if (mergeList.status !== 0 || mergeList.stdout.trim() !== '') {
    fail('B008 Candidate history contains a post-base merge');
  } else ok('B008 Candidate history contains zero post-base merge commits');

  const tracked = git(ctx.repo, ['diff', '--name-only', '--no-renames', BASE_COMMIT], { check: false });
  const untracked = git(ctx.repo, ['ls-files', '--others', '--exclude-standard'], { check: false });
  const changed = [...new Set([
    ...tracked.stdout.split('\n'), ...untracked.stdout.split('\n'),
  ].filter(Boolean))].sort();
  for (const problem of validateChangedPaths(changed)) fail(problem);
  for (const relative of REQUIRED_CHANGED_PATHS) {
    if (!changed.includes(relative)) fail('required B008 Candidate path is absent: ' + relative);
  }
  if (changed.length === REQUIRED_CHANGED_PATHS.length &&
      changed.every((relative) => REQUIRED_CHANGED_PATHS.includes(relative))) {
    ok('changed-path set is the exact 15-path B008 Candidate surface');
  }

  for (const relative of FROZEN_FILES) {
    const base = git(ctx.repo, ['show', BASE_COMMIT + ':' + relative], { check: false });
    let current;
    try {
      current = fs.readFileSync(path.join(ctx.repo, relative), 'utf8');
    } catch (error) {
      fail('frozen file unreadable: ' + relative + ': ' + error.message);
      continue;
    }
    if (base.status !== 0 || base.stdout !== current) fail('frozen file changed: ' + relative);
  }
  if (!details.some((line) => line.startsWith('FAIL: frozen file'))) {
    ok('dependency, lock, toolchain and frozen authority files are byte-identical to Base');
  }

  const rawRecord = fs.readFileSync(path.join(ctx.repo, RECORD_PATH), 'utf8');
  const disclosurePatterns = [
    [/\/home\//, 'absolute local path'],
    [/file:\/\//i, 'local URI'],
    [/PRIVATE_REASONING/i, 'private reasoning marker'],
    [/\bsk-[A-Za-z0-9_-]{8,}\b/, 'credential-like marker'],
  ];
  for (const [pattern, label] of disclosurePatterns) {
    if (pattern.test(rawRecord)) fail('milestone record contains ' + label);
  }
  if (disclosurePatterns.every(([pattern]) => !pattern.test(rawRecord))) {
    ok('milestone record contains no local path, prompt/reasoning body or credential marker');
  }

  const probes = runNegativeProbes(record);
  const rejected = probes.filter(([, good]) => good).length;
  for (const [label, good] of probes) {
    if (!good) fail('negative probe was accepted: ' + label);
  }
  if (rejected === probes.length) ok('all ' + rejected + ' required negative probes reject');

  return {
    result: pass ? 'PASS' : 'FAIL',
    details,
    negative_probes: rejected === probes.length ? 'PASS' : 'FAIL',
    negative_probe_count: probes.length,
    changed_paths: changed,
  };
}

runAsMain(import.meta.url, 'm0-development-pass', run);
