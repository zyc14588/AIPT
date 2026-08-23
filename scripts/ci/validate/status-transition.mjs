#!/usr/bin/env node
// AIPT-M0-B007 construction/status-transition validator.
import fs from 'node:fs';
import path from 'node:path';
import {
  ACTIVE_BATCH, B000, B001, B002, B002_CLOSEOUT, B003, B003_CLOSEOUT,
  B004_CANDIDATE, B004_CLOSEOUT, B004_IMPLEMENTATION_MERGE,
  B004_POST_MERGE_REPAIR, B005_CANDIDATE, B005_CLOSEOUT,
  B005_IMPLEMENTATION_MERGE, B006_CANDIDATE, B006_CLOSEOUT,
  B006_IMPLEMENTATION_MERGE, B007_BASE_COMMIT, B007_BASE_TREE,
  B007_CONSTRUCTION_HARNESS, B007_EXTERNAL_SERIAL_PREDECESSOR,
  CURRENT_BATCH, EXTERNAL_SERIAL_HISTORY, FROZEN_REGISTRY_PATHS,
  HARNESS_SOURCE, STATUS_DATE, STATUS_TRANSITION_PATHS,
} from '../lib/constants.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

const SCHEMA = 'aipt.public.project-status/v1';
const SNAPSHOT_ID = 'AIPT-M0-B007-CONSTRUCTION-001';
const DESIGN = 'FROZEN_R0_R16_DCA_BOOTSTRAP';
const CONSTRUCTION = 'IN_PROGRESS';
const NEXT_BATCH = 'INT-AIPT-UNREGISTERED-001';
const NEXT_STATE = 'NOT_AUTHORIZED';
const PLATFORM = 'FROZEN_WAITING_M1_ENGINE';
const CLOSED_BATCH_IDS = [
  'AIPT-M0-B000', 'AIPT-M0-B001', 'AIPT-M0-B002', 'AIPT-M0-B003',
  'AIPT-M0-B004', 'AIPT-M0-B005', 'AIPT-M0-B006',
];
const ROOT_KEYS = [
  'as_of', 'auditing', 'authority_snapshot_id', 'prompt_assets',
  'public_reference', 'repositories', 'runtime', 'schema', 'tracks',
];
const STANDALONE_KEYS = [
  'batch_history', 'construction', 'current_batch', 'design',
  'external_batch_history', 'external_serial_predecessor', 'global_wip',
  'next_batch_authorized', 'next_batch_started', 'next_batch_state',
  'next_serial_batch',
];
const PREDECESSOR_KEYS = [
  'candidate_commit', 'candidate_tree', 'closeout_ci_conclusion',
  'closeout_ci_run', 'closeout_commit', 'closeout_tree', 'id',
  'implementation_merge', 'status',
];
const AIPT_REPOSITORY_KEYS = [
  'default_branch', 'url', 'verified_head', 'verified_state', 'verified_tree',
];
const UNREGISTERED_REPOSITORY_KEYS = [
  'default_branch', 'formal_name_zh', 'planning_snapshot', 'readiness', 'url',
  'verified_batch', 'verified_closeout', 'verified_closeout_tree',
  'verified_head', 'verified_tree',
];
const RUNTIME_KEYS = [
  'deepseek_harness_commit', 'deepseek_harness_previous_commit',
  'deepseek_harness_release', 'deepseek_harness_upgrade_authority', 'gpu',
  'harness_installation', 'llama_cpp_build', 'local_model', 'os',
  'primary_remote_model', 'shell', 'status', 'unified_memory',
];
const STATUS_PATHS_LITERAL = [
  'README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'docs/runtime/README.md',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
];
const EXPECTED_VERIFIED_STATE =
  'AIPT-M0-B007 IN_PROGRESS: fixed Base ' + B007_BASE_COMMIT + ' (tree ' + B007_BASE_TREE +
  '); repositories.AIPT verified implementation remains immutable B006 merge ' +
  B006_IMPLEMENTATION_MERGE.commit + ' (tree ' + B006_IMPLEMENTATION_MERGE.tree +
  '); local-only read-only Web Dashboard construction with exact Config/Health/Queue/Run/StatusTable/Report panels; ' +
  'Queue/Run/Status backend and Report UI export/generators NOT_IMPLEMENTED; installed bridge identity did not match ' +
  'the prior qualification baseline and fresh Q1 failed before provider use, so final construction route ' +
  B007_CONSTRUCTION_HARNESS.final_route + ' with zero provider calls and split-memory manual edit ' +
  String(B007_CONSTRUCTION_HARNESS.split_memory_manual_edit) + '; external serial predecessor ' +
  B007_EXTERNAL_SERIAL_PREDECESSOR.batch + ' MERGED_CLOSED at closeout ' +
  B007_EXTERNAL_SERIAL_PREDECESSOR.closeout_commit + ' (tree ' +
  B007_EXTERNAL_SERIAL_PREDECESSOR.closeout_tree + ', closeout CI ' +
  B007_EXTERNAL_SERIAL_PREDECESSOR.closeout_ci_run + ' success); B000/B001/B002/B003/B004/B005/B006 remain ' +
  'MERGED_CLOSED; construction IN_PROGRESS with current_batch AIPT-M0-B007 and global WIP 1; next serial batch ' +
  NEXT_BATCH + ' is NOT_AUTHORIZED and not started; platform integration remains frozen';

function same(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function exactKeys(value, expected) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    same(Object.keys(value).sort(), [...expected].sort());
}

function expectedExternalHistory() {
  return [
    {
      id: EXTERNAL_SERIAL_HISTORY[0].batch,
      status: EXTERNAL_SERIAL_HISTORY[0].status,
      closeout_commit: EXTERNAL_SERIAL_HISTORY[0].closeout_commit,
      closeout_ci_run: EXTERNAL_SERIAL_HISTORY[0].closeout_ci_run,
      closeout_ci_conclusion: EXTERNAL_SERIAL_HISTORY[0].closeout_ci_conclusion,
    },
    {
      id: EXTERNAL_SERIAL_HISTORY[1].batch,
      status: EXTERNAL_SERIAL_HISTORY[1].status,
      candidate_commit: EXTERNAL_SERIAL_HISTORY[1].candidate,
      candidate_tree: EXTERNAL_SERIAL_HISTORY[1].candidate_tree,
      implementation_merge: EXTERNAL_SERIAL_HISTORY[1].merge_commit,
      closeout_commit: EXTERNAL_SERIAL_HISTORY[1].closeout_commit,
      closeout_tree: EXTERNAL_SERIAL_HISTORY[1].closeout_tree,
      closeout_ci_run: EXTERNAL_SERIAL_HISTORY[1].closeout_ci_run,
      closeout_ci_conclusion: EXTERNAL_SERIAL_HISTORY[1].closeout_ci_conclusion,
    },
  ];
}

export function checkStatusDocument(status) {
  const problems = [];
  const standalone = status?.tracks?.['AIPT-STANDALONE'];
  const platform = status?.tracks?.['AIPT-PLATFORM-INTEGRATION'];
  const repo = status?.repositories?.AIPT;
  const unregistered = status?.repositories?.UNREGISTERED;
  const predecessor = standalone?.external_serial_predecessor;
  if (!exactKeys(status, ROOT_KEYS)) problems.push('root keys are not exact');
  if (status?.schema !== SCHEMA) problems.push('status schema drifted');
  if (status?.as_of !== STATUS_DATE) problems.push('status date drifted');
  if (status?.authority_snapshot_id !== SNAPSHOT_ID) problems.push('snapshot id drifted');
  if (!exactKeys(standalone, STANDALONE_KEYS)) problems.push('standalone keys are not exact');
  if (standalone?.design !== DESIGN) problems.push('standalone design drifted');
  if (standalone?.construction !== CONSTRUCTION) problems.push('construction is not IN_PROGRESS');
  if (standalone?.current_batch !== ACTIVE_BATCH || ACTIVE_BATCH !== CURRENT_BATCH ||
      CURRENT_BATCH !== 'AIPT-M0-B007') problems.push('current/active batch is not exact B007');
  if (standalone?.global_wip !== 1) problems.push('GLOBAL_WIP is not one');
  if (standalone?.next_serial_batch !== NEXT_BATCH || standalone?.next_batch_state !== NEXT_STATE) {
    problems.push('next serial batch/state drifted');
  }
  if (standalone?.next_batch_authorized !== false) problems.push('next batch was authorized');
  if (standalone?.next_batch_started !== false) problems.push('next batch was started');
  const expectedHistoryKeys = [...CLOSED_BATCH_IDS, CURRENT_BATCH];
  if (!exactKeys(standalone?.batch_history, expectedHistoryKeys)) problems.push('batch history keys are not exact');
  for (const id of CLOSED_BATCH_IDS) {
    if (standalone?.batch_history?.[id] !== 'MERGED_CLOSED') problems.push(id + ' is not MERGED_CLOSED');
  }
  if (standalone?.batch_history?.[CURRENT_BATCH] !== 'IN_PROGRESS') problems.push('B007 is not IN_PROGRESS');
  if (!exactKeys(predecessor, PREDECESSOR_KEYS)) problems.push('external predecessor keys are not exact');
  const expectedPredecessor = {
    id: B007_EXTERNAL_SERIAL_PREDECESSOR.batch,
    status: B007_EXTERNAL_SERIAL_PREDECESSOR.status,
    candidate_commit: B007_EXTERNAL_SERIAL_PREDECESSOR.candidate,
    candidate_tree: B007_EXTERNAL_SERIAL_PREDECESSOR.candidate_tree,
    implementation_merge: B007_EXTERNAL_SERIAL_PREDECESSOR.merge_commit,
    closeout_commit: B007_EXTERNAL_SERIAL_PREDECESSOR.closeout_commit,
    closeout_tree: B007_EXTERNAL_SERIAL_PREDECESSOR.closeout_tree,
    closeout_ci_run: B007_EXTERNAL_SERIAL_PREDECESSOR.closeout_ci_run,
    closeout_ci_conclusion: B007_EXTERNAL_SERIAL_PREDECESSOR.closeout_ci_conclusion,
  };
  if (!same(predecessor, expectedPredecessor)) problems.push('external predecessor provenance drifted');
  if (!same(standalone?.external_batch_history, expectedExternalHistory())) {
    problems.push('external serial history drifted');
  }
  if (!exactKeys(platform, ['status', 'unfreeze_authorized']) ||
      platform?.status !== PLATFORM || platform?.unfreeze_authorized !== false) {
    problems.push('platform integration was unfrozen or widened');
  }
  if (!exactKeys(repo, AIPT_REPOSITORY_KEYS) ||
      repo?.url !== 'https://github.com/zyc14588/AIPT' || repo?.default_branch !== 'main' ||
      repo?.verified_head !== B006_IMPLEMENTATION_MERGE.commit ||
      repo?.verified_tree !== B006_IMPLEMENTATION_MERGE.tree ||
      repo?.verified_state !== EXPECTED_VERIFIED_STATE) {
    problems.push('AIPT verified implementation identity/state drifted');
  }
  if (!exactKeys(unregistered, UNREGISTERED_REPOSITORY_KEYS) ||
      unregistered?.url !== 'https://github.com/zyc14588/UNREGISTERED' ||
      unregistered?.default_branch !== 'main' ||
      unregistered?.planning_snapshot !== '3e4a28bba1caf44828412f90bb6715b6955e3604' ||
      unregistered?.verified_batch !== B007_EXTERNAL_SERIAL_PREDECESSOR.batch ||
      unregistered?.verified_head !== B007_EXTERNAL_SERIAL_PREDECESSOR.merge_commit ||
      unregistered?.verified_tree !== B007_EXTERNAL_SERIAL_PREDECESSOR.candidate_tree ||
      unregistered?.verified_closeout !== B007_EXTERNAL_SERIAL_PREDECESSOR.closeout_commit ||
      unregistered?.verified_closeout_tree !== B007_EXTERNAL_SERIAL_PREDECESSOR.closeout_tree ||
      unregistered?.readiness !== 'PLAYTESTABLE_DRAFT' || unregistered?.formal_name_zh !== '《未登记》') {
    problems.push('UNREGISTERED repository status drifted');
  }
  if (!exactKeys(status?.runtime, RUNTIME_KEYS)) problems.push('runtime keys are not exact');
  if (status?.runtime?.deepseek_harness_commit !== HARNESS_SOURCE.commit ||
      status?.runtime?.deepseek_harness_previous_commit !== HARNESS_SOURCE.previous_commit ||
      status?.runtime?.deepseek_harness_release !== HARNESS_SOURCE.release ||
      status?.runtime?.deepseek_harness_upgrade_authority !== HARNESS_SOURCE.upgrade_authority ||
      status?.runtime?.harness_installation !== HARNESS_SOURCE.installation ||
      status?.runtime?.status !== 'AIPT-M0-B007 local Web dashboard construction in progress') {
    problems.push('runtime/Harness identity or B007 status drifted');
  }
  return problems;
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function identityChecks(repo) {
  const checks = [
    ['B000 merge', B000.commit, B000.tree],
    ['B001 merge', B001.merge_commit, B001.tree],
    ['B002 merge', B002.merge_commit, B002.tree],
    ['B002 closeout', B002_CLOSEOUT.commit, B002_CLOSEOUT.tree],
    ['B003 merge', B003.merge_commit, B003.tree],
    ['B003 closeout', B003_CLOSEOUT.commit, B003_CLOSEOUT.tree],
    ['B004 Candidate', B004_CANDIDATE.commit, B004_CANDIDATE.tree],
    ['B004 merge', B004_IMPLEMENTATION_MERGE.commit, B004_IMPLEMENTATION_MERGE.tree],
    ['B004 repair', B004_POST_MERGE_REPAIR.commit, B004_POST_MERGE_REPAIR.tree],
    ['B004 closeout', B004_CLOSEOUT.commit, B004_CLOSEOUT.tree],
    ['B005 Candidate', B005_CANDIDATE.commit, B005_CANDIDATE.tree],
    ['B005 merge', B005_IMPLEMENTATION_MERGE.commit, B005_IMPLEMENTATION_MERGE.tree],
    ['B005 closeout', B005_CLOSEOUT.commit, B005_CLOSEOUT.tree],
    ['B006 Candidate', B006_CANDIDATE.commit, B006_CANDIDATE.tree],
    ['B006 merge', B006_IMPLEMENTATION_MERGE.commit, B006_IMPLEMENTATION_MERGE.tree],
    ['B006 closeout/B007 base', B006_CLOSEOUT.commit, B006_CLOSEOUT.tree],
  ];
  return checks.map(([label, commit, tree]) => {
    const actual = git(repo, ['rev-parse', commit + '^{tree}'], { check: false });
    return [label, actual.status === 0 && actual.stdout.trim() === tree];
  });
}

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push('ok: ' + message);
  const fail = (message) => { pass = false; details.push('FAIL: ' + message); };
  let status;
  try {
    status = JSON.parse(fs.readFileSync(path.join(ctx.repo, 'docs/authority/registry/project-status.json'), 'utf8'));
  } catch (error) {
    fail('project-status.json is unreadable: ' + error.message);
    return { result: 'FAIL', details };
  }
  for (const problem of checkStatusDocument(status)) fail(problem);
  if (pass) ok('machine status is the exact B007 IN_PROGRESS construction state');
  if (!same(STATUS_TRANSITION_PATHS, STATUS_PATHS_LITERAL)) fail('STATUS_TRANSITION_PATHS drifted');
  else ok('future seven-path closeout status surface is exact');

  for (const [label, good] of identityChecks(ctx.repo)) {
    if (good) ok(label + ' immutable tree verified'); else fail(label + ' immutable tree drifted');
  }
  const closeoutParents = git(ctx.repo, ['rev-list', '--parents', '-n', '1', B006_CLOSEOUT.commit], { check: false });
  if (closeoutParents.status !== 0 ||
      closeoutParents.stdout.trim() !== B006_CLOSEOUT.commit + ' ' + B006_CLOSEOUT.parent) {
    fail('B006 closeout parent drifted');
  } else ok('B006 closeout is the exact single-parent B007 base');

  for (const relative of FROZEN_REGISTRY_PATHS) {
    const base = git(ctx.repo, ['show', B007_BASE_COMMIT + ':' + relative], { check: false });
    const current = fs.readFileSync(path.join(ctx.repo, relative), 'utf8');
    if (base.status !== 0 || base.stdout !== current) fail('frozen registry changed: ' + relative);
    else ok('frozen registry unchanged: ' + relative);
  }

  const docs = [
    ['README.md', [SNAPSHOT_ID, 'AIPT-M0-B007', 'IN_PROGRESS', NEXT_BATCH, NEXT_STATE, 'next_batch_started = false']],
    ['docs/authority/PROJECT_STATUS.md', [SNAPSHOT_ID, 'AIPT-M0-B007', 'GLOBAL_WIP = 1', NEXT_BATCH, NEXT_STATE]],
  ];
  for (const [relative, needles] of docs) {
    const body = fs.readFileSync(path.join(ctx.repo, relative), 'utf8');
    const missing = needles.filter((needle) => !body.includes(needle));
    if (missing.length) fail(relative + ' misses B007 construction tokens: ' + missing.join(', '));
    else ok(relative + ' carries the B007 construction boundary');
  }

  const mutations = [
    ['construction closed', (s) => { s.tracks['AIPT-STANDALONE'].construction = 'IDLE_WAITING_NEXT_BATCH'; }],
    ['active batch changed', (s) => { s.tracks['AIPT-STANDALONE'].current_batch = 'AIPT-M0-B008'; }],
    ['GLOBAL_WIP zero', (s) => { s.tracks['AIPT-STANDALONE'].global_wip = 0; }],
    ['next batch authorized', (s) => { s.tracks['AIPT-STANDALONE'].next_batch_authorized = true; }],
    ['next batch started', (s) => { s.tracks['AIPT-STANDALONE'].next_batch_started = true; }],
    ['B007 falsely closed', (s) => { s.tracks['AIPT-STANDALONE'].batch_history[CURRENT_BATCH] = 'MERGED_CLOSED'; }],
    ['predecessor tree drift', (s) => { s.tracks['AIPT-STANDALONE'].external_serial_predecessor.candidate_tree = 'wrong'; }],
    ['external history removed', (s) => { s.tracks['AIPT-STANDALONE'].external_batch_history.pop(); }],
    ['platform unfrozen', (s) => { s.tracks['AIPT-PLATFORM-INTEGRATION'].unfreeze_authorized = true; }],
    ['verified head changed to construction', (s) => { s.repositories.AIPT.verified_head = B007_BASE_COMMIT; }],
    ['verified state drift', (s) => { s.repositories.AIPT.verified_state += ' drift'; }],
    ['Harness identity drift', (s) => { s.runtime.deepseek_harness_commit = HARNESS_SOURCE.previous_commit; }],
    ['runtime closed', (s) => { s.runtime.status = 'closed'; }],
    ['UNREGISTERED implementation drift', (s) => { s.repositories.UNREGISTERED.verified_head = 'wrong'; }],
    ['unknown root field', (s) => { s.b008_started = true; }],
  ];
  let rejected = 0;
  for (const [, mutate] of mutations) {
    const copy = clone(status);
    mutate(copy);
    if (checkStatusDocument(copy).length > 0) rejected += 1;
  }
  if (rejected !== mutations.length) fail('status mutation probes rejected ' + rejected + '/' + mutations.length);
  else ok('all ' + rejected + ' status mutation probes fail closed');

  return { result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'status-transition', run);
