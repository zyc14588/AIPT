#!/usr/bin/env node
// AIPT-M0-B008 Candidate status-transition validator.
import fs from 'node:fs';
import path from 'node:path';
import {
  ACTIVE_BATCH, B000, B001, B002, B002_CLOSEOUT, B003, B003_CLOSEOUT,
  B004_CANDIDATE, B004_CLOSEOUT, B004_IMPLEMENTATION_MERGE,
  B004_POST_MERGE_REPAIR, B005_CANDIDATE, B005_CLOSEOUT,
  B005_IMPLEMENTATION_MERGE, B006_CANDIDATE, B006_CLOSEOUT,
  B006_IMPLEMENTATION_MERGE, B007_CANDIDATE, B007_CLOSEOUT,
  B007_EXTERNAL_SERIAL_PREDECESSOR, B007_IMPLEMENTATION_MERGE,
  B007_ORIGINAL_CANDIDATE, CURRENT_BATCH, EXTERNAL_SERIAL_HISTORY,
  FROZEN_REGISTRY_PATHS, HARNESS_SOURCE, STATUS_DATE,
  STATUS_TRANSITION_PATHS,
} from '../lib/constants.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

const SCHEMA = 'aipt.public.project-status/v1';
const SNAPSHOT_ID = 'AIPT-M0-B008-CANDIDATE-001';
const DESIGN = 'FROZEN_R0_R16_DCA_BOOTSTRAP';
const CONSTRUCTION = 'IN_PROGRESS';
const NEXT_BATCH = 'NONE';
const NEXT_STATE = 'NOT_AUTHORIZED';
const PLATFORM = 'FROZEN_WAITING_M1_ENGINE';
const CLOSED_BATCH_IDS = [
  'AIPT-M0-B000', 'AIPT-M0-B001', 'AIPT-M0-B002', 'AIPT-M0-B003',
  'AIPT-M0-B004', 'AIPT-M0-B005', 'AIPT-M0-B006', 'AIPT-M0-B007',
];
const BATCH_HISTORY_KEYS = [...CLOSED_BATCH_IDS, 'AIPT-M0-B008'];
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
  'default_branch', 'pending_candidate', 'url', 'verified_head',
  'verified_state', 'verified_tree',
];
const PENDING_CANDIDATE_KEYS = [
  'base_commit', 'base_tree', 'branch', 'current_effective_status',
  'effective_after', 'proposed_result', 'state', 'task_id',
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
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/validate/status-transition.mjs',
];

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

export function checkStatusDocument(status, acceptedVerifiedState) {
  const problems = [];
  const standalone = status?.tracks?.['AIPT-STANDALONE'];
  const platform = status?.tracks?.['AIPT-PLATFORM-INTEGRATION'];
  const repo = status?.repositories?.AIPT;
  const unregistered = status?.repositories?.UNREGISTERED;
  const predecessor = standalone?.external_serial_predecessor;
  const pending = repo?.pending_candidate;

  if (!exactKeys(status, ROOT_KEYS)) problems.push('root keys are not exact');
  if (status?.schema !== SCHEMA) problems.push('status schema drifted');
  if (status?.as_of !== STATUS_DATE) problems.push('status date drifted');
  if (status?.authority_snapshot_id !== SNAPSHOT_ID) problems.push('snapshot id drifted');
  if (!exactKeys(standalone, STANDALONE_KEYS)) problems.push('standalone keys are not exact');
  if (standalone?.design !== DESIGN) problems.push('standalone design drifted');
  if (standalone?.construction !== CONSTRUCTION) problems.push('construction is not IN_PROGRESS');
  if (standalone?.current_batch !== ACTIVE_BATCH || ACTIVE_BATCH !== CURRENT_BATCH ||
      CURRENT_BATCH !== 'AIPT-M0-B008') {
    problems.push('B008 is not the sole active batch');
  }
  if (standalone?.global_wip !== 1) problems.push('GLOBAL_WIP is not one');
  if (standalone?.next_serial_batch !== NEXT_BATCH || standalone?.next_batch_state !== NEXT_STATE) {
    problems.push('next serial batch/state is not NONE/NOT_AUTHORIZED');
  }
  if (standalone?.next_batch_authorized !== false) problems.push('next batch was authorized');
  if (standalone?.next_batch_started !== false) problems.push('next batch was started');
  if (!exactKeys(standalone?.batch_history, BATCH_HISTORY_KEYS)) {
    problems.push('batch history keys are not exact');
  }
  for (const id of CLOSED_BATCH_IDS) {
    if (standalone?.batch_history?.[id] !== 'MERGED_CLOSED') problems.push(id + ' is not MERGED_CLOSED');
  }
  if (standalone?.batch_history?.['AIPT-M0-B008'] !== 'IN_PROGRESS') {
    problems.push('B008 is not IN_PROGRESS');
  }

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
      repo?.verified_head !== B007_IMPLEMENTATION_MERGE.commit ||
      repo?.verified_tree !== B007_IMPLEMENTATION_MERGE.tree ||
      repo?.verified_state !== acceptedVerifiedState) {
    problems.push('accepted AIPT implementation identity/state drifted');
  }
  if (!exactKeys(pending, PENDING_CANDIDATE_KEYS) ||
      pending?.task_id !== CURRENT_BATCH || pending?.branch !== 'task/AIPT-M0-B008' ||
      pending?.base_commit !== B007_CLOSEOUT.commit || pending?.base_tree !== B007_CLOSEOUT.tree ||
      pending?.state !== 'IN_PROGRESS' || pending?.proposed_result !== 'M0_DEVELOPMENT_PASS' ||
      pending?.current_effective_status !== 'NOT_YET_GRANTED' ||
      pending?.effective_after !== 'AIPT-M0-B008_MERGED_CLOSED') {
    problems.push('pending B008 Candidate surface drifted or became effective');
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
      status?.runtime?.status !== 'secure local Web dashboard merged/closed') {
    problems.push('runtime/Harness accepted identity drifted');
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
    ['B007 original Candidate', B007_ORIGINAL_CANDIDATE.commit, B007_ORIGINAL_CANDIDATE.tree],
    ['B007 final Candidate', B007_CANDIDATE.commit, B007_CANDIDATE.tree],
    ['B007 implementation merge', B007_IMPLEMENTATION_MERGE.commit, B007_IMPLEMENTATION_MERGE.tree],
    ['B007 closeout/B008 base', B007_CLOSEOUT.commit, B007_CLOSEOUT.tree],
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
  let acceptedVerifiedState;
  try {
    status = JSON.parse(fs.readFileSync(
      path.join(ctx.repo, 'docs/authority/registry/project-status.json'), 'utf8',
    ));
    const baseStatus = git(ctx.repo, [
      'show', B007_CLOSEOUT.commit + ':docs/authority/registry/project-status.json',
    ]);
    acceptedVerifiedState = JSON.parse(baseStatus.stdout).repositories.AIPT.verified_state;
  } catch (error) {
    fail('project status or accepted base status is unreadable: ' + error.message);
    return { result: 'FAIL', details };
  }

  for (const problem of checkStatusDocument(status, acceptedVerifiedState)) fail(problem);
  if (pass) ok('machine status is the exact B008 IN_PROGRESS Candidate transition');
  if (!same(STATUS_TRANSITION_PATHS, STATUS_PATHS_LITERAL)) fail('STATUS_TRANSITION_PATHS drifted');
  else ok('five-path Candidate status surface is exact');

  for (const [label, good] of identityChecks(ctx.repo)) {
    if (good) ok(label + ' immutable tree verified'); else fail(label + ' immutable tree drifted');
  }
  const closeoutParents = git(ctx.repo, [
    'rev-list', '--parents', '-n', '1', B007_CLOSEOUT.commit,
  ], { check: false });
  if (closeoutParents.status !== 0 ||
      closeoutParents.stdout.trim() !== B007_CLOSEOUT.commit + ' ' + B007_CLOSEOUT.parent) {
    fail('B007 closeout parent drifted');
  } else ok('B007 closeout is the exact single-parent B008 base');

  for (const relative of FROZEN_REGISTRY_PATHS) {
    const base = git(ctx.repo, ['show', B007_CLOSEOUT.commit + ':' + relative], { check: false });
    const current = fs.readFileSync(path.join(ctx.repo, relative), 'utf8');
    if (base.status !== 0 || base.stdout !== current) fail('frozen registry changed: ' + relative);
    else ok('frozen registry unchanged: ' + relative);
  }

  const docs = [
    ['README.md', [SNAPSHOT_ID, CURRENT_BATCH, 'IN_PROGRESS Candidate', CONSTRUCTION,
      'GLOBAL_WIP = 1', 'NOT_YET_GRANTED', 'next_serial_batch = NONE']],
    ['docs/authority/PROJECT_STATUS.md', [SNAPSHOT_ID, CURRENT_BATCH,
      'IN_PROGRESS Candidate', CONSTRUCTION, 'GLOBAL_WIP = 1',
      'NOT_YET_GRANTED', 'next_serial_batch = NONE']],
  ];
  for (const [relative, needles] of docs) {
    const body = fs.readFileSync(path.join(ctx.repo, relative), 'utf8');
    const missing = needles.filter((needle) => !body.includes(needle));
    if (missing.length) fail(relative + ' misses B008 Candidate tokens: ' + missing.join(', '));
    else ok(relative + ' carries the B008 Candidate boundary');
  }

  const mutations = [
    ['construction closed early', (s) => { s.tracks['AIPT-STANDALONE'].construction = 'IDLE_WAITING_NEXT_BATCH'; }],
    ['active batch cleared', (s) => { s.tracks['AIPT-STANDALONE'].current_batch = 'NO_ACTIVE_BATCH'; }],
    ['GLOBAL_WIP zero', (s) => { s.tracks['AIPT-STANDALONE'].global_wip = 0; }],
    ['next batch added', (s) => { s.tracks['AIPT-STANDALONE'].next_serial_batch = 'AIPT-M1-B000'; }],
    ['next batch authorized', (s) => { s.tracks['AIPT-STANDALONE'].next_batch_authorized = true; }],
    ['next batch started', (s) => { s.tracks['AIPT-STANDALONE'].next_batch_started = true; }],
    ['B008 claims merged closed', (s) => { s.tracks['AIPT-STANDALONE'].batch_history[CURRENT_BATCH] = 'MERGED_CLOSED'; }],
    ['B007 reopened', (s) => { s.tracks['AIPT-STANDALONE'].batch_history['AIPT-M0-B007'] = 'IN_PROGRESS'; }],
    ['predecessor tree drift', (s) => { s.tracks['AIPT-STANDALONE'].external_serial_predecessor.candidate_tree = 'wrong'; }],
    ['external history removed', (s) => { s.tracks['AIPT-STANDALONE'].external_batch_history.pop(); }],
    ['platform unfrozen', (s) => { s.tracks['AIPT-PLATFORM-INTEGRATION'].unfreeze_authorized = true; }],
    ['verified head changed to base', (s) => { s.repositories.AIPT.verified_head = B007_CLOSEOUT.commit; }],
    ['verified state drift', (s) => { s.repositories.AIPT.verified_state += ' drift'; }],
    ['pending pass effective early', (s) => { s.repositories.AIPT.pending_candidate.current_effective_status = 'GRANTED'; }],
    ['pending Candidate claims closed', (s) => { s.repositories.AIPT.pending_candidate.state = 'MERGED_CLOSED'; }],
    ['pending base drift', (s) => { s.repositories.AIPT.pending_candidate.base_tree = 'wrong'; }],
    ['Harness identity drift', (s) => { s.runtime.deepseek_harness_commit = HARNESS_SOURCE.previous_commit; }],
    ['UNREGISTERED implementation drift', (s) => { s.repositories.UNREGISTERED.verified_head = 'wrong'; }],
    ['unknown root field', (s) => { s.m0_development_pass_effective = true; }],
  ];
  let rejected = 0;
  for (const [, mutate] of mutations) {
    const copy = clone(status);
    mutate(copy);
    if (checkStatusDocument(copy, acceptedVerifiedState).length > 0) rejected += 1;
  }
  if (rejected !== mutations.length) fail('status mutation probes rejected ' + rejected + '/' + mutations.length);
  else ok('all ' + rejected + ' status mutation probes fail closed');

  return { result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'status-transition', run);
