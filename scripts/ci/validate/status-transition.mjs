#!/usr/bin/env node
// AIPT-M0-B006 construction/status-transition validator.
import fs from 'node:fs';
import path from 'node:path';
import {
  ACTIVE_BATCH, B000, B001, B002, B002_CLOSEOUT, B003, B003_CLOSEOUT,
  B004_CANDIDATE, B004_CLOSEOUT, B004_IMPLEMENTATION_MERGE,
  B004_POST_MERGE_REPAIR, B005_CANDIDATE, B005_CLOSEOUT,
  B005_IMPLEMENTATION_MERGE, BASE_COMMIT, BASE_TREE, CURRENT_BATCH,
  EXTERNAL_SERIAL_PREDECESSOR, FROZEN_REGISTRY_PATHS, HARNESS_SOURCE,
  HARNESS_UPGRADE_RATIFICATION, STATUS_DATE, STATUS_TRANSITION_PATHS,
} from '../lib/constants.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

const SCHEMA = 'aipt.public.project-status/v1';
const SNAPSHOT_ID = 'AIPT-M0-B006-CONSTRUCTION-001';
const DESIGN = 'FROZEN_R0_R16_DCA_BOOTSTRAP';
const CONSTRUCTION = 'IN_PROGRESS';
const NEXT_BATCH = 'UNREGISTERED-AIPT-P0-B002';
const NEXT_STATE = 'NOT_AUTHORIZED';
const PLATFORM = 'FROZEN_WAITING_M1_ENGINE';
const CLOSED_BATCH_IDS = [
  'AIPT-M0-B000', 'AIPT-M0-B001', 'AIPT-M0-B002', 'AIPT-M0-B003',
  'AIPT-M0-B004', 'AIPT-M0-B005',
];
const ROOT_KEYS = [
  'as_of', 'auditing', 'authority_snapshot_id', 'prompt_assets',
  'public_reference', 'repositories', 'runtime', 'schema', 'tracks',
];
const STANDALONE_KEYS = [
  'batch_history', 'construction', 'current_batch', 'design',
  'external_serial_predecessor', 'global_wip', 'next_batch_authorized',
  'next_batch_started', 'next_batch_state', 'next_serial_batch',
];
const PREDECESSOR_KEYS = [
  'closeout_ci_conclusion', 'closeout_ci_run', 'closeout_commit', 'id', 'status',
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
  'docs/harness/README.md',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
];
const EXPECTED_VERIFIED_STATE =
  'AIPT-M0-B006 IN_PROGRESS from accepted B005 closeout ' + BASE_COMMIT +
  ' (tree ' + BASE_TREE + '); immutable B005 Candidate ' + B005_CANDIDATE.commit +
  ' (tree ' + B005_CANDIDATE.tree + ', CI run ' + B005_CANDIDATE.ci_run +
  ' success), implementation merge ' + B005_IMPLEMENTATION_MERGE.commit +
  ' (same tree, post-merge CI run ' + B005_IMPLEMENTATION_MERGE.post_merge_ci_run +
  ' success), and closeout CI run ' + B005_CLOSEOUT.ci_run +
  ' remain historical facts; Harness identity ' + HARNESS_SOURCE.commit + ' / ' +
  HARNESS_SOURCE.release + ' / ' + HARNESS_UPGRADE_RATIFICATION.disposition +
  ' with prior authorization timing independently verified false remains unchanged; ' +
  'B000/B001/B002/B003/B004/B005 remain MERGED_CLOSED; construction IN_PROGRESS ' +
  'with current_batch AIPT-M0-B006 and global WIP 1; next serial batch ' + NEXT_BATCH +
  ' is NOT_AUTHORIZED and not started; platform integration remains frozen';

function same(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function exactKeys(value, expected) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    same(Object.keys(value).sort(), [...expected].sort());
}

export function checkStatusDocument(status) {
  const problems = [];
  const standalone = status?.tracks?.['AIPT-STANDALONE'];
  const platform = status?.tracks?.['AIPT-PLATFORM-INTEGRATION'];
  const repo = status?.repositories?.AIPT;
  const predecessor = standalone?.external_serial_predecessor;
  if (!exactKeys(status, ROOT_KEYS)) problems.push('root keys are not exact');
  if (status?.schema !== SCHEMA) problems.push('status schema drifted');
  if (status?.as_of !== STATUS_DATE) problems.push('status date drifted');
  if (status?.authority_snapshot_id !== SNAPSHOT_ID) problems.push('snapshot id drifted');
  if (!exactKeys(standalone, STANDALONE_KEYS)) problems.push('standalone keys are not exact');
  if (standalone?.design !== DESIGN) problems.push('standalone design drifted');
  if (standalone?.construction !== CONSTRUCTION) problems.push('construction is not IN_PROGRESS');
  if (standalone?.current_batch !== CURRENT_BATCH || ACTIVE_BATCH !== CURRENT_BATCH) {
    problems.push('current/active batch is not B006');
  }
  if (standalone?.global_wip !== 1) problems.push('GLOBAL_WIP is not 1');
  if (standalone?.next_serial_batch !== NEXT_BATCH || standalone?.next_batch_state !== NEXT_STATE) {
    problems.push('next serial batch/state drifted');
  }
  if (standalone?.next_batch_authorized !== false || standalone?.next_batch_started !== false) {
    problems.push('next batch authorization/start must both be false');
  }
  if (!exactKeys(standalone?.batch_history, CLOSED_BATCH_IDS)) problems.push('batch history keys are not exact');
  for (const id of CLOSED_BATCH_IDS) {
    if (standalone?.batch_history?.[id] !== 'MERGED_CLOSED') problems.push(id + ' is not MERGED_CLOSED');
  }
  if (Object.hasOwn(standalone?.batch_history ?? {}, CURRENT_BATCH)) problems.push('active B006 appears in closed history');
  if (!exactKeys(predecessor, PREDECESSOR_KEYS)) problems.push('external predecessor keys are not exact');
  if (predecessor?.id !== EXTERNAL_SERIAL_PREDECESSOR.batch ||
      predecessor?.status !== EXTERNAL_SERIAL_PREDECESSOR.status ||
      predecessor?.closeout_commit !== EXTERNAL_SERIAL_PREDECESSOR.closeout_commit ||
      predecessor?.closeout_ci_run !== EXTERNAL_SERIAL_PREDECESSOR.closeout_ci_run ||
      predecessor?.closeout_ci_conclusion !== EXTERNAL_SERIAL_PREDECESSOR.closeout_ci_conclusion) {
    problems.push('external predecessor provenance drifted');
  }
  if (!exactKeys(platform, ['status', 'unfreeze_authorized']) ||
      platform?.status !== PLATFORM || platform?.unfreeze_authorized !== false) {
    problems.push('platform integration was unfrozen or widened');
  }
  if (repo?.url !== 'https://github.com/zyc14588/AIPT' || repo?.default_branch !== 'main' ||
      repo?.verified_head !== BASE_COMMIT || repo?.verified_tree !== BASE_TREE ||
      repo?.verified_state !== EXPECTED_VERIFIED_STATE) {
    problems.push('AIPT verified base/state drifted');
  }
  if (!exactKeys(status?.runtime, RUNTIME_KEYS)) problems.push('runtime keys are not exact');
  if (status?.runtime?.deepseek_harness_commit !== HARNESS_SOURCE.commit ||
      status?.runtime?.deepseek_harness_previous_commit !== HARNESS_SOURCE.previous_commit ||
      status?.runtime?.deepseek_harness_release !== HARNESS_SOURCE.release ||
      status?.runtime?.deepseek_harness_upgrade_authority !== HARNESS_SOURCE.upgrade_authority ||
      status?.runtime?.harness_installation !== HARNESS_SOURCE.installation ||
      status?.runtime?.status !== 'minimal RAW_CAPTURE evidence exporter under construction') {
    problems.push('runtime/Harness identity or B006 runtime status drifted');
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
    ['B005 closeout/B006 base', B005_CLOSEOUT.commit, B005_CLOSEOUT.tree],
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
  if (pass) ok('machine status is the exact B006 construction transition');

  if (!same(STATUS_TRANSITION_PATHS, STATUS_PATHS_LITERAL)) fail('STATUS_TRANSITION_PATHS drifted');
  else ok('first-leaf status surface is exact');

  for (const [label, good] of identityChecks(ctx.repo)) {
    if (good) ok(label + ' immutable tree verified'); else fail(label + ' immutable tree drifted');
  }
  const closeoutParents = git(ctx.repo, ['rev-list', '--parents', '-n', '1', B005_CLOSEOUT.commit], { check: false });
  if (closeoutParents.status !== 0 || closeoutParents.stdout.trim() !== B005_CLOSEOUT.commit + ' ' + B005_CLOSEOUT.parent) {
    fail('B005 closeout parent drifted');
  } else ok('B005 closeout is the exact single-parent B006 base');

  for (const relative of FROZEN_REGISTRY_PATHS) {
    const base = git(ctx.repo, ['show', BASE_COMMIT + ':' + relative], { check: false });
    const current = fs.readFileSync(path.join(ctx.repo, relative), 'utf8');
    if (base.status !== 0 || base.stdout !== current) fail('frozen registry changed: ' + relative);
    else ok('frozen registry unchanged: ' + relative);
  }

  const docs = [
    ['README.md', ['current_batch = AIPT-M0-B006', 'GLOBAL_WIP = 1', NEXT_BATCH, 'NOT_AUTHORIZED']],
    ['docs/authority/PROJECT_STATUS.md', [SNAPSHOT_ID, 'current_batch = AIPT-M0-B006', NEXT_BATCH, 'next_batch_started = false']],
    ['docs/harness/README.md', ['AIPT-M0-B006', 'IN_PROGRESS', NEXT_BATCH, 'NOT_AUTHORIZED']],
  ];
  for (const [relative, needles] of docs) {
    const text = fs.readFileSync(path.join(ctx.repo, relative), 'utf8');
    const missing = needles.filter((needle) => !text.includes(needle));
    if (missing.length) fail(relative + ' misses B006 status tokens: ' + missing.join(', '));
    else ok(relative + ' carries the B006 construction boundary');
  }

  const mutations = [
    ['construction idle', (s) => { s.tracks['AIPT-STANDALONE'].construction = 'IDLE_WAITING_NEXT_BATCH'; }],
    ['wrong active batch', (s) => { s.tracks['AIPT-STANDALONE'].current_batch = 'AIPT-M0-B007'; }],
    ['GLOBAL_WIP zero', (s) => { s.tracks['AIPT-STANDALONE'].global_wip = 0; }],
    ['next batch authorized', (s) => { s.tracks['AIPT-STANDALONE'].next_batch_authorized = true; }],
    ['next batch started', (s) => { s.tracks['AIPT-STANDALONE'].next_batch_started = true; }],
    ['B006 falsely closed', (s) => { s.tracks['AIPT-STANDALONE'].batch_history['AIPT-M0-B006'] = 'MERGED_CLOSED'; }],
    ['B005 reopened', (s) => { s.tracks['AIPT-STANDALONE'].batch_history['AIPT-M0-B005'] = 'IN_PROGRESS'; }],
    ['platform unfrozen', (s) => { s.tracks['AIPT-PLATFORM-INTEGRATION'].unfreeze_authorized = true; }],
    ['base identity drift', (s) => { s.repositories.AIPT.verified_head = B005_IMPLEMENTATION_MERGE.commit; }],
    ['Harness identity drift', (s) => { s.runtime.deepseek_harness_commit = HARNESS_SOURCE.previous_commit; }],
    ['unknown root field', (s) => { s.unregistered_started = true; }],
  ];
  let rejected = 0;
  for (const [, mutate] of mutations) {
    const copy = clone(status); mutate(copy);
    if (checkStatusDocument(copy).length > 0) rejected += 1;
  }
  if (rejected !== mutations.length) fail('status mutation probes rejected ' + rejected + '/' + mutations.length);
  else ok('all ' + rejected + ' status mutation probes fail closed');

  return { result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'status-transition', run);
