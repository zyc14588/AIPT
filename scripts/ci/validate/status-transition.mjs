#!/usr/bin/env node
// AIPT-M0-B006 closeout/status-transition validator.
import fs from 'node:fs';
import path from 'node:path';
import {
  ACTIVE_BATCH, B000, B001, B002, B002_CLOSEOUT, B003, B003_CLOSEOUT,
  B004_CANDIDATE, B004_CLOSEOUT, B004_IMPLEMENTATION_MERGE,
  B004_POST_MERGE_REPAIR, B005_CANDIDATE, B005_CLOSEOUT,
  B005_IMPLEMENTATION_MERGE, B006_CANDIDATE, B006_CANDIDATE_HISTORY,
  B006_CONSTRUCTION_HARNESS, B006_IMPLEMENTATION_MERGE, BASE_COMMIT,
  BASE_TREE, CURRENT_BATCH, EXTERNAL_SERIAL_PREDECESSOR,
  FROZEN_REGISTRY_PATHS, HARNESS_SOURCE, STATUS_DATE,
  STATUS_TRANSITION_PATHS,
} from '../lib/constants.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

const SCHEMA = 'aipt.public.project-status/v1';
const SNAPSHOT_ID = 'AIPT-M0-B006-CLOSEOUT-001';
const DESIGN = 'FROZEN_R0_R16_DCA_BOOTSTRAP';
const CONSTRUCTION = 'IDLE_WAITING_NEXT_BATCH';
const NEXT_BATCH = 'UNREGISTERED-AIPT-P0-B002';
const NEXT_STATE = 'AUTHORIZED_TO_PREPARE';
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
  'external_serial_predecessor', 'global_wip', 'next_batch_authorized',
  'next_batch_started', 'next_batch_state', 'next_serial_batch',
];
const PREDECESSOR_KEYS = [
  'closeout_ci_conclusion', 'closeout_ci_run', 'closeout_commit', 'id', 'status',
];
const AIPT_REPOSITORY_KEYS = [
  'default_branch', 'url', 'verified_head', 'verified_state', 'verified_tree',
];
const UNREGISTERED_REPOSITORY_KEYS = [
  'default_branch', 'formal_name_zh', 'planning_snapshot', 'readiness', 'url',
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
  'docs/evidence/README.md',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
];
const EXPECTED_VERIFIED_STATE =
  'AIPT-M0-B006 MERGED_CLOSED: Base ' + BASE_COMMIT + ' (tree ' + BASE_TREE +
  '); Candidate ' + B006_CANDIDATE.commit + ' (tree ' + B006_CANDIDATE.tree +
  ', Candidate CI run ' + B006_CANDIDATE.ci_run + ' ' + B006_CANDIDATE.ci_conclusion +
  '); Implementation merge ' + B006_IMPLEMENTATION_MERGE.commit + ' (tree ' +
  B006_IMPLEMENTATION_MERGE.tree + ', parents ' + B006_IMPLEMENTATION_MERGE.parent1 +
  ' and ' + B006_IMPLEMENTATION_MERGE.parent2 + ', subject ' +
  B006_IMPLEMENTATION_MERGE.subject + '), Post-merge CI run ' +
  B006_IMPLEMENTATION_MERGE.post_merge_ci_run + ' ' +
  B006_IMPLEMENTATION_MERGE.post_merge_ci_conclusion +
  '; Evidence Schema PASS; RAW_CAPTURE exporter PASS; verifier PASS; PostgreSQL Evidence ' +
  'source PASS; determinism PASS; tamper detection PASS; root algorithm ' +
  'SHA-256(manifest.json exact bytes); AUDIT_READY generator NOT_IMPLEMENTED; ' +
  'AUDIT_RESULT generator NOT_IMPLEMENTED; signing/encryption/chunking NOT_IMPLEMENTED; ' +
  'construction Harness initial route ' + B006_CONSTRUCTION_HARNESS.initial_route +
  ', failure ' + B006_CONSTRUCTION_HARNESS.failure + ', observed input ' +
  B006_CONSTRUCTION_HARNESS.observed_input_tokens + ', gate ' +
  B006_CONSTRUCTION_HARNESS.input_token_limit + ', worker patch ' +
  (B006_CONSTRUCTION_HARNESS.patch_produced ? 'present' : 'none') + ', final route ' +
  B006_CONSTRUCTION_HARNESS.final_route + ', split-memory manual edit ' +
  String(B006_CONSTRUCTION_HARNESS.split_memory_manual_edit) +
  '; B000/B001/B002/B003/B004/B005/B006 remain MERGED_CLOSED; construction ' +
  CONSTRUCTION + ' with current_batch NO_ACTIVE_BATCH and global WIP 0; next serial batch ' +
  NEXT_BATCH + ' is ' + NEXT_STATE + ' and not started; platform integration remains frozen';

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
  const unregistered = status?.repositories?.UNREGISTERED;
  const predecessor = standalone?.external_serial_predecessor;
  if (!exactKeys(status, ROOT_KEYS)) problems.push('root keys are not exact');
  if (status?.schema !== SCHEMA) problems.push('status schema drifted');
  if (status?.as_of !== STATUS_DATE) problems.push('status date drifted');
  if (status?.authority_snapshot_id !== SNAPSHOT_ID) problems.push('snapshot id drifted');
  if (!exactKeys(standalone, STANDALONE_KEYS)) problems.push('standalone keys are not exact');
  if (standalone?.design !== DESIGN) problems.push('standalone design drifted');
  if (standalone?.construction !== CONSTRUCTION) problems.push('construction is not ' + CONSTRUCTION);
  if (standalone?.current_batch !== ACTIVE_BATCH || ACTIVE_BATCH !== 'NO_ACTIVE_BATCH') {
    problems.push('current/active batch is not NO_ACTIVE_BATCH');
  }
  if (standalone?.global_wip !== 0) problems.push('GLOBAL_WIP is not zero');
  if (standalone?.next_serial_batch !== NEXT_BATCH || standalone?.next_batch_state !== NEXT_STATE) {
    problems.push('next serial batch/state drifted');
  }
  if (standalone?.next_batch_authorized !== true) problems.push('next batch is not authorized to prepare');
  if (standalone?.next_batch_started !== false) problems.push('next batch was started');
  if (!exactKeys(standalone?.batch_history, CLOSED_BATCH_IDS)) problems.push('batch history keys are not exact');
  for (const id of CLOSED_BATCH_IDS) {
    if (standalone?.batch_history?.[id] !== 'MERGED_CLOSED') problems.push(id + ' is not MERGED_CLOSED');
  }
  if (CURRENT_BATCH !== 'AIPT-M0-B006' || standalone?.batch_history?.[CURRENT_BATCH] !== 'MERGED_CLOSED') {
    problems.push('B006 is not the exact closed current task identity');
  }
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
      unregistered?.readiness !== 'PLAYTESTABLE_DRAFT' ||
      unregistered?.formal_name_zh !== '《未登记》') {
    problems.push('UNREGISTERED repository status was modified');
  }
  if (!exactKeys(status?.runtime, RUNTIME_KEYS)) problems.push('runtime keys are not exact');
  if (status?.runtime?.deepseek_harness_commit !== HARNESS_SOURCE.commit ||
      status?.runtime?.deepseek_harness_previous_commit !== HARNESS_SOURCE.previous_commit ||
      status?.runtime?.deepseek_harness_release !== HARNESS_SOURCE.release ||
      status?.runtime?.deepseek_harness_upgrade_authority !== HARNESS_SOURCE.upgrade_authority ||
      status?.runtime?.harness_installation !== HARNESS_SOURCE.installation ||
      status?.runtime?.status !== 'minimal RAW_CAPTURE evidence exporter merged/closed') {
    problems.push('runtime/Harness identity or B006 closeout status drifted');
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
    ['B006 Candidate', B006_CANDIDATE.commit, B006_CANDIDATE.tree],
    ['B006 implementation merge', B006_IMPLEMENTATION_MERGE.commit, B006_IMPLEMENTATION_MERGE.tree],
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
  const anchor = (label, actual, expected) => {
    if (actual === expected) ok(label + ' anchored'); else fail(label + ' drifted');
  };
  let status;
  try {
    status = JSON.parse(fs.readFileSync(path.join(ctx.repo, 'docs/authority/registry/project-status.json'), 'utf8'));
  } catch (error) {
    fail('project-status.json is unreadable: ' + error.message);
    return { result: 'FAIL', details };
  }
  for (const problem of checkStatusDocument(status)) fail(problem);
  if (pass) ok('machine status is the exact B006 MERGED_CLOSED transition');

  if (!same(STATUS_TRANSITION_PATHS, STATUS_PATHS_LITERAL)) fail('STATUS_TRANSITION_PATHS drifted');
  else ok('seven-path closeout status surface is exact');

  const anchors = [
    ['B006 Candidate commit', B006_CANDIDATE.commit, '3987b8d4c26ac079d01c214ba90e113eeffd5713'],
    ['B006 Candidate tree', B006_CANDIDATE.tree, '4271a3fb71236a8b003b4d9ddc84727c6fec8d46'],
    ['B006 Candidate CI', B006_CANDIDATE.ci_run, 32577246851],
    ['B006 Candidate CI conclusion', B006_CANDIDATE.ci_conclusion, 'success'],
    ['B006 merge directive', B006_IMPLEMENTATION_MERGE.directive, 'AIPT-M0-B006-MERGE-001'],
    ['B006 implementation merge', B006_IMPLEMENTATION_MERGE.commit, '35acba9fb629f50087def3b720df304fadfd2158'],
    ['B006 post-merge CI', B006_IMPLEMENTATION_MERGE.post_merge_ci_run, 32578143923],
    ['B006 post-merge CI conclusion', B006_IMPLEMENTATION_MERGE.post_merge_ci_conclusion, 'success'],
    ['Harness observed input', B006_CONSTRUCTION_HARNESS.observed_input_tokens, 190183],
    ['Harness input limit', B006_CONSTRUCTION_HARNESS.input_token_limit, 180000],
    ['Harness final route', B006_CONSTRUCTION_HARNESS.final_route, 'CODEX_ONLY'],
    ['Harness split-memory manual edit', B006_CONSTRUCTION_HARNESS.split_memory_manual_edit, false],
  ];
  for (const item of anchors) anchor(...item);

  for (const [label, good] of identityChecks(ctx.repo)) {
    if (good) ok(label + ' immutable tree verified'); else fail(label + ' immutable tree drifted');
  }
  const baseParents = git(ctx.repo, ['rev-list', '--parents', '-n', '1', B005_CLOSEOUT.commit], { check: false });
  if (baseParents.status !== 0 || baseParents.stdout.trim() !== B005_CLOSEOUT.commit + ' ' + B005_CLOSEOUT.parent) {
    fail('B005 closeout parent drifted');
  } else ok('B005 closeout is the exact single-parent B006 base');

  const candidateHistory = git(ctx.repo, [
    'rev-list', '--reverse', '--first-parent', BASE_COMMIT + '..' + B006_CANDIDATE.commit,
  ], { check: false });
  const actualHistory = candidateHistory.status === 0
    ? candidateHistory.stdout.split('\n').filter(Boolean) : null;
  if (!same(actualHistory, B006_CANDIDATE_HISTORY)) fail('B006 Candidate history drifted');
  else ok('B006 Candidate history is the exact one-commit linear history');

  const mergeParents = git(ctx.repo, [
    'rev-list', '--parents', '-n', '1', B006_IMPLEMENTATION_MERGE.commit,
  ], { check: false });
  const expectedMerge = [
    B006_IMPLEMENTATION_MERGE.commit,
    B006_IMPLEMENTATION_MERGE.parent1,
    B006_IMPLEMENTATION_MERGE.parent2,
  ].join(' ');
  if (mergeParents.status !== 0 || mergeParents.stdout.trim() !== expectedMerge) {
    fail('B006 implementation merge parents drifted');
  } else ok('B006 implementation merge has the exact ordered parents');
  const mergeSubject = git(ctx.repo, [
    'show', '-s', '--format=%s', B006_IMPLEMENTATION_MERGE.commit,
  ], { check: false });
  if (mergeSubject.status !== 0 || mergeSubject.stdout.trim() !== B006_IMPLEMENTATION_MERGE.subject) {
    fail('B006 implementation merge subject drifted');
  } else ok('B006 implementation merge subject is exact');
  const mergeDiff = git(ctx.repo, [
    'diff', '--quiet', B006_CANDIDATE.commit, B006_IMPLEMENTATION_MERGE.commit,
  ], { check: false });
  if (mergeDiff.status !== 0) fail('B006 implementation merge differs from the accepted Candidate tree');
  else ok('B006 Candidate and implementation merge share the accepted tree');

  for (const relative of FROZEN_REGISTRY_PATHS) {
    const base = git(ctx.repo, ['show', BASE_COMMIT + ':' + relative], { check: false });
    const current = fs.readFileSync(path.join(ctx.repo, relative), 'utf8');
    if (base.status !== 0 || base.stdout !== current) fail('frozen registry changed: ' + relative);
    else ok('frozen registry unchanged: ' + relative);
  }

  const docs = [
    ['README.md', [SNAPSHOT_ID, 'current_batch = NO_ACTIVE_BATCH', 'GLOBAL_WIP = 0', NEXT_BATCH, NEXT_STATE, 'next_batch_started = false']],
    ['docs/authority/PROJECT_STATUS.md', [SNAPSHOT_ID, 'current_batch = NO_ACTIVE_BATCH', 'GLOBAL_WIP = 0', NEXT_BATCH, NEXT_STATE]],
    ['docs/evidence/README.md', ['B006 = MERGED_CLOSED', String(B006_CANDIDATE.ci_run), String(B006_IMPLEMENTATION_MERGE.post_merge_ci_run)]],
  ];
  for (const [relative, needles] of docs) {
    const text = fs.readFileSync(path.join(ctx.repo, relative), 'utf8');
    const missing = needles.filter((needle) => !text.includes(needle));
    if (missing.length) fail(relative + ' misses B006 closeout tokens: ' + missing.join(', '));
    else ok(relative + ' carries the B006 closeout boundary');
  }

  const mutations = [
    ['construction reopened', (s) => { s.tracks['AIPT-STANDALONE'].construction = 'IN_PROGRESS'; }],
    ['active batch invented', (s) => { s.tracks['AIPT-STANDALONE'].current_batch = 'AIPT-M0-B006'; }],
    ['GLOBAL_WIP nonzero', (s) => { s.tracks['AIPT-STANDALONE'].global_wip = 1; }],
    ['next batch authorization removed', (s) => { s.tracks['AIPT-STANDALONE'].next_batch_authorized = false; }],
    ['next batch started', (s) => { s.tracks['AIPT-STANDALONE'].next_batch_started = true; }],
    ['next batch state drift', (s) => { s.tracks['AIPT-STANDALONE'].next_batch_state = 'IN_PROGRESS'; }],
    ['B006 reopened', (s) => { s.tracks['AIPT-STANDALONE'].batch_history['AIPT-M0-B006'] = 'IN_PROGRESS'; }],
    ['platform unfrozen', (s) => { s.tracks['AIPT-PLATFORM-INTEGRATION'].unfreeze_authorized = true; }],
    ['verified head changed to closeout base', (s) => { s.repositories.AIPT.verified_head = BASE_COMMIT; }],
    ['verified tree changed to base', (s) => { s.repositories.AIPT.verified_tree = BASE_TREE; }],
    ['verified state drift', (s) => { s.repositories.AIPT.verified_state += ' drift'; }],
    ['Harness identity drift', (s) => { s.runtime.deepseek_harness_commit = HARNESS_SOURCE.previous_commit; }],
    ['runtime reopened', (s) => { s.runtime.status = 'minimal RAW_CAPTURE evidence exporter under construction'; }],
    ['UNREGISTERED status mutation', (s) => { s.repositories.UNREGISTERED.readiness = 'IN_PROGRESS'; }],
    ['unknown root field', (s) => { s.unregistered_started = true; }],
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
