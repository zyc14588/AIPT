#!/usr/bin/env node
// AIPT-M0-B005 construction-status validator.
import fs from 'node:fs';
import path from 'node:path';
import {
  ACTIVE_BATCH, B000, B001, B002, B002_CLOSEOUT, B003, B003_CLOSEOUT,
  B004_CANDIDATE, B004_CLOSEOUT, B004_IMPLEMENTATION_MERGE,
  B004_POST_MERGE_REPAIR, BASE_COMMIT, BASE_TREE, CURRENT_BATCH,
  EXTERNAL_SERIAL_PREDECESSOR, FROZEN_REGISTRY_PATHS, HARNESS_SOURCE,
  STATUS_DATE, STATUS_TRANSITION_PATHS,
} from '../lib/constants.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

const SCHEMA = 'aipt.public.project-status/v1';
const SNAPSHOT_ID = 'AIPT-M0-B005-CONSTRUCTION-001';
const DESIGN = 'FROZEN_R0_R16_DCA_BOOTSTRAP';
const PLATFORM = 'FROZEN_WAITING_M1_ENGINE';
const CLOSED_BATCH_IDS = [
  'AIPT-M0-B000', 'AIPT-M0-B001', 'AIPT-M0-B002', 'AIPT-M0-B003', 'AIPT-M0-B004',
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
const EXPECTED_VERIFIED_STATE =
  'AIPT-M0-B005 IN_PROGRESS from accepted B004 closeout ' + B004_CLOSEOUT.commit +
  ' (tree ' + B004_CLOSEOUT.tree + '); immutable B004 Candidate ' +
  B004_CANDIDATE.commit + ' (tree ' + B004_CANDIDATE.tree + ', CI run ' +
  B004_CANDIDATE.ci_run + ' success), implementation merge ' +
  B004_IMPLEMENTATION_MERGE.commit + ', initial post-merge CI run ' +
  B004_POST_MERGE_REPAIR.initial_ci_run + ' failure with immutable cause ' +
  B004_POST_MERGE_REPAIR.failure + ', repair ' + B004_POST_MERGE_REPAIR.commit +
  ' with CI run ' + B004_POST_MERGE_REPAIR.ci_run +
  ' success, and AIPT-M0-B004-DEPENDENCY-SECURITY-REQUAL-001 remain historical facts; ' +
  'B000/B001/B002/B003/B004 remain MERGED_CLOSED; construction IN_PROGRESS with ' +
  'current_batch AIPT-M0-B005 and global WIP 1; next serial batch AIPT-M0-B006 is ' +
  'NOT_AUTHORIZED and not started; platform integration remains frozen';

function exactKeys(value, expected) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

export function criticalMachineProblems(candidate) {
  const problems = [];
  if (candidate?.schema !== SCHEMA) problems.push('schema drifted');
  if (candidate?.as_of !== STATUS_DATE) problems.push('status date drifted');
  if (candidate?.authority_snapshot_id !== SNAPSHOT_ID) problems.push('snapshot drifted');

  const standalone = candidate?.tracks?.['AIPT-STANDALONE'];
  if (!exactKeys(standalone, STANDALONE_KEYS)) problems.push('standalone keys are not exact');
  if (standalone?.design !== DESIGN) problems.push('design drifted');
  if (standalone?.construction !== 'IN_PROGRESS') problems.push('construction is not IN_PROGRESS');
  if (standalone?.current_batch !== ACTIVE_BATCH) problems.push('active batch drifted');
  if (standalone?.global_wip !== 1) problems.push('global WIP must be exactly one');
  if (standalone?.next_serial_batch !== 'AIPT-M0-B006') problems.push('next batch drifted');
  if (standalone?.next_batch_state !== 'NOT_AUTHORIZED') problems.push('B006 state drifted');
  if (standalone?.next_batch_authorized !== false) problems.push('B006 became authorized');
  if (standalone?.next_batch_started !== false) problems.push('B006 was started');

  const history = standalone?.batch_history;
  if (!exactKeys(history, CLOSED_BATCH_IDS)) problems.push('closed history keys are not exact');
  for (const batch of CLOSED_BATCH_IDS) {
    if (history?.[batch] !== 'MERGED_CLOSED') problems.push(batch + ' was reopened');
  }

  const predecessor = standalone?.external_serial_predecessor;
  if (!exactKeys(predecessor, PREDECESSOR_KEYS)) problems.push('external predecessor keys drifted');
  const expectedPredecessor = {
    id: EXTERNAL_SERIAL_PREDECESSOR.batch,
    status: EXTERNAL_SERIAL_PREDECESSOR.status,
    closeout_commit: EXTERNAL_SERIAL_PREDECESSOR.closeout_commit,
    closeout_ci_run: EXTERNAL_SERIAL_PREDECESSOR.closeout_ci_run,
    closeout_ci_conclusion: EXTERNAL_SERIAL_PREDECESSOR.closeout_ci_conclusion,
  };
  for (const [key, expected] of Object.entries(expectedPredecessor)) {
    if (predecessor?.[key] !== expected) problems.push('external predecessor ' + key + ' drifted');
  }

  const platform = candidate?.tracks?.['AIPT-PLATFORM-INTEGRATION'];
  if (!exactKeys(platform, ['status', 'unfreeze_authorized'])) problems.push('platform keys drifted');
  if (platform?.status !== PLATFORM) problems.push('platform status drifted');
  if (platform?.unfreeze_authorized !== false) problems.push('platform was unfrozen');

  const aipt = candidate?.repositories?.AIPT;
  if (aipt?.verified_head !== BASE_COMMIT) problems.push('verified head is not the B005 base');
  if (aipt?.verified_tree !== BASE_TREE) problems.push('verified tree is not the B005 base tree');
  if (aipt?.verified_state !== EXPECTED_VERIFIED_STATE) problems.push('verified state drifted');

  const runtime = candidate?.runtime;
  if (!exactKeys(runtime, RUNTIME_KEYS)) problems.push('runtime keys are not exact');
  if (runtime?.status !== 'harness adapter under construction') problems.push('runtime status drifted');
  if (runtime?.harness_installation !== HARNESS_SOURCE.installation) problems.push('DSH installation drifted');
  if (runtime?.deepseek_harness_previous_commit !== HARNESS_SOURCE.previous_commit) problems.push('historical DSH commit drifted');
  if (runtime?.deepseek_harness_commit !== HARNESS_SOURCE.commit) problems.push('qualified DSH commit drifted');
  if (runtime?.deepseek_harness_release !== HARNESS_SOURCE.release) problems.push('qualified DSH release drifted');
  if (runtime?.deepseek_harness_upgrade_authority !== HARNESS_SOURCE.upgrade_authority) problems.push('DSH upgrade authority drifted');
  return problems;
}

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push('ok: ' + message);
  const fail = (message) => { pass = false; details.push('FAIL: ' + message); };
  const read = (relative) => fs.readFileSync(path.join(ctx.repo, relative), 'utf8');
  const anchor = (label, actual, expected) => {
    if (actual === expected) ok(label + ' anchored');
    else fail(label + ' drifted: ' + JSON.stringify(actual));
  };

  const anchors = [
    ['CURRENT_BATCH', CURRENT_BATCH, 'AIPT-M0-B005'],
    ['ACTIVE_BATCH', ACTIVE_BATCH, 'AIPT-M0-B005'],
    ['BASE_COMMIT', BASE_COMMIT, '8005dd3bec8b367a6d97dcd9397158f1d8618f3e'],
    ['BASE_TREE', BASE_TREE, 'd0f32b7ac1c3f6e5ddb258aaa2ee030844b1eb2b'],
    ['B000', B000.commit, '777a3f39ba78c1ef3168597890c61abf7a55d962'],
    ['B001', B001.merge_commit, '8bcadc9669e7d04f589f883daa6d4f593875fc9e'],
    ['B002', B002.merge_commit, 'fccfb595c23feab38397506505a3e996fe7b9e9c'],
    ['B002 closeout', B002_CLOSEOUT.commit, '45a96087d75a61f2910cb5ce99134e3ca777bca8'],
    ['B003', B003.merge_commit, '725fc005185412d115307b594aa64e84acfabf67'],
    ['B003 closeout', B003_CLOSEOUT.commit, '6d7225828b45b69ecc44d5bb51a04c40f0865aba'],
    ['B004 Candidate', B004_CANDIDATE.commit, '4810d2cfec6146db7c161506ba7f37ab0a4ce69c'],
    ['B004 merge', B004_IMPLEMENTATION_MERGE.commit, 'd07c0c3817620ada47b3ae7344d8ee423ace3b12'],
    ['B004 repair', B004_POST_MERGE_REPAIR.commit, 'bd0c06867da58f89e82a35d82ce1d798c1ec9cae'],
    ['B004 closeout', B004_CLOSEOUT.commit, '8005dd3bec8b367a6d97dcd9397158f1d8618f3e'],
    ['DSH previous commit', HARNESS_SOURCE.previous_commit, '47f943859bef60e4160492346772ded9b24f765a'],
    ['DSH qualified commit', HARNESS_SOURCE.commit, '141eb6fef83422698aef7a981029e843e8161534'],
  ];
  for (const item of anchors) anchor(...item);

  const identities = [
    ['B000', B000.commit, B000.tree], ['B001', B001.merge_commit, B001.tree],
    ['B002', B002.merge_commit, B002.tree], ['B002 closeout', B002_CLOSEOUT.commit, B002_CLOSEOUT.tree],
    ['B003', B003.merge_commit, B003.tree], ['B003 closeout', B003_CLOSEOUT.commit, B003_CLOSEOUT.tree],
    ['B004 Candidate', B004_CANDIDATE.commit, B004_CANDIDATE.tree],
    ['B004 merge', B004_IMPLEMENTATION_MERGE.commit, B004_IMPLEMENTATION_MERGE.tree],
    ['B004 repair', B004_POST_MERGE_REPAIR.commit, B004_POST_MERGE_REPAIR.tree],
    ['B004 closeout', B004_CLOSEOUT.commit, B004_CLOSEOUT.tree],
  ];
  for (const [label, commit, tree] of identities) {
    const resolved = git(ctx.repo, ['rev-parse', commit + '^{tree}'], { check: false });
    if (resolved.status !== 0 || resolved.stdout.trim() !== tree) fail(label + ' Git identity drifted');
    else ok(label + ' Git identity verified');
  }
  const parentTokens = git(ctx.repo, ['rev-list', '--parents', '-n', '1', B004_CLOSEOUT.commit])
    .stdout.trim().split(/\s+/);
  if (JSON.stringify(parentTokens) !== JSON.stringify([B004_CLOSEOUT.commit, B004_CLOSEOUT.parent])) fail('B004 closeout parent drifted');
  else ok('B004 closeout is the exact single-parent B005 base');
  if (git(ctx.repo, ['merge-base', '--is-ancestor', BASE_COMMIT, 'HEAD'], { check: false }).status !== 0) fail('HEAD does not descend from B005 base');
  else ok('HEAD descends from B005 base');

  let status;
  try { status = JSON.parse(read('docs/authority/registry/project-status.json')); }
  catch (error) { fail('machine status parse failed: ' + error.message); }
  if (status) {
    const problems = criticalMachineProblems(status);
    for (const problem of problems) fail(problem);
    if (problems.length === 0) ok('machine status exactly matches B005 construction');
    const probes = [
      ['schema', (s) => { s.schema = 'wrong'; }],
      ['snapshot', (s) => { s.authority_snapshot_id = 'wrong'; }],
      ['construction', (s) => { s.tracks['AIPT-STANDALONE'].construction = 'IDLE'; }],
      ['current batch', (s) => { s.tracks['AIPT-STANDALONE'].current_batch = 'AIPT-M0-B006'; }],
      ['WIP', (s) => { s.tracks['AIPT-STANDALONE'].global_wip = 2; }],
      ['B006 authorization', (s) => { s.tracks['AIPT-STANDALONE'].next_batch_authorized = true; }],
      ['B006 start', (s) => { s.tracks['AIPT-STANDALONE'].next_batch_started = true; }],
      ['B006 state', (s) => { s.tracks['AIPT-STANDALONE'].next_batch_state = 'AUTHORIZED'; }],
      ['reopen B004', (s) => { s.tracks['AIPT-STANDALONE'].batch_history['AIPT-M0-B004'] = 'IN_PROGRESS'; }],
      ['extra batch', (s) => { s.tracks['AIPT-STANDALONE'].batch_history['AIPT-M0-B005'] = 'IN_PROGRESS'; }],
      ['platform', (s) => { s.tracks['AIPT-PLATFORM-INTEGRATION'].unfreeze_authorized = true; }],
      ['verified head', (s) => { s.repositories.AIPT.verified_head = B004_IMPLEMENTATION_MERGE.commit; }],
      ['verified state', (s) => { s.repositories.AIPT.verified_state += ' drift'; }],
      ['DSH current', (s) => { s.runtime.deepseek_harness_commit = HARNESS_SOURCE.previous_commit; }],
      ['DSH previous', (s) => { s.runtime.deepseek_harness_previous_commit = HARNESS_SOURCE.commit; }],
      ['DSH tag', (s) => { s.runtime.deepseek_harness_release = 'latest'; }],
      ['DSH authority', (s) => { delete s.runtime.deepseek_harness_upgrade_authority; }],
      ['ambient runtime key', (s) => { s.runtime.endpoint = 'https://example.invalid'; }],
    ];
    let missed = 0;
    for (const [label, mutate] of probes) {
      const candidate = structuredClone(status);
      mutate(candidate);
      if (criticalMachineProblems(candidate).length === 0) { missed += 1; fail('mutation accepted: ' + label); }
    }
    if (missed === 0) ok('all ' + probes.length + ' machine-state mutations rejected');
  }

  const changed = git(ctx.repo, ['diff', '--name-only', '--no-renames', BASE_COMMIT]).stdout
    .split('\n').filter(Boolean);
  for (const required of STATUS_TRANSITION_PATHS) {
    if (!changed.includes(required)) fail('required status path unchanged: ' + required);
  }
  if (STATUS_TRANSITION_PATHS.every((item) => changed.includes(item))) ok('all six bounded status-transition paths changed');

  for (const relative of FROZEN_REGISTRY_PATHS) {
    const base = git(ctx.repo, ['show', BASE_COMMIT + ':' + relative], { check: false });
    if (base.status !== 0 || base.stdout !== read(relative)) fail('frozen registry changed: ' + relative);
    else ok('frozen registry unchanged: ' + relative);
  }

  const facts = [
    SNAPSHOT_ID, 'IN_PROGRESS', 'current_batch = AIPT-M0-B005', 'GLOBAL_WIP = 1',
    'AIPT-M0-B006', 'NOT_AUTHORIZED', 'next_batch_authorized = false',
    'next_batch_started = false', BASE_COMMIT, BASE_TREE, HARNESS_SOURCE.commit,
    HARNESS_SOURCE.previous_commit, HARNESS_SOURCE.release,
    'AIPT-M0-B005-EXTERNAL-HARNESS-UPGRADE-001', PLATFORM, 'unfreeze_authorized = false',
  ];
  const contradictions = [
    'current_batch = NO_ACTIVE_BATCH', 'GLOBAL_WIP = 0', 'IDLE_WAITING_NEXT_BATCH',
    'AIPT-M0-B005 尚未启动', '不要开始 B005 implementation',
  ];
  const humans = ['README.md', 'docs/authority/PROJECT_STATUS.md'];
  for (const relative of humans) {
    const human = read(relative);
    for (const fact of facts) if (!human.includes(fact)) fail(relative + ' missing ' + fact);
    for (const stale of contradictions) if (human.includes(stale)) fail(relative + ' contains stale ' + stale);
  }
  if (humans.every((relative) => {
    const human = read(relative);
    return facts.every((fact) => human.includes(fact)) && contradictions.every((fact) => !human.includes(fact));
  })) ok('human status agrees with B005 machine authority');

  return { result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'status-transition', run);
