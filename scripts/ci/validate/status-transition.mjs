// B002 merge-closeout public status-transition validator.
//
// Verifies the only legal transition from the B002 construction contract to
// the B002 merged/closed contract. The closeout must preserve the immutable
// B000/B001 history, bind the fixed B002 candidate / implementation merge /
// tree / post-merge CI identities, and keep all three public status sources
// (machine snapshot + README + PROJECT_STATUS) aligned on:
//   - AIPT-M0-B000/B001/B002 = MERGED_CLOSED;
//   - no active implementation batch and GLOBAL_WIP = 0;
//   - UNREGISTERED-AIPT-P0-B000 is AUTHORIZED_TO_PREPARE but not started;
//   - platform integration stays frozen and runtime stays not built.
//
// This gate also fixes the one-time closeout scope to the four explicitly
// authorized paths. It must never be bypassed or widened implicitly.
import fs from 'node:fs';
import path from 'node:path';
import { B000, B001, CURRENT_BATCH } from '../lib/constants.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

const CLOSEOUT_DATE = '2026-08-18';
const NO_ACTIVE_BATCH = 'NO_ACTIVE_BATCH';
const CONSTRUCTION_STATE = 'IDLE_WAITING_NEXT_BATCH';
const NEXT_BATCH = 'UNREGISTERED-AIPT-P0-B000';
const NEXT_BATCH_STATE = 'AUTHORIZED_TO_PREPARE';
const CLOSEOUT_PATHS = [
  'README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'scripts/ci/validate/status-transition.mjs',
];

const B002 = Object.freeze({
  id: 'AIPT-M0-B002',
  candidate: '9968cbc89c09640e3fc2feb8d851220eae98b9b9',
  merge_commit: 'fccfb595c23feab38397506505a3e996fe7b9e9c',
  tree: 'f99570bc3c4307244ca926cec62e82a07ef5aee8',
  post_merge_ci_run: 31985644832,
  post_merge_ci_conclusion: 'success',
});

const EXPECTED_VERIFIED_STATE =
  'AIPT-M0-B002 MERGED_CLOSED: candidate 9968cbc89c09640e3fc2feb8d851220eae98b9b9; ' +
  'implementation merge commit fccfb595c23feab38397506505a3e996fe7b9e9c; ' +
  'implementation tree f99570bc3c4307244ca926cec62e82a07ef5aee8; ' +
  'post-merge CI run 31985644832 success; no active implementation batch; ' +
  'next serial batch UNREGISTERED-AIPT-P0-B000 is AUTHORIZED_TO_PREPARE and not started';

function sameStrings(actual, expected) {
  return JSON.stringify([...actual].sort()) === JSON.stringify([...expected].sort());
}

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };
  const read = (rel) => fs.readFileSync(path.join(ctx.repo, rel), 'utf8');

  const resolveCommit = (label, commit) => {
    const probe = git(ctx.repo, ['rev-parse', `${commit}^{commit}`], { check: false });
    const resolved = probe.stdout.trim();
    if (probe.status !== 0 || resolved !== commit) {
      fail(`${label} does not resolve to fixed commit ${commit}: ${JSON.stringify(resolved)}`);
      return false;
    }
    ok(`${label} resolves to fixed commit ${commit}`);
    return true;
  };

  const verifyTree = (label, commit, expectedTree) => {
    const probe = git(ctx.repo, ['rev-parse', `${commit}^{tree}`], { check: false });
    const resolved = probe.stdout.trim();
    if (probe.status !== 0 || resolved !== expectedTree) {
      fail(`${label} tree drifted: ${JSON.stringify(resolved)} != ${expectedTree}`);
      return false;
    }
    ok(`${label} tree = ${expectedTree}`);
    return true;
  };

  const verifyParents = (label, commit, expectedParents) => {
    const probe = git(ctx.repo, ['rev-list', '--parents', '-n', '1', commit], { check: false });
    const fields = probe.stdout.trim().split(/\s+/).filter(Boolean);
    const actualCommit = fields.shift();
    if (probe.status !== 0 || actualCommit !== commit || JSON.stringify(fields) !== JSON.stringify(expectedParents)) {
      fail(`${label} parent identity drifted: ${JSON.stringify(fields)} != ${JSON.stringify(expectedParents)}`);
      return false;
    }
    ok(`${label} has the fixed two-parent merge identity`);
    return true;
  };

  // ---- one-time closeout scope ----
  const closeoutDiff = git(ctx.repo, ['diff', '--name-only', B002.merge_commit, '--']).stdout
    .split('\n')
    .filter(Boolean);
  if (!sameStrings(closeoutDiff, CLOSEOUT_PATHS)) {
    fail(`B002 closeout changed-path set must be exactly ${JSON.stringify(CLOSEOUT_PATHS)}, got ${JSON.stringify(closeoutDiff)}`);
  } else ok('B002 closeout changed-path set is exactly the four authorized paths');

  // ---- immutable B000/B001/B002 identities ----
  if (CURRENT_BATCH !== B002.id) {
    fail(`shared validator task identity drifted: ${JSON.stringify(CURRENT_BATCH)} != ${B002.id}`);
  } else ok(`shared validator task identity remains ${B002.id}`);

  resolveCommit('B000 merge', B000.commit);
  verifyTree('B000 merge', B000.commit, B000.tree);

  resolveCommit('B001 candidate', B001.candidate);
  resolveCommit('B001 merge', B001.merge_commit);
  verifyTree('B001 merge', B001.merge_commit, B001.tree);
  verifyParents('B001 merge', B001.merge_commit, [B000.commit, B001.candidate]);

  resolveCommit('B002 candidate', B002.candidate);
  resolveCommit('B002 implementation merge', B002.merge_commit);
  verifyTree('B002 candidate', B002.candidate, B002.tree);
  verifyTree('B002 implementation merge', B002.merge_commit, B002.tree);
  verifyParents('B002 implementation merge', B002.merge_commit, [B001.merge_commit, B002.candidate]);

  const headProbe = git(ctx.repo, ['rev-parse', 'HEAD^{commit}'], { check: false });
  const ancestryProbe = git(ctx.repo, ['merge-base', '--is-ancestor', B002.merge_commit, 'HEAD'], { check: false });
  if (headProbe.status !== 0 || ancestryProbe.status !== 0) {
    fail(`fixed B002 implementation merge ${B002.merge_commit} is not an ancestor of closeout HEAD ${JSON.stringify(headProbe.stdout.trim())}`);
  } else ok('fixed B002 implementation merge is an ancestor of closeout HEAD');

  // ---- machine status ----
  const machineText = read('docs/authority/registry/project-status.json');
  let status;
  try {
    status = JSON.parse(machineText);
  } catch (err) {
    fail(`project-status.json unparseable: ${err.message}`);
    return { name: 'status-transition', result: 'FAIL', details };
  }

  const standalone = status.tracks?.['AIPT-STANDALONE'];
  const platform = status.tracks?.['AIPT-PLATFORM-INTEGRATION'];
  const aipt = status.repositories?.AIPT;
  const history = standalone?.batch_history ?? {};

  if (status.schema !== 'aipt.public.project-status/v1') {
    fail(`project-status schema drifted: ${JSON.stringify(status.schema)}`);
  } else ok('project-status schema remains aipt.public.project-status/v1');
  if (status.as_of !== CLOSEOUT_DATE) {
    fail(`project-status.json as_of must be ${CLOSEOUT_DATE}: ${JSON.stringify(status.as_of)}`);
  } else ok(`status date = ${CLOSEOUT_DATE}`);
  if (standalone?.design !== 'FROZEN_R0_R16_DCA_BOOTSTRAP') {
    fail(`AIPT-STANDALONE.design drifted: ${JSON.stringify(standalone?.design)}`);
  } else ok('design remains FROZEN_R0_R16_DCA_BOOTSTRAP');
  if (standalone?.construction !== CONSTRUCTION_STATE) {
    fail(`construction must be ${CONSTRUCTION_STATE}: ${JSON.stringify(standalone?.construction)}`);
  } else ok(`construction = ${CONSTRUCTION_STATE}`);
  if (standalone?.current_batch !== NO_ACTIVE_BATCH) {
    fail(`current_batch must be ${NO_ACTIVE_BATCH}: ${JSON.stringify(standalone?.current_batch)}`);
  } else ok(`current_batch = ${NO_ACTIVE_BATCH}`);

  const closedBatchIds = ['AIPT-M0-B000', 'AIPT-M0-B001', B002.id];
  if (!sameStrings(Object.keys(history), closedBatchIds)) {
    fail(`batch_history keys must be exactly the three closed M0 batches: ${JSON.stringify(history)}`);
  }
  for (const closed of closedBatchIds) {
    if (history[closed] !== 'MERGED_CLOSED') {
      fail(`${closed} is not MERGED_CLOSED: ${JSON.stringify(history[closed])}`);
    } else ok(`${closed} = MERGED_CLOSED`);
  }
  if (standalone?.global_wip !== 0) {
    fail(`global_wip must be 0: ${JSON.stringify(standalone?.global_wip)}`);
  } else ok('GLOBAL_WIP = 0');

  if (standalone?.next_serial_batch !== NEXT_BATCH) {
    fail(`next_serial_batch must be ${NEXT_BATCH}: ${JSON.stringify(standalone?.next_serial_batch)}`);
  } else ok(`next serial batch = ${NEXT_BATCH}`);
  if (standalone?.next_batch_state !== NEXT_BATCH_STATE) {
    fail(`next_batch_state must be ${NEXT_BATCH_STATE}: ${JSON.stringify(standalone?.next_batch_state)}`);
  } else ok(`next batch state = ${NEXT_BATCH_STATE}`);
  if (standalone?.next_batch_authorized !== true) {
    fail(`next_batch_authorized must be true: ${JSON.stringify(standalone?.next_batch_authorized)}`);
  } else ok('next batch is authorized to prepare');
  if (standalone?.next_batch_started !== false) {
    fail(`next_batch_started must be false: ${JSON.stringify(standalone?.next_batch_started)}`);
  } else ok('next batch is not started');

  if (platform?.status !== 'FROZEN_WAITING_M1_ENGINE' || platform?.unfreeze_authorized !== false) {
    fail(`platform integration freeze drifted: ${JSON.stringify(platform)}`);
  } else ok('AIPT-PLATFORM-INTEGRATION remains FROZEN_WAITING_M1_ENGINE and unauthorized to unfreeze');
  if (aipt?.verified_head !== B002.merge_commit) {
    fail(`repositories.AIPT.verified_head must be B002 implementation merge ${B002.merge_commit}: ${JSON.stringify(aipt?.verified_head)}`);
  } else ok(`verified_head = B002 implementation merge ${B002.merge_commit}`);
  if (aipt?.verified_state !== EXPECTED_VERIFIED_STATE) {
    fail(`repositories.AIPT.verified_state must exactly describe the B002 closeout: ${JSON.stringify(aipt?.verified_state)}`);
  } else ok('verified_state exactly binds B002 candidate / merge / tree / post-merge CI and MERGED_CLOSED');
  if (status.runtime?.status !== 'not built yet') {
    fail(`runtime.status must be "not built yet": ${JSON.stringify(status.runtime?.status)}`);
  } else ok('runtime = not built yet');

  // ---- human status sources and three-way consistency ----
  const readme = read('README.md');
  const projectStatus = read('docs/authority/PROJECT_STATUS.md');
  const humanNeedles = [
    CLOSEOUT_DATE,
    'FROZEN_R0_R16_DCA_BOOTSTRAP',
    'FROZEN_WAITING_M1_ENGINE',
    'unfreeze_authorized = false',
    'IDLE_WAITING_NEXT_BATCH',
    'current_batch = NO_ACTIVE_BATCH',
    '当前无活跃实施批次',
    'GLOBAL_WIP = 0',
    NEXT_BATCH,
    NEXT_BATCH_STATE,
    'next_batch_authorized = true',
    'next_batch_started = false',
    B000.commit,
    B000.tree,
    B001.candidate,
    B001.merge_commit,
    B001.tree,
    String(B001.post_merge_ci_run),
    B002.candidate,
    B002.merge_commit,
    B002.tree,
    String(B002.post_merge_ci_run),
    B002.post_merge_ci_conclusion,
    '运行时代码尚未建设',
  ];

  for (const [name, text] of [
    ['README.md', readme],
    ['PROJECT_STATUS.md', projectStatus],
  ]) {
    for (const needle of humanNeedles) {
      if (!text.includes(needle)) fail(`${name} missing required closeout token: ${needle}`);
    }

    const closed = new Set(
      [...text.matchAll(/`(AIPT-M0-B00[0-2])`\s*=\s*\*{0,2}MERGED\/CLOSED\*{0,2}/g)]
        .map((match) => match[1]),
    );
    for (const batch of ['AIPT-M0-B000', 'AIPT-M0-B001', B002.id]) {
      if (!closed.has(batch)) fail(`${name} does not present ${batch} as MERGED/CLOSED`);
    }
    if (closed.size === 3) ok(`${name} presents B000/B001/B002 as MERGED/CLOSED`);

    for (const forbidden of ['B002_IN_PROGRESS', 'AIPT-M0-B002_IN_PROGRESS', 'GLOBAL_WIP = 1', 'task/AIPT-M0-B002']) {
      if (text.includes(forbidden)) fail(`${name} retains forbidden construction-state token: ${forbidden}`);
    }
    if (/IN_PROGRESS/.test(text)) fail(`${name} still presents an implementation batch as IN_PROGRESS`);
    if (/当前批次\s*[=:：]?\s*`?(?:AIPT-M0-B002|UNREGISTERED-AIPT-P0-B000)/.test(text)) {
      fail(`${name} falsely presents a closed or unstarted batch as current`);
    }
  }

  if (machineText.includes('B002_IN_PROGRESS') || /AIPT-M0-B002[^\n"]*in progress/i.test(machineText)) {
    fail('project-status.json retains a B002 in-progress claim');
  } else ok('machine status contains no B002 in-progress claim');
  if (machineText.includes(`${NEXT_BATCH}_IN_PROGRESS`)) {
    fail('project-status.json falsely marks the next serial batch as started');
  } else ok('machine status does not mark the next serial batch IN_PROGRESS');

  return { name: 'status-transition', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'status-transition', run);
