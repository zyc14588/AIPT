// B001 public status-transition validator.
//
// Verifies the candidate no longer presents AIPT-M0-B000 as the current
// READY batch, and that all public status sources agree with the B001
// candidate-time view. `verified_head` may only point at the accepted main
// base, never at a candidate SHA.
import fs from 'node:fs';
import path from 'node:path';
import { BASE_COMMIT, TASK_ID } from '../lib/constants.mjs';
import { runAsMain } from '../lib/cli.mjs';

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };

  const read = (rel) => fs.readFileSync(path.join(ctx.repo, rel), 'utf8');

  // ---- machine status ----
  let status;
  try {
    status = JSON.parse(read('docs/authority/registry/project-status.json'));
  } catch (err) {
    fail(`project-status.json unparseable: ${err.message}`);
    return { name: 'status-transition', result: 'FAIL', details };
  }
  const standalone = status.tracks?.['AIPT-STANDALONE'];
  const platform = status.tracks?.['AIPT-PLATFORM-INTEGRATION'];
  const aipt = status.repositories?.AIPT;

  if (standalone?.design !== 'FROZEN_R0_R16_DCA_BOOTSTRAP') {
    fail(`AIPT-STANDALONE.design drifted: ${JSON.stringify(standalone?.design)}`);
  } else ok('design frozen FROZEN_R0_R16_DCA_BOOTSTRAP');
  if (standalone?.construction !== 'AIPT-M0-B001_IN_PROGRESS') {
    fail(`construction is not AIPT-M0-B001_IN_PROGRESS: ${JSON.stringify(standalone?.construction)}`);
  } else ok('construction = AIPT-M0-B001_IN_PROGRESS');
  if (standalone?.current_batch !== TASK_ID) {
    fail(`current_batch is not ${TASK_ID}: ${JSON.stringify(standalone?.current_batch)}`);
  } else ok('current batch = AIPT-M0-B001');
  if (standalone?.batch_history?.['AIPT-M0-B000'] !== 'MERGED_CLOSED') {
    fail(`AIPT-M0-B000 is not MERGED_CLOSED: ${JSON.stringify(standalone?.batch_history)}`);
  } else ok('AIPT-M0-B000 = MERGED_CLOSED');
  if (standalone?.global_wip !== 1) {
    fail(`global_wip != 1: ${JSON.stringify(standalone?.global_wip)}`);
  } else ok('GLOBAL_WIP = 1');
  if (platform?.status !== 'FROZEN_WAITING_M1_ENGINE' || platform?.unfreeze_authorized !== false) {
    fail(`platform integration freeze drifted: ${JSON.stringify(platform)}`);
  } else ok('AIPT-PLATFORM-INTEGRATION = FROZEN_WAITING_M1_ENGINE, unfreeze not authorized');
  if (aipt?.verified_head !== BASE_COMMIT) {
    fail(`repositories.AIPT.verified_head must be the accepted main base ${BASE_COMMIT}, got ${JSON.stringify(aipt?.verified_head)}`);
  } else ok(`verified_head == accepted main base ${BASE_COMMIT}`);
  if (status.runtime?.status !== 'not built yet') {
    fail(`runtime.status must be "not built yet": ${JSON.stringify(status.runtime?.status)}`);
  } else ok('runtime = not built yet');

  // ---- human docs ----
  const readme = read('README.md');
  for (const needle of [
    'AIPT-M0-B001',
    'B001_IN_PROGRESS',
    BASE_COMMIT,
    'MERGED/CLOSED',
    'FROZEN_WAITING_M1_ENGINE',
  ]) {
    if (!readme.includes(needle)) fail(`README.md missing required token: ${needle}`);
  }
  if (/当前批次\s*`?AIPT-M0-B000`?/.test(readme)) {
    fail('README.md still presents AIPT-M0-B000 as the current batch');
  } else ok('README.md no longer presents B000 as current READY batch');

  const ps = read('docs/authority/PROJECT_STATUS.md');
  for (const needle of ['AIPT-M0-B001', 'IN_PROGRESS', '777a3f39ba78c1ef3168597890c61abf7a55d962', 'MERGED/CLOSED']) {
    if (!ps.includes(needle)) fail(`PROJECT_STATUS.md missing required token: ${needle}`);
  }
  if (/当前批次\s*`?AIPT-M0-B000`?/.test(ps)) {
    fail('PROJECT_STATUS.md still presents AIPT-M0-B000 as the current batch');
  } else ok('PROJECT_STATUS.md no longer presents B000 as current READY batch');
  if (!ps.includes('FROZEN_WAITING_M1_ENGINE')) {
    fail('PROJECT_STATUS.md lost the platform integration freeze statement');
  } else ok('PROJECT_STATUS.md keeps platform integration frozen');

  const statuses = [];
  for (const needle of ['AIPT-M0-B001', 'B001_IN_PROGRESS', BASE_COMMIT, 'MERGED/CLOSED']) {
    if (!readme.includes(needle)) statuses.push(`README.md:${needle}`);
  }
  if (statuses.length === 0) ok('README.md carries the B001 candidate-time view');
  else fail(`README.md missing: ${statuses.join(', ')}`);

  return { name: 'status-transition', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'status-transition', run);
