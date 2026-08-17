// B002 public status-transition validator.
//
// Verifies the first legal B001 -> B002 public status transition. The
// candidate must no longer present AIPT-M0-B001 as the current batch, and
// all public status sources (machine snapshot + README + PROJECT_STATUS)
// must agree that:
//   - AIPT-M0-B000 and AIPT-M0-B001 are both MERGED_CLOSED;
//   - the B001 acceptance is the fixed candidate / merge commit /
//     post-merge CI run recorded in lib/constants.mjs;
//   - AIPT-M0-B002 is IN_PROGRESS and the current batch (GLOBAL_WIP = 1);
//   - the platform integration track stays FROZEN_WAITING_M1_ENGINE with
//     unfreeze_authorized = false, and the runtime stays "not built yet".
// `verified_head` may only point at the accepted main base (the B001 merge
// commit), never at a candidate SHA.
import fs from 'node:fs';
import path from 'node:path';
import { B001, BASE_COMMIT, CURRENT_BATCH, STATUS_DATE } from '../lib/constants.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

const CI_RUN_TOKEN = String(B001.post_merge_ci_run);
// Closed-batch presentation in the human docs: `AIPT-M0-B00x` = **MERGED/CLOSED**
const CLOSED_LINE = /`AIPT-M0-B00[01]`\s*=\s*\*{0,2}\s*MERGED\/CLOSED/g;
const B001_AS_CURRENT = /当前批次\s*[=:：]?\s*`?AIPT-M0-B001`?/;
const B002_AS_CURRENT = /当前批次\s*[=:：]?\s*`?AIPT-M0-B002`?/;

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };

  const read = (rel) => fs.readFileSync(path.join(ctx.repo, rel), 'utf8');

  // ---- fixed identities must resolve in this checkout (fail-closed) ----
  const resolvedBase = git(ctx.repo, ['rev-parse', `${BASE_COMMIT}^{commit}`]).stdout.trim();
  if (resolvedBase !== BASE_COMMIT) {
    fail(`accepted main base does not resolve to the fixed B001 merge commit: ${resolvedBase}`);
  } else ok('accepted main base resolves (B001 merge commit)');
  const resolvedCandidate = git(ctx.repo, ['rev-parse', `${B001.candidate}^{commit}`]).stdout.trim();
  if (resolvedCandidate !== B001.candidate) {
    fail(`B001 candidate does not resolve to the fixed candidate commit: ${resolvedCandidate}`);
  } else ok('B001 candidate commit resolves');

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
  const history = standalone?.batch_history ?? {};

  if (status.as_of !== STATUS_DATE) {
    fail(`project-status.json as_of must be ${STATUS_DATE}: ${JSON.stringify(status.as_of)}`);
  } else ok(`status date = ${STATUS_DATE}`);
  if (standalone?.design !== 'FROZEN_R0_R16_DCA_BOOTSTRAP') {
    fail(`AIPT-STANDALONE.design drifted: ${JSON.stringify(standalone?.design)}`);
  } else ok('design frozen FROZEN_R0_R16_DCA_BOOTSTRAP');
  if (standalone?.construction !== `${CURRENT_BATCH}_IN_PROGRESS`) {
    fail(`construction is not ${CURRENT_BATCH}_IN_PROGRESS: ${JSON.stringify(standalone?.construction)}`);
  } else ok(`construction = ${CURRENT_BATCH}_IN_PROGRESS`);
  if (standalone?.current_batch !== CURRENT_BATCH) {
    fail(`current_batch is not ${CURRENT_BATCH}: ${JSON.stringify(standalone?.current_batch)}`);
  } else ok(`current batch = ${CURRENT_BATCH}`);
  for (const closed of ['AIPT-M0-B000', 'AIPT-M0-B001']) {
    if (history[closed] !== 'MERGED_CLOSED') {
      fail(`${closed} is not MERGED_CLOSED: ${JSON.stringify(history)}`);
    } else ok(`${closed} = MERGED_CLOSED (closed batch history)`);
  }
  if (standalone?.global_wip !== 1) {
    fail(`global_wip != 1: ${JSON.stringify(standalone?.global_wip)}`);
  } else ok('GLOBAL_WIP = 1');
  if (platform?.status !== 'FROZEN_WAITING_M1_ENGINE' || platform?.unfreeze_authorized !== false) {
    fail(`platform integration freeze drifted: ${JSON.stringify(platform)}`);
  } else ok('AIPT-PLATFORM-INTEGRATION = FROZEN_WAITING_M1_ENGINE, unfreeze_authorized = false');
  if (aipt?.verified_head !== BASE_COMMIT) {
    fail(`repositories.AIPT.verified_head must be the accepted main base ${BASE_COMMIT}, got ${JSON.stringify(aipt?.verified_head)}`);
  } else ok(`verified_head == accepted main base ${BASE_COMMIT}`);
  const vState = String(aipt?.verified_state ?? '');
  const vStateNeedles = {
    'AIPT-M0-B001': vState.includes('AIPT-M0-B001'),
    'AIPT-M0-B002': vState.includes('AIPT-M0-B002'),
    'B001 candidate': vState.includes(B001.candidate),
    'post-merge CI run': vState.includes(CI_RUN_TOKEN),
    'merged': /merged/i.test(vState),
    'closed': /closed/i.test(vState),
    'in progress': /in progress/i.test(vState),
  };
  const missingState = Object.entries(vStateNeedles).filter(([, has]) => !has).map(([k]) => k);
  if (missingState.length > 0) {
    fail(`verified_state does not fully describe the B001 merge/closeout and B002 in progress (missing: ${missingState.join(', ')}): ${JSON.stringify(vState)}`);
  } else ok('verified_state describes B001 merge/closeout (candidate + CI run) and B002 in progress');
  if (status.runtime?.status !== 'not built yet') {
    fail(`runtime.status must be "not built yet": ${JSON.stringify(status.runtime?.status)}`);
  } else ok('runtime = not built yet');

  // ---- human docs ----
  const readme = read('README.md');
  const readmeNeedles = [
    'AIPT-M0-B001',
    'AIPT-M0-B002',
    'B002_IN_PROGRESS',
    'MERGED/CLOSED',
    B001.candidate,
    BASE_COMMIT,
    CI_RUN_TOKEN,
    'FROZEN_WAITING_M1_ENGINE',
    STATUS_DATE,
  ];
  for (const needle of readmeNeedles) {
    if (!readme.includes(needle)) fail(`README.md missing required token: ${needle}`);
  }
  if (B001_AS_CURRENT.test(readme)) {
    fail('README.md still presents AIPT-M0-B001 as the current batch');
  } else ok('README.md no longer presents B001 as the current batch');
  if (!B002_AS_CURRENT.test(readme)) {
    fail('README.md does not present AIPT-M0-B002 as the current batch');
  } else ok('README.md presents AIPT-M0-B002 as the current batch');
  const readmeClosed = new Set([...readme.matchAll(CLOSED_LINE)].map((m) => m[0].match(/AIPT-M0-B00[01]/)[0]));
  for (const closed of ['AIPT-M0-B000', 'AIPT-M0-B001']) {
    if (!readmeClosed.has(closed)) fail(`README.md does not present ${closed} as MERGED/CLOSED`);
  }
  if (readmeClosed.size >= 2) ok('README.md presents both closed batch histories as MERGED/CLOSED');
  if (!readme.includes('运行时代码尚未建设')) fail('README.md lost the runtime-not-built statement');

  const ps = read('docs/authority/PROJECT_STATUS.md');
  const psNeedles = [
    'AIPT-M0-B001',
    'AIPT-M0-B002',
    'B002_IN_PROGRESS',
    'MERGED/CLOSED',
    B001.candidate,
    BASE_COMMIT,
    CI_RUN_TOKEN,
    'FROZEN_WAITING_M1_ENGINE',
    STATUS_DATE,
  ];
  for (const needle of psNeedles) {
    if (!ps.includes(needle)) fail(`PROJECT_STATUS.md missing required token: ${needle}`);
  }
  if (B001_AS_CURRENT.test(ps)) {
    fail('PROJECT_STATUS.md still presents AIPT-M0-B001 as the current batch');
  } else ok('PROJECT_STATUS.md no longer presents B001 as the current batch');
  if (!B002_AS_CURRENT.test(ps)) {
    fail('PROJECT_STATUS.md does not present AIPT-M0-B002 as the current batch');
  } else ok('PROJECT_STATUS.md presents AIPT-M0-B002 as the current batch');
  const psClosed = new Set([...ps.matchAll(CLOSED_LINE)].map((m) => m[0].match(/AIPT-M0-B00[01]/)[0]));
  for (const closed of ['AIPT-M0-B000', 'AIPT-M0-B001']) {
    if (!psClosed.has(closed)) fail(`PROJECT_STATUS.md does not present ${closed} as MERGED/CLOSED`);
  }
  if (psClosed.size >= 2) ok('PROJECT_STATUS.md presents both closed batch histories as MERGED/CLOSED');
  if (!ps.includes('FROZEN_WAITING_M1_ENGINE')) {
    fail('PROJECT_STATUS.md lost the platform integration freeze statement');
  } else ok('PROJECT_STATUS.md keeps platform integration frozen');
  if (!ps.includes('尚未建设')) fail('PROJECT_STATUS.md lost the runtime-not-built statement');
  if (!ps.includes('GLOBAL_WIP = 1')) fail('PROJECT_STATUS.md lost the GLOBAL_WIP = 1 statement');
  else ok('PROJECT_STATUS.md keeps GLOBAL_WIP = 1');

  const statuses = [];
  for (const needle of ['AIPT-M0-B002', 'B002_IN_PROGRESS', BASE_COMMIT, 'MERGED/CLOSED']) {
    if (!readme.includes(needle)) statuses.push(`README.md:${needle}`);
  }
  if (statuses.length === 0) ok('README.md carries the B002 current view');
  else fail(`README.md missing: ${statuses.join(', ')}`);

  return { name: 'status-transition', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'status-transition', run);
