// B003 public status-transition validator (compact core).
//
// Proves the immutable B000 / B001 / B002 / B002-closeout identities and the
// fixed historical closeout diff independently of current HEAD, verifies that
// current HEAD descends from the accepted B003 base (the B002 closeout
// commit), validates the exact structured machine status of the
// AIPT-M0-B003-CONSTRUCTION-001 snapshot, and proves the frozen authority
// registries are byte-identical to the base.
//
// Deliberately out of scope here: negative mutation self-probes, and any
// constraint on runtime.status. The human-document section covers the minimal
// current B003 / next B004 relationship plus positive same-line closed-history
// (B000/B001/B002 = MERGED/CLOSED), external-predecessor, accepted-source
// (commit -> tree), and frozen-platform (FROZEN_WAITING_M1_ENGINE ->
// unfreeze_authorized = false) bindings, and two focused
// forbidden-contradiction predicates (B003 must not be bound to
// MERGED/CLOSED; B004 must not be bound to IN_PROGRESS or MERGED/CLOSED, both
// within a bounded same-line gap); mutation and runtime.status checks remain
// out of scope.
import fs from 'node:fs';
import path from 'node:path';
import {
  B000,
  B001,
  B002,
  B002_CLOSEOUT,
  BASE_COMMIT,
  BASE_TREE,
  CURRENT_BATCH,
  EXTERNAL_SERIAL_PREDECESSOR,
  FROZEN_REGISTRY_PATHS,
  STATUS_DATE,
} from '../lib/constants.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

const SCHEMA_V1 = 'aipt.public.project-status/v1';
const SNAPSHOT_ID = 'AIPT-M0-B003-CONSTRUCTION-001';
const DESIGN_FROZEN = 'FROZEN_R0_R16_DCA_BOOTSTRAP';
const CONSTRUCTION_STATE = 'IN_PROGRESS';
const NEXT_SERIAL_BATCH = 'AIPT-M0-B004';
const NEXT_BATCH_STATE = 'NOT_AUTHORIZED';
const PLATFORM_STATUS = 'FROZEN_WAITING_M1_ENGINE';
const MERGED_CLOSED = 'MERGED_CLOSED';

// The four authorized paths of the historical B002 closeout (B002.merge_commit
// -> B002_CLOSEOUT.commit). This set is a fixed immutable fact, never derived
// from HEAD.
const CLOSEOUT_PATHS = [
  'README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'scripts/ci/validate/status-transition.mjs',
];

const CLOSED_BATCH_IDS = ['AIPT-M0-B000', 'AIPT-M0-B001', 'AIPT-M0-B002'];

// Exact verified_state currently bound in the registry snapshot: the B003
// construction description over the accepted B002-closeout base.
const EXPECTED_VERIFIED_STATE =
  'AIPT-M0-B003 construction IN_PROGRESS (global WIP 1): accepted source base is the ' +
  'AIPT-M0-B002 closeout commit 45a96087d75a61f2910cb5ce99134e3ca777bca8, tree ' +
  '8b16b599c261879406f0435e80c878e092683a50; B000/B001/B002 remain MERGED_CLOSED; ' +
  'B003 is not yet accepted or closed; next serial batch AIPT-M0-B004 is NOT_AUTHORIZED and not started';

function sameStrings(actual, expected) {
  return JSON.stringify([...actual].sort()) === JSON.stringify([...expected].sort());
}

// Pure, deterministic critical-machine gate over the parsed live status. Reads
// only candidateStatus.tracks['AIPT-STANDALONE'] and reports a descriptive
// problem per strict mismatch of exactly the seven standalone current/WIP/
// next-B004 fields plus the external serial predecessor binding (its exact
// five-key set and the five immutable values against EXTERNAL_SERIAL_PREDECESSOR).
// Side-effect-free: never touches ctx, git, or fs.
export function criticalMachineProblems(candidateStatus) {
  const problems = [];
  const standalone = candidateStatus?.tracks?.['AIPT-STANDALONE'];
  if (standalone?.construction !== CONSTRUCTION_STATE) {
    problems.push(`construction must be ${CONSTRUCTION_STATE}: ${JSON.stringify(standalone?.construction)}`);
  }
  if (standalone?.current_batch !== CURRENT_BATCH) {
    problems.push(`current_batch must be ${CURRENT_BATCH}: ${JSON.stringify(standalone?.current_batch)}`);
  }
  if (standalone?.global_wip !== 1) {
    problems.push(`global_wip must be 1: ${JSON.stringify(standalone?.global_wip)}`);
  }
  if (standalone?.next_serial_batch !== NEXT_SERIAL_BATCH) {
    problems.push(`next_serial_batch must be ${NEXT_SERIAL_BATCH}: ${JSON.stringify(standalone?.next_serial_batch)}`);
  }
  if (standalone?.next_batch_state !== NEXT_BATCH_STATE) {
    problems.push(`next_batch_state must be ${NEXT_BATCH_STATE}: ${JSON.stringify(standalone?.next_batch_state)}`);
  }
  if (standalone?.next_batch_authorized !== false) {
    problems.push(`next_batch_authorized must be false: ${JSON.stringify(standalone?.next_batch_authorized)}`);
  }
  if (standalone?.next_batch_started !== false) {
    problems.push(`next_batch_started must be false: ${JSON.stringify(standalone?.next_batch_started)}`);
  }
  const predecessor = standalone?.external_serial_predecessor ?? {};
  const expectedPredecessorKeys = ['id', 'status', 'closeout_commit', 'closeout_ci_run', 'closeout_ci_conclusion'];
  if (!sameStrings(Object.keys(predecessor), expectedPredecessorKeys)) {
    problems.push(`external_serial_predecessor keys must be exactly ${JSON.stringify(expectedPredecessorKeys)}: ${JSON.stringify(predecessor)}`);
  } else if (
    predecessor.id !== EXTERNAL_SERIAL_PREDECESSOR.batch ||
    predecessor.status !== EXTERNAL_SERIAL_PREDECESSOR.status ||
    predecessor.closeout_commit !== EXTERNAL_SERIAL_PREDECESSOR.closeout_commit ||
    predecessor.closeout_ci_run !== EXTERNAL_SERIAL_PREDECESSOR.closeout_ci_run ||
    predecessor.closeout_ci_conclusion !== EXTERNAL_SERIAL_PREDECESSOR.closeout_ci_conclusion
  ) {
    problems.push(`external_serial_predecessor values drifted: ${JSON.stringify(predecessor)}`);
  }
  return problems;
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

  const verifyAnchor = (label, actual, expected) => {
    if (actual !== expected) {
      fail(`${label} drifted from its independent literal self-anchor: ${JSON.stringify(actual)} != ${JSON.stringify(expected)}`);
      return false;
    }
    ok(`${label} anchored to literal ${JSON.stringify(expected)}`);
    return true;
  };

  // ---- independent literal self-anchors ----
  // Every critical identity below is hard-coded in this gate and compared
  // against the imported constants BEFORE any Git/history or machine-status
  // validation runs. Drifting constants.mjs and the status data together can
  // therefore never make a historical identity change pass silently: each
  // imported field must equal its fixed literal.
  verifyAnchor('BASE_COMMIT', BASE_COMMIT, '45a96087d75a61f2910cb5ce99134e3ca777bca8');
  verifyAnchor('BASE_TREE', BASE_TREE, '8b16b599c261879406f0435e80c878e092683a50');
  verifyAnchor('CURRENT_BATCH', CURRENT_BATCH, 'AIPT-M0-B003');
  verifyAnchor('STATUS_DATE', STATUS_DATE, '2026-08-19');
  verifyAnchor('B000.commit', B000.commit, '777a3f39ba78c1ef3168597890c61abf7a55d962');
  verifyAnchor('B000.tree', B000.tree, 'f5f845b860ba0944ef104b4679fa074ad6efecbb');
  verifyAnchor('B001.candidate', B001.candidate, '2e904ddc2d4f1313a99e19f6751a991d589f8336');
  verifyAnchor('B001.merge_commit', B001.merge_commit, '8bcadc9669e7d04f589f883daa6d4f593875fc9e');
  verifyAnchor('B001.tree', B001.tree, 'fefc25f1acb523d013c2a7d8db9801ccdab37d2d');
  verifyAnchor('B002.candidate', B002.candidate, '9968cbc89c09640e3fc2feb8d851220eae98b9b9');
  verifyAnchor('B002.merge_commit', B002.merge_commit, 'fccfb595c23feab38397506505a3e996fe7b9e9c');
  verifyAnchor('B002.tree', B002.tree, 'f99570bc3c4307244ca926cec62e82a07ef5aee8');
  verifyAnchor('B002.post_merge_ci_run', B002.post_merge_ci_run, 31985644832);
  verifyAnchor('B002.post_merge_ci_conclusion', B002.post_merge_ci_conclusion, 'success');
  verifyAnchor('B002_CLOSEOUT.commit', B002_CLOSEOUT.commit, '45a96087d75a61f2910cb5ce99134e3ca777bca8');
  verifyAnchor('B002_CLOSEOUT.tree', B002_CLOSEOUT.tree, '8b16b599c261879406f0435e80c878e092683a50');
  verifyAnchor('B002_CLOSEOUT.parent', B002_CLOSEOUT.parent, 'fccfb595c23feab38397506505a3e996fe7b9e9c');
  verifyAnchor('EXTERNAL_SERIAL_PREDECESSOR.batch', EXTERNAL_SERIAL_PREDECESSOR.batch, 'UNREGISTERED-AIPT-P0-B001');
  verifyAnchor('EXTERNAL_SERIAL_PREDECESSOR.status', EXTERNAL_SERIAL_PREDECESSOR.status, 'MERGED_CLOSED');
  verifyAnchor('EXTERNAL_SERIAL_PREDECESSOR.closeout_commit', EXTERNAL_SERIAL_PREDECESSOR.closeout_commit, 'a37b284bf5ec35895f436abe71d22599edb6da53');
  verifyAnchor('EXTERNAL_SERIAL_PREDECESSOR.closeout_ci_run', EXTERNAL_SERIAL_PREDECESSOR.closeout_ci_run, 32194224161);
  verifyAnchor('EXTERNAL_SERIAL_PREDECESSOR.closeout_ci_conclusion', EXTERNAL_SERIAL_PREDECESSOR.closeout_ci_conclusion, 'success');

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
    ok(`${label} has the fixed parent identity ${JSON.stringify(expectedParents)}`);
    return true;
  };

  // ---- immutable B000/B001/B002/B002-closeout identities ----
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

  resolveCommit('B002 closeout', B002_CLOSEOUT.commit);
  verifyTree('B002 closeout', B002_CLOSEOUT.commit, B002_CLOSEOUT.tree);
  verifyParents('B002 closeout', B002_CLOSEOUT.commit, [B002.merge_commit]);

  // ---- historical closeout scope (fixed two-commit diff, never ..HEAD) ----
  const closeoutDiff = git(ctx.repo, ['diff', '--name-only', B002.merge_commit, B002_CLOSEOUT.commit]).stdout
    .split('\n')
    .filter(Boolean);
  if (!sameStrings(closeoutDiff, CLOSEOUT_PATHS)) {
    fail(`B002 closeout changed-path set must be exactly ${JSON.stringify(CLOSEOUT_PATHS)}, got ${JSON.stringify(closeoutDiff)}`);
  } else ok('B002 closeout changed-path set is exactly the four authorized paths');

  // ---- current HEAD descends from the accepted B003 base ----
  const headProbe = git(ctx.repo, ['rev-parse', 'HEAD^{commit}'], { check: false });
  const ancestryProbe = git(ctx.repo, ['merge-base', '--is-ancestor', BASE_COMMIT, 'HEAD'], { check: false });
  if (headProbe.status !== 0 || ancestryProbe.status !== 0) {
    fail(`current HEAD ${JSON.stringify(headProbe.stdout.trim())} does not descend from accepted base ${BASE_COMMIT}`);
  } else ok(`current HEAD descends from accepted base ${BASE_COMMIT}`);

  // ---- machine status (exact structured snapshot) ----
  const machinePath = 'docs/authority/registry/project-status.json';
  let status;
  try {
    status = JSON.parse(read(machinePath));
  } catch (err) {
    fail(`project-status.json unparseable: ${err.message}`);
    return { name: 'status-transition', result: 'FAIL', details };
  }

  for (const problem of criticalMachineProblems(status)) {
    fail(`critical machine: ${problem}`);
  }

  const standalone = status.tracks?.['AIPT-STANDALONE'];
  const platform = status.tracks?.['AIPT-PLATFORM-INTEGRATION'];
  const aipt = status.repositories?.AIPT;
  const history = standalone?.batch_history ?? {};
  const predecessor = standalone?.external_serial_predecessor ?? {};

  if (status.schema !== SCHEMA_V1) {
    fail(`project-status schema drifted: ${JSON.stringify(status.schema)}`);
  } else ok(`schema = ${SCHEMA_V1}`);
  if (status.as_of !== STATUS_DATE) {
    fail(`project-status as_of must be ${STATUS_DATE}: ${JSON.stringify(status.as_of)}`);
  } else ok(`status date = ${STATUS_DATE}`);
  if (status.authority_snapshot_id !== SNAPSHOT_ID) {
    fail(`authority_snapshot_id must be ${SNAPSHOT_ID}: ${JSON.stringify(status.authority_snapshot_id)}`);
  } else ok(`snapshot = ${SNAPSHOT_ID}`);
  if (standalone?.design !== DESIGN_FROZEN) {
    fail(`AIPT-STANDALONE.design must be ${DESIGN_FROZEN}: ${JSON.stringify(standalone?.design)}`);
  } else ok('design remains FROZEN_R0_R16_DCA_BOOTSTRAP');
  if (standalone?.construction !== CONSTRUCTION_STATE) {
    fail(`construction must be ${CONSTRUCTION_STATE}: ${JSON.stringify(standalone?.construction)}`);
  } else ok(`construction = ${CONSTRUCTION_STATE}`);
  if (standalone?.current_batch !== CURRENT_BATCH) {
    fail(`current_batch must be ${CURRENT_BATCH}: ${JSON.stringify(standalone?.current_batch)}`);
  } else ok(`current batch = ${CURRENT_BATCH}`);

  if (!sameStrings(Object.keys(history), CLOSED_BATCH_IDS)) {
    fail(`batch_history keys must be exactly the three closed M0 batches: ${JSON.stringify(history)}`);
  } else {
    let allClosed = true;
    for (const id of CLOSED_BATCH_IDS) {
      if (history[id] !== MERGED_CLOSED) {
        fail(`${id} must be ${MERGED_CLOSED}: ${JSON.stringify(history[id])}`);
        allClosed = false;
      }
    }
    if (allClosed) ok('batch_history is exactly B000/B001/B002 = MERGED_CLOSED');
  }

  const expectedPredecessorKeys = ['id', 'status', 'closeout_commit', 'closeout_ci_run', 'closeout_ci_conclusion'];
  if (!sameStrings(Object.keys(predecessor), expectedPredecessorKeys)) {
    fail(`external_serial_predecessor keys must be exactly ${JSON.stringify(expectedPredecessorKeys)}: ${JSON.stringify(predecessor)}`);
  } else if (
    predecessor.id !== EXTERNAL_SERIAL_PREDECESSOR.batch ||
    predecessor.status !== EXTERNAL_SERIAL_PREDECESSOR.status ||
    predecessor.closeout_commit !== EXTERNAL_SERIAL_PREDECESSOR.closeout_commit ||
    predecessor.closeout_ci_run !== EXTERNAL_SERIAL_PREDECESSOR.closeout_ci_run ||
    predecessor.closeout_ci_conclusion !== EXTERNAL_SERIAL_PREDECESSOR.closeout_ci_conclusion
  ) {
    fail(`external_serial_predecessor values drifted: ${JSON.stringify(predecessor)}`);
  } else ok('external_serial_predecessor is exactly the five-key UNREGISTERED-AIPT-P0-B001 MERGED_CLOSED record');
  if (standalone?.global_wip !== 1) {
    fail(`global_wip must be 1: ${JSON.stringify(standalone?.global_wip)}`);
  } else ok('GLOBAL_WIP = 1');

  if (standalone?.next_serial_batch !== NEXT_SERIAL_BATCH) {
    fail(`next_serial_batch must be ${NEXT_SERIAL_BATCH}: ${JSON.stringify(standalone?.next_serial_batch)}`);
  } else ok(`next serial batch = ${NEXT_SERIAL_BATCH}`);
  if (standalone?.next_batch_state !== NEXT_BATCH_STATE) {
    fail(`next_batch_state must be ${NEXT_BATCH_STATE}: ${JSON.stringify(standalone?.next_batch_state)}`);
  } else ok(`next batch state = ${NEXT_BATCH_STATE}`);
  if (standalone?.next_batch_authorized !== false) {
    fail(`next_batch_authorized must be false: ${JSON.stringify(standalone?.next_batch_authorized)}`);
  } else ok('next batch is not authorized');
  if (standalone?.next_batch_started !== false) {
    fail(`next_batch_started must be false: ${JSON.stringify(standalone?.next_batch_started)}`);
  } else ok('next batch is not started');

  if (platform?.status !== PLATFORM_STATUS || platform?.unfreeze_authorized !== false) {
    fail(`platform integration freeze drifted: ${JSON.stringify(platform)}`);
  } else ok('AIPT-PLATFORM-INTEGRATION remains FROZEN_WAITING_M1_ENGINE and unauthorized to unfreeze');
  if (aipt?.verified_head !== BASE_COMMIT) {
    fail(`repositories.AIPT.verified_head must be accepted base ${BASE_COMMIT}: ${JSON.stringify(aipt?.verified_head)}`);
  } else ok(`verified_head = accepted base ${BASE_COMMIT}`);
  if (aipt?.verified_tree !== BASE_TREE) {
    fail(`repositories.AIPT.verified_tree must be accepted base tree ${BASE_TREE}: ${JSON.stringify(aipt?.verified_tree)}`);
  } else ok(`verified_tree = accepted base tree ${BASE_TREE}`);
  if (aipt?.verified_state !== EXPECTED_VERIFIED_STATE) {
    fail(`repositories.AIPT.verified_state must exactly describe the B003 construction snapshot: ${JSON.stringify(aipt?.verified_state)}`);
  } else ok('verified_state exactly binds the B003 construction snapshot over the B002-closeout base');

  // ---- frozen registries: working-tree bytes == BASE_COMMIT blobs ----
  for (const rel of FROZEN_REGISTRY_PATHS) {
    const workingBlob = git(ctx.repo, ['hash-object', rel]).stdout.trim();
    const baseBlob = git(ctx.repo, ['rev-parse', `${BASE_COMMIT}:${rel}`]).stdout.trim();
    if (workingBlob !== baseBlob) {
      fail(`frozen registry ${rel} working-tree bytes differ from base blob: ${workingBlob} != ${baseBlob}`);
    } else ok(`frozen registry ${rel} byte-identical to base`);
  }

  // ---- human-current-state (README.md / PROJECT_STATUS.md) ----
  // Same-line consistency checks for the current B003 construction snapshot
  // (date, snapshot id, IN_PROGRESS, GLOBAL_WIP = 1), the accepted source
  // (commit -> tree), the frozen platform (FROZEN_WAITING_M1_ENGINE ->
  // unfreeze_authorized = false), the next B004 relationship (NOT_AUTHORIZED,
  // not authorized, not started), the immutable closed history (AIPT-M0-B000 /
  // B001 / B002 each = MERGED/CLOSED on one line), and the external serial
  // predecessor (UNREGISTERED-AIPT-P0-B001 = MERGED/CLOSED with its closeout
  // commit / CI run / success conclusion, in order on one line). Every
  // relationship must be bound on a single document line — no whole-document
  // token bags. Two focused forbidden-contradiction checks are also applied
  // here: AIPT-M0-B003 must not be bound to MERGED/CLOSED (either order, 0..40
  // same-line character gap), and AIPT-M0-B004 must not be bound to
  // IN_PROGRESS or MERGED/CLOSED (either order, 0..80 same-line character
  // gap). Machine mutation probes and runtime.status checks remain out of
  // scope.
  const HUMAN_DOCS = ['README.md', 'docs/authority/PROJECT_STATUS.md'];
  const HUMAN_CHECKS = [
    { re: /2026-08-19/, fact: 'contains status date 2026-08-19' },
    { re: /AIPT-M0-B003-CONSTRUCTION-001/, fact: 'contains snapshot AIPT-M0-B003-CONSTRUCTION-001' },
    { re: /AIPT-M0-B003[^\n]*IN_PROGRESS/, fact: 'binds AIPT-M0-B003 to IN_PROGRESS on one line' },
    { re: /(?:AIPT-M0-B003[^\n]*GLOBAL_WIP = 1|GLOBAL_WIP = 1[^\n]*AIPT-M0-B003)/, fact: 'binds AIPT-M0-B003 and GLOBAL_WIP = 1 on one line' },
    { re: /AIPT-M0-B004[^\n]*NOT_AUTHORIZED[^\n]*next_batch_authorized = false[^\n]*next_batch_started = false/, fact: 'binds AIPT-M0-B004 to NOT_AUTHORIZED, next_batch_authorized = false, next_batch_started = false in order on one line' },
    { re: /AIPT-M0-B000[^\n]*MERGED\/CLOSED/, fact: 'binds AIPT-M0-B000 to MERGED/CLOSED on one line' },
    { re: /AIPT-M0-B001[^\n]*MERGED\/CLOSED/, fact: 'binds AIPT-M0-B001 to MERGED/CLOSED on one line' },
    { re: /AIPT-M0-B002[^\n]*MERGED\/CLOSED/, fact: 'binds AIPT-M0-B002 to MERGED/CLOSED on one line' },
    { re: /UNREGISTERED-AIPT-P0-B001[^\n]*MERGED\/CLOSED[^\n]*a37b284bf5ec35895f436abe71d22599edb6da53[^\n]*32194224161[^\n]*success/, fact: 'binds UNREGISTERED-AIPT-P0-B001 to MERGED/CLOSED, closeout commit a37b284bf5ec35895f436abe71d22599edb6da53, CI run 32194224161, success in order on one line' },
    { re: /45a96087d75a61f2910cb5ce99134e3ca777bca8[^\n]*8b16b599c261879406f0435e80c878e092683a50/, fact: 'binds accepted source commit 45a96087d75a61f2910cb5ce99134e3ca777bca8 to tree 8b16b599c261879406f0435e80c878e092683a50 in order on one line' },
    { re: /FROZEN_WAITING_M1_ENGINE[^\n]*unfreeze_authorized = false/, fact: 'binds FROZEN_WAITING_M1_ENGINE to unfreeze_authorized = false in order on one line' },
  ];
  // Forbidden contradiction predicates: the closed history may never claim
  // B003, and the next serial batch may never be presented as in progress or
  // closed. Each fact string positively describes the unwanted relation.
  const HUMAN_FORBIDDEN_CHECKS = [
    { re: /(?:AIPT-M0-B003[^\n]{0,40}MERGED\/CLOSED|MERGED\/CLOSED[^\n]{0,40}AIPT-M0-B003)/, fact: 'binds AIPT-M0-B003 to MERGED/CLOSED within 40 characters on one line' },
    { re: /(?:AIPT-M0-B004[^\n]{0,80}(?:IN_PROGRESS|MERGED\/CLOSED)|(?:IN_PROGRESS|MERGED\/CLOSED)[^\n]{0,80}AIPT-M0-B004)/, fact: 'binds AIPT-M0-B004 to IN_PROGRESS or MERGED/CLOSED within 80 characters on one line' },
  ];
  const verifyHumanLine = (rel, text, check, forbidden) => {
    const matched = text.split('\n').some((line) => check.re.test(line));
    if (forbidden) {
      if (matched) {
        fail(`${rel}: forbidden ${check.fact}`);
      } else {
        ok(`${rel}: no ${check.fact}`);
      }
    } else if (matched) {
      ok(`${rel}: ${check.fact}`);
    } else {
      fail(`${rel}: missing ${check.fact} (no line matches /${check.re.source}/)`);
    }
  };
  for (const rel of HUMAN_DOCS) {
    const text = read(rel);
    for (const check of HUMAN_CHECKS) verifyHumanLine(rel, text, check);
    for (const check of HUMAN_FORBIDDEN_CHECKS) verifyHumanLine(rel, text, check, true);
  }

  return { name: 'status-transition', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'status-transition', run);
