// B003 public closeout/status-transition validator (compact core).
//
// Proves the immutable B000 / B001 / B002 / B002-closeout identities and the
// fixed historical closeout diff independently of current HEAD, verifies that
// fixed B003 Candidate / implementation merge / tree identities, verifies
// that current HEAD descends from the accepted B003 implementation merge,
// validates the exact AIPT-M0-B003-CLOSEOUT-001 machine status, and proves
// the frozen authority registries are byte-identical to the B003 base.
//
// The machine-status section also runs fourteen in-memory mutation probes
// against a structuredClone of the parsed status: each mutates exactly one
// field (or removes one key) and must be rejected by the critical gate. The
// probes give all-seven-field coverage for standalone/B004, exact-key-set
// plus representative closeout_ci_run value coverage for the external
// predecessor, both-field coverage for the frozen platform, and
// all-three-field coverage for the verified implementation/state; every critical
// binding group therefore has in-memory negative coverage. The live status
// object is never mutated and no file is written. runtime.status stays
// deliberately unconstrained. The human-document section covers the minimal
// closed B003 / next B004 relationship plus positive same-line
// closed-history (B000/B001/B002/B003 = MERGED/CLOSED), external-predecessor,
// accepted implementation (merge -> tree), and frozen-platform
// (FROZEN_WAITING_M1_ENGINE -> unfreeze_authorized = false) bindings, and
// two focused forbidden-contradiction predicates (B003 must not be bound to
// IN_PROGRESS; B004 must not be bound to IN_PROGRESS or MERGED/CLOSED,
// both within a bounded same-line gap); those human checks remain
// non-mutating and runtime.status stays unconstrained.
import fs from 'node:fs';
import path from 'node:path';
import {
  ACTIVE_BATCH,
  B000,
  B001,
  B002,
  B002_CLOSEOUT,
  B003,
  BASE_COMMIT,
  BASE_TREE,
  CURRENT_BATCH,
  EXTERNAL_SERIAL_PREDECESSOR,
  FROZEN_REGISTRY_PATHS,
  STATUS_DATE,
} from '../lib/constants.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

const SCHEMA_V1 = 'aipt.public.project-status/v1';
const SNAPSHOT_ID = 'AIPT-M0-B003-CLOSEOUT-001';
const DESIGN_FROZEN = 'FROZEN_R0_R16_DCA_BOOTSTRAP';
const CONSTRUCTION_STATE = 'IDLE_WAITING_NEXT_BATCH';
const NEXT_SERIAL_BATCH = 'AIPT-M0-B004';
const NEXT_BATCH_STATE = 'AUTHORIZED_TO_PREPARE';
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

const CLOSED_BATCH_IDS = ['AIPT-M0-B000', 'AIPT-M0-B001', 'AIPT-M0-B002', 'AIPT-M0-B003'];

// Exact verified_state bound in the closeout registry. verified_head is the
// implementation merge, never the later closeout commit itself.
const EXPECTED_VERIFIED_STATE =
  'AIPT-M0-B003 MERGED_CLOSED: Candidate fbe1363acd977759c4effa2687483c0b78b63ab6 ' +
  '(tree 60bcdd0df2c29391c2564bfeae17013c07723cd3, CI run 32334341279 success); ' +
  'implementation merge 725fc005185412d115307b594aa64e84acfabf67 ' +
  '(tree 60bcdd0df2c29391c2564bfeae17013c07723cd3); post-merge CI run 32336615560 success; ' +
  'Go 1.26.6 security requalification AIPT-M0-B003-SECURITY-TOOLCHAIN-QUAL-001 PASS; ' +
  'B000/B001/B002/B003 remain MERGED_CLOSED; construction IDLE_WAITING_NEXT_BATCH with ' +
  'current_batch NO_ACTIVE_BATCH and global WIP 0; next serial batch AIPT-M0-B004 is ' +
  'AUTHORIZED_TO_PREPARE and not started';

function sameStrings(actual, expected) {
  return JSON.stringify([...actual].sort()) === JSON.stringify([...expected].sort());
}

// Pure, deterministic critical-machine gate over the parsed live status. Reads
// candidateStatus.tracks['AIPT-STANDALONE'], candidateStatus.tracks
// ['AIPT-PLATFORM-INTEGRATION'], and candidateStatus.repositories.AIPT, and
// reports a descriptive problem per strict mismatch of exactly the seven
// standalone current/WIP/next-B004 fields, the external serial predecessor
// binding (its exact five-key set and the five immutable values against
// EXTERNAL_SERIAL_PREDECESSOR), the frozen platform
// (FROZEN_WAITING_M1_ENGINE with unfreeze_authorized = false), and the
// verified implementation/state (repositories.AIPT verified_head/tree/state
// against B003.merge_commit, B003.tree, and EXPECTED_VERIFIED_STATE).
// Side-effect-free:
// never touches ctx, git, or fs.
export function criticalMachineProblems(candidateStatus) {
  const problems = [];
  const standalone = candidateStatus?.tracks?.['AIPT-STANDALONE'];
  if (standalone?.construction !== CONSTRUCTION_STATE) {
    problems.push(`construction must be ${CONSTRUCTION_STATE}: ${JSON.stringify(standalone?.construction)}`);
  }
  if (standalone?.current_batch !== ACTIVE_BATCH) {
    problems.push(`current_batch must be ${ACTIVE_BATCH}: ${JSON.stringify(standalone?.current_batch)}`);
  }
  if (standalone?.global_wip !== 0) {
    problems.push(`global_wip must be 0: ${JSON.stringify(standalone?.global_wip)}`);
  }
  if (standalone?.next_serial_batch !== NEXT_SERIAL_BATCH) {
    problems.push(`next_serial_batch must be ${NEXT_SERIAL_BATCH}: ${JSON.stringify(standalone?.next_serial_batch)}`);
  }
  if (standalone?.next_batch_state !== NEXT_BATCH_STATE) {
    problems.push(`next_batch_state must be ${NEXT_BATCH_STATE}: ${JSON.stringify(standalone?.next_batch_state)}`);
  }
  if (standalone?.next_batch_authorized !== true) {
    problems.push(`next_batch_authorized must be true: ${JSON.stringify(standalone?.next_batch_authorized)}`);
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
  const platform = candidateStatus?.tracks?.['AIPT-PLATFORM-INTEGRATION'];
  if (platform?.status !== PLATFORM_STATUS) {
    problems.push(`platform status must be ${PLATFORM_STATUS}: ${JSON.stringify(platform?.status)}`);
  }
  if (platform?.unfreeze_authorized !== false) {
    problems.push(`platform unfreeze_authorized must be false: ${JSON.stringify(platform?.unfreeze_authorized)}`);
  }
  const aipt = candidateStatus?.repositories?.AIPT;
  if (aipt?.verified_head !== B003.merge_commit) {
    problems.push(`repositories.AIPT.verified_head must be B003 implementation merge ${B003.merge_commit}: ${JSON.stringify(aipt?.verified_head)}`);
  }
  if (aipt?.verified_tree !== B003.tree) {
    problems.push(`repositories.AIPT.verified_tree must be B003 implementation tree ${B003.tree}: ${JSON.stringify(aipt?.verified_tree)}`);
  }
  if (aipt?.verified_state !== EXPECTED_VERIFIED_STATE) {
    problems.push(`repositories.AIPT.verified_state must exactly describe the B003 closeout snapshot: ${JSON.stringify(aipt?.verified_state)}`);
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
  verifyAnchor('ACTIVE_BATCH', ACTIVE_BATCH, 'NO_ACTIVE_BATCH');
  verifyAnchor('STATUS_DATE', STATUS_DATE, '2026-08-20');
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
  verifyAnchor('B003.candidate', B003.candidate, 'fbe1363acd977759c4effa2687483c0b78b63ab6');
  verifyAnchor('B003.tree', B003.tree, '60bcdd0df2c29391c2564bfeae17013c07723cd3');
  verifyAnchor('B003.candidate_ci_run', B003.candidate_ci_run, 32334341279);
  verifyAnchor('B003.candidate_ci_conclusion', B003.candidate_ci_conclusion, 'success');
  verifyAnchor('B003.merge_commit', B003.merge_commit, '725fc005185412d115307b594aa64e84acfabf67');
  verifyAnchor('B003.post_merge_ci_run', B003.post_merge_ci_run, 32336615560);
  verifyAnchor('B003.post_merge_ci_conclusion', B003.post_merge_ci_conclusion, 'success');
  verifyAnchor(
    'B003.security_toolchain_requalification',
    B003.security_toolchain_requalification,
    'AIPT-M0-B003-SECURITY-TOOLCHAIN-QUAL-001',
  );
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

  resolveCommit('B003 candidate', B003.candidate);
  resolveCommit('B003 implementation merge', B003.merge_commit);
  verifyTree('B003 candidate', B003.candidate, B003.tree);
  verifyTree('B003 implementation merge', B003.merge_commit, B003.tree);
  verifyParents('B003 implementation merge', B003.merge_commit, [B002_CLOSEOUT.commit, B003.candidate]);

  // ---- historical closeout scope (fixed two-commit diff, never ..HEAD) ----
  const closeoutDiff = git(ctx.repo, ['diff', '--name-only', B002.merge_commit, B002_CLOSEOUT.commit]).stdout
    .split('\n')
    .filter(Boolean);
  if (!sameStrings(closeoutDiff, CLOSEOUT_PATHS)) {
    fail(`B002 closeout changed-path set must be exactly ${JSON.stringify(CLOSEOUT_PATHS)}, got ${JSON.stringify(closeoutDiff)}`);
  } else ok('B002 closeout changed-path set is exactly the four authorized paths');

  // ---- current HEAD descends from the accepted B003 implementation merge ----
  const headProbe = git(ctx.repo, ['rev-parse', 'HEAD^{commit}'], { check: false });
  const ancestryProbe = git(ctx.repo, ['merge-base', '--is-ancestor', B003.merge_commit, 'HEAD'], { check: false });
  if (headProbe.status !== 0 || ancestryProbe.status !== 0) {
    fail(`current HEAD ${JSON.stringify(headProbe.stdout.trim())} does not descend from B003 implementation merge ${B003.merge_commit}`);
  } else ok(`current HEAD descends from B003 implementation merge ${B003.merge_commit}`);

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

  // ---- machine-status mutation probes (in-memory only) ----
  // Each probe clones the parsed live status, mutates exactly one field (or
  // removes one key) on the clone, and requires the critical gate to report a
  // problem containing that field's specific fragment. The live status
  // object is never changed and nothing is written to disk.
  const proveCriticalMutation = (label, expectedProblemFragment, mutate) => {
    const clone = structuredClone(status);
    mutate(clone);
    const problems = criticalMachineProblems(clone);
    if (!problems.some((p) => p.includes(expectedProblemFragment))) {
      fail(`mutation probe ${label}: expected a problem containing ${JSON.stringify(expectedProblemFragment)}, got ${JSON.stringify(problems)}`);
    } else {
      ok(`mutation probe ${label}: rejected with ${JSON.stringify(expectedProblemFragment)}`);
    }
  };

  proveCriticalMutation('construction', 'construction must be IDLE_WAITING_NEXT_BATCH', (s) => { s.tracks['AIPT-STANDALONE'].construction = 'IN_PROGRESS'; });
  proveCriticalMutation('current_batch', 'current_batch must be NO_ACTIVE_BATCH', (s) => { s.tracks['AIPT-STANDALONE'].current_batch = 'AIPT-M0-B003'; });
  proveCriticalMutation('global_wip', 'global_wip must be 0', (s) => { s.tracks['AIPT-STANDALONE'].global_wip = 1; });
  proveCriticalMutation('next_serial_batch', 'next_serial_batch must be AIPT-M0-B004', (s) => { s.tracks['AIPT-STANDALONE'].next_serial_batch = 'AIPT-M0-B099'; });
  proveCriticalMutation('next_batch_state', 'next_batch_state must be AUTHORIZED_TO_PREPARE', (s) => { s.tracks['AIPT-STANDALONE'].next_batch_state = 'IN_PROGRESS'; });
  proveCriticalMutation('next_batch_authorized', 'next_batch_authorized must be true', (s) => { s.tracks['AIPT-STANDALONE'].next_batch_authorized = false; });
  proveCriticalMutation('next_batch_started', 'next_batch_started must be false', (s) => { s.tracks['AIPT-STANDALONE'].next_batch_started = true; });
  proveCriticalMutation('predecessor closeout_commit key deletion', 'external_serial_predecessor keys must be exactly', (s) => { delete s.tracks['AIPT-STANDALONE'].external_serial_predecessor.closeout_commit; });
  proveCriticalMutation('predecessor closeout_ci_run value drift', 'external_serial_predecessor values drifted', (s) => { s.tracks['AIPT-STANDALONE'].external_serial_predecessor.closeout_ci_run = 0; });
  proveCriticalMutation('platform status drift', 'platform status must be FROZEN_WAITING_M1_ENGINE', (s) => { s.tracks['AIPT-PLATFORM-INTEGRATION'].status = 'UNFROZEN'; });
  proveCriticalMutation('platform unfreeze_authorized = true', 'platform unfreeze_authorized must be false', (s) => { s.tracks['AIPT-PLATFORM-INTEGRATION'].unfreeze_authorized = true; });
  proveCriticalMutation('repositories.AIPT verified_head drift', 'repositories.AIPT.verified_head must be B003 implementation merge', (s) => { s.repositories.AIPT.verified_head = '0'.repeat(40); });
  proveCriticalMutation('verified_tree drift', 'repositories.AIPT.verified_tree must be B003 implementation tree', (s) => { s.repositories.AIPT.verified_tree = '0'.repeat(40); });
  proveCriticalMutation('verified_state drift', 'repositories.AIPT.verified_state must exactly describe', (s) => { s.repositories.AIPT.verified_state = 'drifted'; });

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
  if (standalone?.current_batch !== ACTIVE_BATCH) {
    fail(`current_batch must be ${ACTIVE_BATCH}: ${JSON.stringify(standalone?.current_batch)}`);
  } else ok(`current batch = ${ACTIVE_BATCH}`);

  if (!sameStrings(Object.keys(history), CLOSED_BATCH_IDS)) {
    fail(`batch_history keys must be exactly the four closed M0 batches: ${JSON.stringify(history)}`);
  } else {
    let allClosed = true;
    for (const id of CLOSED_BATCH_IDS) {
      if (history[id] !== MERGED_CLOSED) {
        fail(`${id} must be ${MERGED_CLOSED}: ${JSON.stringify(history[id])}`);
        allClosed = false;
      }
    }
    if (allClosed) ok('batch_history is exactly B000/B001/B002/B003 = MERGED_CLOSED');
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
  if (standalone?.global_wip !== 0) {
    fail(`global_wip must be 0: ${JSON.stringify(standalone?.global_wip)}`);
  } else ok('GLOBAL_WIP = 0');

  if (standalone?.next_serial_batch !== NEXT_SERIAL_BATCH) {
    fail(`next_serial_batch must be ${NEXT_SERIAL_BATCH}: ${JSON.stringify(standalone?.next_serial_batch)}`);
  } else ok(`next serial batch = ${NEXT_SERIAL_BATCH}`);
  if (standalone?.next_batch_state !== NEXT_BATCH_STATE) {
    fail(`next_batch_state must be ${NEXT_BATCH_STATE}: ${JSON.stringify(standalone?.next_batch_state)}`);
  } else ok(`next batch state = ${NEXT_BATCH_STATE}`);
  if (standalone?.next_batch_authorized !== true) {
    fail(`next_batch_authorized must be true: ${JSON.stringify(standalone?.next_batch_authorized)}`);
  } else ok('next batch is authorized to prepare');
  if (standalone?.next_batch_started !== false) {
    fail(`next_batch_started must be false: ${JSON.stringify(standalone?.next_batch_started)}`);
  } else ok('next batch is not started');

  if (platform?.status !== PLATFORM_STATUS || platform?.unfreeze_authorized !== false) {
    fail(`platform integration freeze drifted: ${JSON.stringify(platform)}`);
  } else ok('AIPT-PLATFORM-INTEGRATION remains FROZEN_WAITING_M1_ENGINE and unauthorized to unfreeze');
  if (aipt?.verified_head !== B003.merge_commit) {
    fail(`repositories.AIPT.verified_head must be B003 implementation merge ${B003.merge_commit}: ${JSON.stringify(aipt?.verified_head)}`);
  } else ok(`verified_head = B003 implementation merge ${B003.merge_commit}`);
  if (aipt?.verified_tree !== B003.tree) {
    fail(`repositories.AIPT.verified_tree must be B003 implementation tree ${B003.tree}: ${JSON.stringify(aipt?.verified_tree)}`);
  } else ok(`verified_tree = B003 implementation tree ${B003.tree}`);
  if (aipt?.verified_state !== EXPECTED_VERIFIED_STATE) {
    fail(`repositories.AIPT.verified_state must exactly describe the B003 closeout snapshot: ${JSON.stringify(aipt?.verified_state)}`);
  } else ok('verified_state exactly binds the B003 Candidate, implementation merge, post-merge CI, security requalification, and closeout state');

  // ---- frozen registries: working-tree bytes == BASE_COMMIT blobs ----
  for (const rel of FROZEN_REGISTRY_PATHS) {
    const workingBlob = git(ctx.repo, ['hash-object', rel]).stdout.trim();
    const baseBlob = git(ctx.repo, ['rev-parse', `${BASE_COMMIT}:${rel}`]).stdout.trim();
    if (workingBlob !== baseBlob) {
      fail(`frozen registry ${rel} working-tree bytes differ from base blob: ${workingBlob} != ${baseBlob}`);
    } else ok(`frozen registry ${rel} byte-identical to base`);
  }

  // ---- human-current-state (README.md / PROJECT_STATUS.md) ----
  // Same-line consistency checks for the B003 closeout snapshot (date,
  // snapshot id, MERGED/CLOSED, NO_ACTIVE_BATCH, GLOBAL_WIP = 0), the accepted
  // Candidate and implementation identities, the frozen platform
  // (FROZEN_WAITING_M1_ENGINE -> unfreeze_authorized = false), the next B004
  // relationship (AUTHORIZED_TO_PREPARE, authorized, not started), the
  // immutable closed history (AIPT-M0-B000 / B001 / B002 / B003 each =
  // MERGED/CLOSED on one line), and the external serial
  // predecessor (UNREGISTERED-AIPT-P0-B001 = MERGED/CLOSED with its closeout
  // commit / CI run / success conclusion, in order on one line). Every
  // relationship must be bound on a single document line — no whole-document
  // token bags. Two focused forbidden-contradiction checks are also applied
  // here: AIPT-M0-B003 must not be bound to IN_PROGRESS, and AIPT-M0-B004
  // must not be bound to
  // IN_PROGRESS or MERGED/CLOSED (either order, 0..80 same-line character
  // gap). All machine-status mutation probes are covered in-memory above;
  // runtime.status remains unconstrained.
  const HUMAN_DOCS = ['README.md', 'docs/authority/PROJECT_STATUS.md'];
  const HUMAN_CHECKS = [
    { re: /2026-08-20/, fact: 'contains status date 2026-08-20' },
    { re: /AIPT-M0-B003-CLOSEOUT-001/, fact: 'contains snapshot AIPT-M0-B003-CLOSEOUT-001' },
    { re: /AIPT-M0-B003[^\n]*MERGED\/CLOSED/, fact: 'binds AIPT-M0-B003 to MERGED/CLOSED on one line' },
    { re: /(?:NO_ACTIVE_BATCH[^\n]*GLOBAL_WIP = 0|GLOBAL_WIP = 0[^\n]*NO_ACTIVE_BATCH)/, fact: 'binds NO_ACTIVE_BATCH and GLOBAL_WIP = 0 on one line' },
    { re: /AIPT-M0-B004[^\n]*AUTHORIZED_TO_PREPARE[^\n]*next_batch_authorized = true[^\n]*next_batch_started = false/, fact: 'binds AIPT-M0-B004 to AUTHORIZED_TO_PREPARE, next_batch_authorized = true, next_batch_started = false in order on one line' },
    { re: /AIPT-M0-B000[^\n]*MERGED\/CLOSED/, fact: 'binds AIPT-M0-B000 to MERGED/CLOSED on one line' },
    { re: /AIPT-M0-B001[^\n]*MERGED\/CLOSED/, fact: 'binds AIPT-M0-B001 to MERGED/CLOSED on one line' },
    { re: /AIPT-M0-B002[^\n]*MERGED\/CLOSED/, fact: 'binds AIPT-M0-B002 to MERGED/CLOSED on one line' },
    { re: /AIPT-M0-B003[^\n]*MERGED\/CLOSED/, fact: 'binds AIPT-M0-B003 to MERGED/CLOSED on one line' },
    { re: /UNREGISTERED-AIPT-P0-B001[^\n]*MERGED\/CLOSED[^\n]*a37b284bf5ec35895f436abe71d22599edb6da53[^\n]*32194224161[^\n]*success/, fact: 'binds UNREGISTERED-AIPT-P0-B001 to MERGED/CLOSED, closeout commit a37b284bf5ec35895f436abe71d22599edb6da53, CI run 32194224161, success in order on one line' },
    { re: /fbe1363acd977759c4effa2687483c0b78b63ab6[^\n]*60bcdd0df2c29391c2564bfeae17013c07723cd3[^\n]*32334341279[^\n]*success/, fact: 'binds B003 Candidate to its tree and successful Candidate CI on one line' },
    { re: /725fc005185412d115307b594aa64e84acfabf67[^\n]*60bcdd0df2c29391c2564bfeae17013c07723cd3[^\n]*32336615560[^\n]*success/, fact: 'binds B003 implementation merge to its tree and successful post-merge CI on one line' },
    { re: /Go[^0-9\n]{0,24}1\.26\.6[^\n]*AIPT-M0-B003-SECURITY-TOOLCHAIN-QUAL-001[^\n]*PASS/, fact: 'binds Go 1.26.6 to the B003 security requalification PASS on one line' },
    { re: /FROZEN_WAITING_M1_ENGINE[^\n]*unfreeze_authorized = false/, fact: 'binds FROZEN_WAITING_M1_ENGINE to unfreeze_authorized = false in order on one line' },
  ];
  // Forbidden contradiction predicates: closed B003 may never be presented
  // as in progress, and the next serial batch may never be presented as in progress or
  // closed. Each fact string positively describes the unwanted relation.
  const HUMAN_FORBIDDEN_CHECKS = [
    { re: /(?:AIPT-M0-B003[^\n]{0,80}IN_PROGRESS|IN_PROGRESS[^\n]{0,80}AIPT-M0-B003)/, fact: 'binds AIPT-M0-B003 to IN_PROGRESS within 80 characters on one line' },
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
