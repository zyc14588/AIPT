#!/usr/bin/env node
// AIPT-M0-B004 closeout/status-transition validator.
//
// This gate anchors every accepted predecessor identity independently, checks
// the exact closed-B004 / prepare-only-B005 / frozen-platform machine state,
// preserves the immutable failed post-merge CI beside the successful repair,
// exercises deterministic mutations for every critical binding, and keeps
// the non-status authority registries byte-identical to the accepted B004 base.
import fs from 'node:fs';
import path from 'node:path';
import {
  ACTIVE_BATCH,
  B000,
  B001,
  B002,
  B002_CLOSEOUT,
  B003,
  B003_CLOSEOUT,
  B004_CANDIDATE,
  B004_BASE_COMMIT,
  B004_BASE_TREE,
  B004_DEPENDENCY_SECURITY_REQUALIFICATION,
  B004_IMPLEMENTATION_MERGE,
  B004_POST_MERGE_REPAIR,
  BASE_COMMIT,
  BASE_TREE,
  CURRENT_BATCH,
  EXTERNAL_SERIAL_PREDECESSOR,
  FROZEN_REGISTRY_PATHS,
  STATUS_DATE,
  STATUS_TRANSITION_PATHS,
} from '../lib/constants.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

const SCHEMA = 'aipt.public.project-status/v1';
const SNAPSHOT_ID = 'AIPT-M0-B004-CLOSEOUT-001';
const DESIGN = 'FROZEN_R0_R16_DCA_BOOTSTRAP';
const CONSTRUCTION = 'IDLE_WAITING_NEXT_BATCH';
const NEXT_BATCH = 'AIPT-M0-B005';
const NEXT_STATE = 'AUTHORIZED_TO_PREPARE';
const PLATFORM = 'FROZEN_WAITING_M1_ENGINE';
const MERGED_CLOSED = 'MERGED_CLOSED';

const STANDALONE_KEYS = [
  'batch_history',
  'construction',
  'current_batch',
  'design',
  'external_serial_predecessor',
  'global_wip',
  'next_batch_authorized',
  'next_batch_started',
  'next_batch_state',
  'next_serial_batch',
];
const CLOSED_BATCH_IDS = [
  'AIPT-M0-B000',
  'AIPT-M0-B001',
  'AIPT-M0-B002',
  'AIPT-M0-B003',
  'AIPT-M0-B004',
];
const PREDECESSOR_KEYS = [
  'closeout_ci_conclusion',
  'closeout_ci_run',
  'closeout_commit',
  'id',
  'status',
];
const EXPECTED_VERIFIED_STATE =
  'AIPT-M0-B004 MERGED_CLOSED: Candidate ' +
  '4810d2cfec6146db7c161506ba7f37ab0a4ce69c ' +
  '(tree f35365d0ad47fdd513fbecb84a03b1559026637e, CI run 32392886647 success); ' +
  'implementation merge d07c0c3817620ada47b3ae7344d8ee423ace3b12 ' +
  '(tree f35365d0ad47fdd513fbecb84a03b1559026637e); initial post-merge CI run ' +
  '32557930038 failure, immutable cause AIPT-B004-TREE-INTEGRITY-LIFECYCLE-001; ' +
  'post-merge repair directive AIPT-M0-B004-POSTMERGE-TREE-INTEGRITY-REPAIR-001, ' +
  'commit bd0c06867da58f89e82a35d82ce1d798c1ec9cae, CI run 32558813381 success; ' +
  'accepted post-merge gate PASS; dependency security requalification ' +
  'AIPT-M0-B004-DEPENDENCY-SECURITY-REQUAL-001 PASS, GO-2026-5970 ' +
  'RESOLVED_BY_X_TEXT_V0_39_0; B000/B001/B002/B003/B004 remain MERGED_CLOSED; ' +
  'construction IDLE_WAITING_NEXT_BATCH with current_batch NO_ACTIVE_BATCH and global WIP 0; ' +
  'next serial batch AIPT-M0-B005 is AUTHORIZED_TO_PREPARE and not started';

function sameKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  return JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

// Pure critical-state predicate shared by the live check and mutation probes.
export function criticalMachineProblems(candidate) {
  const problems = [];
  if (candidate?.schema !== SCHEMA) problems.push('schema must be ' + SCHEMA);
  if (candidate?.as_of !== STATUS_DATE) problems.push('as_of must be ' + STATUS_DATE);
  if (candidate?.authority_snapshot_id !== SNAPSHOT_ID) {
    problems.push('authority_snapshot_id must be ' + SNAPSHOT_ID);
  }

  const standalone = candidate?.tracks?.['AIPT-STANDALONE'];
  if (!sameKeys(standalone, STANDALONE_KEYS)) {
    problems.push('AIPT-STANDALONE keys must be exact');
  }
  if (standalone?.design !== DESIGN) problems.push('design must be ' + DESIGN);
  if (standalone?.construction !== CONSTRUCTION) {
    problems.push('construction must be ' + CONSTRUCTION);
  }
  if (standalone?.current_batch !== ACTIVE_BATCH) {
    problems.push('current_batch must be ' + ACTIVE_BATCH);
  }
  if (standalone?.global_wip !== 0) problems.push('global_wip must be 0');
  if (standalone?.next_serial_batch !== NEXT_BATCH) {
    problems.push('next_serial_batch must be ' + NEXT_BATCH);
  }
  if (standalone?.next_batch_state !== NEXT_STATE) {
    problems.push('next_batch_state must be ' + NEXT_STATE);
  }
  if (standalone?.next_batch_authorized !== true) {
    problems.push('next_batch_authorized must be true');
  }
  if (standalone?.next_batch_started !== false) {
    problems.push('next_batch_started must be false');
  }

  const history = standalone?.batch_history;
  if (!sameKeys(history, CLOSED_BATCH_IDS)) problems.push('batch_history keys must be exact');
  for (const id of CLOSED_BATCH_IDS) {
    if (history?.[id] !== MERGED_CLOSED) problems.push(id + ' must remain ' + MERGED_CLOSED);
  }

  const predecessor = standalone?.external_serial_predecessor;
  if (!sameKeys(predecessor, PREDECESSOR_KEYS)) {
    problems.push('external_serial_predecessor keys must be exact');
  }
  const expectedPredecessor = {
    id: EXTERNAL_SERIAL_PREDECESSOR.batch,
    status: EXTERNAL_SERIAL_PREDECESSOR.status,
    closeout_commit: EXTERNAL_SERIAL_PREDECESSOR.closeout_commit,
    closeout_ci_run: EXTERNAL_SERIAL_PREDECESSOR.closeout_ci_run,
    closeout_ci_conclusion: EXTERNAL_SERIAL_PREDECESSOR.closeout_ci_conclusion,
  };
  for (const [key, expected] of Object.entries(expectedPredecessor)) {
    if (predecessor?.[key] !== expected) {
      problems.push('external_serial_predecessor.' + key + ' drifted');
    }
  }

  const platform = candidate?.tracks?.['AIPT-PLATFORM-INTEGRATION'];
  if (platform?.status !== PLATFORM) problems.push('platform status must be ' + PLATFORM);
  if (platform?.unfreeze_authorized !== false) {
    problems.push('platform unfreeze_authorized must be false');
  }

  const aipt = candidate?.repositories?.AIPT;
  if (aipt?.verified_head !== B004_IMPLEMENTATION_MERGE.commit) {
    problems.push('repositories.AIPT.verified_head must equal the B004 implementation merge');
  }
  if (aipt?.verified_tree !== B004_IMPLEMENTATION_MERGE.tree) {
    problems.push('repositories.AIPT.verified_tree must equal the B004 implementation tree');
  }
  if (aipt?.verified_state !== EXPECTED_VERIFIED_STATE) {
    problems.push('repositories.AIPT.verified_state drifted');
  }
  return problems;
}

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push('ok: ' + message);
  const fail = (message) => {
    pass = false;
    details.push('FAIL: ' + message);
  };
  const read = (relative) => fs.readFileSync(path.join(ctx.repo, relative), 'utf8');
  const anchor = (label, actual, expected) => {
    if (actual !== expected) {
      fail(label + ' drifted: ' + JSON.stringify(actual) + ' != ' + JSON.stringify(expected));
    } else {
      ok(label + ' anchored to ' + JSON.stringify(expected));
    }
  };

  const anchors = [
    ['CURRENT_BATCH', CURRENT_BATCH, 'AIPT-M0-B004'],
    ['ACTIVE_BATCH', ACTIVE_BATCH, 'NO_ACTIVE_BATCH'],
    ['STATUS_DATE', STATUS_DATE, '2026-08-22'],
    ['B004_BASE_COMMIT', B004_BASE_COMMIT, '6d7225828b45b69ecc44d5bb51a04c40f0865aba'],
    ['B004_BASE_TREE', B004_BASE_TREE, 'f557a9f54cbac11474f2d56f78e2d983a7d6a7be'],
    ['BASE_COMMIT', BASE_COMMIT, '6d7225828b45b69ecc44d5bb51a04c40f0865aba'],
    ['BASE_TREE', BASE_TREE, 'f557a9f54cbac11474f2d56f78e2d983a7d6a7be'],
    ['B000.commit', B000.commit, '777a3f39ba78c1ef3168597890c61abf7a55d962'],
    ['B000.tree', B000.tree, 'f5f845b860ba0944ef104b4679fa074ad6efecbb'],
    ['B001.candidate', B001.candidate, '2e904ddc2d4f1313a99e19f6751a991d589f8336'],
    ['B001.merge_commit', B001.merge_commit, '8bcadc9669e7d04f589f883daa6d4f593875fc9e'],
    ['B001.tree', B001.tree, 'fefc25f1acb523d013c2a7d8db9801ccdab37d2d'],
    ['B002.candidate', B002.candidate, '9968cbc89c09640e3fc2feb8d851220eae98b9b9'],
    ['B002.merge_commit', B002.merge_commit, 'fccfb595c23feab38397506505a3e996fe7b9e9c'],
    ['B002.tree', B002.tree, 'f99570bc3c4307244ca926cec62e82a07ef5aee8'],
    ['B002_CLOSEOUT.commit', B002_CLOSEOUT.commit, '45a96087d75a61f2910cb5ce99134e3ca777bca8'],
    ['B002_CLOSEOUT.tree', B002_CLOSEOUT.tree, '8b16b599c261879406f0435e80c878e092683a50'],
    ['B003.candidate', B003.candidate, 'fbe1363acd977759c4effa2687483c0b78b63ab6'],
    ['B003.merge_commit', B003.merge_commit, '725fc005185412d115307b594aa64e84acfabf67'],
    ['B003.tree', B003.tree, '60bcdd0df2c29391c2564bfeae17013c07723cd3'],
    ['B003.candidate_ci_run', B003.candidate_ci_run, 32334341279],
    ['B003.post_merge_ci_run', B003.post_merge_ci_run, 32336615560],
    ['B003 security requalification', B003.security_toolchain_requalification, 'AIPT-M0-B003-SECURITY-TOOLCHAIN-QUAL-001'],
    ['B003_CLOSEOUT.commit', B003_CLOSEOUT.commit, '6d7225828b45b69ecc44d5bb51a04c40f0865aba'],
    ['B003_CLOSEOUT.tree', B003_CLOSEOUT.tree, 'f557a9f54cbac11474f2d56f78e2d983a7d6a7be'],
    ['B003_CLOSEOUT.parent', B003_CLOSEOUT.parent, '725fc005185412d115307b594aa64e84acfabf67'],
    ['B004_CANDIDATE.commit', B004_CANDIDATE.commit, '4810d2cfec6146db7c161506ba7f37ab0a4ce69c'],
    ['B004_CANDIDATE.tree', B004_CANDIDATE.tree, 'f35365d0ad47fdd513fbecb84a03b1559026637e'],
    ['B004_CANDIDATE.ci_run', B004_CANDIDATE.ci_run, 32392886647],
    ['B004_IMPLEMENTATION_MERGE.directive', B004_IMPLEMENTATION_MERGE.directive, 'AIPT-M0-B004-MERGE-001'],
    ['B004_IMPLEMENTATION_MERGE.commit', B004_IMPLEMENTATION_MERGE.commit, 'd07c0c3817620ada47b3ae7344d8ee423ace3b12'],
    ['B004_IMPLEMENTATION_MERGE.tree', B004_IMPLEMENTATION_MERGE.tree, 'f35365d0ad47fdd513fbecb84a03b1559026637e'],
    ['B004_IMPLEMENTATION_MERGE.parent1', B004_IMPLEMENTATION_MERGE.parent1, '6d7225828b45b69ecc44d5bb51a04c40f0865aba'],
    ['B004_IMPLEMENTATION_MERGE.parent2', B004_IMPLEMENTATION_MERGE.parent2, '4810d2cfec6146db7c161506ba7f37ab0a4ce69c'],
    ['B004_POST_MERGE_REPAIR.directive', B004_POST_MERGE_REPAIR.directive, 'AIPT-M0-B004-POSTMERGE-TREE-INTEGRITY-REPAIR-001'],
    ['B004_POST_MERGE_REPAIR.initial_ci_run', B004_POST_MERGE_REPAIR.initial_ci_run, 32557930038],
    ['B004_POST_MERGE_REPAIR.initial_ci_conclusion', B004_POST_MERGE_REPAIR.initial_ci_conclusion, 'failure'],
    ['B004_POST_MERGE_REPAIR.failure', B004_POST_MERGE_REPAIR.failure, 'AIPT-B004-TREE-INTEGRITY-LIFECYCLE-001'],
    ['B004_POST_MERGE_REPAIR.commit', B004_POST_MERGE_REPAIR.commit, 'bd0c06867da58f89e82a35d82ce1d798c1ec9cae'],
    ['B004_POST_MERGE_REPAIR.tree', B004_POST_MERGE_REPAIR.tree, '02e53e65ea194236e0b34a96768f9a848ecfd3a7'],
    ['B004_POST_MERGE_REPAIR.parent', B004_POST_MERGE_REPAIR.parent, 'd07c0c3817620ada47b3ae7344d8ee423ace3b12'],
    ['B004_POST_MERGE_REPAIR.ci_run', B004_POST_MERGE_REPAIR.ci_run, 32558813381],
    ['B004_POST_MERGE_REPAIR.ci_conclusion', B004_POST_MERGE_REPAIR.ci_conclusion, 'success'],
    ['B004 dependency security directive', B004_DEPENDENCY_SECURITY_REQUALIFICATION.directive, 'AIPT-M0-B004-DEPENDENCY-SECURITY-REQUAL-001'],
    ['B004 dependency security advisory', B004_DEPENDENCY_SECURITY_REQUALIFICATION.advisory, 'GO-2026-5970'],
    ['B004 dependency x/text', B004_DEPENDENCY_SECURITY_REQUALIFICATION.current_version, 'v0.39.0'],
    ['B004 dependency x/sync', B004_DEPENDENCY_SECURITY_REQUALIFICATION.mvs_induced_changes.find((item) => item.module === 'golang.org/x/sync')?.current_version, 'v0.21.0'],
    ['B004 dependency x/mod', B004_DEPENDENCY_SECURITY_REQUALIFICATION.mvs_induced_changes.find((item) => item.module === 'golang.org/x/mod')?.current_version, 'v0.37.0'],
    ['B004 dependency x/tools', B004_DEPENDENCY_SECURITY_REQUALIFICATION.mvs_induced_changes.find((item) => item.module === 'golang.org/x/tools')?.current_version, 'v0.47.0'],
    ['B004 dependency pgx', B004_DEPENDENCY_SECURITY_REQUALIFICATION.pgx_version, 'v5.10.0'],
  ];
  for (const [label, actual, expected] of anchors) anchor(label, actual, expected);

  const verifyCommitTree = (label, commit, tree) => {
    const commitProbe = git(ctx.repo, ['rev-parse', commit + '^{commit}'], { check: false });
    const treeProbe = git(ctx.repo, ['rev-parse', commit + '^{tree}'], { check: false });
    if (commitProbe.status !== 0 || commitProbe.stdout.trim() !== commit) {
      fail(label + ' commit does not resolve');
    } else if (treeProbe.status !== 0 || treeProbe.stdout.trim() !== tree) {
      fail(label + ' tree drifted');
    } else {
      ok(label + ' commit/tree identity verified');
    }
  };
  verifyCommitTree('B000', B000.commit, B000.tree);
  verifyCommitTree('B001 merge', B001.merge_commit, B001.tree);
  verifyCommitTree('B002 merge', B002.merge_commit, B002.tree);
  verifyCommitTree('B002 closeout', B002_CLOSEOUT.commit, B002_CLOSEOUT.tree);
  verifyCommitTree('B003 Candidate', B003.candidate, B003.tree);
  verifyCommitTree('B003 implementation merge', B003.merge_commit, B003.tree);
  verifyCommitTree('B003 closeout/B004 base', B003_CLOSEOUT.commit, B003_CLOSEOUT.tree);
  verifyCommitTree('B004 Candidate', B004_CANDIDATE.commit, B004_CANDIDATE.tree);
  verifyCommitTree(
    'B004 implementation merge',
    B004_IMPLEMENTATION_MERGE.commit,
    B004_IMPLEMENTATION_MERGE.tree,
  );
  verifyCommitTree(
    'B004 post-merge repair',
    B004_POST_MERGE_REPAIR.commit,
    B004_POST_MERGE_REPAIR.tree,
  );

  const parents = git(
    ctx.repo,
    ['rev-list', '--parents', '-n', '1', B003_CLOSEOUT.commit],
    { check: false },
  ).stdout.trim().split(/\s+/);
  if (
    parents[0] !== B003_CLOSEOUT.commit ||
    JSON.stringify(parents.slice(1)) !== JSON.stringify([B003_CLOSEOUT.parent])
  ) {
    fail('B003 closeout parent drifted: ' + JSON.stringify(parents.slice(1)));
  } else {
    ok('B003 closeout has the immutable implementation-merge parent');
  }

  const verifyParents = (label, commit, expected) => {
    const probe = git(ctx.repo, ['rev-list', '--parents', '-n', '1', commit], { check: false });
    const tokens = probe.status === 0
      ? probe.stdout.trim().split(/\s+/).filter(Boolean)
      : [];
    if (tokens[0] !== commit || JSON.stringify(tokens.slice(1)) !== JSON.stringify(expected)) {
      fail(label + ' parents drifted: ' + JSON.stringify(tokens.slice(1)));
    } else {
      ok(label + ' has the exact ordered parents');
    }
  };
  verifyParents(
    'B004 implementation merge',
    B004_IMPLEMENTATION_MERGE.commit,
    [B004_IMPLEMENTATION_MERGE.parent1, B004_IMPLEMENTATION_MERGE.parent2],
  );
  verifyParents(
    'B004 post-merge repair',
    B004_POST_MERGE_REPAIR.commit,
    [B004_POST_MERGE_REPAIR.parent],
  );

  const ancestry = git(
    ctx.repo,
    ['merge-base', '--is-ancestor', B004_POST_MERGE_REPAIR.commit, 'HEAD'],
    { check: false },
  );
  if (ancestry.status !== 0) fail('HEAD does not descend from the accepted B004 repair');
  else ok('HEAD descends from the accepted B004 repair');

  let status;
  try {
    status = JSON.parse(read('docs/authority/registry/project-status.json'));
    ok('machine status parses as JSON');
  } catch (error) {
    fail('machine status JSON parse failed: ' + error.message);
  }
  if (status) {
    const problems = criticalMachineProblems(status);
    if (problems.length > 0) {
      for (const problem of problems) fail(problem);
    } else {
      ok('machine status exactly matches the B004 closeout contract');
    }

    const probes = [
      ['schema drift', (s) => { s.schema = 'wrong'; }],
      ['date drift', (s) => { s.as_of = '1970-01-01'; }],
      ['snapshot drift', (s) => { s.authority_snapshot_id = 'wrong'; }],
      ['construction drift', (s) => { s.tracks['AIPT-STANDALONE'].construction = 'IN_PROGRESS'; }],
      ['current batch drift', (s) => { s.tracks['AIPT-STANDALONE'].current_batch = 'AIPT-M0-B004'; }],
      ['global WIP drift', (s) => { s.tracks['AIPT-STANDALONE'].global_wip = 1; }],
      ['next batch drift', (s) => { s.tracks['AIPT-STANDALONE'].next_serial_batch = 'AIPT-M0-B004'; }],
      ['B005 state drift', (s) => { s.tracks['AIPT-STANDALONE'].next_batch_state = 'NOT_AUTHORIZED'; }],
      ['B005 authorization drift', (s) => { s.tracks['AIPT-STANDALONE'].next_batch_authorized = false; }],
      ['B005 started drift', (s) => { s.tracks['AIPT-STANDALONE'].next_batch_started = true; }],
      ['B004 reopened', (s) => { s.tracks['AIPT-STANDALONE'].batch_history['AIPT-M0-B004'] = 'IN_PROGRESS'; }],
      ['history key removed', (s) => { delete s.tracks['AIPT-STANDALONE'].batch_history['AIPT-M0-B002']; }],
      ['standalone key removed', (s) => { delete s.tracks['AIPT-STANDALONE'].next_batch_state; }],
      ['standalone extra key', (s) => { s.tracks['AIPT-STANDALONE'].unexpected = true; }],
      ['predecessor commit drift', (s) => { s.tracks['AIPT-STANDALONE'].external_serial_predecessor.closeout_commit = '0'.repeat(40); }],
      ['predecessor CI drift', (s) => { s.tracks['AIPT-STANDALONE'].external_serial_predecessor.closeout_ci_run = 0; }],
      ['predecessor key removed', (s) => { delete s.tracks['AIPT-STANDALONE'].external_serial_predecessor.status; }],
      ['platform status drift', (s) => { s.tracks['AIPT-PLATFORM-INTEGRATION'].status = 'ACTIVE'; }],
      ['platform unfreeze', (s) => { s.tracks['AIPT-PLATFORM-INTEGRATION'].unfreeze_authorized = true; }],
      ['verified head drift', (s) => { s.repositories.AIPT.verified_head = BASE_COMMIT; }],
      ['verified tree drift', (s) => { s.repositories.AIPT.verified_tree = BASE_TREE; }],
      ['verified state drift', (s) => { s.repositories.AIPT.verified_state += ' drift'; }],
    ];
    let missed = 0;
    for (const [label, mutate] of probes) {
      const candidate = structuredClone(status);
      mutate(candidate);
      if (criticalMachineProblems(candidate).length === 0) {
        missed += 1;
        fail('negative probe was accepted: ' + label);
      }
    }
    if (missed === 0) {
      ok('all ' + probes.length + ' critical machine-state mutation probes were rejected');
    }
  }

  const changed = git(
    ctx.repo,
    ['diff', '--name-only', '--no-renames', B004_POST_MERGE_REPAIR.commit],
  )
    .stdout.split('\n').filter(Boolean);
  for (const required of STATUS_TRANSITION_PATHS) {
    if (!changed.includes(required)) {
      fail('required B004 closeout status-transition path is unchanged: ' + required);
    }
  }
  if (STATUS_TRANSITION_PATHS.every((required) => changed.includes(required))) {
    ok('all six B004 status-transition paths are present in the closeout delta');
  }

  for (const relative of FROZEN_REGISTRY_PATHS) {
    const base = git(ctx.repo, ['show', BASE_COMMIT + ':' + relative], { check: false });
    if (base.status !== 0) {
      fail('cannot read frozen base blob ' + relative);
    } else if (read(relative) !== base.stdout) {
      fail('frozen authority registry changed: ' + relative);
    } else {
      ok('frozen authority registry unchanged: ' + relative);
    }
  }

  const humanFiles = ['README.md', 'docs/authority/PROJECT_STATUS.md'];
  const requiredHumanFacts = [
    SNAPSHOT_ID,
    'IDLE_WAITING_NEXT_BATCH',
    'current_batch = NO_ACTIVE_BATCH',
    'GLOBAL_WIP = 0',
    'AIPT-M0-B005',
    'AUTHORIZED_TO_PREPARE',
    'next_batch_authorized = true',
    'next_batch_started = false',
    '4810d2cfec6146db7c161506ba7f37ab0a4ce69c',
    'f35365d0ad47fdd513fbecb84a03b1559026637e',
    '32392886647',
    'd07c0c3817620ada47b3ae7344d8ee423ace3b12',
    '32557930038',
    'AIPT-B004-TREE-INTEGRITY-LIFECYCLE-001',
    'AIPT-M0-B004-POSTMERGE-TREE-INTEGRITY-REPAIR-001',
    'bd0c06867da58f89e82a35d82ce1d798c1ec9cae',
    '32558813381',
    'AIPT-M0-B004-DEPENDENCY-SECURITY-REQUAL-001',
    'GO-2026-5970',
    'RESOLVED_BY_X_TEXT_V0_39_0',
    PLATFORM,
    'unfreeze_authorized = false',
  ];
  const forbiddenHumanFacts = [
    'current_batch = AIPT-M0-B004',
    'GLOBAL_WIP = 1',
    'next_batch_authorized = false',
    'AIPT-M0-B005' + String.fromCharCode(96) + ' = ' + String.fromCharCode(96) + 'IN_PROGRESS',
  ];
  for (const relative of humanFiles) {
    const text = read(relative);
    for (const fact of requiredHumanFacts) {
      if (!text.includes(fact)) {
        fail(relative + ' is missing required fact ' + JSON.stringify(fact));
      }
    }
    for (const contradiction of forbiddenHumanFacts) {
      if (text.includes(contradiction)) {
        fail(relative + ' contains stale contradiction ' + JSON.stringify(contradiction));
      }
    }
  }
  if (humanFiles.every((relative) => {
    const text = read(relative);
    return requiredHumanFacts.every((fact) => text.includes(fact)) &&
      forbiddenHumanFacts.every((fact) => !text.includes(fact));
  })) {
    ok('README and PROJECT_STATUS agree with the machine B004 closeout state');
  }

  return { result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'status-transition', run);
