#!/usr/bin/env node
// AIPT-M0-B008 final closeout status-transition validator.
import fs from 'node:fs';
import path from 'node:path';
import {
  ACTIVE_BATCH, B000, B001, B002, B002_CLOSEOUT, B003, B003_CLOSEOUT,
  B004_CANDIDATE, B004_CLOSEOUT, B004_IMPLEMENTATION_MERGE,
  B004_POST_MERGE_REPAIR, B005_CANDIDATE, B005_CLOSEOUT,
  B005_IMPLEMENTATION_MERGE, B006_CANDIDATE, B006_CLOSEOUT,
  B006_IMPLEMENTATION_MERGE, B007_CANDIDATE, B007_CLOSEOUT,
  B007_EXTERNAL_SERIAL_PREDECESSOR, B007_IMPLEMENTATION_MERGE,
  B007_ORIGINAL_CANDIDATE, B008_CANDIDATE_HISTORY, B008_FINAL_CANDIDATE,
  B008_IMPLEMENTATION_MERGE, B008_INITIAL_CANDIDATE, B008_LIFECYCLE_REPAIR,
  CURRENT_BATCH, EXTERNAL_SERIAL_HISTORY,
  FROZEN_REGISTRY_PATHS, HARNESS_SOURCE, STATUS_DATE,
  STATUS_TRANSITION_PATHS,
} from '../lib/constants.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

const SCHEMA = 'aipt.public.project-status/v1';
const SNAPSHOT_ID = 'AIPT-M0-B008-CLOSEOUT-001';
const DESIGN = 'FROZEN_R0_R16_DCA_BOOTSTRAP';
const CONSTRUCTION = 'IDLE_WAITING_NEXT_BATCH';
const NEXT_BATCH = 'NONE';
const NEXT_STATE = 'NOT_AUTHORIZED';
const PLATFORM = 'FROZEN_WAITING_M1_ENGINE';
const CLOSED_BATCH_IDS = [
  'AIPT-M0-B000', 'AIPT-M0-B001', 'AIPT-M0-B002', 'AIPT-M0-B003',
  'AIPT-M0-B004', 'AIPT-M0-B005', 'AIPT-M0-B006', 'AIPT-M0-B007',
  'AIPT-M0-B008',
];
const BATCH_HISTORY_KEYS = [...CLOSED_BATCH_IDS];
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
  'default_branch', 'url', 'verified_head', 'verified_state', 'verified_tree',
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
const AUDIT_ARCHIVE_SHA256 = '0eb777d62c8045acc29b0a80216951b4aeb36f856bf690d2cd394019a1f7119d';
const AUDIT_ROOT_SHA256 = '33becf9c765902442ec7d7445c50d3ac00737c50bccfc33b5bb4f56e2bdaa90b';
const GPT_AUDIT_SHA256 = 'd35fca102f28387c0e4c7045d65da8418ffc947189500bf639d4edb11bbba207';
const INTEGRATION_ROOT_SHA256 = '329c98d00600ede1e9bdd7830b30f7968cc3de4d458b57bb3f6730a0bfedac91';
const CLOSED_FINDINGS = [
  'AIPT-B008-AUDIT-EVIDENCE-SELF-CONTAINMENT-001',
  'AIPT-B008-SOURCE-TREE-DIGEST-001',
  'AIPT-B008-SOURCE-TREE-SUMMARY-FACT-001',
  B008_LIFECYCLE_REPAIR.finding,
];

function expectedVerifiedState() {
  return {
    task_id: CURRENT_BATCH,
    state: 'MERGED_CLOSED',
    audited_product_implementation: {
      commit: B007_IMPLEMENTATION_MERGE.commit,
      tree: B007_IMPLEMENTATION_MERGE.tree,
    },
    base: { commit: B007_CLOSEOUT.commit, tree: B007_CLOSEOUT.tree },
    initial_candidate: { commit: B008_INITIAL_CANDIDATE.commit },
    final_candidate: {
      commit: B008_FINAL_CANDIDATE.commit,
      tree: B008_FINAL_CANDIDATE.tree,
      ci_run: B008_FINAL_CANDIDATE.ci_run,
      ci_conclusion: B008_FINAL_CANDIDATE.ci_conclusion,
    },
    lifecycle_repair: {
      finding: B008_LIFECYCLE_REPAIR.finding,
      status: B008_LIFECYCLE_REPAIR.status,
      commit: B008_LIFECYCLE_REPAIR.commit,
      parent: B008_LIFECYCLE_REPAIR.parent,
      changed_paths: B008_LIFECYCLE_REPAIR.changed_paths,
    },
    implementation_merge: {
      commit: B008_IMPLEMENTATION_MERGE.commit,
      tree: B008_IMPLEMENTATION_MERGE.tree,
      parents: [B008_IMPLEMENTATION_MERGE.parent1, B008_IMPLEMENTATION_MERGE.parent2],
      subject: B008_IMPLEMENTATION_MERGE.subject,
    },
    post_merge_ci: {
      run: B008_IMPLEMENTATION_MERGE.post_merge_ci_run,
      conclusion: B008_IMPLEMENTATION_MERGE.post_merge_ci_conclusion,
    },
    gpt_hard_gate: {
      directive: 'AIPT-M0-B008-GPT-PASS-AND-FINALIZE-001',
      result: 'PASS',
      open_findings: [],
      audit_ready_archive_sha256: AUDIT_ARCHIVE_SHA256,
      audit_ready_root_sha256: AUDIT_ROOT_SHA256,
      gpt_audit_result_sha256: GPT_AUDIT_SHA256,
      integration_root_sha256: INTEGRATION_ROOT_SHA256,
    },
    findings_closed: CLOSED_FINDINGS,
    m0_development_pass: {
      result: 'GRANTED',
      effective_condition: 'AIPT-M0-B008_MERGED_CLOSED',
      effective_by: SNAPSHOT_ID,
    },
    lifecycle: {
      global_wip: 0,
      next_serial_batch: NEXT_BATCH,
      next_batch_authorized: false,
      next_batch_started: false,
    },
    boundaries: {
      production_qualification: 'NOT_GRANTED',
      release_qualification: 'NOT_GRANTED',
      mvp_development_pass: 'NOT_GRANTED',
      human_equivalence: 'NOT_CLAIMED',
      real_playtest_completion: 'NOT_CLAIMED',
      platform_integration: PLATFORM,
    },
  };
}

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
  if (standalone?.construction !== CONSTRUCTION) {
    problems.push('construction is not IDLE_WAITING_NEXT_BATCH');
  }
  if (standalone?.current_batch !== ACTIVE_BATCH || ACTIVE_BATCH !== 'NO_ACTIVE_BATCH' ||
      CURRENT_BATCH !== 'AIPT-M0-B008') {
    problems.push('closeout does not leave NO_ACTIVE_BATCH while retaining the B008 history id');
  }
  if (standalone?.global_wip !== 0) problems.push('GLOBAL_WIP is not zero');
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
  if (standalone?.batch_history?.['AIPT-M0-B008'] !== 'MERGED_CLOSED') {
    problems.push('B008 is not MERGED_CLOSED');
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
      repo?.verified_head !== B008_IMPLEMENTATION_MERGE.commit ||
      repo?.verified_tree !== B008_IMPLEMENTATION_MERGE.tree ||
      !same(repo?.verified_state, expectedVerifiedState())) {
    problems.push('final B008 implementation identity/state drifted');
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
    ['B008 final Candidate', B008_FINAL_CANDIDATE.commit, B008_FINAL_CANDIDATE.tree],
    ['B008 implementation merge', B008_IMPLEMENTATION_MERGE.commit, B008_IMPLEMENTATION_MERGE.tree],
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
    status = JSON.parse(fs.readFileSync(
      path.join(ctx.repo, 'docs/authority/registry/project-status.json'), 'utf8',
    ));
  } catch (error) {
    fail('project status is unreadable: ' + error.message);
    return { result: 'FAIL', details };
  }

  for (const problem of checkStatusDocument(status)) fail(problem);
  if (pass) ok('machine status is the exact B008 MERGED_CLOSED final transition');
  if (!same(STATUS_TRANSITION_PATHS, STATUS_PATHS_LITERAL)) fail('STATUS_TRANSITION_PATHS drifted');
  else ok('five-path final closeout status subset is exact');

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

  const b008Lineage = git(ctx.repo, [
    'rev-list', '--reverse', B007_CLOSEOUT.commit + '..' + B008_FINAL_CANDIDATE.commit,
  ], { check: false });
  const b008Merges = git(ctx.repo, [
    'rev-list', '--merges', B007_CLOSEOUT.commit + '..' + B008_FINAL_CANDIDATE.commit,
  ], { check: false });
  if (b008Lineage.status !== 0 ||
      !same(b008Lineage.stdout.split('\n').filter(Boolean), B008_CANDIDATE_HISTORY) ||
      b008Merges.status !== 0 || b008Merges.stdout.trim() !== '') {
    fail('B008 Candidate lineage is not the exact three-commit zero-merge history');
  } else ok('B008 Candidate lineage is the exact three-commit zero-merge history');

  const repairParents = git(ctx.repo, [
    'rev-list', '--parents', '-n', '1', B008_LIFECYCLE_REPAIR.commit,
  ], { check: false });
  const repairPaths = git(ctx.repo, [
    'diff', '--name-only', '--no-renames', B008_LIFECYCLE_REPAIR.parent,
    B008_LIFECYCLE_REPAIR.commit,
  ], { check: false });
  if (repairParents.status !== 0 ||
      repairParents.stdout.trim() !== B008_LIFECYCLE_REPAIR.commit + ' ' + B008_LIFECYCLE_REPAIR.parent ||
      repairPaths.status !== 0 ||
      !same(repairPaths.stdout.split('\n').filter(Boolean), B008_LIFECYCLE_REPAIR.changed_paths) ||
      B008_LIFECYCLE_REPAIR.status !== 'CLOSED') {
    fail('B008 lifecycle repair identity/scope/finding disposition drifted');
  } else ok('B008 lifecycle repair finding is CLOSED with exact one-path scope');

  const mergeIdentity = git(ctx.repo, [
    'rev-list', '--parents', '-n', '1', B008_IMPLEMENTATION_MERGE.commit,
  ], { check: false });
  const mergeSubject = git(ctx.repo, [
    'show', '-s', '--format=%s', B008_IMPLEMENTATION_MERGE.commit,
  ], { check: false });
  const mergeTreeQuiet = git(ctx.repo, [
    'diff', '--quiet', B008_FINAL_CANDIDATE.commit, B008_IMPLEMENTATION_MERGE.commit,
  ], { check: false });
  if (mergeIdentity.status !== 0 ||
      mergeIdentity.stdout.trim() !== B008_IMPLEMENTATION_MERGE.commit + ' ' +
        B008_IMPLEMENTATION_MERGE.parent1 + ' ' + B008_IMPLEMENTATION_MERGE.parent2 ||
      mergeSubject.status !== 0 || mergeSubject.stdout.trim() !== B008_IMPLEMENTATION_MERGE.subject ||
      mergeTreeQuiet.status !== 0) {
    fail('B008 implementation merge topology/subject/tree drifted');
  } else ok('B008 implementation merge topology, subject and Candidate tree verified');

  for (const relative of FROZEN_REGISTRY_PATHS) {
    const base = git(ctx.repo, ['show', B007_CLOSEOUT.commit + ':' + relative], { check: false });
    const current = fs.readFileSync(path.join(ctx.repo, relative), 'utf8');
    if (base.status !== 0 || base.stdout !== current) fail('frozen registry changed: ' + relative);
    else ok('frozen registry unchanged: ' + relative);
  }

  const docs = [
    ['README.md', [SNAPSHOT_ID, CURRENT_BATCH, 'MERGED_CLOSED', CONSTRUCTION,
      'GLOBAL_WIP = 0', 'M0 Development Pass = GRANTED', 'next_serial_batch = NONE']],
    ['docs/authority/PROJECT_STATUS.md', [SNAPSHOT_ID, CURRENT_BATCH,
      'MERGED_CLOSED', CONSTRUCTION, 'GLOBAL_WIP = 0',
      'M0 Development Pass = GRANTED', 'next_serial_batch = NONE']],
  ];
  for (const [relative, needles] of docs) {
    const body = fs.readFileSync(path.join(ctx.repo, relative), 'utf8');
    const missing = needles.filter((needle) => !body.includes(needle));
    if (missing.length) fail(relative + ' misses B008 final tokens: ' + missing.join(', '));
    else ok(relative + ' carries the B008 final closeout boundary');
  }

  const mutations = [
    ['construction reopened', (s) => { s.tracks['AIPT-STANDALONE'].construction = 'IN_PROGRESS'; }],
    ['active batch added', (s) => { s.tracks['AIPT-STANDALONE'].current_batch = CURRENT_BATCH; }],
    ['GLOBAL_WIP raised', (s) => { s.tracks['AIPT-STANDALONE'].global_wip = 1; }],
    ['next batch added', (s) => { s.tracks['AIPT-STANDALONE'].next_serial_batch = 'AIPT-M1-B000'; }],
    ['next batch authorized', (s) => { s.tracks['AIPT-STANDALONE'].next_batch_authorized = true; }],
    ['next batch started', (s) => { s.tracks['AIPT-STANDALONE'].next_batch_started = true; }],
    ['B008 reopened', (s) => { s.tracks['AIPT-STANDALONE'].batch_history[CURRENT_BATCH] = 'IN_PROGRESS'; }],
    ['B007 reopened', (s) => { s.tracks['AIPT-STANDALONE'].batch_history['AIPT-M0-B007'] = 'IN_PROGRESS'; }],
    ['predecessor tree drift', (s) => { s.tracks['AIPT-STANDALONE'].external_serial_predecessor.candidate_tree = 'wrong'; }],
    ['external history removed', (s) => { s.tracks['AIPT-STANDALONE'].external_batch_history.pop(); }],
    ['platform unfrozen', (s) => { s.tracks['AIPT-PLATFORM-INTEGRATION'].unfreeze_authorized = true; }],
    ['verified head changed to base', (s) => { s.repositories.AIPT.verified_head = B007_CLOSEOUT.commit; }],
    ['verified tree changed to audited product tree', (s) => { s.repositories.AIPT.verified_tree = B007_IMPLEMENTATION_MERGE.tree; }],
    ['verified state reopened', (s) => { s.repositories.AIPT.verified_state.state = 'IN_PROGRESS'; }],
    ['Development Pass revoked', (s) => { s.repositories.AIPT.verified_state.m0_development_pass.result = 'NOT_GRANTED'; }],
    ['production boundary elevated', (s) => { s.repositories.AIPT.verified_state.boundaries.production_qualification = 'GRANTED'; }],
    ['audit root drift', (s) => { s.repositories.AIPT.verified_state.gpt_hard_gate.audit_ready_root_sha256 = '0'.repeat(64); }],
    ['lifecycle finding reopened', (s) => { s.repositories.AIPT.verified_state.lifecycle_repair.status = 'OPEN'; }],
    ['pending Candidate reintroduced', (s) => { s.repositories.AIPT.pending_candidate = {}; }],
    ['Harness identity drift', (s) => { s.runtime.deepseek_harness_commit = HARNESS_SOURCE.previous_commit; }],
    ['UNREGISTERED implementation drift', (s) => { s.repositories.UNREGISTERED.verified_head = 'wrong'; }],
    ['unknown root field', (s) => { s.m0_development_pass_effective = true; }],
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
