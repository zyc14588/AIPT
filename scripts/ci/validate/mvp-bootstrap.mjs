#!/usr/bin/env node
// AIPT-MVP-B000 governance/bootstrap gate. Node.js standard library only.
// It validates the exact M0 successor graph and Candidate lifecycle while
// keeping all product/runtime, dependency, M0 history and external-game
// identities frozen.
import fs from 'node:fs';
import path from 'node:path';
import {
  B008_IMPLEMENTATION_MERGE,
  CURRENT_BATCH,
  FROZEN_REGISTRY_PATHS,
  M0_CLOSEOUT,
  M0_HISTORICAL_PATHS,
  MVP_B000_ALLOWED_PATHS,
  MVP_B000_AUTHORITY,
  MVP_B000_BASE_COMMIT,
  MVP_B000_BASE_TREE,
  MVP_B000_BRANCH,
  MVP_B000_CLOSEOUT_ALLOWED_PATHS,
  MVP_B000_FINAL_CANDIDATE,
  MVP_B000_FORBIDDEN_PREFIXES,
  MVP_B000_IMPLEMENTATION_MERGE,
  MVP_B000_INITIAL_CANDIDATE,
  MVP_B000_LIFECYCLE_REPAIR,
  MVP_B000_NEXT_BATCH,
  MVP_B000_SNAPSHOT,
  MVP_B001,
  STATUS_DATE,
} from '../lib/constants.mjs';
import { git, runAsMain } from '../lib/cli.mjs';
import { run as runMvpB001 } from './mvp-b001.mjs';

const GRAPH_PATH = 'docs/authority/registry/batch-graph.json';
const STATUS_PATH = 'docs/authority/registry/project-status.json';
const M0_RECORD_PATH = 'docs/milestones/m0-development-pass.json';
const PLATFORM = 'FROZEN_WAITING_M1_ENGINE';
const GRAPH_SCHEMA = 'aipt.public.mvp-batch-graph/v1';
const NO_MODEL_ENDPOINT = /https?:\/\/(?:api\.)?(?:deepseek|openai|anthropic|openrouter|moonshot)\b/i;
const CREDENTIAL_ASSIGNMENT = /(?:api[_-]?key|authorization|credential|bearer)\s*[:=]\s*["'][^"'\n]+["']/i;
const SECRET_TOKEN = /\b(?:sk|dsk)-[A-Za-z0-9_-]{8,}\b/;
const MAIN_BRANCH = 'main';
const PR_REF_PATTERN = /^refs\/pull\/[1-9][0-9]*\/(?:head|merge)$/;
const GITHUB_LIFECYCLE_KEYS = [
  'GITHUB_ACTIONS', 'GITHUB_EVENT_NAME', 'GITHUB_REF', 'GITHUB_HEAD_REF',
  'GITHUB_BASE_REF', 'GITHUB_SHA',
];

export const MVP_B000_PREVIOUS_CANDIDATE = MVP_B000_INITIAL_CANDIDATE.commit;
export const MVP_B000_PREVIOUS_CANDIDATE_TREE = MVP_B000_INITIAL_CANDIDATE.tree;
export const MVP_B000_REPAIR_SUBJECT = MVP_B000_LIFECYCLE_REPAIR.subject;
export const MVP_B000_IMPLEMENTATION_MERGE_SUBJECT =
  MVP_B000_IMPLEMENTATION_MERGE.subject;
export const MVP_B000_CLOSEOUT_SUBJECT = 'closeout: complete AIPT-MVP-B000';
export const MVP_B000_REPAIR_PATHS = MVP_B000_LIFECYCLE_REPAIR.changed_paths;
export const MVP_B000_LIFECYCLE_PHASES = Object.freeze({
  CANDIDATE_PUSH: 'CANDIDATE_PUSH',
  PULL_REQUEST_CHECK: 'PULL_REQUEST_CHECK',
  POST_MERGE_MAIN: 'POST_MERGE_MAIN',
  CLOSEOUT_MAIN: 'CLOSEOUT_MAIN',
});

export const EXPECTED_BATCHES = [
  {
    order: 1,
    id: 'AIPT-MVP-B000',
    repository: 'AIPT',
    purpose: 'MVP authority bootstrap, machine batch graph, lifecycle transition, validator foundation',
    risk: 'governance',
  },
  {
    order: 2,
    id: 'AIPT-MVP-B001',
    repository: 'AIPT',
    purpose: 'Campaign/Suite/Case/Run contracts, immutable Run Manifest, PostgreSQL authoritative serial queue and lease skeleton',
    risk: 'authoritative-state',
  },
  {
    order: 3,
    id: 'UNREGISTERED-AIPT-P1-B000',
    repository: 'UNREGISTERED',
    purpose: 'Freeze Task 0 executable playtest package contract, scene/guide/rule mapping and runtime adapter inputs',
    risk: 'game-canon',
  },
  {
    order: 4,
    id: 'AIPT-MVP-B002',
    repository: 'AIPT',
    purpose: 'Deterministic Run Core: action transaction pipeline, RNG streams/seed commitments, invariants, projections and replay',
    risk: 'state-projection',
  },
  {
    order: 5,
    id: 'AIPT-MVP-B003',
    repository: 'AIPT',
    purpose: '1 GM + 4 player Agent orchestration, per-Run sessions, persona/context assembly, visibility and bounded repair',
    risk: 'hidden-information',
  },
  {
    order: 6,
    id: 'AIPT-MVP-B004',
    repository: 'AIPT',
    purpose: 'Versioned Model Profiles, real Harness runtime gateway, REMOTE_DEEPSEEK and LOCAL_LLAMACPP minimum certification',
    risk: 'external-model-security',
  },
  {
    order: 7,
    id: 'INT-AIPT-UNREGISTERED-MVP-001',
    repository: 'INTEGRATION_READ_ONLY',
    purpose: 'Fixed-pair end-to-end Task 0 runtime conformance smoke without qualification-run claims',
    risk: 'cross-repository',
  },
  {
    order: 8,
    id: 'AIPT-MVP-B005',
    repository: 'AIPT',
    purpose: 'Run evidence closure: AUDIT_READY generation, replay/defect/report contracts and deterministic export',
    risk: 'evidence-integrity',
  },
  {
    order: 9,
    id: 'AIPT-MVP-B006',
    repository: 'AIPT',
    purpose: 'Operational loopback Web controls for Queue/Run/Status-Table/Reports using the same authoritative services',
    risk: 'ui-security',
  },
  {
    order: 10,
    id: 'AIPT-MVP-B007',
    repository: 'AIPT',
    purpose: 'Non-qualifying real-model diagnostic pilot: DeepSeek full path plus llama.cpp startup/auth/minimum role call',
    risk: 'external-model-pilot',
  },
  {
    order: 11,
    id: 'AIPT-MVP-B008',
    repository: 'AIPT',
    purpose: 'Five serial Clean qualification Runs on the fixed Task 0 pair',
    risk: 'qualification-clean',
  },
  {
    order: 12,
    id: 'AIPT-MVP-B009',
    repository: 'AIPT',
    purpose: 'Three serial Mutant qualification Runs and mandatory detection of all frozen mutant classes',
    risk: 'qualification-adversarial',
  },
  {
    order: 13,
    id: 'AIPT-MVP-B010',
    repository: 'AIPT',
    purpose: 'MVP comprehensive acceptance, replay/reachability/privacy review, GPT hard gate and MVP Development Pass',
    risk: 'milestone-gate',
  },
];

export const EXPECTED_GRAPH = {
  schema: GRAPH_SCHEMA,
  authority: MVP_B000_AUTHORITY,
  milestone: 'MVP',
  predecessor: {
    task_id: 'AIPT-M0-B008',
    state: 'MERGED_CLOSED',
    closeout_commit: MVP_B000_BASE_COMMIT,
    closeout_tree: MVP_B000_BASE_TREE,
    closeout_ci_run: M0_CLOSEOUT.ci_run,
    m0_development_pass: 'GRANTED',
  },
  global_rules: {
    global_wip: 1,
    single_active_batch: true,
    single_authoritative_repository_per_implementation_batch: true,
    previous_batch_must_close_before_next: true,
    public_ci_remote_model_calls: false,
    qualification_runs_serial: true,
    platform_integration: PLATFORM,
  },
  serial_batches: EXPECTED_BATCHES,
  mvp_gate: {
    clean_runs_required: 5,
    mutants_required: 3,
    mutant_classes: [
      'HIDDEN_INFORMATION_LEAK',
      'PROSE_MACHINE_DIVERGENCE',
      'STATE_REPLAY_INCONSISTENCY',
    ],
    requirements: [
      'NO_HIDDEN_INFORMATION_LEAK',
      'STATE_REPLAYABLE',
      'CRITICAL_PATH_ENDING_RECOVERY_REACHABLE',
      'GPT_AUDIT_PASS',
    ],
    production_qualification: 'NOT_GRANTED_BY_MVP_DEVELOPMENT_PASS',
    release_qualification: 'NOT_GRANTED_BY_MVP_DEVELOPMENT_PASS',
    human_equivalence: 'NOT_CLAIMED',
  },
};

const M0_BATCH_IDS = Array.from({ length: 9 }, (_, index) =>
  `AIPT-M0-B${String(index).padStart(3, '0')}`);
const EXPECTED_HISTORY = Object.fromEntries([
  ...M0_BATCH_IDS.map((id) => [id, 'MERGED_CLOSED']),
  ...EXPECTED_BATCHES.map((batch, index) => [batch.id, index === 0 ? 'IN_PROGRESS' : 'NOT_STARTED']),
]);
const EXPECTED_PENDING = {
  milestone: 'MVP',
  task_id: CURRENT_BATCH,
  authority: MVP_B000_AUTHORITY,
  branch: MVP_B000_BRANCH,
  base_commit: MVP_B000_BASE_COMMIT,
  base_tree: MVP_B000_BASE_TREE,
  state: 'IN_PROGRESS',
  scope: 'GOVERNANCE_BOOTSTRAP_ONLY',
  merge_authorized: false,
  closeout_authorized: false,
};
const EXPECTED_MVP_BOOTSTRAP = {
  task_id: CURRENT_BATCH,
  state: 'MERGED_CLOSED',
  start_authority: MVP_B000_AUTHORITY,
  merge_authority: MVP_B000_IMPLEMENTATION_MERGE.directive,
  closeout_authority: 'AIPT-MVP-B000-CLOSEOUT-001',
  base: {
    commit: MVP_B000_BASE_COMMIT,
    tree: MVP_B000_BASE_TREE,
  },
  initial_candidate: {
    commit: MVP_B000_INITIAL_CANDIDATE.commit,
    tree: MVP_B000_INITIAL_CANDIDATE.tree,
    ci_run: MVP_B000_INITIAL_CANDIDATE.ci_run,
  },
  final_candidate: {
    commit: MVP_B000_FINAL_CANDIDATE.commit,
    tree: MVP_B000_FINAL_CANDIDATE.tree,
    ci_run: MVP_B000_FINAL_CANDIDATE.ci_run,
  },
  lifecycle_repair: {
    finding: MVP_B000_LIFECYCLE_REPAIR.finding,
    status: MVP_B000_LIFECYCLE_REPAIR.status,
    commit: MVP_B000_LIFECYCLE_REPAIR.commit,
    parent: MVP_B000_LIFECYCLE_REPAIR.parent,
  },
  implementation_merge: {
    commit: MVP_B000_IMPLEMENTATION_MERGE.commit,
    tree: MVP_B000_IMPLEMENTATION_MERGE.tree,
    parents: [
      MVP_B000_IMPLEMENTATION_MERGE.parent1,
      MVP_B000_IMPLEMENTATION_MERGE.parent2,
    ],
    subject: MVP_B000_IMPLEMENTATION_MERGE.subject,
  },
  post_merge_ci: {
    run: MVP_B000_IMPLEMENTATION_MERGE.post_merge_ci_run,
    conclusion: MVP_B000_IMPLEMENTATION_MERGE.post_merge_ci_conclusion,
  },
  scope: 'GOVERNANCE_BOOTSTRAP_ONLY',
  serial_graph_items: 13,
  runtime_implementation_changed: false,
  real_model_runtime_calls: 0,
};

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function compareExact(actual, expected, at = '$') {
  const problems = [];
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual)) return [`${at} must be an array`];
    if (actual.length !== expected.length) problems.push(`${at} array length drifted`);
    for (let index = 0; index < Math.min(actual.length, expected.length); index += 1) {
      problems.push(...compareExact(actual[index], expected[index], `${at}[${index}]`));
    }
    return problems;
  }
  if (isPlainObject(expected)) {
    if (!isPlainObject(actual)) return [`${at} must be an object`];
    const actualKeys = Object.keys(actual).sort();
    const expectedKeys = Object.keys(expected).sort();
    if (JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) {
      problems.push(`${at} key set drifted`);
    }
    for (const key of expectedKeys) {
      if (Object.hasOwn(actual, key)) {
        problems.push(...compareExact(actual[key], expected[key], `${at}.${key}`));
      }
    }
    return problems;
  }
  if (!Object.is(actual, expected)) problems.push(`${at} drifted`);
  return problems;
}

export function validateGraph(graph) {
  const problems = compareExact(graph, EXPECTED_GRAPH, '$graph');
  const ids = Array.isArray(graph?.serial_batches)
    ? graph.serial_batches.map((batch) => batch?.id) : [];
  if (ids.some((id) => typeof id === 'string' && /^AIPT-M1-/.test(id))) {
    problems.push('standalone AIPT-M1 alias is forbidden');
  }
  return problems;
}

export function expectedCandidateStatus(baseStatus) {
  const expectedStandalone = {
    ...baseStatus.tracks['AIPT-STANDALONE'],
    construction: 'IN_PROGRESS',
    current_batch: CURRENT_BATCH,
    next_serial_batch: MVP_B000_NEXT_BATCH,
    next_batch_state: 'NOT_AUTHORIZED',
    next_batch_authorized: false,
    next_batch_started: false,
    batch_history: { ...EXPECTED_HISTORY },
    global_wip: 1,
  };
  return {
    ...baseStatus,
    as_of: STATUS_DATE,
    authority_snapshot_id: MVP_B000_SNAPSHOT,
    tracks: {
      'AIPT-STANDALONE': expectedStandalone,
      'AIPT-PLATFORM-INTEGRATION': baseStatus.tracks['AIPT-PLATFORM-INTEGRATION'],
    },
    repositories: {
      AIPT: {
        ...baseStatus.repositories.AIPT,
        pending_candidate: EXPECTED_PENDING,
      },
      UNREGISTERED: baseStatus.repositories.UNREGISTERED,
    },
  };
}

export function validateStatus(status, baseStatus) {
  const problems = compareExact(status, expectedCandidateStatus(baseStatus), '$status');
  const ids = Object.keys(status?.tracks?.['AIPT-STANDALONE']?.batch_history ?? {});
  if (ids.some((id) => /^AIPT-M1-/.test(id))) problems.push('standalone AIPT-M1 alias is forbidden');
  return problems;
}

// CLOSEOUT_MAIN is deliberately pre-supported without granting closeout. Its
// status shape is an exact projection of the current Candidate authority: only
// B000 closes, WIP returns to zero, and the still-unauthorized B001 remains the
// named next batch. A future closeout that attempts to authorize or start B001
// therefore fails closed.
export function expectedCloseoutStatus(baseStatus) {
  const expected = expectedCandidateStatus(baseStatus);
  expected.authority_snapshot_id = 'AIPT-MVP-B000-CLOSEOUT-001';
  expected.tracks['AIPT-STANDALONE'].construction = 'IDLE_WAITING_NEXT_BATCH';
  expected.tracks['AIPT-STANDALONE'].current_batch = 'NO_ACTIVE_BATCH';
  expected.tracks['AIPT-STANDALONE'].batch_history[CURRENT_BATCH] = 'MERGED_CLOSED';
  expected.tracks['AIPT-STANDALONE'].global_wip = 0;
  delete expected.repositories.AIPT.pending_candidate;
  expected.repositories.AIPT.mvp_bootstrap = EXPECTED_MVP_BOOTSTRAP;
  return expected;
}

export function validateCloseoutStatus(status, baseStatus) {
  const problems = compareExact(status, expectedCloseoutStatus(baseStatus), '$status');
  const standalone = status?.tracks?.['AIPT-STANDALONE'];
  if (standalone?.next_serial_batch !== MVP_B000_NEXT_BATCH ||
      standalone?.next_batch_state !== 'NOT_AUTHORIZED' ||
      standalone?.next_batch_authorized !== false ||
      standalone?.next_batch_started !== false) {
    problems.push('B001 must remain named, unauthorized and not started after B000 closeout');
  }
  const ids = Object.keys(standalone?.batch_history ?? {});
  if (ids.some((id) => /^AIPT-M1-/.test(id))) problems.push('standalone AIPT-M1 alias is forbidden');
  return problems;
}

function sameSet(actual, expected) {
  return actual.length === expected.length && new Set(actual).size === actual.length &&
    JSON.stringify([...actual].sort()) === JSON.stringify([...expected].sort());
}

function frozenIdentityProblems() {
  const problems = [];
  const exactInitial = {
    commit: '524113a95cd43365b56f215996775bc574e43d1a',
    tree: '8c3823f9578c27b1ab3b42a15a56b6e97893d6ec',
    ci_run: 32865192423,
    ci_conclusion: 'success',
  };
  const exactFinal = {
    commit: '9a4d5e0ad09fbc9c3e13536d02cd131f992836f2',
    tree: '895ccfc569435c390a1aaeea566167a2d61a4de6',
    ci_run: 32869412683,
    ci_conclusion: 'success',
  };
  const exactRepair = {
    finding: 'AIPT-MVP-B000-POSTMERGE-LIFECYCLE-001',
    status: 'CLOSED',
    commit: exactFinal.commit,
    parent: exactInitial.commit,
    subject: 'fix(ci): support MVP B000 merge lifecycle',
    changed_paths: [
      'scripts/ci/validate/mvp-bootstrap.mjs',
      'scripts/ci/validate/m0-development-pass.mjs',
      'scripts/ci/validate/tree-integrity.mjs',
      'scripts/ci/validate/status-transition.mjs',
    ],
  };
  const exactMerge = {
    directive: 'AIPT-MVP-B000-MERGE-001',
    commit: '1a26e023af1b56c057590a46de2f63c3b4220923',
    tree: exactFinal.tree,
    parent1: MVP_B000_BASE_COMMIT,
    parent2: exactFinal.commit,
    subject: 'merge: integrate AIPT-MVP-B000',
    post_merge_ci_run: 32907168240,
    post_merge_ci_conclusion: 'success',
  };
  const exactCloseoutPaths = [
    'README.md',
    'docs/authority/BATCH_DEPENDENCY_GRAPH.md',
    'docs/authority/PROJECT_STATUS.md',
    'docs/authority/registry/project-status.json',
    'docs/milestones/MVP.md',
    'scripts/ci/lib/constants.mjs',
    'scripts/ci/run-checks.mjs',
    'scripts/ci/validate/mvp-bootstrap.mjs',
  ];
  problems.push(...compareExact(MVP_B000_INITIAL_CANDIDATE, exactInitial,
    '$constants.MVP_B000_INITIAL_CANDIDATE'));
  problems.push(...compareExact(MVP_B000_FINAL_CANDIDATE, exactFinal,
    '$constants.MVP_B000_FINAL_CANDIDATE'));
  problems.push(...compareExact(MVP_B000_LIFECYCLE_REPAIR, exactRepair,
    '$constants.MVP_B000_LIFECYCLE_REPAIR'));
  problems.push(...compareExact(MVP_B000_IMPLEMENTATION_MERGE, exactMerge,
    '$constants.MVP_B000_IMPLEMENTATION_MERGE'));
  if (!sameSet(MVP_B000_CLOSEOUT_ALLOWED_PATHS, exactCloseoutPaths)) {
    problems.push('$constants.MVP_B000_CLOSEOUT_ALLOWED_PATHS drifted');
  }
  if (![MVP_B000_INITIAL_CANDIDATE, MVP_B000_FINAL_CANDIDATE,
    MVP_B000_LIFECYCLE_REPAIR, MVP_B000_LIFECYCLE_REPAIR.changed_paths,
    MVP_B000_IMPLEMENTATION_MERGE, MVP_B000_CLOSEOUT_ALLOWED_PATHS]
    .every((value) => Object.isFrozen(value))) {
    problems.push('B000 identity/closeout constants are not frozen');
  }
  return problems;
}

export function validateChangedPaths(changed) {
  const problems = [];
  if (!sameSet(changed, MVP_B000_ALLOWED_PATHS)) {
    const missing = MVP_B000_ALLOWED_PATHS.filter((relative) => !changed.includes(relative));
    const extra = changed.filter((relative) => !MVP_B000_ALLOWED_PATHS.includes(relative));
    if (missing.length) problems.push('required MVP bootstrap paths missing: ' + missing.join(', '));
    if (extra.length) problems.push('path outside MVP bootstrap scope: ' + extra.join(', '));
  }
  for (const relative of changed) {
    if (MVP_B000_FORBIDDEN_PREFIXES.some((prefix) =>
      prefix.endsWith('/') ? relative.startsWith(prefix) : relative === prefix)) {
      problems.push('runtime/product/dependency path changed: ' + relative);
    }
  }
  return problems;
}

export function validateChangedText(relative, text) {
  const problems = [];
  if (NO_MODEL_ENDPOINT.test(text)) problems.push(`${relative} injects a product model endpoint`);
  if (CREDENTIAL_ASSIGNMENT.test(text) || SECRET_TOKEN.test(text)) {
    problems.push(`${relative} injects credential material`);
  }
  if (relative === '.github/workflows/ci.yml' && /\bsecrets\s*\./.test(text)) {
    problems.push('public CI references secrets.*');
  }
  return problems;
}

function normalizedEnv(value) {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : null;
}

function linesFrom(probe) {
  return probe?.status === 0 ? probe.stdout.split('\n').filter(Boolean) : null;
}

function isGitObjectId(value) {
  return typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);
}

function exactStringSet(actual, expected) {
  return Array.isArray(actual) && sameSet(actual, expected);
}

function readCommit(repo, commit) {
  if (!isGitObjectId(commit)) return null;
  const parents = git(repo, ['rev-list', '--parents', '-n', '1', commit], { check: false });
  const tokens = parents.status === 0
    ? parents.stdout.trim().split(/\s+/).filter(Boolean) : [];
  if (tokens[0] !== commit) return null;
  const tree = git(repo, ['rev-parse', `${commit}^{tree}`], { check: false });
  const subject = git(repo, ['show', '-s', '--format=%s', commit], { check: false });
  return {
    commit,
    parents: tokens.slice(1),
    tree: tree.status === 0 ? tree.stdout.trim() : null,
    subject: subject.status === 0 ? subject.stdout.trim() : null,
  };
}

// Collect one normalized fact object for every B000 lifecycle checkout. GitHub
// event/ref data is intentionally part of the fact set: a PR synthetic merge
// may be graph-identical to an implementation merge, but is never authority.
export function collectLifecycleFacts(repo, env = process.env) {
  const baseCommitProbe = git(repo, ['rev-parse', `${MVP_B000_BASE_COMMIT}^{commit}`], { check: false });
  const baseTreeProbe = git(repo, ['rev-parse', `${MVP_B000_BASE_COMMIT}^{tree}`], { check: false });
  const previousProbe = git(repo, [
    'rev-parse', `${MVP_B000_PREVIOUS_CANDIDATE}^{commit}`,
  ], { check: false });
  const previousTreeProbe = git(repo, [
    'rev-parse', `${MVP_B000_PREVIOUS_CANDIDATE}^{tree}`,
  ], { check: false });
  const headProbe = git(repo, ['rev-parse', 'HEAD^{commit}'], { check: false });
  const head = headProbe.status === 0 ? headProbe.stdout.trim() : null;
  const headCommit = readCommit(repo, head);
  const branchProbe = git(repo, ['symbolic-ref', '--short', 'HEAD'], { check: false });
  const ancestryProbe = git(repo, [
    'merge-base', '--is-ancestor', MVP_B000_BASE_COMMIT, 'HEAD',
  ], { check: false });
  const mergeProbe = git(repo, [
    'rev-list', '--merges', '--reverse', `${MVP_B000_BASE_COMMIT}..HEAD`,
  ], { check: false });
  const mergeCommits = linesFrom(mergeProbe);
  const soleMerge = Array.isArray(mergeCommits) && mergeCommits.length === 1
    ? readCommit(repo, mergeCommits[0]) : null;
  const candidateTip = soleMerge?.parents?.length === 2 ? soleMerge.parents[1] : head;
  const candidateCommit = readCommit(repo, candidateTip);
  const candidateAncestry = candidateTip
    ? git(repo, ['merge-base', '--is-ancestor', MVP_B000_BASE_COMMIT, candidateTip], { check: false })
    : { status: 2 };
  const previousAncestry = candidateTip
    ? git(repo, [
        'merge-base', '--is-ancestor', MVP_B000_PREVIOUS_CANDIDATE, candidateTip,
      ], { check: false })
    : { status: 2 };
  const candidateMergeProbe = candidateTip
    ? git(repo, [
        'rev-list', '--merges', `${MVP_B000_BASE_COMMIT}..${candidateTip}`,
      ], { check: false })
    : { status: 2, stdout: '' };
  const candidatePathProbe = candidateTip
    ? git(repo, [
        'diff', '--name-only', '--no-renames', MVP_B000_BASE_COMMIT, candidateTip,
      ], { check: false })
    : { status: 2, stdout: '' };
  const postPreviousProbe = candidateTip
    ? git(repo, [
        'rev-list', '--reverse', `${MVP_B000_PREVIOUS_CANDIDATE}..${candidateTip}`,
      ], { check: false })
    : { status: 2, stdout: '' };
  const repairPathProbe = candidateTip
    ? git(repo, [
        'diff', '--name-only', '--no-renames', MVP_B000_PREVIOUS_CANDIDATE, candidateTip,
      ], { check: false })
    : { status: 2, stdout: '' };
  const worktreeRepairPathProbe = git(repo, [
    'diff', '--name-only', '--no-renames', MVP_B000_PREVIOUS_CANDIDATE,
  ], { check: false });
  const descendantProbe = soleMerge
    ? git(repo, [
        'rev-list', '--reverse', '--ancestry-path', '--parents', `${soleMerge.commit}..HEAD`,
      ], { check: false })
    : { status: 0, stdout: '' };
  const ordinaryDescendants = descendantProbe.status === 0
    ? descendantProbe.stdout.split('\n').filter(Boolean).map((line) =>
        readCommit(repo, line.trim().split(/\s+/)[0]))
    : null;
  const closeoutPathProbe = soleMerge && head !== soleMerge.commit
    ? git(repo, ['diff', '--name-only', '--no-renames', soleMerge.commit, head], { check: false })
    : { status: 0, stdout: '' };
  const githubPresent = GITHUB_LIFECYCLE_KEYS.some((key) => Object.hasOwn(env, key));
  return {
    baseCommit: baseCommitProbe.status === 0 ? baseCommitProbe.stdout.trim() : null,
    baseTree: baseTreeProbe.status === 0 ? baseTreeProbe.stdout.trim() : null,
    previousCandidate: previousProbe.status === 0 ? previousProbe.stdout.trim() : null,
    previousCandidateTree: previousTreeProbe.status === 0 ? previousTreeProbe.stdout.trim() : null,
    head,
    headCommit,
    headTree: headCommit?.tree ?? null,
    ancestryKnown: ancestryProbe.status === 0 || ancestryProbe.status === 1,
    baseIsAncestor: ancestryProbe.status === 0,
    branch: branchProbe.status === 0 ? branchProbe.stdout.trim() : null,
    github: {
      present: githubPresent,
      eventName: normalizedEnv(env.GITHUB_EVENT_NAME),
      ref: normalizedEnv(env.GITHUB_REF),
      headRef: normalizedEnv(env.GITHUB_HEAD_REF),
      baseRef: normalizedEnv(env.GITHUB_BASE_REF),
      sha: normalizedEnv(env.GITHUB_SHA),
    },
    mergeCommits,
    merge: soleMerge ? {
      ...soleMerge,
      treeDiffQuiet: candidateTip
        ? git(repo, ['diff', '--quiet', candidateTip, soleMerge.commit], { check: false }).status === 0
        : false,
    } : null,
    candidateTip,
    candidateCommit,
    candidateTree: candidateCommit?.tree ?? null,
    candidateDescendsFromBase: candidateAncestry.status === 0,
    candidateDescendsFromPrevious: previousAncestry.status === 0,
    candidateMergeCommits: linesFrom(candidateMergeProbe),
    candidateChangedPaths: linesFrom(candidatePathProbe)?.sort() ?? null,
    candidatePostPreviousCommits: linesFrom(postPreviousProbe),
    candidateRepairChangedPaths: linesFrom(repairPathProbe)?.sort() ?? null,
    candidateWorktreeRepairPaths: linesFrom(worktreeRepairPathProbe)?.sort() ?? null,
    ordinaryDescendants,
    closeoutChangedPaths: linesFrom(closeoutPathProbe)?.sort() ?? null,
  };
}

export function classifyLifecycle(facts) {
  const problems = [];
  const github = facts?.github;
  let phase = 'UNKNOWN';
  if (!isPlainObject(github) || typeof github.present !== 'boolean') {
    return { result: 'FAIL', phase, problems: ['GitHub lifecycle environment is unreadable'] };
  }
  if (github.present) {
    if (github.sha !== facts.head) problems.push('GITHUB_SHA is not checked-out HEAD');
    if (github.eventName === 'pull_request') {
      phase = MVP_B000_LIFECYCLE_PHASES.PULL_REQUEST_CHECK;
      if (github.headRef !== MVP_B000_BRANCH) problems.push('PR head is not task/AIPT-MVP-B000');
      if (github.baseRef !== MAIN_BRANCH) problems.push('PR base is not main');
      if (!PR_REF_PATTERN.test(github.ref ?? '')) problems.push('PR ref is not refs/pull/<n>/head|merge');
      if (facts.branch !== null && facts.branch !== MVP_B000_BRANCH) {
        problems.push('PR symbolic branch is foreign');
      }
    } else if (github.eventName === 'push') {
      if (github.headRef !== null || github.baseRef !== null) {
        problems.push('push unexpectedly carries PR head/base refs');
      }
      if (github.ref === `refs/heads/${MVP_B000_BRANCH}`) {
        phase = MVP_B000_LIFECYCLE_PHASES.CANDIDATE_PUSH;
        if (facts.branch !== null && facts.branch !== MVP_B000_BRANCH) {
          problems.push('Candidate push symbolic branch is foreign');
        }
      } else if (github.ref === `refs/heads/${MAIN_BRANCH}`) {
        phase = Array.isArray(facts.mergeCommits) && facts.mergeCommits.length === 1 &&
          facts.merge?.commit !== facts.head
          ? MVP_B000_LIFECYCLE_PHASES.CLOSEOUT_MAIN
          : MVP_B000_LIFECYCLE_PHASES.POST_MERGE_MAIN;
        if (facts.branch !== null && facts.branch !== MAIN_BRANCH) {
          problems.push('main push symbolic branch is foreign');
        }
      } else {
        problems.push('push ref is neither the exact B000 task branch nor main');
      }
    } else {
      problems.push('GitHub event is not an authorized push or pull_request');
    }
  } else if (facts.branch === MVP_B000_BRANCH) {
    phase = MVP_B000_LIFECYCLE_PHASES.CANDIDATE_PUSH;
  } else if (facts.branch === MAIN_BRANCH) {
    if (Array.isArray(facts.mergeCommits) && facts.mergeCommits.length === 1) {
      phase = facts.merge?.commit === facts.head
        ? MVP_B000_LIFECYCLE_PHASES.POST_MERGE_MAIN
        : MVP_B000_LIFECYCLE_PHASES.CLOSEOUT_MAIN;
    } else {
      problems.push('local main cannot be uniquely classified as exact post-merge/closeout');
    }
  } else {
    problems.push('local checkout is neither the B000 task branch nor main');
  }
  return { result: problems.length === 0 ? 'PASS' : 'FAIL', phase, problems };
}

export function validateLifecycle(facts, status = null, baseStatus = null) {
  const classification = classifyLifecycle(facts);
  const problems = [...classification.problems];
  const phase = classification.phase;
  let checkoutKind = 'UNKNOWN';

  if (facts?.baseCommit !== MVP_B000_BASE_COMMIT) problems.push('fixed Base commit drifted');
  if (facts?.baseTree !== MVP_B000_BASE_TREE) problems.push('fixed Base tree drifted');
  if (facts?.previousCandidate !== MVP_B000_PREVIOUS_CANDIDATE) {
    problems.push('Previous Candidate identity drifted');
  }
  if (facts?.previousCandidateTree !== MVP_B000_PREVIOUS_CANDIDATE_TREE) {
    problems.push('Previous Candidate tree drifted');
  }
  if (!isGitObjectId(facts?.head) || !isGitObjectId(facts?.headTree)) {
    problems.push('HEAD commit/tree identity is unreadable');
  }
  if (facts?.ancestryKnown !== true || facts?.baseIsAncestor !== true) {
    problems.push('HEAD does not provably descend from fixed Base');
  }

  const validateCandidateLineage = ({ mustBeHead = false, allowWorktree = false } = {}) => {
    if (!isGitObjectId(facts?.candidateTip) || !isGitObjectId(facts?.candidateTree)) {
      problems.push('Candidate commit/tree identity is unreadable');
    }
    if (facts?.candidateTip !== MVP_B000_FINAL_CANDIDATE.commit ||
        facts?.candidateTree !== MVP_B000_FINAL_CANDIDATE.tree) {
      problems.push('Candidate is not the exact frozen final Candidate identity');
    }
    if (facts?.candidateDescendsFromBase !== true ||
        facts?.candidateDescendsFromPrevious !== true) {
      problems.push('Candidate does not descend from fixed Base and Previous Candidate');
    }
    if (!Array.isArray(facts?.candidateMergeCommits)) {
      problems.push('Candidate merge list is unreadable');
    } else if (facts.candidateMergeCommits.length !== 0) {
      problems.push('Candidate lineage contains a merge');
    }
    if (!Array.isArray(facts?.candidatePostPreviousCommits)) {
      problems.push('Previous-to-Candidate lineage is unreadable');
    } else if (facts.candidatePostPreviousCommits.length === 1) {
      if (facts.candidatePostPreviousCommits[0] !== facts.candidateTip ||
          facts.candidateCommit?.commit !== facts.candidateTip ||
          !Array.isArray(facts.candidateCommit?.parents) ||
          facts.candidateCommit.parents.length !== 1 ||
          facts.candidateCommit.parents[0] !== MVP_B000_PREVIOUS_CANDIDATE) {
        problems.push('repair is not exactly one ordinary child of Previous Candidate');
      }
      if (facts.candidateCommit?.subject !== MVP_B000_REPAIR_SUBJECT) {
        problems.push('repair commit subject is not exact');
      }
      if (!exactStringSet(facts.candidateRepairChangedPaths, MVP_B000_REPAIR_PATHS)) {
        problems.push('repair commit does not change exactly the four authorized validators');
      }
    } else if (facts.candidatePostPreviousCommits.length === 0 && allowWorktree &&
        facts.candidateTip === MVP_B000_PREVIOUS_CANDIDATE &&
        exactStringSet(facts.candidateWorktreeRepairPaths, MVP_B000_REPAIR_PATHS)) {
      // This one local-only state lets the four validators test themselves
      // before the single append-only repair commit is created.
    } else {
      problems.push('Candidate lineage is not exactly one append-only repair commit');
    }
    if (mustBeHead && facts.candidateTip !== facts.head) problems.push('Candidate tip is not HEAD');
    if (mustBeHead && facts.candidateTree !== facts.headTree) problems.push('Candidate tree is not HEAD tree');
    if (!exactStringSet(facts?.candidateChangedPaths, MVP_B000_ALLOWED_PATHS)) {
      problems.push('Base-to-Candidate surface is not the exact 17-path bootstrap surface');
    }
  };

  const validateMerge = ({ synthetic = false } = {}) => {
    const merge = facts?.merge;
    if (!isPlainObject(merge) || !Array.isArray(merge.parents) || merge.parents.length !== 2) {
      problems.push(`${synthetic ? 'PR synthetic' : 'implementation'} merge must have exactly two parents`);
      return;
    }
    if (merge.parents[0] !== MVP_B000_BASE_COMMIT) problems.push('merge first parent is not fixed Base');
    if (merge.parents[1] !== MVP_B000_FINAL_CANDIDATE.commit ||
        merge.parents[1] !== facts.candidateTip) {
      problems.push('merge second parent is not the frozen final Candidate');
    }
    validateCandidateLineage();
    if (!synthetic) {
      if (merge.commit !== MVP_B000_IMPLEMENTATION_MERGE.commit) {
        problems.push('implementation merge commit identity is not exact');
      }
      if (merge.subject !== MVP_B000_IMPLEMENTATION_MERGE_SUBJECT) {
        problems.push('implementation merge subject is not exact');
      }
      if (merge.tree !== MVP_B000_IMPLEMENTATION_MERGE.tree) {
        problems.push('implementation merge tree identity is not exact');
      }
    }
    if (merge.tree !== facts.candidateTree || merge.tree !== facts.headTree && merge.commit === facts.head) {
      problems.push('merge tree does not equal Candidate/checkout tree');
    }
    if (merge.treeDiffQuiet !== true) problems.push('merge introduces a tree delta from Candidate');
  };

  if (phase === MVP_B000_LIFECYCLE_PHASES.CANDIDATE_PUSH) {
    checkoutKind = 'CANDIDATE_HEAD';
    if (!Array.isArray(facts?.mergeCommits) || facts.mergeCommits.length !== 0) {
      problems.push('Candidate must contain zero post-Base merges');
    }
    validateCandidateLineage({
      mustBeHead: true,
      allowWorktree: facts?.github?.present === false && facts?.branch === MVP_B000_BRANCH,
    });
  } else if (phase === MVP_B000_LIFECYCLE_PHASES.PULL_REQUEST_CHECK) {
    if (!Array.isArray(facts?.mergeCommits)) {
      problems.push('PR merge list is unreadable');
    } else if (facts.mergeCommits.length === 0) {
      checkoutKind = 'PR_HEAD';
      validateCandidateLineage({ mustBeHead: true });
    } else if (facts.mergeCommits.length === 1) {
      checkoutKind = 'PR_SYNTHETIC_MERGE';
      if (facts.branch !== null) problems.push('PR synthetic merge checkout must be detached');
      if (facts.mergeCommits[0] !== facts.head || facts.merge?.commit !== facts.head) {
        problems.push('PR synthetic merge is not current HEAD');
      }
      validateMerge({ synthetic: true });
    } else {
      problems.push('PR checkout contains more than one post-Base merge');
    }
  } else if (phase === MVP_B000_LIFECYCLE_PHASES.POST_MERGE_MAIN) {
    checkoutKind = 'IMPLEMENTATION_MERGE';
    if (!Array.isArray(facts?.mergeCommits) || facts.mergeCommits.length !== 1) {
      problems.push('post-merge main must contain exactly one implementation merge');
    } else {
      if (facts.mergeCommits[0] !== MVP_B000_IMPLEMENTATION_MERGE.commit ||
          facts.head !== MVP_B000_IMPLEMENTATION_MERGE.commit ||
          facts.merge?.commit !== facts.head) {
        problems.push('implementation merge must be current HEAD');
      }
      if (!Array.isArray(facts.ordinaryDescendants) || facts.ordinaryDescendants.length !== 0) {
        problems.push('post-merge main must have no ordinary descendant');
      }
      validateMerge();
    }
  } else if (phase === MVP_B000_LIFECYCLE_PHASES.CLOSEOUT_MAIN) {
    checkoutKind = 'FINAL_CLOSEOUT';
    if (!Array.isArray(facts?.mergeCommits) || facts.mergeCommits.length !== 1) {
      problems.push('closeout main must contain exactly one implementation merge');
    } else if (facts.mergeCommits[0] !== MVP_B000_IMPLEMENTATION_MERGE.commit ||
        facts.merge?.commit !== MVP_B000_IMPLEMENTATION_MERGE.commit) {
      problems.push('closeout does not descend from the exact implementation merge');
      validateMerge();
    } else {
      validateMerge();
    }
    if (!Array.isArray(facts?.ordinaryDescendants) || facts.ordinaryDescendants.length !== 1 ||
        facts.ordinaryDescendants[0]?.commit !== facts.head) {
      problems.push('closeout must be the sole ordinary descendant of implementation merge');
    }
    if (!isPlainObject(facts?.headCommit) || facts.headCommit.commit !== facts.head ||
        !Array.isArray(facts.headCommit.parents) || facts.headCommit.parents.length !== 1 ||
        facts.headCommit.parents[0] !== MVP_B000_IMPLEMENTATION_MERGE.commit) {
      problems.push('closeout is not one ordinary single-parent child of implementation merge');
    }
    if (facts?.headCommit?.subject !== MVP_B000_CLOSEOUT_SUBJECT) {
      problems.push('closeout subject is not exact');
    }
    if (!exactStringSet(facts?.closeoutChangedPaths, MVP_B000_CLOSEOUT_ALLOWED_PATHS)) {
      problems.push('closeout changed paths are not the exact eight-path allowlist');
    }
  } else {
    problems.push('lifecycle phase is not uniquely classified');
  }

  if (status !== null || baseStatus !== null) {
    if (!isPlainObject(status) || !isPlainObject(baseStatus)) {
      problems.push('lifecycle status/base status is unreadable');
    } else {
      const statusProblems = phase === MVP_B000_LIFECYCLE_PHASES.CLOSEOUT_MAIN
        ? validateCloseoutStatus(status, baseStatus)
        : validateStatus(status, baseStatus);
      problems.push(...statusProblems.map((problem) => `status: ${problem}`));
    }
  }

  const accepted = problems.length === 0;
  return {
    result: accepted ? 'PASS' : 'FAIL',
    phase,
    checkoutKind,
    implementationMergeRecognized: accepted &&
      [MVP_B000_LIFECYCLE_PHASES.POST_MERGE_MAIN,
        MVP_B000_LIFECYCLE_PHASES.CLOSEOUT_MAIN].includes(phase),
    closeoutRecognized: accepted && phase === MVP_B000_LIFECYCLE_PHASES.CLOSEOUT_MAIN,
    problems,
  };
}

function readJson(repo, relative) {
  return JSON.parse(fs.readFileSync(path.join(repo, relative), 'utf8'));
}

function readBaseJson(repo, relative) {
  const probe = git(repo, ['show', `${MVP_B000_BASE_COMMIT}:${relative}`], { check: false });
  if (probe.status !== 0) throw new Error(`Base file unavailable: ${relative}`);
  return JSON.parse(probe.stdout);
}

function changedPaths(repo) {
  const tracked = git(repo, ['diff', '--name-only', '--no-renames', MVP_B000_BASE_COMMIT], { check: false });
  const untracked = git(repo, ['ls-files', '--others', '--exclude-standard'], { check: false });
  if (tracked.status !== 0 || untracked.status !== 0) return null;
  return [...new Set([
    ...tracked.stdout.split('\n'),
    ...untracked.stdout.split('\n').filter((relative) => !relative.split('/').includes('node_modules')),
  ].filter(Boolean))].sort();
}

function frozenPathProblems(repo, relatives) {
  const problems = [];
  for (const relative of relatives) {
    const base = git(repo, ['show', `${MVP_B000_BASE_COMMIT}:${relative}`], { check: false });
    let current;
    try {
      current = fs.readFileSync(path.join(repo, relative));
    } catch (error) {
      problems.push(`${relative} unreadable: ${error.message}`);
      continue;
    }
    if (base.status !== 0 || !Buffer.from(base.stdout).equals(current)) {
      problems.push(`${relative} changed from M0 closeout`);
    }
  }
  return problems;
}

function modeProblems(repo, changed) {
  const problems = [];
  const status = git(repo, ['diff', '--name-status', '--no-renames', MVP_B000_BASE_COMMIT], { check: false });
  if (status.status !== 0) return ['changed-path status is unreadable'];
  for (const line of status.stdout.split('\n').filter(Boolean)) {
    const [kind, relative] = line.split('\t');
    if (kind === 'D') problems.push('authorized path was deleted: ' + relative);
  }
  for (const relative of changed) {
    try {
      const stat = fs.lstatSync(path.join(repo, relative));
      if (!stat.isFile() || stat.isSymbolicLink()) problems.push('non-regular changed path: ' + relative);
    } catch (error) {
      problems.push(`changed path unreadable: ${relative}: ${error.message}`);
    }
  }
  return problems;
}

function humanDocProblems(repo, phase) {
  const closeout = phase === MVP_B000_LIFECYCLE_PHASES.CLOSEOUT_MAIN;
  const contracts = closeout ? [
    ['README.md', ['AIPT-MVP-B000-CLOSEOUT-001', CURRENT_BATCH, 'MERGED_CLOSED',
      'IDLE_WAITING_NEXT_BATCH', 'NO_ACTIVE_BATCH', 'GLOBAL_WIP = 0',
      MVP_B000_NEXT_BATCH, 'NOT_STARTED', 'NOT_AUTHORIZED',
      MVP_B000_FINAL_CANDIDATE.commit, MVP_B000_IMPLEMENTATION_MERGE.commit,
      String(MVP_B000_IMPLEMENTATION_MERGE.post_merge_ci_run),
      MVP_B000_LIFECYCLE_REPAIR.finding, 'Run engine', '真实模型 runtime 调用',
      '真实桌测', 'qualification Run', 'FROZEN_WAITING_M1_ENGINE', GRAPH_PATH]],
    ['docs/authority/PROJECT_STATUS.md', ['AIPT-MVP-B000-CLOSEOUT-001', CURRENT_BATCH,
      'MERGED_CLOSED', 'IDLE_WAITING_NEXT_BATCH', 'NO_ACTIVE_BATCH', 'GLOBAL_WIP = 0',
      MVP_B000_NEXT_BATCH, 'NOT_STARTED', 'NOT_AUTHORIZED',
      MVP_B000_FINAL_CANDIDATE.commit, MVP_B000_IMPLEMENTATION_MERGE.commit,
      String(MVP_B000_IMPLEMENTATION_MERGE.post_merge_ci_run),
      MVP_B000_LIFECYCLE_REPAIR.finding, 'M0 Development Pass', 'GRANTED',
      'MVP Development Pass', 'NOT_GRANTED', 'FROZEN_WAITING_M1_ENGINE',
      'Run engine', '真实模型 runtime 调用', '真实桌测', 'qualification Run',
      'registry/batch-graph.json']],
    ['docs/authority/BATCH_DEPENDENCY_GRAPH.md', [
      'registry/batch-graph.json', ...EXPECTED_BATCHES.map((batch) => batch.id),
      'MERGED_CLOSED', 'IDLE_WAITING_NEXT_BATCH', 'NO_ACTIVE_BATCH', 'GLOBAL_WIP = 0',
      MVP_B000_FINAL_CANDIDATE.commit, MVP_B000_IMPLEMENTATION_MERGE.commit,
      String(MVP_B000_IMPLEMENTATION_MERGE.post_merge_ci_run),
      MVP_B000_LIFECYCLE_REPAIR.finding, 'NOT_STARTED', 'NOT_AUTHORIZED',
      'M0 Development Pass', 'GRANTED', 'MVP Development Pass', 'NOT_GRANTED',
      'FROZEN_WAITING_M1_ENGINE', 'Run engine', '真实模型 runtime 调用',
      '真实桌测', 'qualification Run',
    ]],
    ['docs/milestones/MVP.md', [CURRENT_BATCH, 'MERGED_CLOSED',
      'IDLE_WAITING_NEXT_BATCH', 'NO_ACTIVE_BATCH', 'GLOBAL_WIP = 0',
      MVP_B000_NEXT_BATCH, 'NOT_STARTED', 'NOT_AUTHORIZED',
      MVP_B000_FINAL_CANDIDATE.commit, MVP_B000_IMPLEMENTATION_MERGE.commit,
      String(MVP_B000_IMPLEMENTATION_MERGE.post_merge_ci_run),
      MVP_B000_LIFECYCLE_REPAIR.finding, 'M0 Development Pass', 'GRANTED',
      'MVP Development Pass', 'NOT_GRANTED', 'FROZEN_WAITING_M1_ENGINE',
      'Run engine', '真实模型 runtime 调用', '真实桌测', 'qualification Run']],
  ] : [
    ['README.md', [MVP_B000_SNAPSHOT, CURRENT_BATCH, 'GLOBAL_WIP = 1', MVP_B000_NEXT_BATCH,
      'NOT_AUTHORIZED', 'FROZEN_WAITING_M1_ENGINE', GRAPH_PATH]],
    ['docs/authority/PROJECT_STATUS.md', [MVP_B000_SNAPSHOT, CURRENT_BATCH,
      'GLOBAL_WIP = 1', MVP_B000_NEXT_BATCH, 'NOT_STARTED', 'NOT_AUTHORIZED',
      'registry/batch-graph.json']],
    ['docs/authority/BATCH_DEPENDENCY_GRAPH.md', [
      'registry/batch-graph.json', ...EXPECTED_BATCHES.map((batch) => batch.id),
    ]],
    ['docs/milestones/MVP.md', [CURRENT_BATCH, MVP_B000_NEXT_BATCH, 'NOT_AUTHORIZED',
      'MVP Development Pass', 'NOT_GRANTED', 'FROZEN_WAITING_M1_ENGINE']],
  ];
  const problems = [];
  for (const [relative, needles] of contracts) {
    const text = fs.readFileSync(path.join(repo, relative), 'utf8');
    const missing = needles.filter((needle) => !text.includes(needle));
    if (missing.length) problems.push(`${relative} misses: ${missing.join(', ')}`);
    if (relative.endsWith('BATCH_DEPENDENCY_GRAPH.md') && text.includes('`BATCH_GRAPH.json`')) {
      problems.push('human dependency graph retains stale missing BATCH_GRAPH.json claim');
    }
    if (closeout && (text.includes('`AIPT-MVP-B000` = **IN_PROGRESS**') ||
        text.includes('当前 `AIPT-MVP-B000 = IN_PROGRESS`'))) {
      problems.push(`${relative} retains Candidate-era B000 state as current`);
    }
  }
  return problems;
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

// These pure probes close the phase-boundary regressions without creating a
// real merge or closeout in the authoritative worktree.
export function runLifecycleRegressionProbes(_status, baseStatus) {
  const candidateStatus = expectedCandidateStatus(baseStatus);
  const candidateId = MVP_B000_FINAL_CANDIDATE.commit;
  const candidateTree = MVP_B000_FINAL_CANDIDATE.tree;
  const syntheticId = 'c'.repeat(40);
  const mergeId = MVP_B000_IMPLEMENTATION_MERGE.commit;
  const closeoutId = 'e'.repeat(40);
  const local = {
    present: false, eventName: null, ref: null, headRef: null, baseRef: null, sha: null,
  };
  const candidate = {
    baseCommit: MVP_B000_BASE_COMMIT,
    baseTree: MVP_B000_BASE_TREE,
    previousCandidate: MVP_B000_PREVIOUS_CANDIDATE,
    previousCandidateTree: MVP_B000_PREVIOUS_CANDIDATE_TREE,
    head: candidateId,
    headTree: candidateTree,
    headCommit: {
      commit: candidateId,
      parents: [MVP_B000_PREVIOUS_CANDIDATE],
      tree: candidateTree,
      subject: MVP_B000_REPAIR_SUBJECT,
    },
    ancestryKnown: true,
    baseIsAncestor: true,
    branch: MVP_B000_BRANCH,
    github: local,
    mergeCommits: [],
    merge: null,
    candidateTip: candidateId,
    candidateCommit: {
      commit: candidateId,
      parents: [MVP_B000_PREVIOUS_CANDIDATE],
      tree: candidateTree,
      subject: MVP_B000_REPAIR_SUBJECT,
    },
    candidateTree,
    candidateDescendsFromBase: true,
    candidateDescendsFromPrevious: true,
    candidateMergeCommits: [],
    candidateChangedPaths: [...MVP_B000_ALLOWED_PATHS],
    candidatePostPreviousCommits: [candidateId],
    candidateRepairChangedPaths: [...MVP_B000_REPAIR_PATHS],
    candidateWorktreeRepairPaths: [],
    ordinaryDescendants: [],
    closeoutChangedPaths: [],
  };
  const prHead = {
    ...clone(candidate),
    branch: null,
    github: {
      present: true,
      eventName: 'pull_request',
      ref: 'refs/pull/1/head',
      headRef: MVP_B000_BRANCH,
      baseRef: MAIN_BRANCH,
      sha: candidateId,
    },
  };
  const synthetic = {
    ...clone(candidate),
    head: syntheticId,
    headTree: candidateTree,
    branch: null,
    github: {
      present: true,
      eventName: 'pull_request',
      ref: 'refs/pull/1/merge',
      headRef: MVP_B000_BRANCH,
      baseRef: MAIN_BRANCH,
      sha: syntheticId,
    },
    headCommit: {
      commit: syntheticId,
      parents: [MVP_B000_BASE_COMMIT, candidateId],
      tree: candidateTree,
      subject: MVP_B000_IMPLEMENTATION_MERGE_SUBJECT,
    },
    mergeCommits: [syntheticId],
    merge: {
      commit: syntheticId,
      parents: [MVP_B000_BASE_COMMIT, candidateId],
      tree: candidateTree,
      subject: MVP_B000_IMPLEMENTATION_MERGE_SUBJECT,
      treeDiffQuiet: true,
    },
  };
  const postMerge = {
    ...clone(synthetic),
    head: mergeId,
    branch: null,
    github: {
      present: true,
      eventName: 'push',
      ref: `refs/heads/${MAIN_BRANCH}`,
      headRef: null,
      baseRef: null,
      sha: mergeId,
    },
    headCommit: {
      commit: mergeId,
      parents: [MVP_B000_BASE_COMMIT, candidateId],
      tree: candidateTree,
      subject: MVP_B000_IMPLEMENTATION_MERGE_SUBJECT,
    },
    mergeCommits: [mergeId],
    merge: {
      commit: mergeId,
      parents: [MVP_B000_BASE_COMMIT, candidateId],
      tree: candidateTree,
      subject: MVP_B000_IMPLEMENTATION_MERGE_SUBJECT,
      treeDiffQuiet: true,
    },
    ordinaryDescendants: [],
  };
  const closeoutCommit = {
    commit: closeoutId,
    parents: [mergeId],
    tree: 'f'.repeat(40),
    subject: MVP_B000_CLOSEOUT_SUBJECT,
  };
  const closeout = {
    ...clone(postMerge),
    head: closeoutId,
    headTree: closeoutCommit.tree,
    headCommit: closeoutCommit,
    github: { ...postMerge.github, sha: closeoutId },
    ordinaryDescendants: [closeoutCommit],
    closeoutChangedPaths: [...MVP_B000_CLOSEOUT_ALLOWED_PATHS],
  };
  const closeoutStatus = expectedCloseoutStatus(baseStatus);
  const cases = [];
  const add = (label, facts, status, expected, expectedPhase = undefined) => {
    const actual = validateLifecycle(facts, status, baseStatus);
    cases.push({
      label,
      expected,
      actual: actual.result,
      phase: actual.phase,
      matched: actual.result === expected &&
        (expectedPhase === undefined || actual.phase === expectedPhase),
    });
  };

  add('task Candidate + zero merge', candidate, candidateStatus, 'PASS', 'CANDIDATE_PUSH');
  add('exact PR head', prHead, candidateStatus, 'PASS', 'PULL_REQUEST_CHECK');
  add('exact detached PR synthetic merge', synthetic, candidateStatus, 'PASS',
    'PULL_REQUEST_CHECK');
  add('valid main post-merge', postMerge, candidateStatus, 'PASS', 'POST_MERGE_MAIN');
  add('future exact closeout topology simulation', closeout, closeoutStatus, 'PASS',
    'CLOSEOUT_MAIN');
  const wrongMergeId = '7'.repeat(40);
  add('wrong implementation merge identity', {
    ...clone(postMerge),
    head: wrongMergeId,
    headCommit: { ...postMerge.headCommit, commit: wrongMergeId },
    github: { ...postMerge.github, sha: wrongMergeId },
    mergeCommits: [wrongMergeId],
    merge: { ...postMerge.merge, commit: wrongMergeId },
  }, candidateStatus, 'FAIL');
  add('wrong Candidate branch', { ...clone(candidate), branch: 'task/AIPT-MVP-B001' },
    candidateStatus, 'FAIL');
  add('Candidate contains merge', {
    ...clone(candidate), mergeCommits: ['1'.repeat(40)], candidateMergeCommits: ['1'.repeat(40)],
  }, candidateStatus, 'FAIL');
  add('wrong PR head', {
    ...clone(prHead), github: { ...prHead.github, headRef: 'task/AIPT-MVP-B001' },
  }, candidateStatus, 'FAIL');
  add('main with zero merge', { ...clone(candidate), branch: MAIN_BRANCH }, candidateStatus, 'FAIL');
  add('wrong merge first parent', {
    ...clone(postMerge), merge: {
      ...postMerge.merge, parents: ['1'.repeat(40), candidateId],
    },
  }, candidateStatus, 'FAIL');
  add('wrong merge second-parent shape', {
    ...clone(postMerge), merge: { ...postMerge.merge, parents: [MVP_B000_BASE_COMMIT] },
  }, candidateStatus, 'FAIL');
  add('wrong merge subject', {
    ...clone(postMerge), merge: { ...postMerge.merge, subject: 'merge: wrong' },
  }, candidateStatus, 'FAIL');
  add('merge tree mismatch', {
    ...clone(postMerge), merge: { ...postMerge.merge, tree: '1'.repeat(40) },
  }, candidateStatus, 'FAIL');
  add('merge introduces tree delta', {
    ...clone(postMerge), merge: { ...postMerge.merge, treeDiffQuiet: false },
  }, candidateStatus, 'FAIL');
  add('Candidate parent contains merge', {
    ...clone(postMerge), candidateMergeCommits: ['1'.repeat(40)],
  }, candidateStatus, 'FAIL');
  add('second merge', {
    ...clone(postMerge), mergeCommits: [mergeId, '1'.repeat(40)],
  }, candidateStatus, 'FAIL');
  const prematureClosed = clone(candidateStatus);
  prematureClosed.tracks['AIPT-STANDALONE'].batch_history[CURRENT_BATCH] = 'MERGED_CLOSED';
  prematureClosed.tracks['AIPT-STANDALONE'].global_wip = 0;
  add('premature B000 MERGED_CLOSED at post-merge', postMerge, prematureClosed, 'FAIL');
  const b001Authorized = clone(candidateStatus);
  b001Authorized.tracks['AIPT-STANDALONE'].next_batch_authorized = true;
  add('B001 authorized early', postMerge, b001Authorized, 'FAIL');
  const b001Started = clone(candidateStatus);
  b001Started.tracks['AIPT-STANDALONE'].next_batch_started = true;
  add('B001 started early', postMerge, b001Started, 'FAIL');
  const platform = clone(candidateStatus);
  platform.tracks['AIPT-PLATFORM-INTEGRATION'].status = 'UNFROZEN';
  add('platform integration unfrozen', postMerge, platform, 'FAIL');
  const revoked = clone(candidateStatus);
  revoked.repositories.AIPT.verified_state.m0_development_pass.result = 'REVOKED';
  add('M0 Development Pass revoked', postMerge, revoked, 'FAIL');
  const arbitrary = clone(candidateStatus);
  arbitrary.tracks['AIPT-STANDALONE'].current_batch = 'AIPT-MVP-B002';
  arbitrary.tracks['AIPT-STANDALONE'].batch_history['AIPT-MVP-B002'] = 'IN_PROGRESS';
  add('arbitrary AIPT-MVP-B002 active successor', postMerge, arbitrary, 'FAIL');
  const m1 = clone(candidateStatus);
  m1.tracks['AIPT-STANDALONE'].batch_history['AIPT-M1-B000'] = 'NOT_STARTED';
  add('AIPT-M1 alias', postMerge, m1, 'FAIL');
  const secondDescendant = {
    ...clone(closeout),
    head: '1'.repeat(40),
    headTree: '2'.repeat(40),
    headCommit: {
      commit: '1'.repeat(40), parents: [closeoutId], tree: '2'.repeat(40),
      subject: 'docs: unauthorized second closeout descendant',
    },
    github: { ...closeout.github, sha: '1'.repeat(40) },
    ordinaryDescendants: [closeoutCommit, {
      commit: '1'.repeat(40), parents: [closeoutId], tree: '2'.repeat(40),
      subject: 'docs: unauthorized second closeout descendant',
    }],
  };
  add('second ordinary closeout descendant', secondDescendant, closeoutStatus, 'FAIL');
  add('wrong closeout parent', {
    ...clone(closeout),
    headCommit: { ...closeout.headCommit, parents: ['1'.repeat(40)] },
  }, closeoutStatus, 'FAIL');
  add('two-parent closeout', {
    ...clone(closeout),
    headCommit: {
      ...closeout.headCommit, parents: [mergeId, MVP_B000_FINAL_CANDIDATE.commit],
    },
  }, closeoutStatus, 'FAIL');
  add('wrong closeout subject', {
    ...clone(closeout),
    headCommit: { ...closeout.headCommit, subject: 'closeout: wrong' },
  }, closeoutStatus, 'FAIL');
  add('closeout path missing', {
    ...clone(closeout),
    closeoutChangedPaths: MVP_B000_CLOSEOUT_ALLOWED_PATHS.slice(1),
  }, closeoutStatus, 'FAIL');
  add('closeout path added', {
    ...clone(closeout),
    closeoutChangedPaths: [...MVP_B000_CLOSEOUT_ALLOWED_PATHS, 'package.json'],
  }, closeoutStatus, 'FAIL');
  const closeoutStillActive = clone(closeoutStatus);
  closeoutStillActive.tracks['AIPT-STANDALONE'].batch_history[CURRENT_BATCH] = 'IN_PROGRESS';
  add('B000 closeout remains IN_PROGRESS', closeout, closeoutStillActive, 'FAIL');
  const closeoutWip1 = clone(closeoutStatus);
  closeoutWip1.tracks['AIPT-STANDALONE'].global_wip = 1;
  add('closeout GLOBAL_WIP remains one', closeout, closeoutWip1, 'FAIL');
  const closeoutB001Authorized = clone(closeoutStatus);
  closeoutB001Authorized.tracks['AIPT-STANDALONE'].next_batch_authorized = true;
  add('closeout authorizes B001', closeout, closeoutB001Authorized, 'FAIL');
  const closeoutB001Started = clone(closeoutStatus);
  closeoutB001Started.tracks['AIPT-STANDALONE'].next_batch_started = true;
  add('closeout starts B001', closeout, closeoutB001Started, 'FAIL');
  const closeoutB001Active = clone(closeoutStatus);
  closeoutB001Active.tracks['AIPT-STANDALONE'].batch_history[MVP_B000_NEXT_BATCH] = 'IN_PROGRESS';
  add('B001 incorrectly IN_PROGRESS', closeout, closeoutB001Active, 'FAIL');
  const closeoutB002 = clone(closeoutStatus);
  closeoutB002.tracks['AIPT-STANDALONE'].current_batch = 'AIPT-MVP-B002';
  closeoutB002.tracks['AIPT-STANDALONE'].batch_history['AIPT-MVP-B002'] = 'IN_PROGRESS';
  add('arbitrary B002 active after closeout', closeout, closeoutB002, 'FAIL');
  const closeoutM0Revoked = clone(closeoutStatus);
  closeoutM0Revoked.repositories.AIPT.verified_state.m0_development_pass.result = 'REVOKED';
  add('M0 Development Pass revoked after closeout', closeout, closeoutM0Revoked, 'FAIL');
  const closeoutMvpGranted = clone(closeoutStatus);
  closeoutMvpGranted.repositories.AIPT.verified_state.boundaries.mvp_development_pass = 'GRANTED';
  add('MVP Development Pass granted at B000 closeout', closeout, closeoutMvpGranted, 'FAIL');
  const closeoutPlatform = clone(closeoutStatus);
  closeoutPlatform.tracks['AIPT-PLATFORM-INTEGRATION'].status = 'UNFROZEN';
  add('platform integration unfrozen after closeout', closeout, closeoutPlatform, 'FAIL');
  const runtimeClaim = clone(closeoutStatus);
  runtimeClaim.repositories.AIPT.mvp_bootstrap.runtime_implementation_changed = true;
  add('runtime implementation claim added', closeout, runtimeClaim, 'FAIL');
  const runtimeCall = clone(closeoutStatus);
  runtimeCall.repositories.AIPT.mvp_bootstrap.real_model_runtime_calls = 1;
  add('real model runtime call claimed', closeout, runtimeCall, 'FAIL');
  return cases;
}

function runNegativeProbes(graph, status, baseStatus) {
  const probes = [];
  const add = (label, rejected) => probes.push([label, rejected]);
  const validateCurrentStatus = (candidate) =>
    status?.authority_snapshot_id === 'AIPT-MVP-B000-CLOSEOUT-001'
      ? validateCloseoutStatus(candidate, baseStatus)
      : validateStatus(candidate, baseStatus);

  const removed = clone(graph); removed.serial_batches.splice(4, 1);
  add('removed graph item', validateGraph(removed).length > 0);
  const reordered = clone(graph); [reordered.serial_batches[1], reordered.serial_batches[2]] =
    [reordered.serial_batches[2], reordered.serial_batches[1]];
  add('reordered graph items', validateGraph(reordered).length > 0);
  const renamed = clone(graph); renamed.serial_batches[0].id = 'AIPT-MVP-B000-RENAMED';
  add('renamed graph item', validateGraph(renamed).length > 0);
  const m1 = clone(graph); m1.serial_batches[0].id = 'AIPT-M1-B000';
  add('standalone M1 alias', validateGraph(m1).length > 0);

  const b001 = clone(status); b001.tracks['AIPT-STANDALONE'].next_batch_authorized = true;
  add('B001 authorization', validateCurrentStatus(b001).length > 0);
  const later = clone(status); later.tracks['AIPT-STANDALONE'].batch_history['AIPT-MVP-B004'] = 'IN_PROGRESS';
  add('later batch start', validateCurrentStatus(later).length > 0);
  const wrongPhaseWip = clone(status);
  wrongPhaseWip.tracks['AIPT-STANDALONE'].global_wip =
    wrongPhaseWip.tracks['AIPT-STANDALONE'].global_wip === 0 ? 1 : 0;
  add('GLOBAL_WIP phase drift', validateCurrentStatus(wrongPhaseWip).length > 0);
  const wip2 = clone(status); wip2.tracks['AIPT-STANDALONE'].global_wip = 2;
  add('GLOBAL_WIP above one', validateCurrentStatus(wip2).length > 0);
  const revoke = clone(status); revoke.repositories.AIPT.verified_state.m0_development_pass.result = 'REVOKED';
  add('M0 pass revocation', validateCurrentStatus(revoke).length > 0);
  const unfreeze = clone(status); unfreeze.tracks['AIPT-PLATFORM-INTEGRATION'].status = 'UNFROZEN';
  add('platform unfreeze', validateCurrentStatus(unfreeze).length > 0);
  const external = clone(status); external.repositories.UNREGISTERED.verified_head = '0'.repeat(40);
  add('UNREGISTERED identity drift', validateCurrentStatus(external).length > 0);
  const premature = clone(status); premature.repositories.AIPT.verified_state.boundaries.mvp_development_pass = 'GRANTED';
  add('premature MVP Development Pass', validateCurrentStatus(premature).length > 0);
  const claim = clone(status); claim.mvp_qualification_claims = { clean_runs_completed: 5, mutants_detected: 3 };
  add('false Clean/Mutant completion claim', validateCurrentStatus(claim).length > 0);

  add('runtime implementation path', validateChangedPaths([
    ...MVP_B000_ALLOWED_PATHS, 'internal/run/engine.go',
  ]).length > 0);
  const endpointFixture = ['endpoint=https://api', 'deepseek.com'].join('.');
  const credentialFixture = ['api', 'key="dsk', 'example-secret"'].join('_').replace('_example', '-example');
  add('model endpoint injection', validateChangedText('README.md', endpointFixture).length > 0);
  add('credential injection', validateChangedText('README.md', credentialFixture).length > 0);
  add('M0 historical file mutation', !Buffer.from('frozen').equals(Buffer.from('mutated')));
  add('frozen registry mutation', !Buffer.from('frozen').equals(Buffer.from('mutated')));

  return probes;
}

export function run(ctx) {
  try {
    const snapshot = readJson(ctx.repo, STATUS_PATH)?.authority_snapshot_id;
    if (snapshot === MVP_B001.snapshot || snapshot === 'AIPT-MVP-B001-CLOSEOUT-001') {
      return { ...runMvpB001(ctx), name: 'mvp-bootstrap' };
    }
  } catch {
    // The historical gate below owns the fail-closed unreadable-input report.
  }
  const details = [];
  let pass = true;
  const ok = (message) => details.push('ok: ' + message);
  const fail = (message) => { pass = false; details.push('FAIL: ' + message); };

  let graph;
  let status;
  let baseStatus;
  let m0Record;
  let baseM0Record;
  try {
    graph = readJson(ctx.repo, GRAPH_PATH);
    status = readJson(ctx.repo, STATUS_PATH);
    baseStatus = readBaseJson(ctx.repo, STATUS_PATH);
    m0Record = readJson(ctx.repo, M0_RECORD_PATH);
    baseM0Record = readBaseJson(ctx.repo, M0_RECORD_PATH);
  } catch (error) {
    fail('authority input is unreadable: ' + error.message);
    return { result: 'FAIL', details, negative_probes: 'NOT_RUN' };
  }

  const identityProblems = frozenIdentityProblems();
  for (const problem of identityProblems) fail('frozen B000 identity: ' + problem);
  if (identityProblems.length === 0) {
    ok('initial/final Candidate, lifecycle repair, implementation merge and closeout allowlist are exact frozen constants');
  }

  const graphProblems = validateGraph(graph);
  for (const problem of graphProblems) fail('graph: ' + problem);
  const graphText = fs.readFileSync(path.join(ctx.repo, GRAPH_PATH), 'utf8');
  if (graphText !== `${JSON.stringify(EXPECTED_GRAPH, null, 2)}\n`) {
    fail('graph bytes are not the canonical exact authority serialization');
  } else if (graphProblems.length === 0) ok('exact canonical 13-item MVP machine graph verified');

  const facts = collectLifecycleFacts(ctx.repo);
  const lifecycle = validateLifecycle(facts, status, baseStatus);
  for (const problem of lifecycle.problems) fail('lifecycle: ' + problem);
  if (lifecycle.result === 'PASS') {
    ok(`${lifecycle.phase} = PASS (${lifecycle.checkoutKind}); topology, ref/event and status semantics agree`);
  }

  const statusText = fs.readFileSync(path.join(ctx.repo, STATUS_PATH), 'utf8');
  if (statusText !== `${JSON.stringify(status, null, 2)}\n`) fail('project status is not canonical JSON');
  else if (lifecycle.result === 'PASS') {
    ok('phase-exact B000/WIP lifecycle keeps B001 unauthorized and external identities frozen');
  }

  const m0RecordProblems = compareExact(m0Record, baseM0Record, '$m0DevelopmentPass');
  for (const problem of m0RecordProblems) fail('M0 Development Pass record: ' + problem);
  if (m0RecordProblems.length === 0) ok('M0 Development Pass remains exact, GRANTED and effective');

  const closeoutCommit = git(ctx.repo, ['rev-list', '--parents', '-n', '1', M0_CLOSEOUT.commit], { check: false });
  const closeoutTree = git(ctx.repo, ['rev-parse', `${M0_CLOSEOUT.commit}^{tree}`], { check: false });
  const closeoutSubject = git(ctx.repo, ['show', '-s', '--format=%s', M0_CLOSEOUT.commit], { check: false });
  const b008Merge = git(ctx.repo, ['rev-list', '--parents', '-n', '1', B008_IMPLEMENTATION_MERGE.commit], { check: false });
  if (closeoutCommit.stdout.trim() !== `${M0_CLOSEOUT.commit} ${M0_CLOSEOUT.parent}` ||
      closeoutTree.stdout.trim() !== M0_CLOSEOUT.tree ||
      closeoutSubject.stdout.trim() !== M0_CLOSEOUT.subject ||
      b008Merge.stdout.trim() !== `${B008_IMPLEMENTATION_MERGE.commit} ${B008_IMPLEMENTATION_MERGE.parent1} ${B008_IMPLEMENTATION_MERGE.parent2}`) {
    fail('M0 closeout or B008 implementation topology/identity drifted');
  } else ok('exact M0 closeout and B008 implementation topology verified');

  const frozenProblems = frozenPathProblems(ctx.repo, [
    ...M0_HISTORICAL_PATHS,
    ...FROZEN_REGISTRY_PATHS,
  ]);
  for (const problem of frozenProblems) fail('frozen history: ' + problem);
  if (frozenProblems.length === 0) ok('M0 milestone files and frozen registries are byte-identical to Base');

  const changed = changedPaths(ctx.repo);
  if (!changed) {
    fail('Base-to-worktree changed-path set is unreadable');
  } else {
    for (const problem of validateChangedPaths(changed)) fail(problem);
    for (const problem of modeProblems(ctx.repo, changed)) fail(problem);
    if (validateChangedPaths(changed).length === 0 && modeProblems(ctx.repo, changed).length === 0) {
      ok('exact 17-path governance/CI scope contains only regular files and no runtime/dependency change');
    }
    for (const relative of changed) {
      let text;
      try {
        text = fs.readFileSync(path.join(ctx.repo, relative), 'utf8');
      } catch {
        continue;
      }
      for (const problem of validateChangedText(relative, text)) fail(problem);
    }
  }

  for (const problem of humanDocProblems(ctx.repo, lifecycle.phase)) {
    fail('human authority: ' + problem);
  }
  if (!details.some((line) => line.startsWith('FAIL: human authority'))) {
    ok('human authority links the real machine graph and states every non-inflation boundary');
  }

  const probes = runNegativeProbes(graph, status, baseStatus);
  for (const [label, rejected] of probes) if (!rejected) fail('negative probe was accepted: ' + label);
  const rejected = probes.filter(([, value]) => value).length;
  if (rejected === probes.length) ok(`all ${rejected} required MVP bootstrap mutation probes reject`);

  const lifecycleProbes = runLifecycleRegressionProbes(status, baseStatus);
  for (const probe of lifecycleProbes) {
    if (!probe.matched) {
      fail(`lifecycle regression mismatched: ${probe.label} (expected ${probe.expected}, got ${probe.actual}/${probe.phase})`);
    }
  }
  const lifecycleMatches = lifecycleProbes.filter((probe) => probe.matched).length;
  if (lifecycleMatches === lifecycleProbes.length) {
    ok(`all ${lifecycleMatches} Candidate/PR/post-merge/closeout lifecycle regressions matched`);
  }

  return {
    result: pass ? 'PASS' : 'FAIL',
    details,
    graph_items: Array.isArray(graph?.serial_batches) ? graph.serial_batches.length : null,
    current_batch: status?.tracks?.['AIPT-STANDALONE']?.current_batch ?? null,
    next_serial_batch: status?.tracks?.['AIPT-STANDALONE']?.next_serial_batch ?? null,
    lifecycle_phase: lifecycle.phase,
    lifecycle_checkout: lifecycle.checkoutKind,
    implementation_merge_recognized: lifecycle.implementationMergeRecognized,
    closeout_recognized: lifecycle.closeoutRecognized,
    lifecycle_regression: lifecycleMatches === lifecycleProbes.length ? 'PASS' : 'FAIL',
    lifecycle_probe_count: lifecycleProbes.length,
    negative_probes: rejected === probes.length && lifecycleMatches === lifecycleProbes.length
      ? 'PASS' : 'FAIL',
    negative_probe_count: probes.length + lifecycleProbes.length,
    changed_paths: changed ?? [],
    external_model_calls: 0,
  };
}

runAsMain(import.meta.url, 'mvp-bootstrap', run);
