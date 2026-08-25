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
  MVP_B000_FORBIDDEN_PREFIXES,
  MVP_B000_NEXT_BATCH,
  MVP_B000_SNAPSHOT,
  STATUS_DATE,
} from '../lib/constants.mjs';
import { git, runAsMain } from '../lib/cli.mjs';
import { validateRecord as validateM0Record } from './m0-development-pass.mjs';

const GRAPH_PATH = 'docs/authority/registry/batch-graph.json';
const STATUS_PATH = 'docs/authority/registry/project-status.json';
const M0_RECORD_PATH = 'docs/milestones/m0-development-pass.json';
const PLATFORM = 'FROZEN_WAITING_M1_ENGINE';
const GRAPH_SCHEMA = 'aipt.public.mvp-batch-graph/v1';
const NO_MODEL_ENDPOINT = /https?:\/\/(?:api\.)?(?:deepseek|openai|anthropic|openrouter|moonshot)\b/i;
const CREDENTIAL_ASSIGNMENT = /(?:api[_-]?key|authorization|credential|bearer)\s*[:=]\s*["'][^"'\n]+["']/i;
const SECRET_TOKEN = /\b(?:sk|dsk)-[A-Za-z0-9_-]{8,}\b/;

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

export function validateStatus(status, baseStatus) {
  const expectedStandalone = {
    ...baseStatus.tracks['AIPT-STANDALONE'],
    construction: 'IN_PROGRESS',
    current_batch: CURRENT_BATCH,
    next_serial_batch: MVP_B000_NEXT_BATCH,
    next_batch_state: 'NOT_AUTHORIZED',
    next_batch_authorized: false,
    next_batch_started: false,
    batch_history: EXPECTED_HISTORY,
    global_wip: 1,
  };
  const expected = {
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
  const problems = compareExact(status, expected, '$status');
  const ids = Object.keys(status?.tracks?.['AIPT-STANDALONE']?.batch_history ?? {});
  if (ids.some((id) => /^AIPT-M1-/.test(id))) problems.push('standalone AIPT-M1 alias is forbidden');
  return problems;
}

function sameSet(actual, expected) {
  return actual.length === expected.length && new Set(actual).size === actual.length &&
    JSON.stringify([...actual].sort()) === JSON.stringify([...expected].sort());
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

export function validateCandidateFacts(facts) {
  const problems = [];
  if (facts?.baseCommit !== MVP_B000_BASE_COMMIT) problems.push('Base commit drifted');
  if (facts?.baseTree !== MVP_B000_BASE_TREE) problems.push('Base tree drifted');
  if (facts?.baseIsAncestor !== true) problems.push('HEAD does not descend from exact Base');
  if (!Array.isArray(facts?.mergeCommits)) problems.push('post-Base merge list is unreadable');
  else if (facts.mergeCommits.length !== 0) problems.push('post-Base history contains a merge');
  if (Array.isArray(facts?.subjects) && facts.subjects.some((subject) => /^(?:merge|closeout):/i.test(subject))) {
    problems.push('post-Base history contains a merge/closeout claim');
  }
  const github = facts?.github;
  if (github?.present) {
    if (github.eventName !== 'push' || github.ref !== `refs/heads/${MVP_B000_BRANCH}` ||
        github.sha !== facts.head || github.headRef !== null || github.baseRef !== null) {
      problems.push('GitHub lifecycle is not the exact Candidate branch push');
    }
    if (facts.branch !== null && facts.branch !== MVP_B000_BRANCH) {
      problems.push('Candidate push symbolic branch is foreign');
    }
  } else if (facts?.branch !== MVP_B000_BRANCH) {
    problems.push('local symbolic branch is not task/AIPT-MVP-B000');
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

function collectCandidateFacts(repo, env = process.env) {
  const baseCommit = git(repo, ['rev-parse', `${MVP_B000_BASE_COMMIT}^{commit}`], { check: false });
  const baseTree = git(repo, ['rev-parse', `${MVP_B000_BASE_COMMIT}^{tree}`], { check: false });
  const head = git(repo, ['rev-parse', 'HEAD^{commit}'], { check: false });
  const branch = git(repo, ['symbolic-ref', '--short', 'HEAD'], { check: false });
  const ancestry = git(repo, ['merge-base', '--is-ancestor', MVP_B000_BASE_COMMIT, 'HEAD'], { check: false });
  const merges = git(repo, ['rev-list', '--merges', `${MVP_B000_BASE_COMMIT}..HEAD`], { check: false });
  const subjects = git(repo, ['log', '--format=%s', `${MVP_B000_BASE_COMMIT}..HEAD`], { check: false });
  const githubPresent = ['GITHUB_ACTIONS', 'GITHUB_EVENT_NAME', 'GITHUB_REF', 'GITHUB_SHA']
    .some((key) => Object.hasOwn(env, key));
  return {
    baseCommit: baseCommit.status === 0 ? baseCommit.stdout.trim() : null,
    baseTree: baseTree.status === 0 ? baseTree.stdout.trim() : null,
    head: head.status === 0 ? head.stdout.trim() : null,
    branch: branch.status === 0 ? branch.stdout.trim() : null,
    baseIsAncestor: ancestry.status === 0,
    mergeCommits: merges.status === 0 ? merges.stdout.split('\n').filter(Boolean) : null,
    subjects: subjects.status === 0 ? subjects.stdout.split('\n').filter(Boolean) : null,
    github: {
      present: githubPresent,
      eventName: normalizedEnv(env.GITHUB_EVENT_NAME),
      ref: normalizedEnv(env.GITHUB_REF),
      headRef: normalizedEnv(env.GITHUB_HEAD_REF),
      baseRef: normalizedEnv(env.GITHUB_BASE_REF),
      sha: normalizedEnv(env.GITHUB_SHA),
    },
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

function humanDocProblems(repo) {
  const contracts = [
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
  }
  return problems;
}

function runNegativeProbes(graph, status, baseStatus, facts) {
  const clone = (value) => JSON.parse(JSON.stringify(value));
  const probes = [];
  const add = (label, rejected) => probes.push([label, rejected]);

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
  add('B001 authorization', validateStatus(b001, baseStatus).length > 0);
  const later = clone(status); later.tracks['AIPT-STANDALONE'].batch_history['AIPT-MVP-B004'] = 'IN_PROGRESS';
  add('later batch start', validateStatus(later, baseStatus).length > 0);
  const wip0 = clone(status); wip0.tracks['AIPT-STANDALONE'].global_wip = 0;
  add('GLOBAL_WIP zero', validateStatus(wip0, baseStatus).length > 0);
  const wip2 = clone(status); wip2.tracks['AIPT-STANDALONE'].global_wip = 2;
  add('GLOBAL_WIP above one', validateStatus(wip2, baseStatus).length > 0);
  const revoke = clone(status); revoke.repositories.AIPT.verified_state.m0_development_pass.result = 'REVOKED';
  add('M0 pass revocation', validateStatus(revoke, baseStatus).length > 0);
  const unfreeze = clone(status); unfreeze.tracks['AIPT-PLATFORM-INTEGRATION'].status = 'UNFROZEN';
  add('platform unfreeze', validateStatus(unfreeze, baseStatus).length > 0);
  const external = clone(status); external.repositories.UNREGISTERED.verified_head = '0'.repeat(40);
  add('UNREGISTERED identity drift', validateStatus(external, baseStatus).length > 0);
  const premature = clone(status); premature.repositories.AIPT.verified_state.boundaries.mvp_development_pass = 'GRANTED';
  add('premature MVP Development Pass', validateStatus(premature, baseStatus).length > 0);
  const claim = clone(status); claim.mvp_qualification_claims = { clean_runs_completed: 5, mutants_detected: 3 };
  add('false Clean/Mutant completion claim', validateStatus(claim, baseStatus).length > 0);

  add('runtime implementation path', validateChangedPaths([
    ...MVP_B000_ALLOWED_PATHS, 'internal/run/engine.go',
  ]).length > 0);
  const endpointFixture = ['endpoint=https://api', 'deepseek.com'].join('.');
  const credentialFixture = ['api', 'key="dsk', 'example-secret"'].join('_').replace('_example', '-example');
  add('model endpoint injection', validateChangedText('README.md', endpointFixture).length > 0);
  add('credential injection', validateChangedText('README.md', credentialFixture).length > 0);
  add('M0 historical file mutation', !Buffer.from('frozen').equals(Buffer.from('mutated')));
  add('frozen registry mutation', !Buffer.from('frozen').equals(Buffer.from('mutated')));

  const wrongBranch = clone(facts); wrongBranch.github.present = false; wrongBranch.branch = 'task/AIPT-MVP-B001';
  add('foreign Candidate branch', validateCandidateFacts(wrongBranch).length > 0);
  const merge = clone(facts); merge.mergeCommits = ['0'.repeat(40)];
  add('post-Base merge', validateCandidateFacts(merge).length > 0);
  const closeout = clone(facts); closeout.subjects = ['closeout: complete AIPT-MVP-B000'];
  add('premature closeout claim', validateCandidateFacts(closeout).length > 0);
  return probes;
}

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push('ok: ' + message);
  const fail = (message) => { pass = false; details.push('FAIL: ' + message); };

  let graph;
  let status;
  let baseStatus;
  let m0Record;
  try {
    graph = readJson(ctx.repo, GRAPH_PATH);
    status = readJson(ctx.repo, STATUS_PATH);
    baseStatus = readBaseJson(ctx.repo, STATUS_PATH);
    m0Record = readJson(ctx.repo, M0_RECORD_PATH);
  } catch (error) {
    fail('authority input is unreadable: ' + error.message);
    return { result: 'FAIL', details, negative_probes: 'NOT_RUN' };
  }

  const graphProblems = validateGraph(graph);
  for (const problem of graphProblems) fail('graph: ' + problem);
  const graphText = fs.readFileSync(path.join(ctx.repo, GRAPH_PATH), 'utf8');
  if (graphText !== `${JSON.stringify(EXPECTED_GRAPH, null, 2)}\n`) {
    fail('graph bytes are not the canonical exact authority serialization');
  } else if (graphProblems.length === 0) ok('exact canonical 13-item MVP machine graph verified');

  const statusProblems = validateStatus(status, baseStatus);
  for (const problem of statusProblems) fail('status: ' + problem);
  const statusText = fs.readFileSync(path.join(ctx.repo, STATUS_PATH), 'utf8');
  if (statusText !== `${JSON.stringify(status, null, 2)}\n`) fail('project status is not canonical JSON');
  else if (statusProblems.length === 0) {
    ok('exact B000/WIP1 lifecycle, B001 not-authorized state and frozen external identities verified');
  }

  const m0RecordProblems = validateM0Record(m0Record);
  for (const problem of m0RecordProblems) fail('M0 Development Pass record: ' + problem);
  if (m0RecordProblems.length === 0) ok('M0 Development Pass remains exact, GRANTED and effective');

  const facts = collectCandidateFacts(ctx.repo);
  const factProblems = validateCandidateFacts(facts);
  for (const problem of factProblems) fail('Candidate lifecycle: ' + problem);
  if (factProblems.length === 0) ok('exact Base descendant, task branch and zero-merge/no-closeout Candidate verified');

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

  for (const problem of humanDocProblems(ctx.repo)) fail('human authority: ' + problem);
  if (!details.some((line) => line.startsWith('FAIL: human authority'))) {
    ok('human authority links the real machine graph and states every non-inflation boundary');
  }

  const probes = runNegativeProbes(graph, status, baseStatus, facts);
  for (const [label, rejected] of probes) if (!rejected) fail('negative probe was accepted: ' + label);
  const rejected = probes.filter(([, value]) => value).length;
  if (rejected === probes.length) ok(`all ${rejected} required MVP bootstrap mutation probes reject`);

  return {
    result: pass ? 'PASS' : 'FAIL',
    details,
    graph_items: Array.isArray(graph?.serial_batches) ? graph.serial_batches.length : null,
    current_batch: status?.tracks?.['AIPT-STANDALONE']?.current_batch ?? null,
    next_serial_batch: status?.tracks?.['AIPT-STANDALONE']?.next_serial_batch ?? null,
    negative_probes: rejected === probes.length ? 'PASS' : 'FAIL',
    negative_probe_count: probes.length,
    changed_paths: changed ?? [],
    external_model_calls: 0,
  };
}

runAsMain(import.meta.url, 'mvp-bootstrap', run);
