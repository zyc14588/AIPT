#!/usr/bin/env node
// AIPT-M0-B008 lifecycle/tree/scope validator.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  ALLOWED_PATHS, B004_CANDIDATE, B004_CLOSEOUT,
  B004_CONSTRUCTION_CHECKPOINT, B004_IMPLEMENTATION_MERGE,
  B004_POST_MERGE_REPAIR, B005_CANDIDATE, B005_CLOSEOUT,
  B005_IMPLEMENTATION_MERGE, B006_CANDIDATE, B006_CLOSEOUT,
  B006_IMPLEMENTATION_MERGE, B007_CANDIDATE, B007_CANDIDATE_HISTORY, B007_CLOSEOUT,
  B007_IMPLEMENTATION_MERGE, B007_ORIGINAL_CANDIDATE, B007_REPAIR,
  B008_CANDIDATE_HISTORY, B008_CLOSEOUT_SUBJECT, B008_FINAL_CANDIDATE,
  B008_IMPLEMENTATION_MERGE, B008_INITIAL_CANDIDATE, B008_LIFECYCLE_REPAIR,
  B008_MERGE_SUBJECT, BASE_COMMIT, BASE_TREE,
  CLOSEOUT_ALLOWED_PATHS, EXPECTED_MIT_LICENSE, FORBIDDEN_PREFIXES,
  FROZEN_REGISTRY_PATHS, M0_CLOSEOUT, M0_HISTORICAL_PATHS,
  MVP_B000_ALLOWED_PATHS, MVP_B000_BASE_COMMIT, MVP_B000_BASE_TREE,
  MVP_B000_FORBIDDEN_PREFIXES, MVP_B000_SNAPSHOT, MVP_B001, normalizeText,
  pathMatchesAllowed, pathMatchesCloseoutAllowed,
} from '../lib/constants.mjs';
import { collectMarkdownLinkIssues, scanTreeForHazards, walkFiles } from '../lib/scan.mjs';
import { git, runAsMain } from '../lib/cli.mjs';
import {
  collectLifecycleFacts as collectMvpB000LifecycleFacts,
  runLifecycleRegressionProbes as runMvpB000LifecycleRegressionProbes,
  validateChangedPaths,
  validateLifecycle as validateMvpB000Lifecycle,
} from './mvp-bootstrap.mjs';
import { run as runMvpB001 } from './mvp-b001.mjs';

const MVP_STATUS_PATH = 'docs/authority/registry/project-status.json';

const ALLOWED_PATHS_LITERAL = [
  '.github/workflows/ci.yml',
  'README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'docs/milestones/M0.md',
  'docs/milestones/M0_DEVELOPMENT_PASS.md',
  'docs/milestones/m0-development-pass.json',
  'package.json',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/m0-development-pass.mjs',
  'scripts/ci/validate/standalone-entrypoints.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
  'scripts/ci/validate/workflow.mjs',
];
const CLOSEOUT_ALLOWED_PATHS_LITERAL = [
  '.github/workflows/ci.yml',
  'README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'docs/milestones/M0.md',
  'docs/milestones/M0_DEVELOPMENT_PASS.md',
  'docs/milestones/m0-development-pass.json',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/m0-development-pass.mjs',
  'scripts/ci/validate/standalone-entrypoints.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
  'scripts/ci/validate/workflow.mjs',
];
const FORBIDDEN_PREFIXES_LITERAL = [
  'cmd/',
  'internal/',
  'packages/',
  'schemas/',
  'testdata/',
  'tools/',
  'scripts/ci/sbom/',
  'scripts/ci/validate/sbom.mjs',
  'scripts/ci/validate/supply-chain.mjs',
  'docs/architecture/',
  'docs/integration/',
  'docs/test-model/',
  '.go-version',
  'go.mod',
  'go.sum',
  'LICENSE',
  'pnpm-lock.yaml',
  'pnpm-workspace.yaml',
  'tools/toolchain.lock.json',
  'tools/ci-actions.lock.json',
  'tools/supply-chain/policy.json',
  'tools/supply-chain/licenses.json',
];
const FROZEN_REGISTRY_PATHS_LITERAL = [
  'docs/authority/registry/decisions.json',
  'docs/authority/registry/supersessions.json',
  'docs/authority/registry/deferred-parameters.json',
];
const FROZEN_FILES = [
  '.go-version', 'go.mod', 'go.sum', 'LICENSE', 'pnpm-lock.yaml',
  'pnpm-workspace.yaml', 'tools/toolchain.lock.json',
  'tools/ci-actions.lock.json', 'tools/supply-chain/policy.json',
  'tools/supply-chain/licenses.json', ...FROZEN_REGISTRY_PATHS_LITERAL,
];
const FALSE_ALLOWLIST_PROBES = [
  'internal/model/runtime.go',
  'packages/web-ui/src/dashboard.ts',
  'schemas/protocol/v1/aipt-protocol.schema.json',
  'testdata/evidence/v1/manifest.json',
  'tools/toolchain.lock.json',
  'pnpm-lock.yaml',
  'docs/milestones/M0_DEVELOPMENT_PASS.md.bak',
  'scripts/ci/validate/m0-development-pass.mjs.bak',
  'AIPT-M1-B000/README.md',
];
const FALSE_CLOSEOUT_ALLOWLIST_PROBES = [
  'package.json',
  '.github/workflows/other.yml',
  'scripts/ci/validate/supply-chain.mjs',
  'internal/model/runtime.go',
  'README.md.bak',
];

function same(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function isGeneratedWorktreeArtifact(relative) {
  return relative.split('/').includes('node_modules');
}

// Candidate history is identified by the frozen implementation merge's second
// parent. The validator enforces the exact zero-delta merge and the sole
// Owner-authorized single-parent closeout descendant.
export function evaluateB008Lifecycle(input) {
  const problems = [];
  if (input?.baseCommit !== BASE_COMMIT) problems.push('base commit drifted');
  if (input?.baseTree !== BASE_TREE) problems.push('base tree drifted');
  if (input?.ancestryKnown !== true) problems.push('HEAD ancestry is unknown');
  if (input?.baseIsAncestor !== true) problems.push('HEAD does not descend from the B008 base');
  if (!Array.isArray(input?.candidateMergeCommits)) problems.push('Candidate merge list is unreadable');
  else if (input.candidateMergeCommits.length !== 0) problems.push('Candidate history contains a merge');
  if (!Array.isArray(input?.mergeCommits)) problems.push('post-base merge list is unreadable');
  if (problems.length > 0) return { result: 'FAIL', phase: 'UNKNOWN', problems };

  if (input.mergeCommits.length === 0) {
    if (input.candidateTip !== B008_FINAL_CANDIDATE.commit) {
      problems.push('Candidate tip identity drifted');
    }
    if (input.candidateTree !== B008_FINAL_CANDIDATE.tree) {
      problems.push('Candidate tree identity drifted');
    }
    return { result: problems.length === 0 ? 'PASS' : 'FAIL', phase: 'CANDIDATE', problems };
  }
  if (input.mergeCommits.length !== 1) problems.push('exactly one post-base merge is permitted');
  const merge = input.merge;
  if (!merge || typeof merge !== 'object') problems.push('B008 merge object is missing');
  if (merge?.commit !== input.mergeCommits[0]) problems.push('merge identity mismatch');
  if (merge?.commit !== B008_IMPLEMENTATION_MERGE.commit) {
    problems.push('implementation merge commit drifted');
  }
  if (!Array.isArray(merge?.parents) || merge.parents.length !== 2) {
    problems.push('authorized merge must have exactly two parents');
  } else {
    if (merge.parents[0] !== B008_IMPLEMENTATION_MERGE.parent1) {
      problems.push('merge first parent is not the fixed B008 base');
    }
    if (merge.parents[1] !== B008_IMPLEMENTATION_MERGE.parent2) {
      problems.push('merge second parent is not the frozen final Candidate');
    }
  }
  if (merge?.secondParent !== B008_FINAL_CANDIDATE.commit) {
    problems.push('Owner-approved Candidate parent identity drifted');
  }
  if (merge?.candidateDescendsFromBase !== true) problems.push('Candidate does not descend from base');
  if (merge?.candidateHasMerges !== false) problems.push('Candidate contains a merge commit');
  if (merge?.secondParentTree !== B008_FINAL_CANDIDATE.tree) {
    problems.push('Candidate tree identity drifted');
  }
  if (merge?.tree !== B008_IMPLEMENTATION_MERGE.tree) {
    problems.push('implementation merge tree identity drifted');
  }
  if (merge?.tree !== merge?.secondParentTree) problems.push('merge tree differs from Candidate tree');
  if (merge?.treeDiffQuiet !== true) problems.push('merge introduced tree changes');
  if (merge?.subject !== B008_IMPLEMENTATION_MERGE.subject) problems.push('merge subject drifted');
  if (!Array.isArray(input?.ordinaryDescendants)) problems.push('later history is unreadable');
  else {
    if (input.ordinaryDescendants.length > 1) problems.push('more than one post-merge descendant is not permitted');
    for (const entry of input.ordinaryDescendants) {
      if (!Array.isArray(entry?.parents) || entry.parents.length !== 1) {
        problems.push('closeout is not single-parent');
      } else if (entry.parents[0] !== merge?.commit) {
        problems.push('closeout parent is not the B008 implementation merge');
      }
      if (entry?.subject !== B008_CLOSEOUT_SUBJECT) problems.push('closeout subject drifted');
      if (entry?.commit !== input?.head) problems.push('closeout is not current HEAD');
    }
  }
  const phase = Array.isArray(input?.ordinaryDescendants) && input.ordinaryDescendants.length > 0
    ? 'CLOSEOUT' : 'POST_MERGE';
  if (phase === 'CLOSEOUT' &&
      !same([...(input?.closeoutChangedPaths ?? [])].sort(), [...CLOSEOUT_ALLOWED_PATHS_LITERAL].sort())) {
    problems.push('closeout changed paths are not the exact 14-path surface');
  }
  return { result: problems.length === 0 ? 'PASS' : 'FAIL', phase, problems };
}

function topologyProbes() {
  const candidate = {
    baseCommit: BASE_COMMIT,
    baseTree: BASE_TREE,
    ancestryKnown: true,
    baseIsAncestor: true,
    candidateMergeCommits: [],
    mergeCommits: [],
    ordinaryDescendants: [],
    candidateTip: B008_FINAL_CANDIDATE.commit,
    candidateTree: B008_FINAL_CANDIDATE.tree,
    head: B008_FINAL_CANDIDATE.commit,
    closeoutChangedPaths: [],
  };
  const exactMerge = {
    commit: B008_IMPLEMENTATION_MERGE.commit,
    parents: [B008_IMPLEMENTATION_MERGE.parent1, B008_IMPLEMENTATION_MERGE.parent2],
    secondParent: B008_FINAL_CANDIDATE.commit,
    candidateDescendsFromBase: true,
    candidateHasMerges: false,
    tree: B008_IMPLEMENTATION_MERGE.tree,
    secondParentTree: B008_FINAL_CANDIDATE.tree,
    treeDiffQuiet: true,
    subject: B008_MERGE_SUBJECT,
  };
  const merged = {
    ...candidate,
    head: B008_IMPLEMENTATION_MERGE.commit,
    mergeCommits: [B008_IMPLEMENTATION_MERGE.commit],
    merge: exactMerge,
  };
  const exactCloseout = {
    commit: 'f'.repeat(40),
    parents: [B008_IMPLEMENTATION_MERGE.commit],
    subject: B008_CLOSEOUT_SUBJECT,
  };
  return [
    ['Candidate PASS', candidate, 'PASS'],
    ['Candidate merge FAIL', { ...candidate, candidateMergeCommits: ['merge'] }, 'FAIL'],
    ['exact implementation merge PASS', merged, 'PASS'],
    ['bad first parent FAIL', {
      ...merged, merge: { ...exactMerge, parents: ['wrong', B008_FINAL_CANDIDATE.commit] },
    }, 'FAIL'],
    ['bad Candidate parent FAIL', {
      ...merged, merge: { ...exactMerge, parents: [BASE_COMMIT, 'wrong'] },
    }, 'FAIL'],
    ['Candidate merge hidden FAIL', { ...merged, merge: { ...exactMerge, candidateHasMerges: true } }, 'FAIL'],
    ['bad Candidate tree FAIL', {
      ...merged, merge: { ...exactMerge, secondParentTree: 'wrong' },
    }, 'FAIL'],
    ['merge changes tree FAIL', { ...merged, merge: { ...exactMerge, treeDiffQuiet: false } }, 'FAIL'],
    ['wrong merge subject FAIL', { ...merged, merge: { ...exactMerge, subject: 'merge: wrong' } }, 'FAIL'],
    ['second merge FAIL', {
      ...merged, mergeCommits: [B008_IMPLEMENTATION_MERGE.commit, 'merge-2'],
    }, 'FAIL'],
    ['merge plus exact closeout PASS', {
      ...merged,
      head: exactCloseout.commit,
      ordinaryDescendants: [exactCloseout],
      closeoutChangedPaths: [...CLOSEOUT_ALLOWED_PATHS_LITERAL],
    }, 'PASS'],
    ['wrong closeout parent FAIL', {
      ...merged,
      head: exactCloseout.commit,
      ordinaryDescendants: [{ ...exactCloseout, parents: ['wrong'] }],
      closeoutChangedPaths: [...CLOSEOUT_ALLOWED_PATHS_LITERAL],
    }, 'FAIL'],
    ['later merge FAIL', {
      ...merged,
      head: exactCloseout.commit,
      ordinaryDescendants: [{ ...exactCloseout,
        parents: [B008_IMPLEMENTATION_MERGE.commit, 'other'] }],
      closeoutChangedPaths: [...CLOSEOUT_ALLOWED_PATHS_LITERAL],
    }, 'FAIL'],
    ['bad closeout subject FAIL', {
      ...merged,
      head: exactCloseout.commit,
      ordinaryDescendants: [{ ...exactCloseout, subject: 'wrong' }],
      closeoutChangedPaths: [...CLOSEOUT_ALLOWED_PATHS_LITERAL],
    }, 'FAIL'],
    ['second ordinary descendant FAIL', {
      ...merged,
      head: 'e'.repeat(40),
      ordinaryDescendants: [exactCloseout, {
        commit: 'e'.repeat(40), parents: [exactCloseout.commit], subject: 'unauthorized',
      }],
      closeoutChangedPaths: [...CLOSEOUT_ALLOWED_PATHS_LITERAL],
    }, 'FAIL'],
    ['closeout path expansion FAIL', {
      ...merged,
      head: exactCloseout.commit,
      ordinaryDescendants: [exactCloseout],
      closeoutChangedPaths: [...CLOSEOUT_ALLOWED_PATHS_LITERAL, 'package.json'],
    }, 'FAIL'],
  ];
}

function verifyHistoricalTopology(repo, fail, ok) {
  const historical = [
    ['B004 Candidate', B004_CANDIDATE.commit, B004_CANDIDATE.tree, [B004_CONSTRUCTION_CHECKPOINT.commit]],
    ['B004 merge', B004_IMPLEMENTATION_MERGE.commit, B004_IMPLEMENTATION_MERGE.tree,
      [B004_IMPLEMENTATION_MERGE.parent1, B004_IMPLEMENTATION_MERGE.parent2]],
    ['B004 repair', B004_POST_MERGE_REPAIR.commit, B004_POST_MERGE_REPAIR.tree,
      [B004_POST_MERGE_REPAIR.parent]],
    ['B004 closeout', B004_CLOSEOUT.commit, B004_CLOSEOUT.tree, [B004_CLOSEOUT.parent]],
    ['B005 merge', B005_IMPLEMENTATION_MERGE.commit, B005_IMPLEMENTATION_MERGE.tree,
      [B005_IMPLEMENTATION_MERGE.parent1, B005_IMPLEMENTATION_MERGE.parent2]],
    ['B005 closeout', B005_CLOSEOUT.commit, B005_CLOSEOUT.tree, [B005_CLOSEOUT.parent]],
    ['B006 merge', B006_IMPLEMENTATION_MERGE.commit, B006_IMPLEMENTATION_MERGE.tree,
      [B006_IMPLEMENTATION_MERGE.parent1, B006_IMPLEMENTATION_MERGE.parent2]],
    ['B006 closeout', B006_CLOSEOUT.commit, B006_CLOSEOUT.tree, [B006_CLOSEOUT.parent]],
    ['B007 original Candidate', B007_ORIGINAL_CANDIDATE.commit, B007_ORIGINAL_CANDIDATE.tree,
      [B007_CANDIDATE_HISTORY.at(-3)]],
    ['B007 final Candidate', B007_CANDIDATE.commit, B007_CANDIDATE.tree, [B007_REPAIR.parent]],
    ['B007 implementation merge', B007_IMPLEMENTATION_MERGE.commit, B007_IMPLEMENTATION_MERGE.tree,
      [B007_IMPLEMENTATION_MERGE.parent1, B007_IMPLEMENTATION_MERGE.parent2]],
    ['B007 closeout/B008 base', B007_CLOSEOUT.commit, B007_CLOSEOUT.tree, [B007_CLOSEOUT.parent]],
    ['B008 final Candidate', B008_FINAL_CANDIDATE.commit, B008_FINAL_CANDIDATE.tree,
      [B008_LIFECYCLE_REPAIR.parent]],
    ['B008 implementation merge', B008_IMPLEMENTATION_MERGE.commit,
      B008_IMPLEMENTATION_MERGE.tree,
      [B008_IMPLEMENTATION_MERGE.parent1, B008_IMPLEMENTATION_MERGE.parent2]],
  ];
  for (const [label, commit, tree, parents] of historical) {
    const treeProbe = git(repo, ['rev-parse', commit + '^{tree}'], { check: false });
    const parentProbe = git(repo, ['rev-list', '--parents', '-n', '1', commit], { check: false });
    const tokens = parentProbe.status === 0 ? parentProbe.stdout.trim().split(/\s+/) : [];
    if (treeProbe.status !== 0 || treeProbe.stdout.trim() !== tree || !same(tokens.slice(1), parents)) {
      fail(label + ' immutable topology drifted');
    } else ok(label + ' immutable topology verified');
  }
  const candidateTrees = [
    ['B005', B005_CANDIDATE.commit, B005_CANDIDATE.tree, B005_IMPLEMENTATION_MERGE.commit],
    ['B006', B006_CANDIDATE.commit, B006_CANDIDATE.tree, B006_IMPLEMENTATION_MERGE.commit],
    ['B007', B007_CANDIDATE.commit, B007_CANDIDATE.tree, B007_IMPLEMENTATION_MERGE.commit],
    ['B008', B008_FINAL_CANDIDATE.commit, B008_FINAL_CANDIDATE.tree,
      B008_IMPLEMENTATION_MERGE.commit],
  ];
  for (const [label, candidateCommit, tree, mergeCommit] of candidateTrees) {
    const actualTree = git(repo, ['rev-parse', candidateCommit + '^{tree}'], { check: false });
    const quiet = git(repo, ['diff', '--quiet', candidateCommit, mergeCommit], { check: false });
    if (actualTree.status !== 0 || actualTree.stdout.trim() !== tree || quiet.status !== 0) {
      fail(label + ' Candidate/merge immutable tree relationship drifted');
    } else ok(label + ' Candidate and implementation merge share the accepted tree');
  }
  const repairPaths = git(repo, [
    'diff', '--name-only', '--no-renames', B007_REPAIR.parent, B007_REPAIR.commit,
  ], { check: false });
  const actualRepairPaths = repairPaths.status === 0
    ? repairPaths.stdout.split('\n').filter(Boolean).sort() : null;
  if (!same(actualRepairPaths, [...B007_REPAIR.changed_paths].sort()) ||
      B007_REPAIR.semantic_code_changes !== false || B007_REPAIR.status !== 'CLOSED') {
    fail('B007 repair finding/scope/semantic disposition drifted');
  } else ok('B007 repair finding is CLOSED with exact two-path non-semantic scope');

  const b008History = git(repo, [
    'rev-list', '--reverse', '--topo-order', BASE_COMMIT + '..' + B008_FINAL_CANDIDATE.commit,
  ], { check: false });
  const actualB008History = b008History.status === 0
    ? b008History.stdout.split('\n').filter(Boolean) : null;
  const b008RepairPaths = git(repo, [
    'diff', '--name-only', '--no-renames', B008_LIFECYCLE_REPAIR.parent,
    B008_LIFECYCLE_REPAIR.commit,
  ], { check: false });
  const actualB008RepairPaths = b008RepairPaths.status === 0
    ? b008RepairPaths.stdout.split('\n').filter(Boolean).sort() : null;
  if (!same(actualB008History, B008_CANDIDATE_HISTORY) ||
      B008_INITIAL_CANDIDATE.commit !== B008_CANDIDATE_HISTORY.at(-2) ||
      !same(actualB008RepairPaths, [...B008_LIFECYCLE_REPAIR.changed_paths].sort()) ||
      B008_LIFECYCLE_REPAIR.status !== 'CLOSED') {
    fail('B008 Candidate history or lifecycle repair identity drifted');
  } else ok('B008 three-commit zero-merge Candidate history and repair scope verified');
}

function hasMvpB000Authority(repo) {
  try {
    const status = JSON.parse(fs.readFileSync(path.join(repo, MVP_STATUS_PATH), 'utf8'));
    return status?.authority_snapshot_id === MVP_B000_SNAPSHOT ||
      status?.authority_snapshot_id === 'AIPT-MVP-B000-CLOSEOUT-001';
  } catch {
    return false;
  }
}

export function isUnsafeMvpRawMode(line) {
  const modes = /^:(\d{6}) (\d{6}) /.exec(line);
  if (!modes) return true;
  const unsafeType = [modes[1], modes[2]].some((mode) =>
    mode === '120000' || mode === '160000');
  const deletion = modes[2] === '000000';
  const malformedAddition = modes[1] === '000000' && modes[2] !== '100644';
  return unsafeType || deletion || malformedAddition;
}

function runMvpB000Tree(ctx) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push('ok: ' + message);
  const fail = (message) => { pass = false; details.push('FAIL: ' + message); };
  const expectedPaths = [
    '.github/workflows/ci.yml',
    'README.md',
    'docs/authority/README.md',
    'docs/authority/BATCH_DEPENDENCY_GRAPH.md',
    'docs/authority/PROJECT_STATUS.md',
    'docs/authority/registry/batch-graph.json',
    'docs/authority/registry/project-status.json',
    'docs/milestones/MVP.md',
    'package.json',
    'scripts/ci/lib/constants.mjs',
    'scripts/ci/run-checks.mjs',
    'scripts/ci/validate/m0-development-pass.mjs',
    'scripts/ci/validate/mvp-bootstrap.mjs',
    'scripts/ci/validate/standalone-entrypoints.mjs',
    'scripts/ci/validate/status-transition.mjs',
    'scripts/ci/validate/tree-integrity.mjs',
    'scripts/ci/validate/workflow.mjs',
  ];
  if (!same(MVP_B000_ALLOWED_PATHS, expectedPaths)) fail('MVP B000 allowlist constant drifted');
  else ok('MVP B000 exact 17-path allowlist anchored independently');
  if (MVP_B000_BASE_COMMIT !== 'c617f3c6ab3e56ac88f228ed4825e751537fc1f0' ||
      MVP_B000_BASE_TREE !== '95a8d2980c5a6aa44f3db67c66f07ff008ff3491') {
    fail('MVP B000 Base literal drifted');
  } else ok('MVP B000 Base commit/tree literals anchored independently');

  verifyHistoricalTopology(ctx.repo, fail, ok);
  const closeout = git(ctx.repo, ['rev-list', '--parents', '-n', '1', M0_CLOSEOUT.commit], { check: false });
  const closeoutTree = git(ctx.repo, ['rev-parse', `${M0_CLOSEOUT.commit}^{tree}`], { check: false });
  const closeoutSubject = git(ctx.repo, ['show', '-s', '--format=%s', M0_CLOSEOUT.commit], { check: false });
  if (closeout.stdout.trim() !== `${M0_CLOSEOUT.commit} ${M0_CLOSEOUT.parent}` ||
      closeoutTree.stdout.trim() !== M0_CLOSEOUT.tree ||
      closeoutSubject.stdout.trim() !== M0_CLOSEOUT.subject) {
    fail('M0 closeout topology/tree/subject drifted');
  } else ok('M0 closeout topology/tree/subject verified');

  let status;
  let baseStatus;
  try {
    status = JSON.parse(fs.readFileSync(path.join(ctx.repo, MVP_STATUS_PATH), 'utf8'));
    const baseStatusProbe = git(ctx.repo, [
      'show', `${MVP_B000_BASE_COMMIT}:${MVP_STATUS_PATH}`,
    ], { check: false });
    if (baseStatusProbe.status !== 0) throw new Error('fixed Base status is unavailable');
    baseStatus = JSON.parse(baseStatusProbe.stdout);
  } catch (error) {
    fail('MVP B000 lifecycle status is unreadable: ' + error.message);
  }
  const facts = collectMvpB000LifecycleFacts(ctx.repo);
  const lifecycle = validateMvpB000Lifecycle(facts, status, baseStatus);
  for (const problem of lifecycle.problems) fail('MVP B000 lifecycle: ' + problem);
  if (lifecycle.result === 'PASS') {
    ok(`${lifecycle.phase} = PASS (${lifecycle.checkoutKind}): exact B000 topology and status`);
  }

  const tracked = git(ctx.repo, ['diff', '--name-only', '--no-renames', MVP_B000_BASE_COMMIT], { check: false });
  const untracked = git(ctx.repo, ['ls-files', '--others', '--exclude-standard'], { check: false });
  const changed = [...new Set([
    ...tracked.stdout.split('\n'),
    ...untracked.stdout.split('\n').filter((relative) =>
      relative && !isGeneratedWorktreeArtifact(relative)),
  ].filter(Boolean))].sort();
  const scopeProblems = validateChangedPaths(changed);
  for (const problem of scopeProblems) fail(problem);
  if (scopeProblems.length === 0) ok('exact 17-path MVP governance/CI scope verified');
  for (const relative of changed) {
    const forbidden = MVP_B000_FORBIDDEN_PREFIXES.find((prefix) =>
      prefix.endsWith('/') ? relative.startsWith(prefix) : relative === prefix);
    if (forbidden) fail(`forbidden MVP B000 path changed (${forbidden}): ${relative}`);
    try {
      const stat = fs.lstatSync(path.join(ctx.repo, relative));
      if (!stat.isFile() || stat.isSymbolicLink()) fail('changed path is not a regular file: ' + relative);
    } catch (error) {
      fail(`changed path lstat failed: ${relative}: ${error.message}`);
    }
  }
  for (const line of git(ctx.repo, [
    'diff', '--raw', '--no-abbrev', '--no-renames', MVP_B000_BASE_COMMIT,
  ], { check: false }).stdout.split('\n').filter(Boolean)) {
    if (isUnsafeMvpRawMode(line)) {
      fail('unsafe changed mode: ' + line);
    }
  }
  const localWorktrees = fs.readdirSync(ctx.repo).filter((name) => name.startsWith('.wt-'));
  if (localWorktrees.length) fail('repository-local .wt-* content is forbidden');
  else ok('no repository-local worktree content');

  for (const relative of [...FROZEN_FILES, ...M0_HISTORICAL_PATHS]) {
    const base = git(ctx.repo, ['show', `${MVP_B000_BASE_COMMIT}:${relative}`], { check: false });
    let current;
    try {
      current = fs.readFileSync(path.join(ctx.repo, relative), 'utf8');
    } catch (error) {
      fail(`frozen file unreadable: ${relative}: ${error.message}`);
      continue;
    }
    if (base.status !== 0 || base.stdout !== current) fail('frozen file changed: ' + relative);
  }
  if (!details.some((line) => line.startsWith('FAIL: frozen file'))) {
    ok('dependencies, toolchains, registries and all M0 milestone files are byte-identical to Base');
  }

  const license = fs.readFileSync(path.join(ctx.repo, 'LICENSE'), 'utf8');
  if (normalizeText(license) !== normalizeText(EXPECTED_MIT_LICENSE)) fail('LICENSE drifted from exact MIT text');
  else ok('LICENSE remains exact MIT text');
  const markdown = collectMarkdownLinkIssues(ctx.repo);
  for (const issue of markdown.issues) fail('Markdown link issue: ' + JSON.stringify(issue));
  if (markdown.issues.length === 0) ok(markdown.mdCount + ' Markdown documents have contained links');
  let jsonFailures = 0;
  for (const file of walkFiles(ctx.repo, (candidatePath) => candidatePath.endsWith('.json'))) {
    try { JSON.parse(fs.readFileSync(file, 'utf8')); } catch {
      jsonFailures += 1;
      fail('JSON parse failed: ' + path.relative(ctx.repo, file));
    }
  }
  if (jsonFailures === 0) ok('all source JSON parses');
  const hazards = scanTreeForHazards(ctx.repo);
  for (const finding of hazards) fail('public-tree hygiene finding: ' + JSON.stringify(finding));
  if (hazards.length === 0) ok('public tree has no secret/path/endpoint/prompt hazard');

  const lifecycleProbes = status && baseStatus
    ? runMvpB000LifecycleRegressionProbes(status, baseStatus) : [];
  let rejected = 0;
  for (const probe of lifecycleProbes) {
    if (probe.matched) rejected += 1;
    else fail('tree lifecycle regression mismatched: ' + probe.label);
  }
  const pathProbeRejected = validateChangedPaths([...expectedPaths, 'internal/run/engine.go']).length > 0;
  if (pathProbeRejected) rejected += 1;
  else fail('runtime path negative probe was accepted');
  const regularAddition = ':000000 100644 ' + '0'.repeat(40) + ' ' + '1'.repeat(40) + ' A\tnew.json';
  if (isUnsafeMvpRawMode(regularAddition)) fail('regular 100644 addition mode control was rejected');
  const unsafeModeProbes = [
    ':100644 000000 ' + '1'.repeat(40) + ' ' + '0'.repeat(40) + ' D\tdeleted.json',
    ':000000 120000 ' + '0'.repeat(40) + ' ' + '1'.repeat(40) + ' A\tsymlink',
    ':000000 160000 ' + '0'.repeat(40) + ' ' + '1'.repeat(40) + ' A\tgitlink',
    'malformed raw mode line',
  ];
  for (const probe of unsafeModeProbes) {
    if (isUnsafeMvpRawMode(probe)) rejected += 1;
    else fail('unsafe raw-mode negative probe was accepted: ' + probe);
  }
  const expectedRejected = lifecycleProbes.length + 1 + unsafeModeProbes.length;
  if (rejected === expectedRejected) ok(`all ${rejected} MVP tree/scope/mode mutation probes reject`);

  return {
    result: pass ? 'PASS' : 'FAIL',
    phase: lifecycle.phase === 'CLOSEOUT_MAIN' ? 'CLOSEOUT' :
      lifecycle.phase === 'POST_MERGE_MAIN' ? 'POST_MERGE' : 'CANDIDATE',
    lifecycle_phase: lifecycle.phase,
    lifecycle_checkout: lifecycle.checkoutKind,
    details,
    changed_paths: changed,
    negative_probes: rejected === expectedRejected ? 'PASS' : 'FAIL',
    negative_probe_count: expectedRejected,
  };
}

export function run(ctx) {
  try {
    const status = JSON.parse(fs.readFileSync(path.join(ctx.repo, MVP_STATUS_PATH), 'utf8'));
    if (status?.authority_snapshot_id === MVP_B001.snapshot || status?.authority_snapshot_id === 'AIPT-MVP-B001-CLOSEOUT-001') {
      return { ...runMvpB001(ctx), name: 'tree-integrity' };
    }
  } catch {
    // The historical gate below owns the fail-closed unreadable-input report.
  }
  // Preserve the complete B008 lifecycle implementation below for historical
  // checkouts. Exact B000 authority routes Candidate, PR, post-merge and the
  // fail-closed future closeout shape through the shared successor classifier.
  if (hasMvpB000Authority(ctx.repo)) return runMvpB000Tree(ctx);
  const details = [];
  let pass = true;
  const ok = (message) => details.push('ok: ' + message);
  const fail = (message) => { pass = false; details.push('FAIL: ' + message); };
  const anchor = (label, actual, expected) => {
    if (same(actual, expected)) ok(label + ' anchored'); else fail(label + ' drifted');
  };
  anchor('ALLOWED_PATHS', ALLOWED_PATHS, ALLOWED_PATHS_LITERAL);
  anchor('CLOSEOUT_ALLOWED_PATHS', CLOSEOUT_ALLOWED_PATHS, CLOSEOUT_ALLOWED_PATHS_LITERAL);
  anchor('FORBIDDEN_PREFIXES', FORBIDDEN_PREFIXES, FORBIDDEN_PREFIXES_LITERAL);
  anchor('FROZEN_REGISTRY_PATHS', FROZEN_REGISTRY_PATHS, FROZEN_REGISTRY_PATHS_LITERAL);

  let probeFailures = 0;
  let probeCount = 0;
  const pathProbe = (relative, expected) => {
    probeCount += 1;
    if (pathMatchesAllowed(relative) !== expected) {
      probeFailures += 1;
      fail('allowlist probe mismatch: ' + relative);
    }
  };
  for (const relative of ALLOWED_PATHS_LITERAL) pathProbe(relative, true);
  for (const relative of FALSE_ALLOWLIST_PROBES) pathProbe(relative, false);
  if (probeFailures === 0) ok('all ' + probeCount + ' allowlist/lookalike probes matched');

  let closeoutProbeFailures = 0;
  for (const relative of CLOSEOUT_ALLOWED_PATHS_LITERAL) {
    if (!pathMatchesCloseoutAllowed(relative)) closeoutProbeFailures += 1;
  }
  for (const relative of FALSE_CLOSEOUT_ALLOWLIST_PROBES) {
    if (pathMatchesCloseoutAllowed(relative)) closeoutProbeFailures += 1;
  }
  if (closeoutProbeFailures > 0) fail('closeout allowlist/lookalike probes failed');
  else ok('all closeout allowlist/lookalike probes matched');

  const baseCommit = git(ctx.repo, ['rev-parse', BASE_COMMIT + '^{commit}'], { check: false });
  const baseTree = git(ctx.repo, ['rev-parse', BASE_COMMIT + '^{tree}'], { check: false });
  if (baseCommit.status !== 0 || baseCommit.stdout.trim() !== BASE_COMMIT ||
      baseTree.status !== 0 || baseTree.stdout.trim() !== BASE_TREE) {
    fail('B008 base commit/tree does not resolve exactly');
  } else ok('B008 base commit/tree verified');
  verifyHistoricalTopology(ctx.repo, fail, ok);

  const tracked = git(ctx.repo, ['diff', '--name-only', '--no-renames', BASE_COMMIT])
    .stdout.split('\n').filter(Boolean);
  const untracked = git(ctx.repo, ['ls-files', '--others', '--exclude-standard'])
    .stdout.split('\n').filter((relative) => relative && !isGeneratedWorktreeArtifact(relative));
  const changed = [...new Set([...tracked, ...untracked])].sort();
  if (changed.length === 0) fail('B008 history has no changed paths');
  else ok(changed.length + ' B008 paths differ from the accepted base');
  let scopeFailures = 0;
  for (const relative of changed) {
    if (!pathMatchesAllowed(relative)) {
      scopeFailures += 1;
      fail('path outside B008 scope: ' + relative);
    }
    const forbidden = FORBIDDEN_PREFIXES.find((prefix) => relative.startsWith(prefix));
    if (forbidden) {
      scopeFailures += 1;
      fail('forbidden path changed (' + forbidden + '): ' + relative);
    }
    if (FROZEN_REGISTRY_PATHS.includes(relative)) {
      scopeFailures += 1;
      fail('frozen registry changed: ' + relative);
    }
  }
  if (scopeFailures === 0) ok('all cumulative changed paths remain inside the exact B008 surface');

  const ancestry = git(ctx.repo, ['merge-base', '--is-ancestor', BASE_COMMIT, 'HEAD'], { check: false });
  const mergeListProbe = git(ctx.repo, ['rev-list', '--merges', '--reverse', BASE_COMMIT + '..HEAD'], { check: false });
  const mergeCommits = mergeListProbe.status === 0
    ? mergeListProbe.stdout.split('\n').filter(Boolean) : null;
  let candidateTip = 'HEAD';
  let merge;
  let ordinaryDescendants = [];
  let closeoutChanged = [];
  if (Array.isArray(mergeCommits) && mergeCommits.length === 1) {
    const commit = mergeCommits[0];
    const tokens = git(ctx.repo, ['rev-list', '--parents', '-n', '1', commit], { check: false })
      .stdout.trim().split(/\s+/).filter(Boolean);
    const parents = tokens.slice(1);
    candidateTip = parents[1] || '';
    const candidateMergeProbe = candidateTip
      ? git(ctx.repo, ['rev-list', '--merges', BASE_COMMIT + '..' + candidateTip], { check: false })
      : { status: 2, stdout: '' };
    merge = {
      commit,
      parents,
      secondParent: candidateTip,
      candidateDescendsFromBase: candidateTip
        ? git(ctx.repo, ['merge-base', '--is-ancestor', BASE_COMMIT, candidateTip], { check: false }).status === 0
        : false,
      candidateHasMerges: candidateMergeProbe.status !== 0 || candidateMergeProbe.stdout.trim() !== '',
      tree: git(ctx.repo, ['rev-parse', commit + '^{tree}'], { check: false }).stdout.trim(),
      secondParentTree: candidateTip
        ? git(ctx.repo, ['rev-parse', candidateTip + '^{tree}'], { check: false }).stdout.trim() : '',
      treeDiffQuiet: candidateTip
        ? git(ctx.repo, ['diff', '--quiet', candidateTip, commit], { check: false }).status === 0 : false,
      subject: git(ctx.repo, ['show', '-s', '--format=%s', commit], { check: false }).stdout.trim(),
    };
    const later = git(ctx.repo, ['rev-list', '--reverse', '--ancestry-path', '--parents', commit + '..HEAD'], {
      check: false,
    });
    ordinaryDescendants = later.status === 0
      ? later.stdout.split('\n').filter(Boolean).map((line) => {
          const parts = line.trim().split(/\s+/);
          return {
            commit: parts[0],
            parents: parts.slice(1),
            subject: git(ctx.repo, ['show', '-s', '--format=%s', parts[0]], { check: false }).stdout.trim(),
          };
        })
      : null;
    if (commit !== git(ctx.repo, ['rev-parse', 'HEAD^{commit}']).stdout.trim()) {
      const closeoutDiff = git(ctx.repo, [
        'diff', '--name-only', '--no-renames', commit, 'HEAD',
      ], { check: false });
      closeoutChanged = closeoutDiff.status === 0
        ? closeoutDiff.stdout.split('\n').filter(Boolean).sort() : null;
    }
  }
  const candidateMergeProbe = candidateTip
    ? git(ctx.repo, ['rev-list', '--merges', BASE_COMMIT + '..' + candidateTip], { check: false })
    : { status: 2, stdout: '' };
  const candidateMergeCommits = candidateMergeProbe.status === 0
    ? candidateMergeProbe.stdout.split('\n').filter(Boolean) : null;
  const candidateTreeProbe = candidateTip
    ? git(ctx.repo, ['rev-parse', candidateTip + '^{tree}'], { check: false })
    : { status: 2, stdout: '' };
  const headProbe = git(ctx.repo, ['rev-parse', 'HEAD^{commit}'], { check: false });
  const lifecycle = evaluateB008Lifecycle({
    baseCommit: BASE_COMMIT,
    baseTree: BASE_TREE,
    ancestryKnown: ancestry.status === 0 || ancestry.status === 1,
    baseIsAncestor: ancestry.status === 0,
    candidateMergeCommits,
    candidateTip,
    candidateTree: candidateTreeProbe.status === 0 ? candidateTreeProbe.stdout.trim() : null,
    head: headProbe.status === 0 ? headProbe.stdout.trim() : null,
    mergeCommits,
    merge,
    ordinaryDescendants,
    closeoutChangedPaths: closeoutChanged,
  });
  if (lifecycle.result === 'FAIL') {
    for (const problem of lifecycle.problems) fail('B008 lifecycle: ' + problem);
  } else if (lifecycle.phase === 'CLOSEOUT') {
    ok('CLOSEOUT = PASS: exact B008 merge plus one single-parent exact 14-path closeout');
  } else if (lifecycle.phase === 'POST_MERGE') {
    ok('POST_MERGE = PASS: exact B008 implementation merge without a closeout descendant');
  } else {
    ok('CANDIDATE = PASS: Base..HEAD contains zero merge commits');
  }
  const probes = topologyProbes();
  let topologyFailures = 0;
  for (const [label, input, expected] of probes) {
    const actual = evaluateB008Lifecycle(input).result;
    if (actual !== expected) {
      topologyFailures += 1;
      fail('lifecycle probe ' + label + ': expected ' + expected + ', got ' + actual);
    }
  }
  if (topologyFailures === 0) ok('all ' + probes.length + ' lifecycle mutation probes matched');

  let statusClaimsCloseout = false;
  try {
    const status = JSON.parse(fs.readFileSync(
      path.join(ctx.repo, 'docs/authority/registry/project-status.json'), 'utf8',
    ));
    statusClaimsCloseout =
      status?.authority_snapshot_id === 'AIPT-M0-B008-CLOSEOUT-001' &&
      status?.tracks?.['AIPT-STANDALONE']?.batch_history?.['AIPT-M0-B008'] === 'MERGED_CLOSED';
  } catch (error) {
    fail('B008 status claim is unreadable: ' + error.message);
  }
  if (statusClaimsCloseout && lifecycle.phase !== 'CLOSEOUT') {
    fail('final project status claims closeout but exact closeout topology is absent');
  }
  if (!statusClaimsCloseout) fail('final project status does not claim exact B008 closeout');
  if (lifecycle.phase !== 'CLOSEOUT') fail('final tree-integrity gate is not in CLOSEOUT phase');
  if (lifecycle.phase === 'CLOSEOUT') {
    for (const relative of closeoutChanged) {
      if (!pathMatchesCloseoutAllowed(relative)) fail('path outside B008 closeout scope: ' + relative);
    }
    if (same(closeoutChanged, [...CLOSEOUT_ALLOWED_PATHS_LITERAL].sort())) {
      ok('closeout changed paths are the exact 14-path allowlist');
    }
  }

  for (const line of git(ctx.repo, ['diff', '--raw', '--no-abbrev', '--no-renames', BASE_COMMIT])
    .stdout.split('\n').filter(Boolean)) {
    const modes = /^:(\d{6}) (\d{6}) /.exec(line);
    if (modes && [modes[1], modes[2]].some((mode) => mode === '120000' || mode === '160000')) {
      fail('unsafe changed symlink/gitlink: ' + line);
    }
  }
  for (const line of git(ctx.repo, ['ls-files', '-s'], { check: false }).stdout.split('\n').filter(Boolean)) {
    const mode = line.split(/\s+/, 1)[0];
    if (mode === '120000' || mode === '160000') fail('tracked symlink/gitlink is forbidden: ' + line);
  }
  for (const relative of changed) {
    try {
      const stat = fs.lstatSync(path.join(ctx.repo, relative));
      if (stat.isSymbolicLink() || (!stat.isFile() && !stat.isDirectory())) fail('unsafe worktree node: ' + relative);
    } catch (error) {
      if (error?.code !== 'ENOENT') fail('lstat failed for ' + relative + ': ' + error.message);
    }
  }
  const localWorktrees = fs.readdirSync(ctx.repo).filter((name) => name.startsWith('.wt-'));
  if (localWorktrees.length > 0) fail('repository-local .wt-* content is forbidden');
  else ok('no repository-local worktree content');

  for (const relative of FROZEN_FILES) {
    const base = git(ctx.repo, ['show', BASE_COMMIT + ':' + relative], { check: false });
    let current;
    try {
      current = fs.readFileSync(path.join(ctx.repo, relative), 'utf8');
    } catch (error) {
      fail('frozen file unreadable: ' + relative + ': ' + error.message);
      continue;
    }
    if (base.status !== 0 || current !== base.stdout) fail('frozen file changed: ' + relative);
    else ok('frozen file unchanged: ' + relative);
  }
  const license = fs.readFileSync(path.join(ctx.repo, 'LICENSE'), 'utf8');
  if (normalizeText(license) !== normalizeText(EXPECTED_MIT_LICENSE)) fail('LICENSE drifted from exact MIT text');
  else ok('LICENSE remains exact MIT text');

  const baseMarkdown = git(ctx.repo, ['ls-tree', '-r', '--name-only', BASE_COMMIT]).stdout
    .split('\n').filter((relative) => relative.endsWith('.md'));
  for (const relative of baseMarkdown) {
    if (!fs.existsSync(path.join(ctx.repo, relative))) fail('base Markdown removed: ' + relative);
  }
  const markdown = collectMarkdownLinkIssues(ctx.repo);
  for (const issue of markdown.issues) fail('Markdown link issue: ' + JSON.stringify(issue));
  if (markdown.issues.length === 0) ok(markdown.mdCount + ' Markdown documents have contained links');
  let jsonFailures = 0;
  for (const file of walkFiles(ctx.repo, (candidatePath) => candidatePath.endsWith('.json'))) {
    try {
      JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch {
      jsonFailures += 1;
      fail('JSON parse failed: ' + path.relative(ctx.repo, file));
    }
  }
  if (jsonFailures === 0) ok('all source JSON parses');
  const hazards = scanTreeForHazards(ctx.repo);
  for (const finding of hazards) fail('public-tree hygiene finding: ' + JSON.stringify(finding));
  if (hazards.length === 0) ok('public tree has no secret/path/endpoint/prompt hazard');

  const probeRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aipt-b008-hygiene-'));
  try {
    const scriptDir = path.join(probeRoot, 'scripts', 'ci');
    fs.mkdirSync(scriptDir, { recursive: true });
    fs.writeFileSync(path.join(scriptDir, 'probe.mjs'), 'const value = "' + 'sk-' + 'A'.repeat(24) + '";\n');
    if (!scanTreeForHazards(probeRoot).some((finding) => finding.hazard === 'API_KEY_LIKE')) {
      fail('hygiene probe failed');
    } else ok('hygiene probe detects executable-source credentials');
  } finally {
    fs.rmSync(probeRoot, { recursive: true, force: true });
  }

  return {
    result: pass ? 'PASS' : 'FAIL',
    phase: lifecycle.phase,
    details,
    changed_paths: changed,
    closeout_changed_paths: closeoutChanged,
  };
}

runAsMain(import.meta.url, 'tree-integrity', run);
