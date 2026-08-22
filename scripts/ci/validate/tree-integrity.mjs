#!/usr/bin/env node
// AIPT-M0-B005 lifecycle-aware tree/scope validator.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  ALLOWED_PATHS, B004_CANDIDATE, B004_CLOSEOUT, B004_CONSTRUCTION_CHECKPOINT,
  B004_IMPLEMENTATION_MERGE, B004_POST_MERGE_REPAIR, B005_CANDIDATE,
  B005_CANDIDATE_HISTORY, B005_CLOSEOUT_SUBJECT, B005_IMPLEMENTATION_MERGE,
  B005_MERGE_SUBJECT, BASE_COMMIT, BASE_TREE, CLOSEOUT_ALLOWED_PATHS,
  EXPECTED_MIT_LICENSE, FORBIDDEN_PREFIXES, FROZEN_REGISTRY_PATHS,
  normalizeText, pathMatchesAllowed, pathMatchesCloseoutAllowed,
} from '../lib/constants.mjs';
import { collectMarkdownLinkIssues, scanTreeForHazards, walkFiles } from '../lib/scan.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

const ALLOWED_PATHS_LITERAL = [
  'packages/harness-adapter/**', 'docs/harness/**', 'scripts/ci/smoke/**',
  'README.md', 'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json', 'docs/supply-chain/README.md',
  'package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml',
  'scripts/ci/lib/constants.mjs', 'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/tree-integrity.mjs', 'scripts/ci/validate/workflow.mjs',
  'scripts/ci/validate/supply-chain.mjs', 'scripts/ci/validate/sbom.mjs',
  'scripts/ci/validate/harness-adapter.mjs',
  'scripts/ci/validate/standalone-entrypoints.mjs',
  'scripts/ci/sbom/generate-sbom.mjs', 'tools/supply-chain/licenses.json',
  '.github/workflows/ci.yml',
];
const FORBIDDEN_PREFIXES_LITERAL = [
  'api/', 'migrations/', 'deploy/', 'runtime/', 'packages/adapter-sdk/',
  'schemas/protocol/', 'testdata/protocol/', 'docs/architecture/',
  'docs/integration/', 'docs/test-model/', 'docs/security/', 'docs/evidence/',
  'schemas/evidence/', 'internal/evidence/', 'packages/evidence/',
  'internal/protocol/', 'internal/storage/postgres/', 'internal/harness/',
  'internal/model/', 'internal/web/', 'internal/ipc/', 'internal/campaign/',
  '.go-version', 'go.mod', 'go.sum', 'LICENSE', 'tools/toolchain.lock.json',
  'tools/ci-actions.lock.json', 'tools/supply-chain/policy.json',
];
const FROZEN_REGISTRY_PATHS_LITERAL = [
  'docs/authority/registry/decisions.json',
  'docs/authority/registry/supersessions.json',
  'docs/authority/registry/deferred-parameters.json',
];
const CLOSEOUT_ALLOWED_PATHS_LITERAL = [
  'README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'docs/harness/README.md',
  'docs/harness/compatibility.json',
  'docs/supply-chain/README.md',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
];
const B005_CANDIDATE_HISTORY_LITERAL = [
  'cae7c38a57da0b52e9a19e713ca8abeb9074698c',
  'ca8951529adb179c7e5f9e5a407aabb2ffa791f9',
  'd9e24cbac30a1472c41cc8719848acbbc2426fa5',
];
const FROZEN_FILES = [
  '.go-version', 'go.mod', 'go.sum', 'LICENSE', 'tools/ci-actions.lock.json',
  'tools/toolchain.lock.json', 'tools/supply-chain/policy.json',
  ...FROZEN_REGISTRY_PATHS_LITERAL,
];
const FALSE_ALLOWLIST_PROBES = [
  'packages/adapter-sdk/src/index.ts', 'packages/harness-adapter-evil/src/index.ts',
  'packages/harness-adapter.ts', 'schemas/protocol/v1/new.json',
  'testdata/protocol/v1/minimal-fixture/new.json', 'docs/evidence/README.md',
  'schemas/evidence/v1/evidence.json', 'internal/evidence/export.go',
  'internal/harness/adapter.go', 'internal/model/client.go', 'internal/web/server.go',
  'README.md.bak', 'pnpm-lock.yaml.bak', 'scripts/ci/validate/harness-adapter.mjs.bak',
];
const FALSE_CLOSEOUT_ALLOWLIST_PROBES = [
  'packages/harness-adapter/src/worker.ts', 'packages/adapter-sdk/src/index.ts',
  'schemas/protocol/v1/aipt-protocol.schema.json', 'testdata/protocol/v1/minimal-fixture/manifest.json',
  'internal/launcher/launcher.go', 'go.mod', 'go.sum', 'pnpm-lock.yaml',
  'package.json', '.github/workflows/ci.yml', 'scripts/ci/validate/harness-adapter.mjs',
  'docs/harness/compatibility.json.bak',
];

function same(actual, expected) {
  return JSON.stringify(actual) === JSON.stringify(expected);
}

function isGeneratedWorktreeArtifact(relative) {
  return relative.split('/').includes('node_modules') ||
    relative === '.b001-toolcache' || relative.startsWith('.b001-toolcache/');
}

// Pure evaluator used by the live Git gate and deterministic mutation probes.
export function evaluateB005Lifecycle(input) {
  const problems = [];
  if (input?.baseCommit !== BASE_COMMIT) problems.push('base commit drifted');
  if (input?.baseTree !== BASE_TREE) problems.push('base tree drifted');
  if (input?.ancestryKnown !== true) problems.push('HEAD ancestry is unknown');
  if (input?.baseIsAncestor !== true) problems.push('HEAD does not descend from the base');
  if (!same(input?.candidateHistory, B005_CANDIDATE_HISTORY)) {
    problems.push('Candidate history drifted');
  }
  if (!Array.isArray(input?.mergeCommits)) problems.push('merge list is unreadable');
  if (problems.length > 0) return { result: 'FAIL', phase: 'UNKNOWN', problems };

  if (input.mergeCommits.length === 0) {
    return { result: 'PASS', phase: 'CANDIDATE', problems: [] };
  }
  if (input.mergeCommits.length !== 1) problems.push('exactly one post-base merge is permitted');
  const merge = input.merge;
  if (!merge || typeof merge !== 'object') problems.push('authorized merge object is missing');
  if (input.mergeCommits[0] !== B005_IMPLEMENTATION_MERGE.commit) {
    problems.push('post-base merge is not the authorized B005 implementation merge');
  }
  if (merge?.commit !== B005_IMPLEMENTATION_MERGE.commit) problems.push('merge identity mismatch');
  if (!Array.isArray(merge?.parents) || merge.parents.length !== 2) {
    problems.push('authorized merge must have exactly two parents');
  } else {
    if (merge.parents[0] !== B005_IMPLEMENTATION_MERGE.parent1) {
      problems.push('merge first parent is not the B005 base');
    }
    if (merge.parents[1] !== B005_IMPLEMENTATION_MERGE.parent2) {
      problems.push('merge second parent is not the approved Candidate');
    }
  }
  if (merge?.secondParent !== B005_CANDIDATE.commit) problems.push('merge second parent identity drifted');
  if (merge?.candidateDescendsFromBase !== true) problems.push('second parent does not descend from base');
  if (!Array.isArray(merge?.candidateMergeCommits) || merge.candidateMergeCommits.length !== 0) {
    problems.push('candidate history contains a merge');
  }
  if (merge?.secondParentTree !== B005_CANDIDATE.tree) problems.push('Candidate tree drifted');
  if (merge?.tree !== B005_IMPLEMENTATION_MERGE.tree) problems.push('merge tree drifted');
  if (merge?.tree !== merge?.secondParentTree) problems.push('merge tree differs from Candidate tree');
  if (merge?.treeDiffQuiet !== true) problems.push('merge introduced tree changes');
  if (merge?.subject !== B005_MERGE_SUBJECT) problems.push('merge subject drifted');
  if (!Array.isArray(input?.ordinaryDescendants)) problems.push('later history is unreadable');
  else {
    if (input.ordinaryDescendants.length > 1) {
      problems.push('more than one closeout descendant is not permitted');
    }
    let expectedParent = merge?.commit;
    for (const entry of input.ordinaryDescendants) {
      if (!Array.isArray(entry?.parents) || entry.parents.length !== 1) {
        problems.push('later descendant is not single-parent');
      } else if (entry.parents[0] !== expectedParent) {
        problems.push('later descendants are not one linear chain');
      }
      if (entry?.subject !== B005_CLOSEOUT_SUBJECT) {
        problems.push('closeout subject drifted');
      }
      expectedParent = entry?.commit;
    }
  }
  return { result: problems.length === 0 ? 'PASS' : 'FAIL', phase: 'POST_MERGE', problems };
}

function topologyProbes() {
  const base = {
    baseCommit: BASE_COMMIT, baseTree: BASE_TREE, ancestryKnown: true,
    baseIsAncestor: true, candidateHistory: B005_CANDIDATE_HISTORY,
    mergeCommits: [], ordinaryDescendants: [],
  };
  const exactMerge = {
    commit: B005_IMPLEMENTATION_MERGE.commit,
    parents: [B005_IMPLEMENTATION_MERGE.parent1, B005_IMPLEMENTATION_MERGE.parent2],
    secondParent: B005_CANDIDATE.commit,
    candidateDescendsFromBase: true, candidateMergeCommits: [],
    tree: B005_IMPLEMENTATION_MERGE.tree, secondParentTree: B005_CANDIDATE.tree,
    treeDiffQuiet: true,
    subject: B005_MERGE_SUBJECT,
  };
  return [
    ['candidate PASS', base, 'PASS'],
    ['Candidate history drift FAIL', { ...base, candidateHistory: B005_CANDIDATE_HISTORY.slice(1) }, 'FAIL'],
    ['unauthorized merge FAIL', { ...base, mergeCommits: ['x'], merge: { ...exactMerge, commit: 'x' } }, 'FAIL'],
    ['exact merge PASS', {
      ...base, mergeCommits: [B005_IMPLEMENTATION_MERGE.commit], merge: exactMerge,
    }, 'PASS'],
    ['bad first parent FAIL', {
      ...base, mergeCommits: [B005_IMPLEMENTATION_MERGE.commit],
      merge: { ...exactMerge, parents: ['wrong', B005_CANDIDATE.commit] },
    }, 'FAIL'],
    ['bad Candidate parent FAIL', {
      ...base, mergeCommits: [B005_IMPLEMENTATION_MERGE.commit],
      merge: { ...exactMerge, parents: [BASE_COMMIT, 'wrong'] },
    }, 'FAIL'],
    ['bad Candidate tree FAIL', {
      ...base, mergeCommits: [B005_IMPLEMENTATION_MERGE.commit],
      merge: { ...exactMerge, secondParentTree: 'wrong' },
    }, 'FAIL'],
    ['bad merge tree FAIL', {
      ...base, mergeCommits: [B005_IMPLEMENTATION_MERGE.commit],
      merge: { ...exactMerge, tree: 'wrong' },
    }, 'FAIL'],
    ['merge changes tree FAIL', {
      ...base, mergeCommits: [B005_IMPLEMENTATION_MERGE.commit],
      merge: { ...exactMerge, treeDiffQuiet: false },
    }, 'FAIL'],
    ['second merge FAIL', {
      ...base, mergeCommits: [B005_IMPLEMENTATION_MERGE.commit, 'n'], merge: exactMerge,
    }, 'FAIL'],
    ['merge plus exact closeout PASS', {
      ...base, mergeCommits: [B005_IMPLEMENTATION_MERGE.commit], merge: exactMerge,
      ordinaryDescendants: [{
        commit: 'closeout', parents: [B005_IMPLEMENTATION_MERGE.commit],
        subject: B005_CLOSEOUT_SUBJECT,
      }],
    }, 'PASS'],
    ['second ordinary descendant FAIL', {
      ...base, mergeCommits: [B005_IMPLEMENTATION_MERGE.commit], merge: exactMerge,
      ordinaryDescendants: [
        { commit: 'closeout', parents: [B005_IMPLEMENTATION_MERGE.commit], subject: B005_CLOSEOUT_SUBJECT },
        { commit: 'extra', parents: ['closeout'], subject: B005_CLOSEOUT_SUBJECT },
      ],
    }, 'FAIL'],
    ['later merge FAIL', {
      ...base, mergeCommits: [B005_IMPLEMENTATION_MERGE.commit], merge: exactMerge,
      ordinaryDescendants: [{
        commit: 'closeout', parents: [B005_IMPLEMENTATION_MERGE.commit, 'other'],
        subject: B005_CLOSEOUT_SUBJECT,
      }],
    }, 'FAIL'],
    ['bad closeout subject FAIL', {
      ...base, mergeCommits: [B005_IMPLEMENTATION_MERGE.commit], merge: exactMerge,
      ordinaryDescendants: [{
        commit: 'closeout', parents: [B005_IMPLEMENTATION_MERGE.commit], subject: 'wrong',
      }],
    }, 'FAIL'],
  ];
}

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push('ok: ' + message);
  const fail = (message) => { pass = false; details.push('FAIL: ' + message); };
  const anchor = (label, actual, expected) => {
    if (same(actual, expected)) ok(label + ' anchored');
    else fail(label + ' drifted');
  };
  anchor('ALLOWED_PATHS', ALLOWED_PATHS, ALLOWED_PATHS_LITERAL);
  anchor('FORBIDDEN_PREFIXES', FORBIDDEN_PREFIXES, FORBIDDEN_PREFIXES_LITERAL);
  anchor('FROZEN_REGISTRY_PATHS', FROZEN_REGISTRY_PATHS, FROZEN_REGISTRY_PATHS_LITERAL);
  anchor('CLOSEOUT_ALLOWED_PATHS', CLOSEOUT_ALLOWED_PATHS, CLOSEOUT_ALLOWED_PATHS_LITERAL);
  anchor('B005_CANDIDATE_HISTORY', B005_CANDIDATE_HISTORY, B005_CANDIDATE_HISTORY_LITERAL);

  let pathProbeFailures = 0;
  let pathProbeCount = 0;
  const pathProbe = (relative, expected) => {
    pathProbeCount += 1;
    const actual = pathMatchesAllowed(relative);
    if (actual !== expected) { pathProbeFailures += 1; fail('allowlist probe mismatch: ' + relative); }
  };
  for (const pattern of ALLOWED_PATHS_LITERAL) {
    if (pattern.endsWith('/**')) {
      const root = pattern.slice(0, -3);
      pathProbe(root + '/direct.txt', true);
      pathProbe(root + '/nested/deep.txt', true);
    } else pathProbe(pattern, true);
  }
  for (const relative of FALSE_ALLOWLIST_PROBES) pathProbe(relative, false);
  if (pathProbeFailures === 0) ok('all ' + pathProbeCount + ' allowlist/lookalike probes matched');

  let closeoutPathProbeFailures = 0;
  for (const relative of CLOSEOUT_ALLOWED_PATHS_LITERAL) {
    if (!pathMatchesCloseoutAllowed(relative)) {
      closeoutPathProbeFailures += 1;
      fail('closeout allowlist rejected exact path: ' + relative);
    }
  }
  for (const relative of FALSE_CLOSEOUT_ALLOWLIST_PROBES) {
    if (pathMatchesCloseoutAllowed(relative)) {
      closeoutPathProbeFailures += 1;
      fail('closeout allowlist accepted forbidden/lookalike path: ' + relative);
    }
  }
  if (closeoutPathProbeFailures === 0) {
    ok('all exact closeout allowlist/lookalike probes matched');
  }

  const baseCommit = git(ctx.repo, ['rev-parse', BASE_COMMIT + '^{commit}'], { check: false });
  const baseTree = git(ctx.repo, ['rev-parse', BASE_COMMIT + '^{tree}'], { check: false });
  if (baseCommit.status !== 0 || baseCommit.stdout.trim() !== BASE_COMMIT ||
      baseTree.status !== 0 || baseTree.stdout.trim() !== BASE_TREE) fail('B005 base commit/tree does not resolve exactly');
  else ok('B005 base commit/tree verified');

  const historical = [
    ['B004 Candidate', B004_CANDIDATE.commit, B004_CANDIDATE.tree,
      [B004_CONSTRUCTION_CHECKPOINT.commit]],
    ['B004 merge', B004_IMPLEMENTATION_MERGE.commit, B004_IMPLEMENTATION_MERGE.tree,
      [B004_IMPLEMENTATION_MERGE.parent1, B004_IMPLEMENTATION_MERGE.parent2]],
    ['B004 repair', B004_POST_MERGE_REPAIR.commit, B004_POST_MERGE_REPAIR.tree,
      [B004_POST_MERGE_REPAIR.parent]],
    ['B004 closeout', B004_CLOSEOUT.commit, B004_CLOSEOUT.tree, [B004_CLOSEOUT.parent]],
  ];
  for (const [label, commit, tree, expectedParents] of historical) {
    const treeProbe = git(ctx.repo, ['rev-parse', commit + '^{tree}'], { check: false });
    const parentProbe = git(ctx.repo, ['rev-list', '--parents', '-n', '1', commit], { check: false });
    const tokens = parentProbe.status === 0 ? parentProbe.stdout.trim().split(/\s+/) : [];
    if (treeProbe.status !== 0 || treeProbe.stdout.trim() !== tree ||
        !same(tokens.slice(1), expectedParents)) fail(label + ' immutable topology drifted');
    else ok(label + ' immutable topology verified');
  }
  const mergeTreeDiff = git(ctx.repo, ['diff', '--quiet', B004_CANDIDATE.commit, B004_IMPLEMENTATION_MERGE.commit], { check: false });
  if (mergeTreeDiff.status !== 0) fail('B004 accepted merge no longer shares the Candidate tree');
  else ok('B004 accepted merge still shares the Candidate tree');

  const b005Historical = [
    ['B005 Candidate', B005_CANDIDATE.commit, B005_CANDIDATE.tree],
    ['B005 implementation merge', B005_IMPLEMENTATION_MERGE.commit, B005_IMPLEMENTATION_MERGE.tree],
  ];
  for (const [label, commit, tree] of b005Historical) {
    const resolvedTree = git(ctx.repo, ['rev-parse', commit + '^{tree}'], { check: false });
    if (resolvedTree.status !== 0 || resolvedTree.stdout.trim() !== tree) fail(label + ' tree drifted');
    else ok(label + ' tree verified');
  }
  const candidateHistoryProbe = git(ctx.repo, [
    'rev-list', '--reverse', '--first-parent', BASE_COMMIT + '..' + B005_CANDIDATE.commit,
  ], { check: false });
  const candidateHistory = candidateHistoryProbe.status === 0
    ? candidateHistoryProbe.stdout.split('\n').filter(Boolean) : null;

  const trackedChanged = git(ctx.repo, ['diff', '--name-only', '--no-renames', BASE_COMMIT])
    .stdout.split('\n').filter(Boolean);
  const artifactProbes = [
    ['node_modules/.pnpm/lock.yaml', true],
    ['packages/harness-adapter/node_modules/@aipt/adapter-sdk', true],
    ['packages/node_modules-shadow/file.ts', false],
    ['packages/harness-adapter/src/node_modules-guard.ts', false],
  ];
  let artifactProbeFailures = 0;
  for (const [relative, expected] of artifactProbes) {
    if (isGeneratedWorktreeArtifact(relative) !== expected) {
      artifactProbeFailures += 1;
      fail('generated-worktree artifact probe mismatch: ' + relative);
    }
  }
  if (artifactProbeFailures === 0) {
    ok('generated-worktree artifact filter matches exact node_modules path segments only');
  }
  const untracked = git(ctx.repo, ['ls-files', '--others', '--exclude-standard'])
    .stdout.split('\n').filter((relative) => relative && !isGeneratedWorktreeArtifact(relative));
  const changed = [...new Set([...trackedChanged, ...untracked])].sort();
  if (changed.length === 0) fail('B005 candidate has no changed paths');
  else ok(changed.length + ' B005 paths differ from the accepted base');
  let scopeFailures = 0;
  for (const relative of changed) {
    if (!pathMatchesAllowed(relative)) { scopeFailures += 1; fail('path outside B005 scope: ' + relative); }
    const forbidden = FORBIDDEN_PREFIXES.find((prefix) => relative.startsWith(prefix));
    if (forbidden) { scopeFailures += 1; fail('forbidden path changed (' + forbidden + '): ' + relative); }
    if (FROZEN_REGISTRY_PATHS.includes(relative)) { scopeFailures += 1; fail('frozen registry changed: ' + relative); }
  }
  if (scopeFailures === 0) ok('all changed paths remain inside exact B005 scope');

  const ancestry = git(ctx.repo, ['merge-base', '--is-ancestor', BASE_COMMIT, 'HEAD'], { check: false });
  const mergeListProbe = git(ctx.repo, ['rev-list', '--merges', '--reverse', BASE_COMMIT + '..HEAD'], { check: false });
  const mergeCommits = mergeListProbe.status === 0
    ? mergeListProbe.stdout.split('\n').filter(Boolean) : null;
  let merge;
  let ordinaryDescendants = [];
  if (Array.isArray(mergeCommits) && mergeCommits.length === 1) {
    const commit = mergeCommits[0];
    const tokens = git(ctx.repo, ['rev-list', '--parents', '-n', '1', commit], { check: false })
      .stdout.trim().split(/\s+/).filter(Boolean);
    const parents = tokens.slice(1);
    const secondParent = parents[1];
    const tree = git(ctx.repo, ['rev-parse', commit + '^{tree}'], { check: false }).stdout.trim();
    const secondParentTree = secondParent
      ? git(ctx.repo, ['rev-parse', secondParent + '^{tree}'], { check: false }).stdout.trim() : '';
    const candidateAncestry = secondParent
      ? git(ctx.repo, ['merge-base', '--is-ancestor', BASE_COMMIT, secondParent], { check: false }) : { status: 2 };
    const candidateMerges = secondParent
      ? git(ctx.repo, ['rev-list', '--merges', BASE_COMMIT + '..' + secondParent], { check: false }) : { status: 2, stdout: '' };
    merge = {
      commit, parents, secondParent, tree, secondParentTree,
      candidateDescendsFromBase: candidateAncestry.status === 0,
      candidateMergeCommits: candidateMerges.status === 0
        ? candidateMerges.stdout.split('\n').filter(Boolean) : ['UNREADABLE'],
      treeDiffQuiet: secondParent
        ? git(ctx.repo, ['diff', '--quiet', secondParent, commit], { check: false }).status === 0 : false,
      subject: git(ctx.repo, ['show', '-s', '--format=%s', commit], { check: false }).stdout.trim(),
    };
    const later = git(ctx.repo, ['rev-list', '--reverse', '--ancestry-path', '--parents', commit + '..HEAD'], { check: false });
    ordinaryDescendants = later.status === 0
      ? later.stdout.split('\n').filter(Boolean).map((line) => {
          const parts = line.trim().split(/\s+/);
          return {
            commit: parts[0], parents: parts.slice(1),
            subject: git(ctx.repo, ['show', '-s', '--format=%s', parts[0]], { check: false }).stdout.trim(),
          };
        }) : null;
  }
  const lifecycle = evaluateB005Lifecycle({
    baseCommit: BASE_COMMIT, baseTree: BASE_TREE,
    ancestryKnown: ancestry.status === 0 || ancestry.status === 1,
    baseIsAncestor: ancestry.status === 0, candidateHistory,
    mergeCommits, merge, ordinaryDescendants,
  });
  if (lifecycle.result === 'FAIL') for (const problem of lifecycle.problems) fail('B005 lifecycle: ' + problem);
  else ok(lifecycle.phase === 'CANDIDATE'
    ? 'candidate history contains no post-base merge'
    : 'post-merge history has the exact structural merge and linear descendants');

  let topologyFailures = 0;
  const probes = topologyProbes();
  for (const [label, input, expected] of probes) {
    const actual = evaluateB005Lifecycle(input).result;
    if (actual !== expected) { topologyFailures += 1; fail(label + ': expected ' + expected + ', got ' + actual); }
  }
  if (topologyFailures === 0) ok('all ' + probes.length + ' lifecycle mutation probes matched');

  const closeoutTracked = git(ctx.repo, [
    'diff', '--name-only', '--no-renames', B005_IMPLEMENTATION_MERGE.commit,
  ]).stdout.split('\n').filter(Boolean);
  const closeoutChanged = [...new Set([...closeoutTracked, ...untracked])].sort();
  const expectedCloseoutChanged = [...CLOSEOUT_ALLOWED_PATHS_LITERAL].sort();
  if (!same(closeoutChanged, expectedCloseoutChanged)) {
    fail('closeout changed-path set is not exact: ' + JSON.stringify(closeoutChanged));
  } else ok('closeout changed-path set is the exact nine-path authority surface');
  for (const relative of closeoutChanged) {
    if (!pathMatchesCloseoutAllowed(relative)) fail('path outside B005 closeout scope: ' + relative);
  }

  for (const line of git(ctx.repo, ['diff', '--raw', '--no-abbrev', '--no-renames', BASE_COMMIT]).stdout.split('\n').filter(Boolean)) {
    const modes = /^:(\d{6}) (\d{6}) /.exec(line);
    if (modes && [modes[1], modes[2]].some((mode) => mode === '120000' || mode === '160000')) fail('unsafe changed symlink/gitlink: ' + line);
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
    try { current = fs.readFileSync(path.join(ctx.repo, relative), 'utf8'); }
    catch (error) { fail('frozen file unreadable: ' + relative + ': ' + error.message); continue; }
    if (base.status !== 0 || current !== base.stdout) fail('frozen file changed: ' + relative);
    else ok('frozen file unchanged: ' + relative);
  }
  const license = fs.readFileSync(path.join(ctx.repo, 'LICENSE'), 'utf8');
  if (normalizeText(license) !== normalizeText(EXPECTED_MIT_LICENSE)) fail('LICENSE drifted from exact MIT text');
  else ok('LICENSE remains exact MIT text');

  const baseMarkdown = git(ctx.repo, ['ls-tree', '-r', '--name-only', BASE_COMMIT]).stdout
    .split('\n').filter((relative) => relative.endsWith('.md'));
  for (const relative of baseMarkdown) if (!fs.existsSync(path.join(ctx.repo, relative))) fail('base Markdown removed: ' + relative);
  const markdown = collectMarkdownLinkIssues(ctx.repo);
  for (const issue of markdown.issues) fail('Markdown link issue: ' + JSON.stringify(issue));
  if (markdown.issues.length === 0) ok(markdown.mdCount + ' Markdown documents have contained links');
  let jsonFailures = 0;
  for (const file of walkFiles(ctx.repo, (candidate) => candidate.endsWith('.json'))) {
    try { JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch (error) { jsonFailures += 1; fail('JSON parse failed: ' + path.relative(ctx.repo, file)); }
  }
  if (jsonFailures === 0) ok('all source JSON parses');
  const hazards = scanTreeForHazards(ctx.repo);
  for (const finding of hazards) fail('public-tree hygiene finding: ' + JSON.stringify(finding));
  if (hazards.length === 0) ok('public tree has no secret/path/endpoint/prompt hazard');

  const probeRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aipt-b005-hygiene-'));
  try {
    const scriptDir = path.join(probeRoot, 'scripts', 'ci');
    fs.mkdirSync(scriptDir, { recursive: true });
    fs.writeFileSync(path.join(scriptDir, 'probe.mjs'), 'const value = "' + 'sk-' + 'A'.repeat(24) + '";\n');
    if (!scanTreeForHazards(probeRoot).some((finding) => finding.hazard === 'API_KEY_LIKE')) fail('hygiene probe failed');
    else ok('hygiene probe detects executable-source credentials');
  } finally { fs.rmSync(probeRoot, { recursive: true, force: true }); }

  return { result: pass ? 'PASS' : 'FAIL', details, changed_paths: changed };
}

runAsMain(import.meta.url, 'tree-integrity', run);
