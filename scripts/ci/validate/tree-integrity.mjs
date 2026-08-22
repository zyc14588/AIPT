#!/usr/bin/env node
// AIPT-M0-B006 lifecycle-aware tree/scope validator.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  ALLOWED_PATHS, B004_CANDIDATE, B004_CLOSEOUT, B004_CONSTRUCTION_CHECKPOINT,
  B004_IMPLEMENTATION_MERGE, B004_POST_MERGE_REPAIR, B005_CANDIDATE,
  B005_CLOSEOUT, B005_IMPLEMENTATION_MERGE, B006_MERGE_SUBJECT, BASE_COMMIT,
  BASE_TREE, EXPECTED_MIT_LICENSE, FORBIDDEN_PREFIXES, FROZEN_REGISTRY_PATHS,
  normalizeText, pathMatchesAllowed,
} from '../lib/constants.mjs';
import { collectMarkdownLinkIssues, scanTreeForHazards, walkFiles } from '../lib/scan.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

const ALLOWED_PATHS_LITERAL = [
  'schemas/evidence/v1/**',
  'internal/evidence/**',
  'testdata/evidence/v1/**',
  'docs/evidence/**',
  'docs/harness/README.md',
  'README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'package.json',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
  'scripts/ci/validate/workflow.mjs',
  'scripts/ci/validate/evidence.mjs',
  'scripts/ci/validate/harness-adapter.mjs',
  'scripts/ci/validate/standalone-entrypoints.mjs',
  '.github/workflows/ci.yml',
];
const FORBIDDEN_PREFIXES_LITERAL = [
  'api/',
  'migrations/',
  'deploy/',
  'runtime/',
  'packages/adapter-sdk/',
  'schemas/protocol/',
  'testdata/protocol/',
  'docs/architecture/',
  'docs/integration/',
  'docs/test-model/',
  'docs/security/',
  'packages/evidence/',
  'packages/harness-adapter/',
  'internal/protocol/',
  'internal/storage/postgres/',
  'internal/harness/',
  'internal/model/',
  'internal/web/',
  'internal/ipc/',
  'internal/campaign/',
  '.go-version',
  'go.mod',
  'go.sum',
  'LICENSE',
  'tools/toolchain.lock.json',
  'tools/ci-actions.lock.json',
  'tools/supply-chain/policy.json',
  'tools/supply-chain/licenses.json',
  'pnpm-lock.yaml',
  'pnpm-workspace.yaml',
];
const FROZEN_REGISTRY_PATHS_LITERAL = [
  'docs/authority/registry/decisions.json',
  'docs/authority/registry/supersessions.json',
  'docs/authority/registry/deferred-parameters.json',
];
const FROZEN_FILES = [
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
  ...FROZEN_REGISTRY_PATHS_LITERAL,
];
const FALSE_ALLOWLIST_PROBES = [
  'schemas/evidence-v1/lookalike.json',
  'internal/evidences/export.go',
  'testdata/evidence/v2/fixture.json',
  'docs/evidence.md',
  'scripts/ci/validate/evidence.mjs.bak',
  'packages/evidence/export.ts',
  'internal/storage/postgres/evidence.go',
  'internal/protocol/evidence.go',
  'UNREGISTERED-AIPT-P0-B002/README.md',
];

function same(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function isGeneratedWorktreeArtifact(relative) {
  return relative.split('/').includes('node_modules');
}

export function evaluateB006Lifecycle(input) {
  const problems = [];
  if (input?.baseCommit !== BASE_COMMIT) problems.push('base commit drifted');
  if (input?.baseTree !== BASE_TREE) problems.push('base tree drifted');
  if (input?.ancestryKnown !== true) problems.push('base ancestry is unreadable');
  if (input?.baseIsAncestor !== true) problems.push('HEAD does not descend from the B006 base');
  if (!Array.isArray(input?.mergeCommits)) {
    problems.push('post-base merge history is unreadable');
    return { result: 'FAIL', phase: 'UNKNOWN', problems };
  }
  if (input.mergeCommits.length === 0) {
    return { result: problems.length === 0 ? 'PASS' : 'FAIL', phase: 'CANDIDATE', problems };
  }
  if (input.mergeCommits.length !== 1) {
    problems.push('exactly one post-base merge is permitted after Candidate acceptance');
    return { result: 'FAIL', phase: 'POST_MERGE', problems };
  }
  const merge = input?.merge;
  if (!merge || merge.commit !== input.mergeCommits[0]) problems.push('merge identity is unreadable');
  if (!Array.isArray(merge?.parents) || merge.parents.length !== 2) {
    problems.push('authorized merge must have exactly two parents');
  } else if (merge.parents[0] !== BASE_COMMIT) {
    problems.push('merge first parent is not the B006 base');
  }
  if (merge?.secondParent !== merge?.parents?.[1]) problems.push('merge second parent identity drifted');
  if (merge?.candidateDescendsFromBase !== true) problems.push('merge second parent does not descend from base');
  if (!Array.isArray(merge?.candidateMergeCommits) || merge.candidateMergeCommits.length !== 0) {
    problems.push('Candidate history contains a merge');
  }
  if (merge?.tree !== merge?.secondParentTree) problems.push('merge tree differs from Candidate tree');
  if (merge?.treeDiffQuiet !== true) problems.push('merge introduced tree changes');
  if (merge?.subject !== B006_MERGE_SUBJECT) problems.push('merge subject drifted');
  if (!Array.isArray(input?.ordinaryDescendants)) {
    problems.push('later history is unreadable');
  } else {
    let expectedParent = merge?.commit;
    for (const entry of input.ordinaryDescendants) {
      if (!Array.isArray(entry?.parents) || entry.parents.length !== 1) {
        problems.push('later descendant is not single-parent');
      } else if (entry.parents[0] !== expectedParent) {
        problems.push('later descendants are not one linear chain');
      }
      expectedParent = entry?.commit;
    }
  }
  return { result: problems.length === 0 ? 'PASS' : 'FAIL', phase: 'POST_MERGE', problems };
}

function topologyProbes() {
  const candidate = {
    baseCommit: BASE_COMMIT,
    baseTree: BASE_TREE,
    ancestryKnown: true,
    baseIsAncestor: true,
    mergeCommits: [],
    ordinaryDescendants: [],
  };
  const merge = {
    commit: 'a'.repeat(40),
    parents: [BASE_COMMIT, 'b'.repeat(40)],
    secondParent: 'b'.repeat(40),
    candidateDescendsFromBase: true,
    candidateMergeCommits: [],
    tree: 'c'.repeat(40),
    secondParentTree: 'c'.repeat(40),
    treeDiffQuiet: true,
    subject: B006_MERGE_SUBJECT,
  };
  const merged = { ...candidate, mergeCommits: [merge.commit], merge };
  return [
    ['candidate history', candidate, 'PASS'],
    ['wrong base', { ...candidate, baseCommit: '0'.repeat(40) }, 'FAIL'],
    ['base is not ancestor', { ...candidate, baseIsAncestor: false }, 'FAIL'],
    ['exact structural merge', merged, 'PASS'],
    ['second merge', { ...merged, mergeCommits: [merge.commit, 'd'.repeat(40)] }, 'FAIL'],
    ['bad first parent', { ...merged, merge: { ...merge, parents: ['e'.repeat(40), merge.secondParent] } }, 'FAIL'],
    ['nested Candidate merge', { ...merged, merge: { ...merge, candidateMergeCommits: ['f'.repeat(40)] } }, 'FAIL'],
    ['changed merge tree', { ...merged, merge: { ...merge, treeDiffQuiet: false } }, 'FAIL'],
    ['wrong merge subject', { ...merged, merge: { ...merge, subject: 'merge: integrate something else' } }, 'FAIL'],
    ['linear descendant', {
      ...merged,
      ordinaryDescendants: [{ commit: '1'.repeat(40), parents: [merge.commit] }],
    }, 'PASS'],
    ['later merge', {
      ...merged,
      ordinaryDescendants: [{ commit: '1'.repeat(40), parents: [merge.commit, '2'.repeat(40)] }],
    }, 'FAIL'],
    ['nonlinear descendant', {
      ...merged,
      ordinaryDescendants: [{ commit: '1'.repeat(40), parents: ['3'.repeat(40)] }],
    }, 'FAIL'],
  ];
}

function verifyHistoricalTopology(repo, fail, ok) {
  const historical = [
    ['B004 Candidate', B004_CANDIDATE.commit, B004_CANDIDATE.tree,
      [B004_CONSTRUCTION_CHECKPOINT.commit]],
    ['B004 merge', B004_IMPLEMENTATION_MERGE.commit, B004_IMPLEMENTATION_MERGE.tree,
      [B004_IMPLEMENTATION_MERGE.parent1, B004_IMPLEMENTATION_MERGE.parent2]],
    ['B004 repair', B004_POST_MERGE_REPAIR.commit, B004_POST_MERGE_REPAIR.tree,
      [B004_POST_MERGE_REPAIR.parent]],
    ['B004 closeout', B004_CLOSEOUT.commit, B004_CLOSEOUT.tree, [B004_CLOSEOUT.parent]],
    ['B005 implementation merge', B005_IMPLEMENTATION_MERGE.commit, B005_IMPLEMENTATION_MERGE.tree,
      [B005_IMPLEMENTATION_MERGE.parent1, B005_IMPLEMENTATION_MERGE.parent2]],
    ['B005 closeout/B006 base', B005_CLOSEOUT.commit, B005_CLOSEOUT.tree, [B005_CLOSEOUT.parent]],
  ];
  for (const [label, commit, tree, parents] of historical) {
    const treeProbe = git(repo, ['rev-parse', commit + '^{tree}'], { check: false });
    const parentProbe = git(repo, ['rev-list', '--parents', '-n', '1', commit], { check: false });
    const tokens = parentProbe.status === 0 ? parentProbe.stdout.trim().split(/\s+/) : [];
    if (treeProbe.status !== 0 || treeProbe.stdout.trim() !== tree || !same(tokens.slice(1), parents)) {
      fail(label + ' immutable topology drifted');
    } else ok(label + ' immutable topology verified');
  }
  const candidateTree = git(repo, ['rev-parse', B005_CANDIDATE.commit + '^{tree}'], { check: false });
  const mergeDiff = git(repo, ['diff', '--quiet', B005_CANDIDATE.commit, B005_IMPLEMENTATION_MERGE.commit], { check: false });
  if (candidateTree.status !== 0 || candidateTree.stdout.trim() !== B005_CANDIDATE.tree || mergeDiff.status !== 0) {
    fail('B005 Candidate/merge immutable tree relationship drifted');
  } else ok('B005 Candidate and implementation merge still share the accepted tree');
}

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push('ok: ' + message);
  const fail = (message) => { pass = false; details.push('FAIL: ' + message); };
  const anchor = (label, actual, expected) => {
    if (same(actual, expected)) ok(label + ' anchored'); else fail(label + ' drifted');
  };
  anchor('ALLOWED_PATHS', ALLOWED_PATHS, ALLOWED_PATHS_LITERAL);
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
  for (const pattern of ALLOWED_PATHS_LITERAL) {
    if (pattern.endsWith('/**')) {
      const root = pattern.slice(0, -3);
      pathProbe(root + '/direct.txt', true);
      pathProbe(root + '/nested/deep.txt', true);
    } else pathProbe(pattern, true);
  }
  for (const relative of FALSE_ALLOWLIST_PROBES) pathProbe(relative, false);
  if (probeFailures === 0) ok('all ' + probeCount + ' allowlist/lookalike probes matched');

  const baseCommit = git(ctx.repo, ['rev-parse', BASE_COMMIT + '^{commit}'], { check: false });
  const baseTree = git(ctx.repo, ['rev-parse', BASE_COMMIT + '^{tree}'], { check: false });
  if (baseCommit.status !== 0 || baseCommit.stdout.trim() !== BASE_COMMIT ||
      baseTree.status !== 0 || baseTree.stdout.trim() !== BASE_TREE) {
    fail('B006 base commit/tree does not resolve exactly');
  } else ok('B006 base commit/tree verified');
  verifyHistoricalTopology(ctx.repo, fail, ok);

  const tracked = git(ctx.repo, ['diff', '--name-only', '--no-renames', BASE_COMMIT])
    .stdout.split('\n').filter(Boolean);
  const artifactProbes = [
    ['node_modules/.pnpm/lock.yaml', true],
    ['internal/evidence/node_modules/probe.js', true],
    ['internal/node_modules-shadow/probe.js', false],
    ['internal/evidence/node_modules-guard.go', false],
  ];
  for (const [relative, expected] of artifactProbes) {
    if (isGeneratedWorktreeArtifact(relative) !== expected) fail('artifact filter probe mismatch: ' + relative);
  }
  const untracked = git(ctx.repo, ['ls-files', '--others', '--exclude-standard'])
    .stdout.split('\n').filter((relative) => relative && !isGeneratedWorktreeArtifact(relative));
  const changed = [...new Set([...tracked, ...untracked])].sort();
  if (changed.length === 0) fail('B006 candidate has no changed paths');
  else ok(changed.length + ' B006 paths differ from the accepted base');
  let scopeFailures = 0;
  for (const relative of changed) {
    if (!pathMatchesAllowed(relative)) {
      scopeFailures += 1;
      fail('path outside B006 scope: ' + relative);
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
  if (scopeFailures === 0) ok('all changed paths remain inside exact B006 scope');

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
    const candidateMerges = secondParent
      ? git(ctx.repo, ['rev-list', '--merges', BASE_COMMIT + '..' + secondParent], { check: false })
      : { status: 2, stdout: '' };
    merge = {
      commit,
      parents,
      secondParent,
      candidateDescendsFromBase: secondParent
        ? git(ctx.repo, ['merge-base', '--is-ancestor', BASE_COMMIT, secondParent], { check: false }).status === 0
        : false,
      candidateMergeCommits: candidateMerges.status === 0
        ? candidateMerges.stdout.split('\n').filter(Boolean) : ['UNREADABLE'],
      tree: git(ctx.repo, ['rev-parse', commit + '^{tree}'], { check: false }).stdout.trim(),
      secondParentTree: secondParent
        ? git(ctx.repo, ['rev-parse', secondParent + '^{tree}'], { check: false }).stdout.trim() : '',
      treeDiffQuiet: secondParent
        ? git(ctx.repo, ['diff', '--quiet', secondParent, commit], { check: false }).status === 0 : false,
      subject: git(ctx.repo, ['show', '-s', '--format=%s', commit], { check: false }).stdout.trim(),
    };
    const later = git(ctx.repo, ['rev-list', '--reverse', '--ancestry-path', '--parents', commit + '..HEAD'], { check: false });
    ordinaryDescendants = later.status === 0
      ? later.stdout.split('\n').filter(Boolean).map((line) => {
          const parts = line.trim().split(/\s+/);
          return { commit: parts[0], parents: parts.slice(1) };
        })
      : null;
  }
  const lifecycle = evaluateB006Lifecycle({
    baseCommit: BASE_COMMIT,
    baseTree: BASE_TREE,
    ancestryKnown: ancestry.status === 0 || ancestry.status === 1,
    baseIsAncestor: ancestry.status === 0,
    mergeCommits,
    merge,
    ordinaryDescendants,
  });
  if (lifecycle.result === 'FAIL') {
    for (const problem of lifecycle.problems) fail('B006 lifecycle: ' + problem);
  } else ok(lifecycle.phase === 'CANDIDATE'
    ? 'Candidate history contains zero post-base merges'
    : 'post-merge history has one exact structural merge and linear descendants');
  for (const [label, input, expected] of topologyProbes()) {
    const actual = evaluateB006Lifecycle(input).result;
    if (actual !== expected) fail('lifecycle probe ' + label + ': expected ' + expected + ', got ' + actual);
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
  for (const file of walkFiles(ctx.repo, (candidate) => candidate.endsWith('.json'))) {
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

  const probeRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aipt-b006-hygiene-'));
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

  return { result: pass ? 'PASS' : 'FAIL', details, changed_paths: changed };
}

runAsMain(import.meta.url, 'tree-integrity', run);
