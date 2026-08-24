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
  B008_CLOSEOUT_SUBJECT, B008_MERGE_SUBJECT, BASE_COMMIT, BASE_TREE,
  CLOSEOUT_ALLOWED_PATHS, EXPECTED_MIT_LICENSE, FORBIDDEN_PREFIXES,
  FROZEN_REGISTRY_PATHS, normalizeText, pathMatchesAllowed,
  pathMatchesCloseoutAllowed,
} from '../lib/constants.mjs';
import { collectMarkdownLinkIssues, scanTreeForHazards, walkFiles } from '../lib/scan.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

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
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
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
  '.github/workflows/ci.yml',
  'scripts/ci/validate/workflow.mjs',
  'scripts/ci/validate/standalone-entrypoints.mjs',
  'internal/model/runtime.go',
  'README.md.bak',
];

function same(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function isGeneratedWorktreeArtifact(relative) {
  return relative.split('/').includes('node_modules');
}

// Candidate history is intentionally identified by the future merge's second
// parent. Owner authorization remains external; the validator enforces the
// exact Git topology and zero-delta merge once that authorization exists.
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
    return { result: 'PASS', phase: 'CANDIDATE', problems: [] };
  }
  if (input.mergeCommits.length !== 1) problems.push('exactly one post-base merge is permitted');
  const merge = input.merge;
  if (!merge || typeof merge !== 'object') problems.push('B008 merge object is missing');
  if (merge?.commit !== input.mergeCommits[0]) problems.push('merge identity mismatch');
  if (!Array.isArray(merge?.parents) || merge.parents.length !== 2) {
    problems.push('authorized merge must have exactly two parents');
  } else {
    if (merge.parents[0] !== BASE_COMMIT) problems.push('merge first parent is not the fixed B008 base');
    if (merge.parents[1] !== merge?.secondParent) problems.push('merge second parent identity drifted');
  }
  if (!merge?.secondParent) problems.push('Owner-approved Candidate parent is missing');
  if (merge?.candidateDescendsFromBase !== true) problems.push('Candidate does not descend from base');
  if (merge?.candidateHasMerges !== false) problems.push('Candidate contains a merge commit');
  if (!merge?.secondParentTree) problems.push('Candidate tree is unreadable');
  if (merge?.tree !== merge?.secondParentTree) problems.push('merge tree differs from Candidate tree');
  if (merge?.treeDiffQuiet !== true) problems.push('merge introduced tree changes');
  if (merge?.subject !== B008_MERGE_SUBJECT) problems.push('merge subject drifted');
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
    candidateMergeCommits: [],
    mergeCommits: [],
    ordinaryDescendants: [],
  };
  const exactMerge = {
    commit: 'b008-merge',
    parents: [BASE_COMMIT, 'owner-approved-candidate'],
    secondParent: 'owner-approved-candidate',
    candidateDescendsFromBase: true,
    candidateHasMerges: false,
    tree: 'candidate-tree',
    secondParentTree: 'candidate-tree',
    treeDiffQuiet: true,
    subject: B008_MERGE_SUBJECT,
  };
  const merged = { ...candidate, mergeCommits: ['b008-merge'], merge: exactMerge };
  return [
    ['Candidate PASS', candidate, 'PASS'],
    ['Candidate merge FAIL', { ...candidate, candidateMergeCommits: ['merge'] }, 'FAIL'],
    ['exact implementation merge PASS', merged, 'PASS'],
    ['bad first parent FAIL', { ...merged, merge: { ...exactMerge, parents: ['wrong', 'owner-approved-candidate'] } }, 'FAIL'],
    ['bad Candidate parent FAIL', { ...merged, merge: { ...exactMerge, parents: [BASE_COMMIT, 'wrong'] } }, 'FAIL'],
    ['Candidate merge hidden FAIL', { ...merged, merge: { ...exactMerge, candidateHasMerges: true } }, 'FAIL'],
    ['bad Candidate tree FAIL', { ...merged, merge: { ...exactMerge, secondParentTree: 'wrong' } }, 'FAIL'],
    ['merge changes tree FAIL', { ...merged, merge: { ...exactMerge, treeDiffQuiet: false } }, 'FAIL'],
    ['wrong merge subject FAIL', { ...merged, merge: { ...exactMerge, subject: 'merge: wrong' } }, 'FAIL'],
    ['second merge FAIL', { ...merged, mergeCommits: ['b008-merge', 'merge-2'] }, 'FAIL'],
    ['merge plus exact closeout PASS', {
      ...merged,
      ordinaryDescendants: [{ commit: 'closeout', parents: ['b008-merge'], subject: B008_CLOSEOUT_SUBJECT }],
    }, 'PASS'],
    ['wrong closeout parent FAIL', {
      ...merged,
      ordinaryDescendants: [{ commit: 'closeout', parents: ['wrong'], subject: B008_CLOSEOUT_SUBJECT }],
    }, 'FAIL'],
    ['later merge FAIL', {
      ...merged,
      ordinaryDescendants: [{ commit: 'closeout', parents: ['b008-merge', 'other'], subject: B008_CLOSEOUT_SUBJECT }],
    }, 'FAIL'],
    ['bad closeout subject FAIL', {
      ...merged,
      ordinaryDescendants: [{ commit: 'closeout', parents: ['b008-merge'], subject: 'wrong' }],
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
  if (scopeFailures === 0) ok('all changed paths remain inside exact B008 Candidate scope');

  const ancestry = git(ctx.repo, ['merge-base', '--is-ancestor', BASE_COMMIT, 'HEAD'], { check: false });
  const mergeListProbe = git(ctx.repo, ['rev-list', '--merges', '--reverse', BASE_COMMIT + '..HEAD'], { check: false });
  const mergeCommits = mergeListProbe.status === 0
    ? mergeListProbe.stdout.split('\n').filter(Boolean) : null;
  let candidateTip = 'HEAD';
  let merge;
  let ordinaryDescendants = [];
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
  }
  const candidateMergeProbe = candidateTip
    ? git(ctx.repo, ['rev-list', '--merges', BASE_COMMIT + '..' + candidateTip], { check: false })
    : { status: 2, stdout: '' };
  const candidateMergeCommits = candidateMergeProbe.status === 0
    ? candidateMergeProbe.stdout.split('\n').filter(Boolean) : null;
  const lifecycle = evaluateB008Lifecycle({
    baseCommit: BASE_COMMIT,
    baseTree: BASE_TREE,
    ancestryKnown: ancestry.status === 0 || ancestry.status === 1,
    baseIsAncestor: ancestry.status === 0,
    candidateMergeCommits,
    mergeCommits,
    merge,
    ordinaryDescendants,
  });
  if (lifecycle.result === 'FAIL') {
    for (const problem of lifecycle.problems) fail('B008 lifecycle: ' + problem);
  } else if (lifecycle.phase === 'POST_MERGE') {
    ok('POST_MERGE = PASS: exact B008 merge topology and at most one single-parent closeout');
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
  const hasCloseout = Array.isArray(ordinaryDescendants) && ordinaryDescendants.length === 1 &&
    ordinaryDescendants[0].subject === B008_CLOSEOUT_SUBJECT;
  let closeoutChanged = [];
  if (lifecycle.phase === 'POST_MERGE' && (hasCloseout || statusClaimsCloseout)) {
    const mergeCommit = merge?.commit;
    const closeoutTracked = git(ctx.repo, ['diff', '--name-only', '--no-renames', mergeCommit])
      .stdout.split('\n').filter(Boolean);
    closeoutChanged = [...new Set([...closeoutTracked, ...untracked])].sort();
    for (const relative of closeoutChanged) {
      if (!pathMatchesCloseoutAllowed(relative)) fail('path outside B008 closeout scope: ' + relative);
    }
  } else ok('B008 closeout is not claimed');

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
