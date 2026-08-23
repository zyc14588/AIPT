#!/usr/bin/env node
// AIPT-M0-B007 lifecycle/tree/scope validator.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  ALLOWED_PATHS, B004_CANDIDATE, B004_CLOSEOUT,
  B004_CONSTRUCTION_CHECKPOINT, B004_IMPLEMENTATION_MERGE,
  B004_POST_MERGE_REPAIR, B005_CANDIDATE, B005_CLOSEOUT,
  B005_IMPLEMENTATION_MERGE, B006_CANDIDATE, B006_CLOSEOUT,
  B006_IMPLEMENTATION_MERGE, B007_CLOSEOUT_SUBJECT, B007_MERGE_SUBJECT,
  BASE_COMMIT, BASE_TREE, CLOSEOUT_ALLOWED_PATHS, EXPECTED_MIT_LICENSE,
  FORBIDDEN_PREFIXES, FROZEN_REGISTRY_PATHS, normalizeText,
  pathMatchesAllowed, pathMatchesCloseoutAllowed,
} from '../lib/constants.mjs';
import { collectMarkdownLinkIssues, scanTreeForHazards, walkFiles } from '../lib/scan.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

const ALLOWED_PATHS_LITERAL = [
  '.github/workflows/ci.yml',
  'README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'docs/runtime/README.md',
  'docs/security/README.md',
  'internal/launcher/dependencies.go',
  'internal/launcher/gates.go',
  'internal/launcher/launcher.go',
  'internal/launcher/launcher_test.go',
  'internal/web/**',
  'package.json',
  'packages/web-ui/**',
  'pnpm-lock.yaml',
  'schemas/web/v1/**',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/run-checks.mjs',
  'scripts/ci/sbom/generate-sbom.mjs',
  'scripts/ci/validate/runtime-shell.mjs',
  'scripts/ci/validate/sbom.mjs',
  'scripts/ci/validate/standalone-entrypoints.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/supply-chain.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
  'scripts/ci/validate/web-ui.mjs',
  'scripts/ci/validate/workflow.mjs',
];
const CLOSEOUT_ALLOWED_PATHS_LITERAL = [
  'README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'docs/runtime/README.md',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
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
  'packages/evidence/',
  'packages/harness-adapter/',
  'internal/protocol/',
  'internal/storage/postgres/',
  'internal/harness/',
  'internal/model/',
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
  'pnpm-workspace.yaml',
  'tools/toolchain.lock.json',
  'tools/ci-actions.lock.json',
  'tools/supply-chain/policy.json',
  'tools/supply-chain/licenses.json',
  ...FROZEN_REGISTRY_PATHS_LITERAL,
];
const FALSE_ALLOWLIST_PROBES = [
  'schemas/web-v1/lookalike.json',
  'schemas/web/v2/aipt-web.schema.json',
  'internal/websocket/server.go',
  'internal/storage/postgres/queue.go',
  'packages/web-ui-copy/src/dashboard.ts',
  'packages/harness-adapter/src/web.ts',
  'docs/security.md',
  'scripts/ci/validate/web-ui.mjs.bak',
  'INT-AIPT-UNREGISTERED-001/README.md',
  'AIPT-M0-B008/README.md',
];
const FALSE_CLOSEOUT_ALLOWLIST_PROBES = [
  'schemas/web/v1/aipt-web.schema.json',
  'internal/web/server.go',
  'packages/web-ui/src/dashboard.ts',
  'docs/security/README.md',
  'package.json',
  'pnpm-lock.yaml',
  '.github/workflows/ci.yml',
  'scripts/ci/validate/web-ui.mjs',
  'tools/toolchain.lock.json',
  'README.md.bak',
];

function same(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function isGeneratedWorktreeArtifact(relative) {
  return relative.split('/').includes('node_modules');
}

// Pure lifecycle evaluator used by the live gate and deterministic probes.
// Candidate identities are deliberately discovered, never self-approved as
// immutable constants before their exact remote CI has succeeded.
export function evaluateB007Lifecycle(input) {
  const problems = [];
  if (input?.baseCommit !== BASE_COMMIT) problems.push('base commit drifted');
  if (input?.baseTree !== BASE_TREE) problems.push('base tree drifted');
  if (input?.ancestryKnown !== true) problems.push('HEAD ancestry is unknown');
  if (input?.baseIsAncestor !== true) problems.push('HEAD does not descend from the B007 base');
  if (!Array.isArray(input?.candidateHistory) || input.candidateHistory.length === 0) {
    problems.push('Candidate history is empty or unreadable');
  }
  if (!Array.isArray(input?.candidateMergeCommits)) problems.push('Candidate merge list is unreadable');
  else if (input.candidateMergeCommits.length !== 0) problems.push('Candidate history contains a merge');
  if (!Array.isArray(input?.mergeCommits)) problems.push('post-base merge list is unreadable');
  if (problems.length > 0) return { result: 'FAIL', phase: 'UNKNOWN', problems };

  if (input.mergeCommits.length === 0) {
    return { result: 'PASS', phase: 'CANDIDATE', problems: [] };
  }
  if (input.mergeCommits.length !== 1) problems.push('exactly one post-base merge is permitted');
  const merge = input.merge;
  if (!merge || typeof merge !== 'object') problems.push('authorized merge object is missing');
  if (input.mergeCommits[0] !== merge?.commit) problems.push('merge list and merge identity differ');
  if (!Array.isArray(merge?.parents) || merge.parents.length !== 2) {
    problems.push('authorized merge must have exactly two parents');
  } else {
    if (merge.parents[0] !== BASE_COMMIT) problems.push('merge first parent is not the B007 base');
    if (merge.parents[1] !== merge?.secondParent) problems.push('merge second parent identity drifted');
  }
  if (merge?.candidateDescendsFromBase !== true) problems.push('Candidate does not descend from base');
  if (merge?.tree !== merge?.secondParentTree) problems.push('merge tree differs from Candidate tree');
  if (merge?.treeDiffQuiet !== true) problems.push('merge introduced tree changes');
  if (merge?.subject !== B007_MERGE_SUBJECT) problems.push('merge subject drifted');
  if (!Array.isArray(input?.ordinaryDescendants)) problems.push('later history is unreadable');
  else {
    let expectedParent = merge?.commit;
    let closeoutSeen = false;
    for (let index = 0; index < input.ordinaryDescendants.length; index += 1) {
      const entry = input.ordinaryDescendants[index];
      if (!Array.isArray(entry?.parents) || entry.parents.length !== 1) {
        problems.push('later descendant is not single-parent');
      } else if (entry.parents[0] !== expectedParent) {
        problems.push('later descendants are not one linear chain');
      }
      if (entry?.subject === B007_MERGE_SUBJECT) problems.push('merge subject repeated in ordinary history');
      if (entry?.subject === B007_CLOSEOUT_SUBJECT) {
        if (closeoutSeen) problems.push('more than one closeout is not permitted');
        if (index !== input.ordinaryDescendants.length - 1) problems.push('closeout is not the final descendant');
        closeoutSeen = true;
      } else if (closeoutSeen) {
        problems.push('repair appears after closeout');
      }
      expectedParent = entry?.commit;
    }
  }
  return { result: problems.length === 0 ? 'PASS' : 'FAIL', phase: 'POST_MERGE', problems };
}

function topologyProbes() {
  const base = {
    baseCommit: BASE_COMMIT,
    baseTree: BASE_TREE,
    ancestryKnown: true,
    baseIsAncestor: true,
    candidateHistory: ['candidate'],
    candidateMergeCommits: [],
    mergeCommits: [],
    ordinaryDescendants: [],
  };
  const exactMerge = {
    commit: 'merge',
    parents: [BASE_COMMIT, 'candidate'],
    secondParent: 'candidate',
    candidateDescendsFromBase: true,
    tree: 'candidate-tree',
    secondParentTree: 'candidate-tree',
    treeDiffQuiet: true,
    subject: B007_MERGE_SUBJECT,
  };
  const merged = { ...base, mergeCommits: ['merge'], merge: exactMerge };
  return [
    ['Candidate PASS', base, 'PASS'],
    ['empty Candidate FAIL', { ...base, candidateHistory: [] }, 'FAIL'],
    ['Candidate merge FAIL', { ...base, candidateMergeCommits: ['m'], mergeCommits: ['m'] }, 'FAIL'],
    ['exact implementation merge PASS', merged, 'PASS'],
    ['bad first parent FAIL', { ...merged, merge: { ...exactMerge, parents: ['wrong', 'candidate'] } }, 'FAIL'],
    ['bad Candidate tree FAIL', { ...merged, merge: { ...exactMerge, secondParentTree: 'wrong' } }, 'FAIL'],
    ['merge changes tree FAIL', { ...merged, merge: { ...exactMerge, treeDiffQuiet: false } }, 'FAIL'],
    ['wrong merge subject FAIL', { ...merged, merge: { ...exactMerge, subject: 'merge: wrong' } }, 'FAIL'],
    ['second merge FAIL', { ...merged, mergeCommits: ['merge', 'merge-2'] }, 'FAIL'],
    ['linear repairs PASS', {
      ...merged,
      ordinaryDescendants: [
        { commit: 'repair-1', parents: ['merge'], subject: 'fix: repair validator' },
        { commit: 'repair-2', parents: ['repair-1'], subject: 'fix: repair docs' },
      ],
    }, 'PASS'],
    ['repairs plus final closeout PASS', {
      ...merged,
      ordinaryDescendants: [
        { commit: 'repair', parents: ['merge'], subject: 'fix: repair validator' },
        { commit: 'closeout', parents: ['repair'], subject: B007_CLOSEOUT_SUBJECT },
      ],
    }, 'PASS'],
    ['nonlinear descendant FAIL', {
      ...merged,
      ordinaryDescendants: [{ commit: 'repair', parents: ['wrong'], subject: 'fix: repair' }],
    }, 'FAIL'],
    ['later merge FAIL', {
      ...merged,
      ordinaryDescendants: [{ commit: 'repair', parents: ['merge', 'other'], subject: 'fix: repair' }],
    }, 'FAIL'],
    ['closeout not final FAIL', {
      ...merged,
      ordinaryDescendants: [
        { commit: 'closeout', parents: ['merge'], subject: B007_CLOSEOUT_SUBJECT },
        { commit: 'repair', parents: ['closeout'], subject: 'fix: late repair' },
      ],
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
    ['B006 closeout/B007 base', B006_CLOSEOUT.commit, B006_CLOSEOUT.tree, [B006_CLOSEOUT.parent]],
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
  ];
  for (const [label, candidate, tree, merge] of candidateTrees) {
    const actualTree = git(repo, ['rev-parse', candidate + '^{tree}'], { check: false });
    const quiet = git(repo, ['diff', '--quiet', candidate, merge], { check: false });
    if (actualTree.status !== 0 || actualTree.stdout.trim() !== tree || quiet.status !== 0) {
      fail(label + ' Candidate/merge immutable tree relationship drifted');
    } else ok(label + ' Candidate and implementation merge share the accepted tree');
  }
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
  for (const pattern of ALLOWED_PATHS_LITERAL) {
    if (pattern.endsWith('/**')) {
      const root = pattern.slice(0, -3);
      pathProbe(root + '/direct.txt', true);
      pathProbe(root + '/nested/deep.txt', true);
    } else pathProbe(pattern, true);
  }
  for (const relative of FALSE_ALLOWLIST_PROBES) pathProbe(relative, false);
  if (probeFailures === 0) ok('all ' + probeCount + ' allowlist/lookalike probes matched');

  let closeoutProbeFailures = 0;
  for (const relative of CLOSEOUT_ALLOWED_PATHS_LITERAL) {
    if (!pathMatchesCloseoutAllowed(relative)) {
      closeoutProbeFailures += 1;
      fail('closeout allowlist rejected exact path: ' + relative);
    }
  }
  for (const relative of FALSE_CLOSEOUT_ALLOWLIST_PROBES) {
    if (pathMatchesCloseoutAllowed(relative)) {
      closeoutProbeFailures += 1;
      fail('closeout allowlist accepted forbidden/lookalike path: ' + relative);
    }
  }
  if (closeoutProbeFailures === 0) ok('all closeout allowlist/lookalike probes matched');

  const baseCommit = git(ctx.repo, ['rev-parse', BASE_COMMIT + '^{commit}'], { check: false });
  const baseTree = git(ctx.repo, ['rev-parse', BASE_COMMIT + '^{tree}'], { check: false });
  if (baseCommit.status !== 0 || baseCommit.stdout.trim() !== BASE_COMMIT ||
      baseTree.status !== 0 || baseTree.stdout.trim() !== BASE_TREE) {
    fail('B007 base commit/tree does not resolve exactly');
  } else ok('B007 base commit/tree verified');
  verifyHistoricalTopology(ctx.repo, fail, ok);

  const tracked = git(ctx.repo, ['diff', '--name-only', '--no-renames', BASE_COMMIT])
    .stdout.split('\n').filter(Boolean);
  const untracked = git(ctx.repo, ['ls-files', '--others', '--exclude-standard'])
    .stdout.split('\n').filter((relative) => relative && !isGeneratedWorktreeArtifact(relative));
  const changed = [...new Set([...tracked, ...untracked])].sort();
  if (changed.length === 0) fail('B007 history has no changed paths');
  else ok(changed.length + ' B007 paths differ from the accepted base');
  let scopeFailures = 0;
  for (const relative of changed) {
    if (!pathMatchesAllowed(relative)) {
      scopeFailures += 1;
      fail('path outside B007 scope: ' + relative);
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
  if (scopeFailures === 0) ok('all changed paths remain inside exact B007 scope');

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
    merge = {
      commit,
      parents,
      secondParent: candidateTip,
      candidateDescendsFromBase: candidateTip
        ? git(ctx.repo, ['merge-base', '--is-ancestor', BASE_COMMIT, candidateTip], { check: false }).status === 0
        : false,
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
  const candidateHistoryProbe = candidateTip
    ? git(ctx.repo, ['rev-list', '--reverse', '--first-parent', BASE_COMMIT + '..' + candidateTip], { check: false })
    : { status: 2, stdout: '' };
  const candidateHistory = candidateHistoryProbe.status === 0
    ? candidateHistoryProbe.stdout.split('\n').filter(Boolean) : null;
  const candidateMergeProbe = candidateTip
    ? git(ctx.repo, ['rev-list', '--merges', BASE_COMMIT + '..' + candidateTip], { check: false })
    : { status: 2, stdout: '' };
  const candidateMergeCommits = candidateMergeProbe.status === 0
    ? candidateMergeProbe.stdout.split('\n').filter(Boolean) : null;
  const lifecycle = evaluateB007Lifecycle({
    baseCommit: BASE_COMMIT,
    baseTree: BASE_TREE,
    ancestryKnown: ancestry.status === 0 || ancestry.status === 1,
    baseIsAncestor: ancestry.status === 0,
    candidateHistory,
    candidateMergeCommits,
    mergeCommits,
    merge,
    ordinaryDescendants,
  });
  if (lifecycle.result === 'FAIL') {
    for (const problem of lifecycle.problems) fail('B007 lifecycle: ' + problem);
  } else if (lifecycle.phase === 'POST_MERGE') {
    ok('POST_MERGE = PASS: only the exact-shape B007 merge and linear descendants exist');
  } else {
    ok('CANDIDATE = PASS: Base..HEAD is non-empty, linear and contains zero merges');
  }
  let topologyFailures = 0;
  const probes = topologyProbes();
  for (const [label, input, expected] of probes) {
    const actual = evaluateB007Lifecycle(input).result;
    if (actual !== expected) {
      topologyFailures += 1;
      fail('lifecycle probe ' + label + ': expected ' + expected + ', got ' + actual);
    }
  }
  if (topologyFailures === 0) ok('all ' + probes.length + ' lifecycle mutation probes matched');

  const hasCloseout = Array.isArray(ordinaryDescendants) &&
    ordinaryDescendants.some((entry) => entry.subject === B007_CLOSEOUT_SUBJECT);
  let closeoutChanged = [];
  if (lifecycle.phase === 'POST_MERGE' && hasCloseout) {
    closeoutChanged = git(ctx.repo, ['diff', '--name-only', '--no-renames', merge.commit, 'HEAD'])
      .stdout.split('\n').filter(Boolean).sort();
    const expected = [...CLOSEOUT_ALLOWED_PATHS_LITERAL].sort();
    if (!same(closeoutChanged, expected)) {
      fail('closeout changed-path set is not exact: ' + JSON.stringify(closeoutChanged));
    } else ok('closeout changed-path set is the exact seven-path authority surface');
    for (const relative of closeoutChanged) {
      if (!pathMatchesCloseoutAllowed(relative)) fail('path outside B007 closeout scope: ' + relative);
    }
  } else ok('no B007 closeout is claimed during Candidate construction');

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

  const probeRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aipt-b007-hygiene-'));
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
