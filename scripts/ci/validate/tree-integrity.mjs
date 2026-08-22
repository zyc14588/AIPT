#!/usr/bin/env node
// AIPT-M0-B004 lifecycle-aware tree-integrity and scope validator.
//
// Candidate history is diffed from the immutable B003 closeout base and
// admits no merge commits. Post-merge history admits only the exact authorized
// B004 implementation merge, the exact two-file validator repair, and the
// exact closeout authority surface. Git objects, ordered parents, and every
// lifecycle path set are re-read from Git. All other historical, scope,
// filesystem, link, JSON, and public-tree hygiene gates remain fail closed.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  ALLOWED_PATHS,
  B003_CLOSEOUT,
  B004_CANDIDATE,
  B004_CONSTRUCTION_CHECKPOINT,
  B004_IMPLEMENTATION_MERGE,
  B004_POST_MERGE_REPAIR,
  BASE_COMMIT,
  BASE_TREE,
  CLOSEOUT_ALLOWED_PATHS,
  EXPECTED_MIT_LICENSE,
  FORBIDDEN_PREFIXES,
  FROZEN_REGISTRY_PATHS,
  normalizeText,
  pathMatchesAllowed,
  pathMatchesCloseoutAllowed,
} from '../lib/constants.mjs';
import {
  collectMarkdownLinkIssues,
  scanTreeForHazards,
  walkFiles,
} from '../lib/scan.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

const ALLOWED_PATHS_LITERAL = [
  'cmd/aipt/**',
  'internal/config/**',
  'internal/core/**',
  'internal/launcher/**',
  'schemas/config/v1/**',
  'docs/runtime/**',
  'README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'go.mod',
  'go.sum',
  'package.json',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/defer-016.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/toolchain-lock.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
  'scripts/ci/validate/workflow.mjs',
  'scripts/ci/validate/storage.mjs',
  'scripts/ci/validate/supply-chain.mjs',
  'scripts/ci/validate/sbom.mjs',
  'scripts/ci/validate/runtime-shell.mjs',
  'scripts/ci/validate/standalone-entrypoints.mjs',
  'scripts/ci/sbom/generate-sbom.mjs',
  'tools/supply-chain/licenses.json',
  'docs/supply-chain/README.md',
  '.github/workflows/ci.yml',
];

const FORBIDDEN_PREFIXES_LITERAL = [
  'api/',
  'migrations/',
  'deploy/',
  'runtime/',
  'packages/',
  'schemas/protocol/',
  'testdata/protocol/',
  'docs/architecture/',
  'docs/integration/',
  'docs/test-model/',
  'docs/security/',
  'docs/evidence/',
  'internal/protocol/',
  'internal/storage/postgres/',
  'internal/harness/',
  'internal/model/',
  'internal/web/',
  'internal/ipc/',
  'internal/campaign/',
  '.go-version',
  'pnpm-lock.yaml',
  'LICENSE',
  'tools/toolchain.lock.json',
  'tools/ci-actions.lock.json',
  'tools/supply-chain/policy.json',
];

const FROZEN_REGISTRY_PATHS_LITERAL = [
  'docs/authority/registry/decisions.json',
  'docs/authority/registry/supersessions.json',
  'docs/authority/registry/deferred-parameters.json',
];

const FROZEN_FILES = [
  '.go-version',
  'LICENSE',
  'pnpm-lock.yaml',
  'tools/ci-actions.lock.json',
  'tools/toolchain.lock.json',
  'tools/supply-chain/policy.json',
  ...FROZEN_REGISTRY_PATHS_LITERAL,
];

const FALSE_ALLOWLIST_PROBES = [
  'cmd/aiptx/main.go',
  'cmd/other/main.go',
  'internal/configuration/config.go',
  'internal/corex/core.go',
  'internal/launch/main.go',
  'internal/harness/adapter.go',
  'internal/model/client.go',
  'internal/storage/postgres/ledger.go',
  'schemas/config/v2/config.json',
  'schemas/config/v1.json',
  'docs/runtimeevil/README.md',
  'README.md.bak',
  'go.mod.bak',
  'go.sum.bak',
  'package.json.bak',
  'scripts/ci/validate/toolchain-lock.mjs.bak',
  'scripts/ci/validate/runtime-shell.mjs.bak',
  'scripts/ci/validate/standalone-entrypoints.mjs.bak',
  'scripts/ci/validate/defer-016.mjs.bak',
  'tools/toolchain.lock.json',
  'AIPT-M0-B005/adapter.go',
];

const B004_CANDIDATE_LITERAL = {
  commit: '4810d2cfec6146db7c161506ba7f37ab0a4ce69c',
  tree: 'f35365d0ad47fdd513fbecb84a03b1559026637e',
  ci_run: 32392886647,
};

const B004_IMPLEMENTATION_MERGE_LITERAL = {
  directive: 'AIPT-M0-B004-MERGE-001',
  commit: 'd07c0c3817620ada47b3ae7344d8ee423ace3b12',
  tree: 'f35365d0ad47fdd513fbecb84a03b1559026637e',
  parent1: '6d7225828b45b69ecc44d5bb51a04c40f0865aba',
  parent2: '4810d2cfec6146db7c161506ba7f37ab0a4ce69c',
};

const B004_POST_MERGE_REPAIR_LITERAL = {
  directive: 'AIPT-M0-B004-POSTMERGE-TREE-INTEGRITY-REPAIR-001',
  initial_ci_run: 32557930038,
  initial_ci_conclusion: 'failure',
  failure: 'AIPT-B004-TREE-INTEGRITY-LIFECYCLE-001',
  commit: 'bd0c06867da58f89e82a35d82ce1d798c1ec9cae',
  tree: '02e53e65ea194236e0b34a96768f9a848ecfd3a7',
  parent: 'd07c0c3817620ada47b3ae7344d8ee423ace3b12',
  ci_run: 32558813381,
  ci_conclusion: 'success',
};

const B004_REPAIR_PATHS_LITERAL = [
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
];

const CLOSEOUT_ALLOWED_PATHS_LITERAL = [
  'README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'docs/runtime/README.md',
  'docs/supply-chain/README.md',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
];

function sameStrings(actual, expected) {
  return JSON.stringify(actual) === JSON.stringify(expected);
}

export function evaluateB004MergeTopology(input) {
  const problems = [];
  const candidate = input?.candidate;
  const implementationMerge = input?.implementationMerge;
  const resolvedCandidate = input?.resolvedCandidate;
  const resolvedMerge = input?.resolvedMerge;
  const mergeCommits = input?.mergeCommits;
  const ordinaryDescendants = input?.ordinaryDescendants;
  const ancestryKnown = input?.implementationMergeAncestryKnown === true;
  const postMerge = input?.implementationMergeIsAncestor === true;

  if (!candidate || typeof candidate !== 'object') {
    problems.push('approved B004 Candidate identity is missing');
  }
  if (!implementationMerge || typeof implementationMerge !== 'object') {
    problems.push('approved B004 implementation merge identity is missing');
  }
  if (!Array.isArray(mergeCommits)) {
    problems.push('merge commit set could not be read');
  }
  if (!ancestryKnown) {
    problems.push('approved B004 implementation merge ancestry could not be determined');
  }
  if (!resolvedCandidate || typeof resolvedCandidate !== 'object') {
    problems.push('approved B004 Candidate Git object is missing');
  }
  if (!resolvedMerge || typeof resolvedMerge !== 'object') {
    problems.push('approved B004 implementation merge Git object is missing');
  }

  if (
    candidate &&
    resolvedCandidate &&
    (resolvedCandidate.commit !== candidate.commit || resolvedCandidate.tree !== candidate.tree)
  ) {
    problems.push('approved B004 Candidate Git object commit/tree mismatch');
  }

  if (candidate && implementationMerge) {
    if (implementationMerge.tree !== candidate.tree) {
      problems.push('approved B004 implementation merge tree does not equal the Candidate tree');
    }
    if (implementationMerge.parent2 !== candidate.commit) {
      problems.push('approved B004 implementation merge parent2 does not equal the Candidate commit');
    }
  }

  if (implementationMerge && resolvedMerge) {
    if (resolvedMerge.commit !== implementationMerge.commit) {
      problems.push('approved B004 implementation merge Git object commit mismatch');
    }
    if (resolvedMerge.tree !== implementationMerge.tree) {
      problems.push('approved B004 implementation merge Git object tree mismatch');
    }
    if (!Array.isArray(resolvedMerge.parents) || resolvedMerge.parents.length !== 2) {
      problems.push('approved B004 implementation merge Git object parent count is not exactly two');
    } else {
      if (resolvedMerge.parents[0] !== implementationMerge.parent1) {
        problems.push('approved B004 implementation merge Git object parent1 mismatch');
      }
      if (resolvedMerge.parents[1] !== implementationMerge.parent2) {
        problems.push('approved B004 implementation merge Git object parent2 mismatch');
      }
    }
    if (candidate && resolvedMerge.tree !== candidate.tree) {
      problems.push('implementation merge Git object tree does not equal the approved Candidate tree');
    }
  }

  if (Array.isArray(mergeCommits) && implementationMerge) {
    if (postMerge) {
      if (!sameStrings(mergeCommits, [implementationMerge.commit])) {
        problems.push(
          'post-merge history must contain exactly the authorized B004 implementation merge: ' +
            JSON.stringify(mergeCommits),
        );
      }
    } else if (mergeCommits.length > 0) {
      problems.push(
        'candidate history contains merge commits after the B004 base: ' + mergeCommits.join(', '),
      );
    }
  }

  if (postMerge) {
    if (!Array.isArray(ordinaryDescendants)) {
      problems.push('ordinary post-merge descendant topology could not be read');
    } else {
      for (const descendant of ordinaryDescendants) {
        if (!Array.isArray(descendant?.parents) || descendant.parents.length !== 1) {
          problems.push(
            'post-merge descendant is not an ordinary single-parent commit: ' +
              JSON.stringify(descendant?.commit ?? null),
          );
        }
      }
    }
  }

  return {
    phase: postMerge ? 'POST_MERGE' : 'CANDIDATE',
    result: problems.length === 0 ? 'PASS' : 'FAIL',
    problems,
  };
}

function runMergeTopologyProbes() {
  const exactResolvedCandidate = {
    commit: B004_CANDIDATE_LITERAL.commit,
    tree: B004_CANDIDATE_LITERAL.tree,
  };
  const exactResolvedMerge = {
    commit: B004_IMPLEMENTATION_MERGE_LITERAL.commit,
    tree: B004_IMPLEMENTATION_MERGE_LITERAL.tree,
    parents: [
      B004_IMPLEMENTATION_MERGE_LITERAL.parent1,
      B004_IMPLEMENTATION_MERGE_LITERAL.parent2,
    ],
  };
  const specimen = (overrides = {}) => ({
    candidate: B004_CANDIDATE_LITERAL,
    implementationMerge: B004_IMPLEMENTATION_MERGE_LITERAL,
    implementationMergeAncestryKnown: true,
    implementationMergeIsAncestor: true,
    mergeCommits: [B004_IMPLEMENTATION_MERGE_LITERAL.commit],
    ordinaryDescendants: [],
    resolvedCandidate: exactResolvedCandidate,
    resolvedMerge: exactResolvedMerge,
    ...overrides,
  });
  const otherMerge = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const wrongParent = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
  const wrongTree = 'cccccccccccccccccccccccccccccccccccccccc';
  const probes = [
    {
      label: 'candidate topology with zero merge commits',
      input: specimen({ implementationMergeIsAncestor: false, mergeCommits: [] }),
      expected: 'PASS',
    },
    {
      label: 'candidate history containing any merge commit',
      input: specimen({ implementationMergeIsAncestor: false }),
      expected: 'FAIL',
    },
    {
      label: 'exact authorized implementation merge topology',
      input: specimen(),
      expected: 'PASS',
    },
    {
      label: 'merge SHA is not the authorized implementation merge',
      input: specimen({ mergeCommits: [otherMerge] }),
      expected: 'FAIL',
    },
    {
      label: 'authorized implementation merge identity missing',
      input: specimen({ implementationMerge: null }),
      expected: 'FAIL',
    },
    {
      label: 'authorized merge parent1 wrong',
      input: specimen({
        resolvedMerge: {
          ...exactResolvedMerge,
          parents: [wrongParent, B004_IMPLEMENTATION_MERGE_LITERAL.parent2],
        },
      }),
      expected: 'FAIL',
    },
    {
      label: 'authorized merge parent2 wrong',
      input: specimen({
        resolvedMerge: {
          ...exactResolvedMerge,
          parents: [B004_IMPLEMENTATION_MERGE_LITERAL.parent1, wrongParent],
        },
      }),
      expected: 'FAIL',
    },
    {
      label: 'authorized merge tree wrong',
      input: specimen({ resolvedMerge: { ...exactResolvedMerge, tree: wrongTree } }),
      expected: 'FAIL',
    },
    {
      label: 'authorized merge parent count is not two',
      input: specimen({
        resolvedMerge: {
          ...exactResolvedMerge,
          parents: [B004_IMPLEMENTATION_MERGE_LITERAL.parent1],
        },
      }),
      expected: 'FAIL',
    },
    {
      label: 'authorized merge plus a second merge commit',
      input: specimen({ mergeCommits: [otherMerge, B004_IMPLEMENTATION_MERGE_LITERAL.commit] }),
      expected: 'FAIL',
    },
    {
      label: 'authorized merge plus ordinary repair commit',
      input: specimen({
        ordinaryDescendants: [
          { commit: 'dddddddddddddddddddddddddddddddddddddddd', parents: [B004_IMPLEMENTATION_MERGE_LITERAL.commit] },
        ],
      }),
      expected: 'PASS',
    },
    {
      label: 'authorized merge plus ordinary repair and closeout-like commits',
      input: specimen({
        ordinaryDescendants: [
          {
            commit: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
            parents: ['dddddddddddddddddddddddddddddddddddddddd'],
          },
          {
            commit: 'dddddddddddddddddddddddddddddddddddddddd',
            parents: [B004_IMPLEMENTATION_MERGE_LITERAL.commit],
          },
        ],
      }),
      expected: 'PASS',
    },
  ];

  return probes.map((probe) => ({
    label: probe.label,
    expected: probe.expected,
    actual: evaluateB004MergeTopology(probe.input).result,
  }));
}

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push('ok: ' + message);
  const fail = (message) => {
    pass = false;
    details.push('FAIL: ' + message);
  };

  const anchor = (label, actual, expected) => {
    if (!sameStrings(actual, expected)) {
      fail(label + ' drifted from its independent literal');
    } else {
      ok(label + ' matches its independent literal');
    }
  };
  if (BASE_COMMIT !== '6d7225828b45b69ecc44d5bb51a04c40f0865aba') {
    fail('BASE_COMMIT literal drifted');
  } else {
    ok('BASE_COMMIT independently anchored');
  }
  if (BASE_TREE !== 'f557a9f54cbac11474f2d56f78e2d983a7d6a7be') {
    fail('BASE_TREE literal drifted');
  } else {
    ok('BASE_TREE independently anchored');
  }
  if (
    B003_CLOSEOUT.commit !== '6d7225828b45b69ecc44d5bb51a04c40f0865aba' ||
    B003_CLOSEOUT.tree !== 'f557a9f54cbac11474f2d56f78e2d983a7d6a7be' ||
    B003_CLOSEOUT.parent !== '725fc005185412d115307b594aa64e84acfabf67'
  ) {
    fail('B003 closeout identity drifted');
  } else {
    ok('B003 closeout identity independently anchored');
  }
  if (
    B004_CONSTRUCTION_CHECKPOINT.commit !== '59230daae0113d35896f192a255633ba2cc1dec7' ||
    B004_CONSTRUCTION_CHECKPOINT.tree !== 'bab4289817a26a07553da4bfcccaac82dbb04319'
  ) {
    fail('B004 preserved construction checkpoint literal drifted');
  } else {
    const checkpointCommit = git(ctx.repo, ['rev-parse', B004_CONSTRUCTION_CHECKPOINT.commit + '^{commit}'], { check: false });
    const checkpointTree = git(ctx.repo, ['rev-parse', B004_CONSTRUCTION_CHECKPOINT.commit + '^{tree}'], { check: false });
    const checkpointAncestor = git(ctx.repo, ['merge-base', '--is-ancestor', B004_CONSTRUCTION_CHECKPOINT.commit, 'HEAD'], { check: false });
    if (
      checkpointCommit.status !== 0 ||
      checkpointCommit.stdout.trim() !== B004_CONSTRUCTION_CHECKPOINT.commit ||
      checkpointTree.status !== 0 ||
      checkpointTree.stdout.trim() !== B004_CONSTRUCTION_CHECKPOINT.tree ||
      checkpointAncestor.status !== 0
    ) {
      fail('B004 dependency repair must descend append-only from the preserved 59230daa construction checkpoint/tree');
    } else {
      ok('B004 preserved construction checkpoint/tree resolve and remain an ancestor of HEAD');
    }
  }
  anchor('B004_CANDIDATE', B004_CANDIDATE, B004_CANDIDATE_LITERAL);
  anchor(
    'B004_IMPLEMENTATION_MERGE',
    B004_IMPLEMENTATION_MERGE,
    B004_IMPLEMENTATION_MERGE_LITERAL,
  );
  anchor(
    'B004_POST_MERGE_REPAIR',
    B004_POST_MERGE_REPAIR,
    B004_POST_MERGE_REPAIR_LITERAL,
  );
  anchor('ALLOWED_PATHS', ALLOWED_PATHS, ALLOWED_PATHS_LITERAL);
  anchor('CLOSEOUT_ALLOWED_PATHS', CLOSEOUT_ALLOWED_PATHS, CLOSEOUT_ALLOWED_PATHS_LITERAL);
  anchor('FORBIDDEN_PREFIXES', FORBIDDEN_PREFIXES, FORBIDDEN_PREFIXES_LITERAL);
  anchor('FROZEN_REGISTRY_PATHS', FROZEN_REGISTRY_PATHS, FROZEN_REGISTRY_PATHS_LITERAL);

  let probeCount = 0;
  let probeFailures = 0;
  const probe = (relative, expected) => {
    probeCount += 1;
    const actual = pathMatchesAllowed(relative);
    if (actual !== expected) {
      probeFailures += 1;
      fail('pathMatchesAllowed mismatch for ' + JSON.stringify(relative));
    }
  };
  for (const pattern of ALLOWED_PATHS_LITERAL) {
    if (pattern.endsWith('/**')) {
      const root = pattern.slice(0, -3);
      probe(root + '/direct.txt', true);
      probe(root + '/nested/deep.txt', true);
    } else {
      probe(pattern, true);
    }
  }
  for (const relative of FALSE_ALLOWLIST_PROBES) probe(relative, false);
  for (const relative of FORBIDDEN_PREFIXES_LITERAL) {
    const representative = relative.endsWith('/') ? relative + 'probe.txt' : relative;
    probe(representative, false);
  }
  if (probeFailures === 0) {
    ok('all ' + probeCount + ' allowlist and lookalike probes matched');
  }

  let closeoutProbeCount = 0;
  let closeoutProbeFailures = 0;
  const closeoutProbe = (relative, expected) => {
    closeoutProbeCount += 1;
    const actual = pathMatchesCloseoutAllowed(relative);
    if (actual !== expected) {
      closeoutProbeFailures += 1;
      fail('pathMatchesCloseoutAllowed mismatch for ' + JSON.stringify(relative));
    }
  };
  for (const relative of CLOSEOUT_ALLOWED_PATHS_LITERAL) closeoutProbe(relative, true);
  closeoutProbe('README.md.bak', false);
  closeoutProbe('docs/runtime/README.md/child', false);
  closeoutProbe('cmd/aipt/main.go', false);
  closeoutProbe('internal/launcher/launcher.go', false);
  if (closeoutProbeFailures === 0) {
    ok('all ' + closeoutProbeCount + ' closeout allowlist and lookalike probes matched');
  }

  const baseCommit = git(ctx.repo, ['rev-parse', BASE_COMMIT + '^{commit}'], { check: false });
  const baseTree = git(ctx.repo, ['rev-parse', BASE_COMMIT + '^{tree}'], { check: false });
  if (baseCommit.status !== 0 || baseCommit.stdout.trim() !== BASE_COMMIT) {
    fail('accepted B004 base commit does not resolve');
  } else if (baseTree.status !== 0 || baseTree.stdout.trim() !== BASE_TREE) {
    fail('accepted B004 base tree drifted');
  } else {
    ok('accepted B004 base commit/tree verified');
  }
  const ancestry = git(ctx.repo, ['merge-base', '--is-ancestor', BASE_COMMIT, 'HEAD'], { check: false });
  if (ancestry.status !== 0) fail('HEAD does not descend from the accepted B004 base');
  else ok('HEAD descends from the accepted B004 base');

  const trackedChanged = git(ctx.repo, ['diff', '--name-only', '--no-renames', BASE_COMMIT])
    .stdout.split('\n').filter(Boolean);
  const untracked = git(ctx.repo, ['ls-files', '--others', '--exclude-standard'])
    .stdout.split('\n')
    .filter((relative) =>
      relative &&
      relative !== 'node_modules' &&
      !relative.startsWith('node_modules/') &&
      relative !== '.b001-toolcache' &&
      !relative.startsWith('.b001-toolcache/'));
  const changed = [...new Set([...trackedChanged, ...untracked])].sort();
  if (changed.length === 0) fail('B004 candidate has no changed paths');
  else ok(changed.length + ' candidate paths differ from the accepted B004 base');

  let scopeFailures = 0;
  for (const relative of changed) {
    if (!pathMatchesAllowed(relative)) {
      scopeFailures += 1;
      fail('path outside AIPT-M0-B004 allowed set: ' + relative);
    }
    const forbidden = FORBIDDEN_PREFIXES.find((prefix) => relative.startsWith(prefix));
    if (forbidden) {
      scopeFailures += 1;
      fail('forbidden B004 path changed (' + forbidden + '): ' + relative);
    }
    if (FROZEN_REGISTRY_PATHS.includes(relative)) {
      scopeFailures += 1;
      fail('frozen authority registry changed: ' + relative);
    }
  }
  if (scopeFailures === 0) ok('all changed paths remain inside the exact B004 scope');

  const mergeList = git(ctx.repo, ['rev-list', '--merges', BASE_COMMIT + '..HEAD'], { check: false });
  const mergeCommits = mergeList.status === 0
    ? mergeList.stdout.split('\n').filter(Boolean)
    : null;
  const mergeAncestor = git(
    ctx.repo,
    ['merge-base', '--is-ancestor', B004_IMPLEMENTATION_MERGE.commit, 'HEAD'],
    { check: false },
  );
  const candidateCommit = git(
    ctx.repo,
    ['rev-parse', B004_CANDIDATE.commit + '^{commit}'],
    { check: false },
  );
  const candidateTree = git(
    ctx.repo,
    ['rev-parse', B004_CANDIDATE.commit + '^{tree}'],
    { check: false },
  );
  const mergeCommit = git(
    ctx.repo,
    ['rev-parse', B004_IMPLEMENTATION_MERGE.commit + '^{commit}'],
    { check: false },
  );
  const mergeTree = git(
    ctx.repo,
    ['rev-parse', B004_IMPLEMENTATION_MERGE.commit + '^{tree}'],
    { check: false },
  );
  const mergeParents = git(
    ctx.repo,
    ['rev-list', '--parents', '-n', '1', B004_IMPLEMENTATION_MERGE.commit],
    { check: false },
  );
  const ordinaryDescendantList = git(
    ctx.repo,
    ['rev-list', '--parents', B004_IMPLEMENTATION_MERGE.commit + '..HEAD'],
    { check: false },
  );
  const parentTokens = mergeParents.status === 0
    ? mergeParents.stdout.trim().split(/\s+/).filter(Boolean)
    : [];
  const resolvedCandidate = candidateCommit.status === 0 && candidateTree.status === 0
    ? { commit: candidateCommit.stdout.trim(), tree: candidateTree.stdout.trim() }
    : null;
  const resolvedMerge =
    mergeCommit.status === 0 && mergeTree.status === 0 && parentTokens.length > 0
      ? {
          commit: mergeCommit.stdout.trim(),
          tree: mergeTree.stdout.trim(),
          parents: parentTokens.slice(1),
      }
      : null;
  const ordinaryDescendants = ordinaryDescendantList.status === 0
    ? ordinaryDescendantList.stdout
        .split('\n')
        .filter(Boolean)
        .map((line) => {
          const tokens = line.trim().split(/\s+/).filter(Boolean);
          return { commit: tokens[0], parents: tokens.slice(1) };
        })
    : null;
  const topology = evaluateB004MergeTopology({
    candidate: B004_CANDIDATE,
    implementationMerge: B004_IMPLEMENTATION_MERGE,
    implementationMergeAncestryKnown: mergeAncestor.status === 0 || mergeAncestor.status === 1,
    implementationMergeIsAncestor: mergeAncestor.status === 0,
    mergeCommits,
    ordinaryDescendants,
    resolvedCandidate,
    resolvedMerge,
  });
  if (topology.result === 'FAIL') {
    for (const problem of topology.problems) fail('B004 merge topology: ' + problem);
  } else if (topology.phase === 'POST_MERGE') {
    ok('post-merge history contains exactly the authorized B004 implementation merge');
    ok('authorized B004 implementation merge Git object has exact tree and ordered parents');
  } else {
    ok('candidate history contains no merge commits after the B004 base');
  }

  if (topology.phase === 'POST_MERGE') {
    const repairCommit = git(
      ctx.repo,
      ['rev-parse', B004_POST_MERGE_REPAIR.commit + '^{commit}'],
      { check: false },
    );
    const repairTree = git(
      ctx.repo,
      ['rev-parse', B004_POST_MERGE_REPAIR.commit + '^{tree}'],
      { check: false },
    );
    const repairParents = git(
      ctx.repo,
      ['rev-list', '--parents', '-n', '1', B004_POST_MERGE_REPAIR.commit],
      { check: false },
    );
    const repairAncestor = git(
      ctx.repo,
      ['merge-base', '--is-ancestor', B004_POST_MERGE_REPAIR.commit, 'HEAD'],
      { check: false },
    );
    const repairParentTokens = repairParents.status === 0
      ? repairParents.stdout.trim().split(/\s+/).filter(Boolean)
      : [];
    if (
      repairCommit.status !== 0 ||
      repairCommit.stdout.trim() !== B004_POST_MERGE_REPAIR.commit ||
      repairTree.status !== 0 ||
      repairTree.stdout.trim() !== B004_POST_MERGE_REPAIR.tree ||
      !sameStrings(
        repairParentTokens,
        [B004_POST_MERGE_REPAIR.commit, B004_POST_MERGE_REPAIR.parent],
      ) ||
      repairAncestor.status !== 0
    ) {
      fail('B004 post-merge repair Git object/tree/parent/ancestry drifted');
    } else {
      ok('B004 post-merge repair has the exact tree, single parent, and ancestry');
    }

    const implementationChanged = git(
      ctx.repo,
      [
        'diff',
        '--name-only',
        '--no-renames',
        BASE_COMMIT,
        B004_IMPLEMENTATION_MERGE.commit,
      ],
    ).stdout.split('\n').filter(Boolean).sort();
    const implementationScopeProblems = implementationChanged.filter((relative) =>
      !pathMatchesAllowed(relative) ||
      FORBIDDEN_PREFIXES.some((prefix) => relative.startsWith(prefix)) ||
      FROZEN_REGISTRY_PATHS.includes(relative));
    if (implementationScopeProblems.length > 0) {
      for (const relative of implementationScopeProblems) {
        fail('immutable B004 implementation path violates its construction scope: ' + relative);
      }
    } else {
      ok('immutable B004 implementation merge remains inside the exact construction scope');
    }

    const repairChanged = git(
      ctx.repo,
      [
        'diff',
        '--name-only',
        '--no-renames',
        B004_IMPLEMENTATION_MERGE.commit,
        B004_POST_MERGE_REPAIR.commit,
      ],
    ).stdout.split('\n').filter(Boolean).sort();
    const expectedRepairChanged = [...B004_REPAIR_PATHS_LITERAL].sort();
    if (!sameStrings(repairChanged, expectedRepairChanged)) {
      fail(
        'B004 repair changed-path set must be exactly ' +
          JSON.stringify(expectedRepairChanged) +
          ', got ' +
          JSON.stringify(repairChanged),
      );
    } else {
      ok('B004 repair changed-path set is exactly the two authorized validator files');
    }

    const postMergeTracked = git(
      ctx.repo,
      ['diff', '--name-only', '--no-renames', B004_IMPLEMENTATION_MERGE.commit],
    ).stdout.split('\n').filter(Boolean);
    const postMergeChanged = [...new Set([...postMergeTracked, ...untracked])].sort();
    const postMergeScopeProblems = postMergeChanged.filter(
      (relative) => !pathMatchesCloseoutAllowed(relative),
    );
    if (postMergeScopeProblems.length > 0) {
      for (const relative of postMergeScopeProblems) {
        fail('path outside exact B004 post-merge repair/closeout set: ' + relative);
      }
    } else {
      ok('all post-merge paths are confined to the exact repair/closeout authority surface');
    }

    const closeoutTracked = git(
      ctx.repo,
      ['diff', '--name-only', '--no-renames', B004_POST_MERGE_REPAIR.commit],
    ).stdout.split('\n').filter(Boolean);
    const closeoutChanged = [...new Set([...closeoutTracked, ...untracked])].sort();
    const expectedCloseoutChanged = [...CLOSEOUT_ALLOWED_PATHS_LITERAL].sort();
    if (!sameStrings(closeoutChanged, expectedCloseoutChanged)) {
      fail(
        'B004 closeout changed-path set must be exactly ' +
          JSON.stringify(expectedCloseoutChanged) +
          ', got ' +
          JSON.stringify(closeoutChanged),
      );
    } else {
      ok('B004 closeout changed-path set is exactly the eight necessary authorized files');
    }

    const closeoutHistory = git(
      ctx.repo,
      ['rev-list', '--reverse', '--parents', B004_POST_MERGE_REPAIR.commit + '..HEAD'],
      { check: false },
    );
    const closeoutLines = closeoutHistory.status === 0
      ? closeoutHistory.stdout.split('\n').filter(Boolean)
      : [];
    if (closeoutHistory.status !== 0 || closeoutLines.length > 1) {
      fail('B004 closeout history must contain at most one ordinary commit after the repair');
    } else if (closeoutLines.length === 1) {
      const tokens = closeoutLines[0].trim().split(/\s+/).filter(Boolean);
      if (tokens.length !== 2 || tokens[1] !== B004_POST_MERGE_REPAIR.commit) {
        fail('B004 closeout commit must have the repair commit as its sole parent');
      } else {
        ok('B004 closeout commit has the repair commit as its sole parent');
      }
    } else {
      ok('pre-commit closeout worktree is based directly on the repair commit');
    }
  }

  const topologyProbes = runMergeTopologyProbes();
  const topologyProbeFailures = topologyProbes.filter((probe) => probe.actual !== probe.expected);
  if (topologyProbeFailures.length > 0) {
    for (const probe of topologyProbeFailures) {
      fail(
        'merge-topology probe mismatch for ' +
          JSON.stringify(probe.label) +
          ': expected ' +
          probe.expected +
          ', got ' +
          probe.actual,
      );
    }
  } else {
    ok('all ' + topologyProbes.length + ' merge-topology lifecycle probes matched');
  }

  const rawDiff = git(ctx.repo, ['diff', '--raw', '--no-abbrev', '--no-renames', BASE_COMMIT])
    .stdout.split('\n').filter(Boolean);
  for (const line of rawDiff) {
    const modes = /^:(\d{6}) (\d{6}) /.exec(line);
    if (modes && [modes[1], modes[2]].some((mode) => mode === '120000' || mode === '160000')) {
      fail('changed path uses unsafe symlink/gitlink mode: ' + line);
    }
  }
  const indexEntries = git(ctx.repo, ['ls-files', '-s'], { check: false })
    .stdout.split('\n').filter(Boolean);
  for (const line of indexEntries) {
    const mode = line.split(/\s+/, 1)[0];
    if (mode === '120000' || mode === '160000') {
      fail('tracked tree contains unsafe symlink/gitlink mode: ' + line);
    }
  }

  let nodeFailures = 0;
  for (const relative of changed) {
    try {
      const stat = fs.lstatSync(path.join(ctx.repo, relative));
      if (stat.isSymbolicLink()) {
        nodeFailures += 1;
        fail('changed worktree path is a symbolic link: ' + relative);
      } else if (!stat.isFile() && !stat.isDirectory()) {
        nodeFailures += 1;
        fail('changed worktree path is not a regular file/directory: ' + relative);
      }
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        nodeFailures += 1;
        fail('lstat failed for changed path ' + relative + ': ' + error.message);
      }
    }
  }
  if (nodeFailures === 0) ok('changed worktree nodes are regular and symlink-free');

  const localWorktrees = fs.readdirSync(ctx.repo)
    .filter((name) => name.startsWith('.wt-'));
  const trackedLocalWorktrees = git(ctx.repo, ['ls-files', '.wt-*'], { check: false })
    .stdout.split('\n').filter(Boolean);
  if (localWorktrees.length > 0 || trackedLocalWorktrees.length > 0) {
    fail('repository-local .wt-* worktree content is forbidden');
  } else {
    ok('no repository-local .wt-* worktree content');
  }

  for (const relative of FROZEN_FILES) {
    const base = git(ctx.repo, ['show', BASE_COMMIT + ':' + relative], { check: false });
    let current;
    try {
      current = fs.readFileSync(path.join(ctx.repo, relative));
    } catch (error) {
      fail('frozen file is unreadable: ' + relative + ': ' + error.message);
      continue;
    }
    if (base.status !== 0) {
      fail('cannot read frozen base blob: ' + relative);
    } else if (!current.equals(Buffer.from(base.stdout))) {
      fail('frozen file differs byte-for-byte from the B004 base: ' + relative);
    } else {
      ok('frozen file unchanged: ' + relative);
    }
  }

  const license = fs.readFileSync(path.join(ctx.repo, 'LICENSE'), 'utf8');
  if (normalizeText(license) !== normalizeText(EXPECTED_MIT_LICENSE)) {
    fail('LICENSE content drifted from the exact MIT text');
  } else {
    ok('LICENSE remains the exact MIT text');
  }

  const baseMarkdown = git(ctx.repo, ['ls-tree', '-r', '--name-only', BASE_COMMIT])
    .stdout.split('\n').filter((relative) => relative.endsWith('.md'));
  const missingMarkdown = baseMarkdown.filter((relative) => !fs.existsSync(path.join(ctx.repo, relative)));
  if (missingMarkdown.length > 0) {
    for (const relative of missingMarkdown) fail('accepted-base Markdown document removed: ' + relative);
  } else {
    ok('all accepted-base Markdown documents remain present');
  }
  const markdown = collectMarkdownLinkIssues(ctx.repo);
  if (markdown.issues.length > 0) {
    for (const issue of markdown.issues) {
      fail('Markdown link issue: ' + JSON.stringify(issue));
    }
  } else {
    ok(markdown.mdCount + ' Markdown documents have repository-contained resolvable links');
  }

  let jsonFailures = 0;
  for (const file of walkFiles(ctx.repo, (candidate) => candidate.endsWith('.json'))) {
    try {
      JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (error) {
      jsonFailures += 1;
      fail('JSON parse failed for ' + path.relative(ctx.repo, file) + ': ' + error.message);
    }
  }
  if (jsonFailures === 0) ok('all tracked-source JSON documents parse');

  const hazards = scanTreeForHazards(ctx.repo);
  if (hazards.length > 0) {
    for (const finding of hazards) fail('public-tree hygiene finding: ' + JSON.stringify(finding));
  } else {
    ok('public tree contains no credential, private path, model endpoint, or prompt-body hazard');
  }

  const probeRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aipt-b004-hygiene-'));
  try {
    const scriptDir = path.join(probeRoot, 'scripts', 'ci');
    fs.mkdirSync(scriptDir, { recursive: true });
    fs.writeFileSync(path.join(scriptDir, 'probe.mjs'), 'const value = "' + 'sk-' + 'A'.repeat(24) + '";\n');
    const probeFindings = scanTreeForHazards(probeRoot);
    if (!probeFindings.some((finding) => finding.hazard === 'API_KEY_LIKE')) {
      fail('hygiene regression probe did not scan a scripts/ci .mjs file');
    } else {
      ok('hygiene regression probe covers executable scripts/ci sources');
    }
  } finally {
    fs.rmSync(probeRoot, { recursive: true, force: true });
  }

  return {
    result: pass ? 'PASS' : 'FAIL',
    details,
    changed_paths: changed,
  };
}

runAsMain(import.meta.url, 'tree-integrity', run);
