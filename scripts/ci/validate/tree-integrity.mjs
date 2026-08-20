#!/usr/bin/env node
// AIPT-M0-B004 candidate tree-integrity and scope validator.
//
// The candidate is always diffed directly from the immutable B003 closeout
// base. Exact path admission is self-anchored here, dependency/toolchain and
// authority registries remain byte-frozen, and unsafe nodes, merge commits,
// repository-local worktrees, broken links, secrets, model endpoints, and
// public prompt bodies fail closed.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  ALLOWED_PATHS,
  B003_CLOSEOUT,
  BASE_COMMIT,
  BASE_TREE,
  EXPECTED_MIT_LICENSE,
  FORBIDDEN_PREFIXES,
  FROZEN_REGISTRY_PATHS,
  normalizeText,
  pathMatchesAllowed,
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
  'package.json',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
  'scripts/ci/validate/workflow.mjs',
  'scripts/ci/validate/storage.mjs',
  'scripts/ci/validate/supply-chain.mjs',
  'scripts/ci/validate/sbom.mjs',
  'scripts/ci/validate/runtime-shell.mjs',
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
  'go.mod',
  'go.sum',
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
  'go.mod',
  'go.sum',
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
  'package.json.bak',
  'scripts/ci/validate/runtime-shell.mjs.bak',
  'tools/toolchain.lock.json',
  'AIPT-M0-B005/adapter.go',
];

function sameStrings(actual, expected) {
  return JSON.stringify(actual) === JSON.stringify(expected);
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
  anchor('ALLOWED_PATHS', ALLOWED_PATHS, ALLOWED_PATHS_LITERAL);
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

  const merges = git(ctx.repo, ['rev-list', '--merges', BASE_COMMIT + '..HEAD'], { check: false })
    .stdout.split('\n').filter(Boolean);
  if (merges.length > 0) fail('merge commits introduced after the B004 base: ' + merges.join(', '));
  else ok('no merge commits introduced after the B004 base');

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
