#!/usr/bin/env node
// Generate the canonical UNREGISTERED P0 predecessor inventory used by
// Authority Amendment-002. The candidate never selects the protected set:
// every entry comes from the immutable predecessor Git tree, and the only
// non-immutable entries are the three successor control surfaces already
// authorized by the frozen Base Authority implementation scope.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const TASK_ID = 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-AMENDMENT-002';
const REPOSITORY = 'zyc14588/UNREGISTERED';
const PREDECESSOR_COMMIT = '358d6d9d08a86818e34fd0c0d9a62bfe66e73abe';
const PREDECESSOR_TREE = '5585271c78d1fe5cd8357c7b36a501bee34f0240';
const CONTROLLED_SURFACES = new Map([
  ['.github/workflows/aipt-content-gate.yml', 'SUCCESSOR_CI_CONTROL_SURFACE'],
  ['aipt/README.md', 'SUCCESSOR_DOCUMENTATION_CONTROL_SURFACE'],
  ['aipt/status.json', 'SUCCESSOR_LIFECYCLE_CONTROL_SURFACE'],
]);

function fail(message) {
  throw new Error(message);
}

function git(repo, args, encoding = 'utf8') {
  const result = spawnSync('git', ['-C', repo, ...args], {
    encoding,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error) fail(`git ${args.join(' ')} could not execute: ${result.error.message}`);
  if (result.status !== 0) {
    fail(`git ${args.join(' ')} failed (${result.status}): ${String(result.stderr ?? '').trim()}`);
  }
  return result.stdout;
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function byteCompare(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function roleFor(relative) {
  if (CONTROLLED_SURFACES.has(relative)) return CONTROLLED_SURFACES.get(relative);
  if (/^scripts\/aipt\/validate-p0-b00[0-3]\.mjs$/u.test(relative)) return 'P0_HISTORICAL_VALIDATOR';
  if (relative === 'aipt/input-manifest.json') return 'P0_INPUT_MANIFEST';
  if (relative.startsWith('aipt/p0-b000/')) return 'P0_B000_MACHINE_ARTIFACT';
  if (relative.startsWith('aipt/p0-b001/')) return 'P0_B001_MACHINE_ARTIFACT';
  if (relative.startsWith('aipt/p0-b002/')) return 'P0_B002_MACHINE_ARTIFACT';
  if (relative.startsWith('aipt/p0-b003/')) return 'P0_B003_MACHINE_OR_TEST_ARTIFACT';
  if (relative.startsWith('campaign/') || relative.startsWith('knowledge/') || relative.startsWith('LICENSES/')) {
    return 'P0_SOURCE_OR_POLICY_ASSET';
  }
  if (relative === 'AGENTS.md') return 'REPOSITORY_OPERATING_RULES';
  if (relative === 'pack-manifest.json') return 'GAME_PACKAGE_MANIFEST';
  if (relative.startsWith('.opencode/')) return 'PREDECESSOR_TOOLING_ASSET';
  if (relative === '.gitignore') return 'REPOSITORY_CONTROL_FILE';
  return 'PREDECESSOR_TRACKED_ASSET';
}

function validatePath(relative, seen, canonicalSeen) {
  if (relative.length === 0 || relative.startsWith('/') || relative.includes('\\') || relative.includes('\0')) {
    fail(`invalid repository-relative POSIX path: ${JSON.stringify(relative)}`);
  }
  const segments = relative.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    fail(`non-canonical path segment: ${JSON.stringify(relative)}`);
  }
  if (relative.normalize('NFC') !== relative) fail(`non-NFC predecessor path: ${JSON.stringify(relative)}`);
  if (seen.has(relative)) fail(`duplicate predecessor path: ${JSON.stringify(relative)}`);
  seen.add(relative);
  const collisionKey = relative.normalize('NFC').toLocaleLowerCase('en-US');
  if (canonicalSeen.has(collisionKey)) {
    fail(`case-folding or Unicode path collision: ${JSON.stringify(relative)} vs ${JSON.stringify(canonicalSeen.get(collisionKey))}`);
  }
  canonicalSeen.set(collisionKey, relative);
}

export function generateInventory(repo) {
  const resolvedCommit = git(repo, ['rev-parse', `${PREDECESSOR_COMMIT}^{commit}`]).trim();
  const resolvedTree = git(repo, ['rev-parse', `${PREDECESSOR_COMMIT}^{tree}`]).trim();
  if (resolvedCommit !== PREDECESSOR_COMMIT) fail(`wrong predecessor commit: ${resolvedCommit}`);
  if (resolvedTree !== PREDECESSOR_TREE) fail(`wrong predecessor tree: ${resolvedTree}`);

  const raw = git(repo, ['ls-tree', '-r', '-z', '--full-tree', PREDECESSOR_COMMIT], null);
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const records = [];
  let start = 0;
  for (let index = 0; index < raw.length; index += 1) {
    if (raw[index] !== 0) continue;
    if (index > start) records.push(raw.subarray(start, index));
    start = index + 1;
  }
  if (start !== raw.length) fail('git ls-tree output is not NUL terminated');

  const seen = new Set();
  const canonicalSeen = new Map();
  const entries = records.map((record) => {
    const tab = record.indexOf(0x09);
    if (tab < 0) fail('malformed git ls-tree record');
    const header = record.subarray(0, tab).toString('ascii');
    const [mode, type, object] = header.split(' ');
    const relative = decoder.decode(record.subarray(tab + 1));
    validatePath(relative, seen, canonicalSeen);
    if (type !== 'blob' || !['100644', '100755'].includes(mode)) {
      fail(`symlink, submodule, tree or unsupported mode in predecessor inventory: ${relative} (${mode} ${type})`);
    }
    if (!/^[0-9a-f]{40}$/u.test(object)) fail(`invalid Git object identity for ${relative}`);
    const bytes = git(repo, ['cat-file', 'blob', object], null);
    const controlled = CONTROLLED_SURFACES.has(relative);
    return {
      path: relative,
      mode,
      git_blob_sha1: object,
      sha256: sha256(bytes),
      role: roleFor(relative),
      protection: controlled ? 'CONTROLLED_SUCCESSOR_MODIFICATION' : 'PRESERVE_EXACT',
    };
  }).sort((left, right) => byteCompare(left.path, right.path));

  for (const relative of CONTROLLED_SURFACES.keys()) {
    if (!entries.some((entry) => entry.path === relative)) fail(`controlled successor surface missing from predecessor: ${relative}`);
  }
  const protectedCount = entries.filter((entry) => entry.protection === 'PRESERVE_EXACT').length;
  const controlledCount = entries.length - protectedCount;
  const projection = {
    repository: REPOSITORY,
    predecessor_commit: PREDECESSOR_COMMIT,
    predecessor_tree: PREDECESSOR_TREE,
    entries,
  };
  return {
    schema: 'aipt.public.p0-predecessor-protected-inventory/v1',
    authority_task_id: TASK_ID,
    repository: REPOSITORY,
    predecessor_commit: PREDECESSOR_COMMIT,
    predecessor_tree: PREDECESSOR_TREE,
    generation_contract: {
      source: 'IMMUTABLE_GIT_COMMIT_TREE_ONLY',
      invocation: `git ls-tree -r -z --full-tree ${PREDECESSOR_COMMIT}`,
      candidate_declared_inventory_permitted: false,
      entry_order: 'UTF8_BYTE_LEX_ASC',
      content_hash: 'SHA-256_OF_EXACT_GIT_BLOB_BYTES',
      path_identity: 'REPOSITORY_RELATIVE_POSIX_NFC_CASE_COLLISION_FREE',
      supported_modes: ['100644', '100755'],
      symlink_submodule_or_non_blob: 'REJECT',
    },
    counts: {
      tracked_entries: entries.length,
      preserve_exact: protectedCount,
      controlled_successor_modification: controlledCount,
    },
    controlled_successor_surfaces: [...CONTROLLED_SURFACES.keys()],
    entries,
    inventory_identity: {
      algorithm: 'SHA-256',
      projection: 'UTF8_JSON_STRINGIFY_OF_REPOSITORY_PREDECESSOR_COMMIT_PREDECESSOR_TREE_AND_ENTRIES',
      sha256: sha256(Buffer.from(JSON.stringify(projection), 'utf8')),
    },
  };
}

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith('--')) fail(`unexpected argument: ${item}`);
    const key = item.slice(2);
    if (index + 1 >= argv.length || argv[index + 1].startsWith('--')) fail(`missing value for --${key}`);
    args[key] = argv[index + 1];
    index += 1;
  }
  return args;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname);
if (isMain) {
  try {
    const args = parseArgs(process.argv.slice(2));
    if (!args.repo) fail('--repo is required');
    const document = `${JSON.stringify(generateInventory(path.resolve(args.repo)), null, 2)}\n`;
    if (args.output) {
      const output = path.resolve(args.output);
      const parent = path.dirname(output);
      const parentStat = fs.lstatSync(parent);
      if (!parentStat.isDirectory() || parentStat.isSymbolicLink()) fail('output parent must be a real directory');
      if (fs.existsSync(output) && fs.lstatSync(output).isSymbolicLink()) fail('output path must not be a symlink');
      fs.writeFileSync(output, document, { encoding: 'utf8', mode: 0o644 });
    } else {
      process.stdout.write(document);
    }
  } catch (error) {
    process.stderr.write(`FAIL ${TASK_ID} inventory generation: ${error.message}\n`);
    process.exitCode = 1;
  }
}
