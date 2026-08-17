// Import side-effect tests: importing the SDK performs no ambient work —
// no environment/credential reads, no file writes, no process/socket/
// database/service activity, no output. A clean child-process import probe
// and an environment-access trap prove the import is inert.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { test } from 'node:test';

const SDK_SRC = path.resolve(import.meta.dirname, '../src');
const SDK_INDEX = path.join(SDK_SRC, 'index.ts');

function listSrcFiles(): string[] {
  const out: string[] = [];
  const stack = [SDK_SRC];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else if (entry.isFile() && entry.name.endsWith('.ts')) out.push(full);
    }
  }
  return out.sort();
}

test('the SDK sources never import ambient-capable Node modules', () => {
  const forbidden = new Set(['net', 'tls', 'http', 'https', 'http2', 'dgram', 'child_process', 'worker_threads', 'cluster', 'vm', 'inspector', 'sqlite']);
  // Forbid real `any` type usage (annotations, casts, generic arguments),
  // while prose mentions of the word stay allowed.
  const anyType = /(:\s*any\b|<\s*any\b|\bas\s+any\b|=\s*any\b|\bany\s*\[|\bany\s*\||\(\s*any\b|\bArray\s*<\s*any\b)/;
  for (const file of listSrcFiles()) {
    const text = fs.readFileSync(file, 'utf8');
    for (const match of text.matchAll(/from\s+['"]node:([a-z_0-9]+)['"]/g)) {
      assert.ok(!forbidden.has(match[1]), `${file} imports forbidden node:${match[1]}`);
    }
    assert.ok(!/process\.env/.test(text), `${file} reads environment credentials (process.env)`);
    assert.ok(!/\bfetch\s*\(/.test(text), `${file} performs a network fetch`);
    assert.ok(!/\bWebSocket\b/.test(text), `${file} opens a socket`);
    assert.ok(!anyType.test(text), `${file} uses the forbidden any type`);
  }
});

test('clean import probe: importing the SDK exits 0 with empty output under a minimal environment', () => {
  const script = [
    `await import(${JSON.stringify(pathToFileURL(SDK_INDEX).href)})`,
    '.then((m) => {',
    '  if (typeof m.PROTOCOL_VERSION !== "string") process.exit(3);',
    '  if (typeof m.buildRequest !== "function") process.exit(4);',
    '  if (typeof m.sha256Hex !== "function") process.exit(5);',
    '});',
  ].join('');
  const result = spawnSync(process.execPath, ['--input-type=module', '--eval', script], {
    cwd: path.resolve(import.meta.dirname, '../../..'),
    env: { PATH: process.env.PATH ?? '' },
    encoding: 'utf8',
    timeout: 30_000,
  });
  assert.equal(result.status, 0, `clean import probe failed: ${result.stderr}`);
  assert.equal(result.stdout, '', 'import must print nothing');
  assert.equal(result.stderr, '', 'import must write nothing to stderr');
});

test('importing every SDK module performs no environment reads', async () => {
  const realEnv = process.env;
  // The Node ESM loader itself consults a couple of NODE_/WATCH_ internal
  // switches during import(); everything outside those internal namespaces
  // (credential variables included) must throw on access.
  const trap = new Proxy({}, {
    get(_target, key): unknown {
      const name = String(key);
      if (name.startsWith('NODE_') || name.startsWith('WATCH_')) return undefined;
      throw new Error(`environment read during import: ${name}`);
    },
    set(): never {
      throw new Error('environment write during import');
    },
    has(): never {
      throw new Error('environment probe during import');
    },
  }) as NodeJS.ProcessEnv;
  process.env = trap;
  try {
    const files = listSrcFiles();
    for (let index = 0; index < files.length; index += 1) {
      await import(`${pathToFileURL(files[index]).href}?env-trap=${index}`);
    }
  } finally {
    process.env = realEnv;
  }
});

test('imports perform no file writes inside the SDK tree', async () => {
  const snapshot = (): string[] => {
    const out: string[] = [];
    const stack = [SDK_SRC];
    while (stack.length > 0) {
      const dir = stack.pop()!;
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) stack.push(full);
        else out.push(full);
      }
    }
    return out.sort();
  };
  const before = snapshot();
  for (let index = 0; index < 3; index += 1) {
    await import(`${pathToFileURL(SDK_INDEX).href}?write-probe=${index}`);
  }
  assert.deepEqual(snapshot(), before, 'import must not create or remove files');
});

test('importing the package entrypoint is idempotent (cached module identity)', async () => {
  const first = await import(pathToFileURL(SDK_INDEX).href);
  const second = await import(pathToFileURL(SDK_INDEX).href);
  assert.equal(first, second, 'ESM module cache must return the identical module');
});
