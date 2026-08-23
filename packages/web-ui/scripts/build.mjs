#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { stripTypeScriptTypes } from 'node:module';
import { fileURLToPath } from 'node:url';

const EXACT_NODE = '24.19.0';
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sourcePath = path.join(packageRoot, 'src', 'dashboard.ts');
const targetPath = path.resolve(packageRoot, '..', '..', 'internal', 'web', 'static', 'app.js');
const check = process.argv.slice(2).includes('--check');

if (process.versions.node !== EXACT_NODE) {
  throw new Error(`@aipt/web-ui artifact generation requires exact Node ${EXACT_NODE}`);
}

const source = fs.readFileSync(sourcePath, 'utf8');
if (source.includes('\r')) throw new Error('dashboard.ts must use LF line endings');
const stripped = stripTypeScriptTypes(source, { mode: 'strip', sourceMap: false });
const artifact = [
  '// Generated deterministically from packages/web-ui/src/dashboard.ts.',
  '// Exact generator: Node 24.19.0 node:module.stripTypeScriptTypes mode=strip.',
  '// Do not edit this served artifact directly.',
  stripped,
].join('\n');

if (check) {
  const current = fs.readFileSync(targetPath, 'utf8');
  if (current !== artifact) throw new Error('served app.js differs from the authoritative TypeScript source');
  process.stdout.write('web-ui served artifact PASS\n');
} else {
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.writeFileSync(targetPath, artifact, 'utf8');
  process.stdout.write(`generated ${path.relative(packageRoot, targetPath)}\n`);
}
