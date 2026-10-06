#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { stripTypeScriptTypes } from 'node:module';
import { fileURLToPath } from 'node:url';
if (process.versions.node !== '24.19.0') throw new Error('controls artifact requires exact Node 24.19.0');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const source = fs.readFileSync(path.join(root, 'packages/web-ui/src/controls.ts'), 'utf8');
if (source.includes('\r')) throw new Error('controls.ts must use LF');
const artifact = '// Generated from packages/web-ui/src/controls.ts with exact Node 24.19.0 type stripping.\n' + stripTypeScriptTypes(source, { mode: 'strip', sourceMap: false });
const target = path.join(root, 'internal/web/operational/controls.js');
if (process.argv.includes('--check')) {
 if (fs.readFileSync(target, 'utf8') !== artifact) throw new Error('controls artifact differs from TypeScript source');
 process.stdout.write('operational artifact PASS\n');
} else { fs.writeFileSync(target, artifact); }
