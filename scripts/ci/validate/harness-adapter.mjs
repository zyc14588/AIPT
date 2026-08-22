#!/usr/bin/env node
// Fail-closed AIPT-M0-B005 Harness Adapter contract and mutation gate.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { HARNESS_SOURCE } from '../lib/constants.mjs';
import { runAsMain } from '../lib/cli.mjs';

const PACKAGE_NAME = '@aipt/harness-adapter';
const PACKAGE_VERSION = '0.1.0';
const SDK = '@aipt/adapter-sdk';
const PRODUCTION_FILES = [
  'backend.ts', 'errors.ts', 'framing.ts', 'index.ts', 'process-worker.ts', 'runtime.ts',
];
const TEST_FILES = ['fixture-backend.ts', 'fixture-worker.ts', 'stdio-smoke.test.ts'];
const FIXTURE_LITERALS = [
  'advance-turn', 'turn-count', 'table-note', 'seat-a', 'seat-b',
  'minimal-v1-arithmetic', 'transition-turn-increment',
];
const NETWORK_PATTERNS = [
  /(?:from\s+|import\s*)['"]node:(?:http|https|http2|net|tls|dgram)['"]/,
  /\bfetch\s*\(/,
  /\bWebSocket\b/,
  /\bEventSource\b/,
];
const COPIED_SCHEMA_PATTERNS = [
  /https:\/\/json-schema\.org\/draft\/2020-12\/schema/,
  /["']\$defs["']\s*:/,
  /["']oneOf["']\s*:/,
];

function exactKeys(value, expected) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

function sourceImports(source) {
  return [...source.matchAll(/(?:import|export)\s+(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"]/g)]
    .map((match) => match[1]);
}

export function harnessAdapterProblems(snapshot) {
  const problems = [];
  const manifest = snapshot?.manifest;
  if (manifest?.name !== PACKAGE_NAME) problems.push('package name drifted');
  if (manifest?.version !== PACKAGE_VERSION) problems.push('package version drifted');
  if (manifest?.private !== true) problems.push('package must remain private');
  if (manifest?.license !== 'MIT') problems.push('package license drifted');
  if (manifest?.type !== 'module') problems.push('package type drifted');
  if (manifest?.main !== 'src/index.ts' || manifest?.types !== 'src/index.ts') {
    problems.push('package entrypoint drifted');
  }
  if (manifest?.engines?.node !== '>=24.19.0 <25') problems.push('Node engine drifted');
  if (!exactKeys(manifest?.dependencies, [SDK]) || manifest?.dependencies?.[SDK] !== 'workspace:*') {
    problems.push('dependencies must be the exact first-party workspace SDK edge');
  }
  for (const field of ['devDependencies', 'optionalDependencies', 'peerDependencies']) {
    if (Object.hasOwn(manifest ?? {}, field)) problems.push(field + ' is forbidden');
  }
  if (manifest?.scripts?.test !== 'node --test "test/**/*.test.ts"') {
    problems.push('focused test command drifted');
  }

  const sources = snapshot?.sources;
  if (!sources || typeof sources !== 'object') problems.push('production sources missing');
  const sourceEntries = Object.entries(sources ?? {});
  if (JSON.stringify(sourceEntries.map(([name]) => name).sort()) !== JSON.stringify(PRODUCTION_FILES)) {
    problems.push('production source file set drifted');
  }
  let sdkImportSeen = false;
  for (const [name, source] of sourceEntries) {
    if (typeof source !== 'string') { problems.push(name + ' is unreadable'); continue; }
    for (const specifier of sourceImports(source)) {
      if (specifier === SDK) sdkImportSeen = true;
      if (!(specifier === SDK || specifier.startsWith('node:') || specifier.startsWith('./') || specifier.startsWith('../'))) {
        problems.push(name + ' imports non-approved module ' + specifier);
      }
      if (specifier.toLowerCase().includes('internal/evidence') || specifier.toLowerCase().includes('schemas/evidence')) {
        problems.push(name + ' couples the frozen B005 Adapter to B006 Evidence runtime/schema');
      }
    }
    if (NETWORK_PATTERNS.some((pattern) => pattern.test(source))) problems.push(name + ' contains network capability');
    if (COPIED_SCHEMA_PATTERNS.some((pattern) => pattern.test(source))) problems.push(name + ' copies schema truth');
    if (FIXTURE_LITERALS.some((literal) => source.includes(literal))) problems.push(name + ' hardcodes fixture literal');
    if (/\bconsole\s*\./.test(source)) problems.push(name + ' uses console on a protocol boundary');
    if (/\bprocess\s*\.\s*env\b/.test(source) || /env\s*:\s*process\.env/.test(source)) {
      problems.push(name + ' accesses or forwards ambient environment');
    }
    if (/\b(?:createServer|serve|listen)\s*\(/.test(source) || /\.listen\s*\(/.test(source)) {
      problems.push(name + ' opens a listener');
    }
    if (/\b(?:spawn|exec|fork)\s*\(/.test(source)) problems.push(name + ' spawns an unmanaged child');
    if (/\b(?:readFile|readFileSync|createReadStream)\s*\(/.test(source)) {
      problems.push(name + ' reads fixture/filesystem data in production');
    }
  }
  if (!sdkImportSeen) problems.push('production source removed the canonical SDK dependency');

  return problems;
}

function cloneSnapshot(snapshot) {
  return structuredClone(snapshot);
}

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push('ok: ' + message);
  const fail = (message) => { pass = false; details.push('FAIL: ' + message); };
  const root = path.join(ctx.repo, 'packages', 'harness-adapter');
  const read = (relative) => fs.readFileSync(path.join(ctx.repo, relative), 'utf8');
  let manifest;
  try { manifest = JSON.parse(read('packages/harness-adapter/package.json')); }
  catch (error) { fail('package manifest parse failed: ' + error.message); }

  const productionNames = fs.existsSync(path.join(root, 'src'))
    ? fs.readdirSync(path.join(root, 'src')).filter((name) => name.endsWith('.ts')).sort() : [];
  const testNames = fs.existsSync(path.join(root, 'test'))
    ? fs.readdirSync(path.join(root, 'test')).filter((name) => name.endsWith('.ts')).sort() : [];
  if (JSON.stringify(productionNames) !== JSON.stringify(PRODUCTION_FILES)) fail('production file set is not exact');
  else ok('production file set is exact');
  if (JSON.stringify(testNames) !== JSON.stringify(TEST_FILES)) fail('test file set is not exact');
  else ok('test file set is exact');
  const sources = Object.fromEntries(productionNames.map((name) => [
    name, fs.readFileSync(path.join(root, 'src', name), 'utf8'),
  ]));
  const snapshot = { manifest, sources };
  for (const problem of harnessAdapterProblems(snapshot)) fail(problem);
  if (harnessAdapterProblems(snapshot).length === 0) ok('live package passes the thin-adapter security contract');

  const lock = read('pnpm-lock.yaml');
  const lockFacts = [
    'packages/harness-adapter:', "'@aipt/adapter-sdk':", 'specifier: workspace:*',
    'version: link:../adapter-sdk',
  ];
  for (const fact of lockFacts) if (!lock.includes(fact)) fail('lockfile missing ' + fact);
  if (/^packages:\s*$/m.test(lock)) fail('lockfile contains a third-party packages section');
  else ok('lockfile records the first-party link and zero third-party packages');

  const fixtureSource = read('packages/harness-adapter/test/fixture-backend.ts');
  const smokeSource = read('packages/harness-adapter/test/stdio-smoke.test.ts');
  const requiredFixtureFacts = [
    'requests/apply-action-request.json', 'responses/apply-action-result-response.json',
    'responses/apply-action-protocol-error-response.json',
    'notifications/state-event-notification.json', 'readFile',
  ];
  for (const fact of requiredFixtureFacts) if (!fixtureSource.includes(fact)) fail('fixture backend missing ' + fact);
  const smokeFacts = [
    'spawn(process.execPath', 'MAX_FRAME_BYTES + 1', 'AIPT_HARNESS_INVALID_UTF8',
    'AIPT_HARNESS_PARTIAL_FRAME', 'AIPT_HARNESS_CANCELLED',
    'an unsupported request method fails closed in the real child',
    'an unsupported protocol version fails closed in the real child',
    'an oversized backend frame fails closed before any stdout write',
    'AIPT_TEST_CREDENTIAL', "startWorker('hang')", "child.kill('SIGTERM')",
    "process.kill(result.pid, 0)",
    'createHash', 'highWaterMark: 1',
  ];
  for (const fact of smokeFacts) if (!smokeSource.includes(fact)) fail('stdio smoke missing ' + fact);
  if (requiredFixtureFacts.every((fact) => fixtureSource.includes(fact)) &&
      smokeFacts.every((fact) => smokeSource.includes(fact))) {
    ok('fixture backend and real-child smoke retain all required behaviors');
  }

  let compatibility;
  try { compatibility = JSON.parse(read('docs/harness/compatibility.json')); }
  catch (error) { fail('compatibility metadata parse failed: ' + error.message); }
  if (compatibility) {
    if (compatibility.schema !== 'aipt.public.harness-compatibility/v1' ||
        compatibility.authority !== HARNESS_SOURCE.upgrade_authority ||
        compatibility.deepseek_harness?.installation !== HARNESS_SOURCE.installation ||
        compatibility.deepseek_harness?.previous_commit !== HARNESS_SOURCE.previous_commit ||
        compatibility.deepseek_harness?.qualified_commit !== HARNESS_SOURCE.commit ||
        compatibility.deepseek_harness?.release !== HARNESS_SOURCE.release ||
        compatibility.deepseek_harness?.source_clean_at_qualification !== true ||
        compatibility.compatibility_seam?.kind !== 'explicit-managed-subprocess-with-pipe-stdio' ||
        compatibility.compatibility_seam?.dsh_wire_vocabulary_reused !== false ||
        compatibility.compatibility_seam?.model_call_required_for_smoke !== false ||
        compatibility.compatibility_seam?.network_required_for_smoke !== false ||
        compatibility.aipt_worker?.max_frame_bytes !== 1048576 ||
        compatibility.aipt_worker?.stdout !== 'protocol-only' ||
        compatibility.aipt_worker?.stderr !== 'redacted-diagnostics-only') {
      fail('DSH compatibility metadata drifted');
    } else ok('DSH compatibility metadata is fixed and model/network-free');
  }

  const importProbe = spawnSync(
    process.execPath,
    ['--input-type=module', '--eval', "import('./packages/harness-adapter/src/index.ts')"],
    { cwd: ctx.repo, encoding: 'utf8', env: { LANG: 'C.UTF-8', TZ: 'UTC' } },
  );
  if (importProbe.status !== 0 || importProbe.stdout !== '' || importProbe.stderr !== '') {
    fail('production import is not side-effect-free');
  } else ok('production import is side-effect-free and silent');

  const probes = [
    ['third-party dependency', (s) => { s.manifest.dependencies['left-pad'] = '1.3.0'; }],
    ['network import', (s) => { s.sources['runtime.ts'] += "\nimport 'node:http';\n"; }],
    ['copied schema', (s) => { s.sources['runtime.ts'] += '\nconst copied = "https://json-schema.org/draft/2020-12/schema";\n'; }],
    ['hardcoded fixture', (s) => { s.sources['runtime.ts'] += '\nconst action = "advance-turn";\n'; }],
    ['stdout console', (s) => { s.sources['runtime.ts'] += '\nconsole.log("wire");\n'; }],
    ['ambient environment', (s) => { s.sources['process-worker.ts'] += '\nconst forwarded = process.env;\n'; }],
    ['SDK dependency removal', (s) => { delete s.manifest.dependencies[SDK]; }],
    ['registry SDK dependency', (s) => { s.manifest.dependencies[SDK] = '^1.0.0'; }],
    ['B006 Evidence coupling', (s) => { s.sources['runtime.ts'] += "\nimport '../../../internal/evidence/export.go';\n"; }],
    ['web listener', (s) => { s.sources['runtime.ts'] += '\ncreateServer().listen(8080);\n'; }],
  ];
  let missed = 0;
  for (const [label, mutate] of probes) {
    const candidate = cloneSnapshot(snapshot);
    mutate(candidate);
    if (harnessAdapterProblems(candidate).length === 0) { missed += 1; fail('mutation accepted: ' + label); }
  }
  if (missed === 0) ok('all ' + probes.length + ' Harness Adapter mutations rejected');

  return { result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'harness-adapter', run);
