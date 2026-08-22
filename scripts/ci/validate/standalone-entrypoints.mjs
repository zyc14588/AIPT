// B001 standalone-entrypoint regression validator (repair for B001-ACC-001).
//
// Guards the defect class: every validator entrypoint must ACTUALLY execute
// when invoked directly (`node scripts/ci/validate/<name>.mjs ...`). Each
// entrypoint is spawned as a real child Node process and must:
//   - print non-empty, machine-readable JSON on stdout;
//   - carry schema / name / result fields;
//   - report its own expected validator name;
//   - exit 0 exactly when result === 'PASS'.
// A silent no-op (empty stdout with exit 0) fails this check. A negative
// probe additionally proves an induced FAIL yields a non-zero exit instead
// of a silent 0. No tracked source is mutated: the probe uses an invalid
// --expected-tree argument, not a fixture.
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { B000 } from '../lib/constants.mjs';
import { runAsMain } from '../lib/cli.mjs';

const VALIDATE_DIR = path.dirname(fileURLToPath(import.meta.url));
const EXPECTED_SCHEMA = 'aipt.public.b001-validator-report/v1';
// Deliberately impossible tree: 40 zeros can never equal the real B000 tree.
const INVALID_TREE = '0000000000000000000000000000000000000000';

function spawnEntrypoint(name, args, repo) {
  return spawnSync(process.execPath, [path.join(VALIDATE_DIR, `${name}.mjs`), ...args], {
    cwd: repo,
    encoding: 'utf8',
  });
}

function verifyReport(expectedName, label, cp, expectedResult, ok, fail) {
  let good = true;
  const stdout = (cp.stdout ?? '').trim();
  if (stdout.length === 0) {
    fail(`standalone ${label}: empty stdout — entrypoint did not run (silent no-op)`);
    return false;
  }
  let report;
  try {
    report = JSON.parse(stdout);
  } catch (err) {
    fail(`standalone ${label}: stdout is not valid JSON: ${err.message}`);
    return false;
  }
  if (typeof report.schema !== 'string' || report.schema.length === 0) {
    fail(`standalone ${label}: report.schema missing/empty`);
    good = false;
  } else if (report.schema !== EXPECTED_SCHEMA) {
    fail(`standalone ${label}: unexpected schema ${JSON.stringify(report.schema)}`);
    good = false;
  }
  if (report.name !== expectedName) {
    fail(`standalone ${label}: report.name = ${JSON.stringify(report.name)}, expected ${expectedName}`);
    good = false;
  }
  if (report.result !== 'PASS' && report.result !== 'FAIL') {
    fail(`standalone ${label}: report.result = ${JSON.stringify(report.result)}, expected PASS|FAIL`);
    good = false;
  }
  if (!Array.isArray(report.details) || report.details.length === 0) {
    fail(`standalone ${label}: report.details missing or empty`);
    good = false;
  }
  const exitOk =
    report.result === 'PASS' ? cp.status === 0 : cp.status !== null && cp.status !== 0;
  if (!exitOk) {
    fail(`standalone ${label}: exit status ${cp.status} does not follow result ${report.result}`);
    good = false;
  }
  if (report.result !== expectedResult) {
    fail(`standalone ${label}: result ${report.result} != expected ${expectedResult}`);
    good = false;
  }
  if (good) {
    ok(`standalone ${label}: executed, ${report.details.length} detail(s), result ${report.result}, exit ${cp.status}`);
  }
  return good;
}

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };

  const positives = [
    {
      name: 'b000-retro',
      label: 'b000-retro (fixed commit + tree)',
      args: ['--repo', ctx.repo, '--commit', B000.commit, '--expected-tree', B000.tree],
      result: 'PASS',
    },
    { name: 'supply-chain', label: 'supply-chain', args: ['--repo', ctx.repo], result: 'PASS' },
    { name: 'sbom', label: 'sbom', args: ['--repo', ctx.repo], result: 'PASS' },
    { name: 'status-transition', label: 'status-transition', args: ['--repo', ctx.repo], result: 'PASS' },
    { name: 'runtime-shell', label: 'runtime-shell', args: ['--repo', ctx.repo], result: 'PASS' },
    { name: 'adapter-sdk', label: 'adapter-sdk', args: ['--repo', ctx.repo], result: 'PASS' },
    { name: 'harness-adapter', label: 'harness-adapter', args: ['--repo', ctx.repo], result: 'PASS' },
  ];
  for (const c of positives) {
    const cp = spawnEntrypoint(c.name, c.args, ctx.repo);
    verifyReport(c.name, c.label, cp, c.result, ok, fail);
  }

  // Negative probe: an induced FAIL must print its JSON report AND exit
  // non-zero. Under the B001-ACC-001 defect this exited 0 with no output.
  const neg = spawnEntrypoint(
    'b000-retro',
    ['--repo', ctx.repo, '--commit', B000.commit, '--expected-tree', INVALID_TREE],
    ctx.repo,
  );
  verifyReport('b000-retro', 'b000-retro negative probe (invalid --expected-tree)', neg, 'FAIL', ok, fail);

  return { name: 'standalone-entrypoints', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'standalone-entrypoints', run);
